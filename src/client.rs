use std::io;
use std::io::prelude::*;
use std::net::TcpStream;
use std::cmp;
use rand::{Rng, OsRng};

use alert;
use tls_result::{TlsResult, TlsError, TlsErrorKind};
use tls_result::TlsErrorKind::{UnexpectedMessage, InternalError, DecryptError, IllegalParameter};
use util::{SurugaError, crypto_compare};
use cipher::{self, Aead};
use cipher::prf::Prf;
use crypto::sha2::sha256;
use tls_item::{TlsItem, DummyItem};
use handshake::{self, Handshake};
use tls::{TlsReader, TlsWriter, TLS_VERSION};

// handshake is done during construction.
pub struct TlsClient<R: Read, W: Write> {
    pub reader: TlsReader<R>,
    pub writer: TlsWriter<W>,
    pub rng: OsRng,
    buf: Vec<u8>,
}

impl<R: Read, W: Write> TlsClient<R, W> {
    pub fn new(reader: R, writer: W, rng: OsRng) -> TlsResult<TlsClient<R, W>> {
        let mut client = TlsClient {
            reader: TlsReader::new(reader),
            writer: TlsWriter::new(writer),
            rng: rng,
            buf: Vec::new(),
        };

        // handshake failed. send alert if necessary
        match client.handshake() {
            Ok(()) => {}
            Err(err) => return Err(client.send_tls_alert(err)),
        }
        Ok(client)
    }

    #[inline]
    pub fn reader(&mut self) -> &mut R {
        self.reader.get_mut()
    }

    #[inline]
    pub fn writer(&mut self) -> &mut W {
        self.writer.get_mut()
    }

    // this does not send alert when error occurs
    fn handshake(&mut self) -> TlsResult<()> {
        // expect specific HandshakeMessage. otherwise return Err
        macro_rules! expect {
            ($var:ident) => ({
                match try!(self.reader.read_handshake()) {
                    handshake::Handshake::$var(data) => data,
                    _ => return tls_err!(UnexpectedMessage, "unexpected handshake message found"),
                }
            })
        }

        let cli_random = {
            let mut random_bytes = [0u8; 32];
            self.rng.fill_bytes(&mut random_bytes);
            random_bytes.to_vec()
        };
        let random = try!(handshake::Random::new(cli_random.clone()));

        // the only cipher we currently support
        let cipher_suite = cipher::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;

        let curve_list = vec!(handshake::NamedCurve::secp256r1);
        let curve_list = try!(handshake::Extension::new_elliptic_curve_list(curve_list));

        let format_list = vec!(handshake::ECPointFormat::uncompressed);
        let format_list = try!(handshake::Extension::new_ec_point_formats(format_list));

        let extensions = vec!(curve_list, format_list);

        let client_hello = try!(Handshake::new_client_hello(random, cipher_suite, extensions));
        try!(self.writer.write_handshake(&client_hello));

        let server_hello_data = expect!(server_hello);
        {
            let server_major = server_hello_data.server_version.major;
            let server_minor = server_hello_data.server_version.minor;
            if (server_major, server_minor) != TLS_VERSION {
                return tls_err!(IllegalParameter,
                                "wrong server version: {} {}",
                                server_major,
                                server_minor);
            }

            if server_hello_data.cipher_suite != cipher_suite {
                return tls_err!(IllegalParameter,
                                "cipher suite mismatch: found {:?}",
                                server_hello_data.cipher_suite);
            }

            if server_hello_data.compression_method != handshake::CompressionMethod::null {
                return tls_err!(IllegalParameter, "compression method mismatch");
            }

            // FIXME: check if server sent unknown extension
            // it is currently done by just not understanding any extensions
            // other than we used.
        }

        // we always expect certificate.
        let certificate_list = expect!(certificate);
        // TODO: cert validation not implemented yet

        // we always use server key exchange
        let server_key_ex_data = expect!(server_key_exchange);
        let kex = cipher_suite.new_kex();
        let (key_data, pre_master_secret) = try!(kex.compute_keys(&server_key_ex_data,
                                                                  &mut self.rng));

        expect!(server_hello_done);

        let client_key_exchange = try!(Handshake::new_client_key_exchange(key_data));
        try!(self.writer.write_handshake(&client_key_exchange));

        try!(self.writer.write_change_cipher_spec());

        // SECRET
        let master_secret = {
            let mut label_seed = b"master secret".to_vec();
            label_seed.extend(&cli_random);
            label_seed.extend(&server_hello_data.random[..]);

            let mut prf = Prf::new(pre_master_secret, label_seed);
            prf.get_bytes(48)
        };

        let aead = cipher_suite.new_aead();

        // SECRET
        let read_key = {
            let mut label_seed = b"key expansion".to_vec();
            label_seed.extend(&server_hello_data.random[..]);
            label_seed.extend(&cli_random);

            let mut prf = Prf::new(master_secret.clone(), label_seed);

            // mac_key is not used in AEAD configuration.

            let enc_key_length = aead.key_size();

            let write_key = prf.get_bytes(enc_key_length);
            let encryptor = aead.new_encryptor(write_key);
            self.writer.set_encryptor(encryptor);

            // this will be set after receiving ChangeCipherSpec.
            let read_key = prf.get_bytes(enc_key_length);

            // chacha20-poly1305 does not use iv.

            read_key
        };

        // FIXME we should get "raw" packet data and hash them incrementally
        let msgs = {
            let mut msgs = Vec::new();
            try!(client_hello.tls_write(&mut msgs));
            try!(Handshake::server_hello(server_hello_data).tls_write(&mut msgs));
            try!(Handshake::certificate(certificate_list).tls_write(&mut msgs));
            try!(Handshake::server_key_exchange(server_key_ex_data).tls_write(&mut msgs));
            try!(Handshake::server_hello_done(DummyItem).tls_write(&mut msgs));
            try!(client_key_exchange.tls_write(&mut msgs));
            msgs
        };

        // this only verifies Handshake messages! what about others?
        // ApplicationData messages are not permitted until now.
        // ChangeCipherSpec messages are only permitted after ClinetKeyExchange.
        // Alert messages can be problematic - they are not verified and
        // can be broken into several records. This leads to alert attack.
        // since we don't accept strange alerts, all "normal" alert messages are
        // treated as error, so now we can assert that we haven't received alerts.
        let verify_hash = sha256(&msgs);

        let client_verify_data = {
            let finished_label = b"client finished";

            let mut label_seed = finished_label.to_vec();
            label_seed.extend(&verify_hash);
            let mut prf = Prf::new(master_secret.clone(), label_seed);
            prf.get_bytes(cipher_suite.verify_data_len())
        };
        let finished = try!(Handshake::new_finished(client_verify_data));
        try!(self.writer.write_handshake(&finished));

        // Although client->server is encrypted, server->client isn't yet.
        // server may send either ChangeCipherSpec or Alert.
        try!(self.reader.read_change_cipher_spec());

        // from now server starts encryption.
        self.reader.set_decryptor(aead.new_decryptor(read_key));

        let server_finished = expect!(finished);
        {
            let verify_hash = {
                // ideally we may save "raw" packet data..
                let mut serv_msgs = Vec::new();
                // FIXME: this should not throw "io error".. should throw "internal error"
                try!(Write::write_all(&mut serv_msgs, &msgs));
                try!(finished.tls_write(&mut serv_msgs));

                let verify_hash = sha256(&serv_msgs);
                verify_hash
            };

            let server_verify_data = {
                let finished_label = b"server finished";

                let mut label_seed = finished_label.to_vec();
                label_seed.extend(&verify_hash);
                let mut prf = Prf::new(master_secret, label_seed);
                prf.get_bytes(cipher_suite.verify_data_len())
            };

            let verify_ok = crypto_compare(&server_finished,
                                           &server_verify_data);
            if !verify_ok {
                return tls_err!(DecryptError, "server sent wrong verify data");
            }
        }

        Ok(())
    }

    pub fn close(&mut self) -> TlsResult<()> {
        let alert_data = alert::Alert {
            level: alert::AlertLevel::fatal,
            description: alert::AlertDescription::close_notify,
        };
        try!(self.writer.write_alert(&alert_data));
        Ok(())
    }

    // send fatal alert and return error
    // (it may be different to `err`, because writing alert can fail)
    pub fn send_tls_alert(&mut self, err: TlsError) -> TlsError {
        match err.kind {
            TlsErrorKind::IoFailure => return err,
            _ => {
                let alert = alert::Alert::from_tls_err(&err);
                let result = self.writer.write_alert(&alert);
                match result {
                    Ok(()) => return err,
                    Err(err) => return err,
                }
            }
        }
    }
}

impl TlsClient<TcpStream, TcpStream> {
    pub fn from_tcp(stream: TcpStream) -> TlsResult<TlsClient<TcpStream, TcpStream>> {
        let rng = match OsRng::new() {
            Ok(rng) => rng,
            Err(..) => return tls_err!(InternalError, "failed to create OsRng"),
        };

        let reader = try!(stream.try_clone());
        let writer = stream;
        TlsClient::new(reader, writer, rng)
    }
}

impl<R: Read, W: Write> Write for TlsClient<R, W> {
    // this either writes all or fails.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        try!(self.write_all(buf));
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        let result = self.writer.write_application_data(buf);
        match result {
            Ok(()) => Ok(()),
            Err(err) => {
                let err = self.send_tls_alert(err);
                // FIXME more verbose io error
                Err(io::Error::new(io::ErrorKind::Other, SurugaError {
                    desc: "TLS write error",
                    cause: Some(Box::new(err)),
                }))
            }
        }
    }
}

// A replacement for the deprecated std::slice::bytes::copy_memory
fn copy_memory(from: &[u8], mut to: &mut [u8]) -> usize {
    to.write(from).unwrap()
}

impl<R: Read, W: Write> Read for TlsClient<R, W> {
    // if ssl connection is failed, return `EndOfFile`.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut pos: usize = 0;
        let len = buf.len();
        while pos < len {
            let remaining = len - pos;
            if self.buf.len() == 0 {
                let data = match self.reader.read_application_data() {
                    Ok(data) => data,
                    Err(_err) => {
                        break; // FIXME: stop if EOF. otherwise raise error?
                    }
                };
                self.buf.extend(&data);
            }

            let selflen = self.buf.len();
            let necessary = cmp::min(remaining, selflen);
            copy_memory(&self.buf[.. necessary], &mut buf[pos .. pos + necessary]);
            pos += necessary;

            self.buf = self.buf[necessary..].to_vec();
        }

        Ok(pos)
    }
}
