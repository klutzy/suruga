use std::io::prelude::*;
use rand::OsRng;
use num::traits::FromPrimitive;

use tls_result::{TlsResult, TlsError, TlsErrorKind};
use tls_result::TlsErrorKind::{UnexpectedMessage, RecordOverflow, BadRecordMac, AlertReceived};
use alert::{self, Alert};
use handshake::{Handshake, HandshakeBuffer};
use util::u64_be_array;
use util::{ReadExt, WriteExt};
use cipher::{Encryptor, Decryptor};
use tls_item::TlsItem;

use self::ContentType::{ChangeCipherSpecTy, AlertTy, HandshakeTy, ApplicationDataTy};
use self::Message::{HandshakeMessage, ChangeCipherSpecMessage, AlertMessage,
                    ApplicationDataMessage};

pub static TLS_VERSION: (u8, u8) = (3, 3);

enum_from_primitive! {
    #[repr(u8)]
    #[derive(Copy, Clone, PartialEq, Debug)]
    pub enum ContentType {
        ChangeCipherSpecTy = 20,
        AlertTy = 21,
        HandshakeTy = 22,
        ApplicationDataTy = 23,
        // HeartBeat = 24, RFC 6520 extension :-)
    }
}

/// maximum length of Record (excluding content_type, version, length fields)
pub const RECORD_MAX_LEN: usize = 1 << 14;

/// maximum length of EncryptedRecord (excluding content_type, version, length fields)
pub const ENC_RECORD_MAX_LEN: usize = (1 << 14) + 2048;

/// corresponds to `TLSPlaintext` in Section 6.2.1.
#[derive(Debug)]
pub struct Record {
    pub content_type: ContentType,
    pub ver_major: u8,
    pub ver_minor: u8,
    // fragment length < 2^14
    pub fragment: Vec<u8>,
}

impl Record {
    pub fn new(content_type: ContentType,
               ver_major: u8,
               ver_minor: u8,
               fragment: Vec<u8>) -> Record {
        let len = fragment.len();
        if len > RECORD_MAX_LEN {
            panic!("record too long: {} > 2^14", len);
        }

        Record {
            content_type: content_type,
            ver_major: ver_major,
            ver_minor: ver_minor,
            fragment: fragment,
        }
    }
}

/// Writes `Record` or higher-layer message to a writable object.
/// Record is internally encrypted before written.
pub struct RecordWriter<W: Write> {
    writer: W,
    // if encryptor is None, handshake is not done yet.
    encryptor: Option<Box<Encryptor + Send + 'static>>,
    write_count: u64,
}

impl<W: Write> RecordWriter<W> {
    /// Create new `RecordWriter` with null encryption.
    /// Invoke `set_encryptor` to set encryptor.
    pub fn new(writer: W) -> RecordWriter<W> {
        RecordWriter {
            writer: writer,
            encryptor: None,
            write_count: 0,
        }
    }

    #[inline]
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.writer
    }

    /// Set encryptor and reset count.
    /// This must be called only once.
    pub fn set_encryptor(&mut self, encryptor: Box<Encryptor + Send + 'static>) {
        assert!(self.encryptor.is_none());
        self.encryptor = Some(encryptor);
        self.write_count = 0;
    }

    pub fn write_record(&mut self, record: Record) -> TlsResult<()> {
        let encrypted_fragment = match self.encryptor {
            None => record.fragment,
            Some(ref mut encryptor) => {
                let seq_num = u64_be_array(self.write_count);

                let mut ad = Vec::new();
                ad.extend(&seq_num);
                ad.push(record.content_type as u8);
                ad.push(record.ver_major);
                ad.push(record.ver_minor);
                let frag_len = record.fragment.len() as u16;
                ad.push((frag_len >> 8) as u8);
                ad.push(frag_len as u8);

                let encrypted_fragment = encryptor.encrypt(&seq_num,
                                                           &record.fragment,
                                                           &ad);
                encrypted_fragment
            }
        };

        let fragment_len = encrypted_fragment.len();
        if fragment_len > ENC_RECORD_MAX_LEN {
            panic!("record too long: {} > 2^14 + 2048", fragment_len);
        }

        try!(self.writer.write_u8(record.content_type as u8));
        try!(self.writer.write_u8(record.ver_major));
        try!(self.writer.write_u8(record.ver_minor));
        try!(self.writer.write_be_u16(fragment_len as u16));
        try!(self.writer.write_all(&encrypted_fragment));

        self.write_count += 1;

        Ok(())
    }

    pub fn write_data(&mut self, ty: ContentType, data: &[u8]) -> TlsResult<()> {
        let (major, minor) = TLS_VERSION;
        // TODO: configurable maxlen
        for fragment in data.chunks(RECORD_MAX_LEN) {
            let fragment = fragment.to_vec();
            let record = Record::new(ty, major, minor, fragment);
            try!(self.write_record(record));
        }

        Ok(())
    }

    pub fn write_handshake(&mut self, handshake: &Handshake) -> TlsResult<()> {
        let mut data = Vec::new();
        try!(handshake.tls_write(&mut data));
        self.write_data(HandshakeTy, &data)
    }

    pub fn write_alert(&mut self, alert: &Alert) -> TlsResult<()> {
        let mut data = Vec::new();
        try!(alert.tls_write(&mut data));
        self.write_data(AlertTy, &data)
    }

    pub fn write_change_cipher_spec(&mut self) -> TlsResult<()> {
        self.write_data(ChangeCipherSpecTy, &[1u8])
    }

    pub fn write_application_data(&mut self, data: &[u8]) -> TlsResult<()> {
        if self.encryptor.is_none() {
            panic!("attempted to write ApplicationData before handshake");
        }
        self.write_data(ApplicationDataTy, data)
    }
}

/// Return type of `RecordReader.read_record()`.
pub enum Message {
    HandshakeMessage(Handshake),
    ChangeCipherSpecMessage,
    AlertMessage(Alert),
    ApplicationDataMessage(Vec<u8>),
}

pub struct RecordReader<R: ReadExt> {
    reader: R,
    // if decryptor is none, handshake is not done yet.
    decryptor: Option<Box<Decryptor + Send + 'static>>,
    read_count: u64,
    handshake_buffer: HandshakeBuffer,
}

/// Reads `Record` or `Message` from a readable object.
/// Record is internally decrypted after read.
impl<R: ReadExt> RecordReader<R> {
    pub fn new(reader: R) -> RecordReader<R> {
        RecordReader {
            reader: reader,
            decryptor: None,
            read_count: 0,
            handshake_buffer: HandshakeBuffer::new(),
        }
    }

    #[inline]
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.reader
    }

    /// Set decryptor and reset count.
    /// This must be called only once.
    pub fn set_decryptor(&mut self, decryptor: Box<Decryptor + Send + 'static>) {
        assert!(self.decryptor.is_none());
        self.decryptor = Some(decryptor);
        self.read_count = 0;
    }

    /// Read a record from readable stream.
    ///
    /// Any record with unknown content type is treated as an error.
    fn read_record(&mut self) -> TlsResult<Record> {
        let content_type = {
            let ty = try!(self.reader.read_u8());
            let ct: Option<ContentType> = FromPrimitive::from_u8(ty);
            match ct {
                Some(ty) => ty,
                None => return tls_err!(UnexpectedMessage, "unexpected ContentType: {}", ty),
            }
        };

        let major = try!(self.reader.read_u8());
        let minor = try!(self.reader.read_u8());

        let len = {
            let len = try!(self.reader.read_be_u16()) as usize;
            if len > ENC_RECORD_MAX_LEN {
                return tls_err!(RecordOverflow, "TLSEncryptedText too long: {}", len);
            }
            len
        };

        let fragment = try!(self.reader.read_exact(len as usize));

        let record = match self.decryptor {
            None => {
                if fragment.len() > RECORD_MAX_LEN {
                    return tls_err!(RecordOverflow,
                                    "decrypted record too long: {}",
                                    fragment.len());
                }
                Record::new(content_type, major, minor, fragment)
            }
            Some(ref mut decryptor) => {
                let seq_num = u64_be_array(self.read_count);

                let mut ad = Vec::new();
                ad.extend(&seq_num);
                ad.push(content_type as u8); // TLSCompressed.type
                ad.push(major);
                ad.push(minor);

                let mac_len = decryptor.mac_len();
                let total_len = fragment.len();
                if total_len < mac_len {
                    return tls_err!(BadRecordMac, "encrypted message too short: {}", total_len);
                }
                let frag_len = (total_len - mac_len) as u16;
                ad.push((frag_len >> 8) as u8);
                ad.push(frag_len as u8);

                // TODO: "seq_num as nonce" is chacha20poly1305-specific
                let data = try!(decryptor.decrypt(&seq_num, &fragment, &ad));
                if data.len() > RECORD_MAX_LEN {
                    // decryption routine went wrong.
                    return panic!("decrypted record too long: {}", data.len());
                }

                Record::new(content_type, major, minor, data)
            }
        };

        self.read_count += 1;

        Ok(record)
    }

    /// Read records until a "complete" message is found, then return the message.
    ///
    /// if invalid ChangeCipherSpec/Alert/Handshake message is found, return Err.
    /// (application record is always considered "complete" and "valid"
    /// since it is opaque to TLS layer.)
    ///
    /// Note: In theory, `Alert` message can be broken into several records.
    /// It is not useful in practice and requires more complex routines.
    /// (Incorrect handling leads to [Alert attack](http://www.mitls.org/wsgi/alert-attack).)
    ///
    /// We treat partial alert message as an error and returns `UnexpectedMessage`.
    pub fn read_message(&mut self) -> TlsResult<Message> {
        match try!(self.handshake_buffer.get_message()) {
            Some(handshake_msg) => return Ok(HandshakeMessage(handshake_msg)),
            None => {}
        }

        // ok, no message found. read it from network!
        loop {
            // TODO: what if handshake record is present in buffer then
            // other record comes? is it legal?

            let record = try!(self.read_record());
            match record.content_type {
                ChangeCipherSpecTy => {
                    if record.fragment.len() != 1 || record.fragment[0] != 1 {
                        return tls_err!(UnexpectedMessage, "invalid ChangeCipherSpec arrived");
                    }
                    return Ok(ChangeCipherSpecMessage);
                }
                AlertTy => {
                    let len = record.fragment.len();
                    if len == 0 {
                        return tls_err!(UnexpectedMessage, "zero-length Alert record arrived");
                    } else if len < 2 {
                        // alert attack
                        return tls_err!(UnexpectedMessage, "awkward Alert record arrived");
                    }
                    let level = FromPrimitive::from_u8(record.fragment[0]);
                    let desc = FromPrimitive::from_u8(record.fragment[1]);
                    match (level, desc) {
                        (Some(level), Some(desc)) => {
                            return Ok(AlertMessage(try!(Alert::new(level, desc))));
                        }
                        _ => return tls_err!(UnexpectedMessage,
                                             "unknown alert: {:?}",
                                             record.fragment),
                    }
                }
                HandshakeTy => {
                    if record.fragment.len() == 0 {
                        return tls_err!(UnexpectedMessage, "zero-length Handshake arrived");
                    }
                    self.handshake_buffer.add_record(&record.fragment);

                    match try!(self.handshake_buffer.get_message()) {
                        Some(handshake_msg) => return Ok(HandshakeMessage(handshake_msg)),
                        _ => {}
                    }
                }
                ApplicationDataTy => {
                    return Ok(ApplicationDataMessage(record.fragment));
                }
            }
        }
    }

    pub fn read_application_data(&mut self) -> TlsResult<Vec<u8>> {
        if self.decryptor.is_none() {
            panic!("ApplicationData called before handshake");
        }
        loop {
            let msg = try!(self.read_message());
            match msg {
                ApplicationDataMessage(msg) => return Ok(msg),
                // TODO: handle other cases
                AlertMessage(..) => unimplemented!(),
                ChangeCipherSpecMessage(..) => unimplemented!(), // this should not come here
                HandshakeMessage(..) => unimplemented!(), // TODO: re-handshake
            }
        }
    }

    pub fn read_handshake(&mut self) -> TlsResult<Handshake> {
        match try!(self.read_message()) {
            HandshakeMessage(handshake) => Ok(handshake),
            AlertMessage(alert) => tls_err!(AlertReceived, "alert: {:?}", alert.description),
            _ => tls_err!(UnexpectedMessage, "expected Handshake"),
        }
    }

    pub fn read_change_cipher_spec(&mut self) -> TlsResult<()> {
        match try!(self.read_message()) {
            ChangeCipherSpecMessage => Ok(()),
            _ => tls_err!(UnexpectedMessage, "expected ChangeCipherSpec"),
        }
    }
}

pub struct Tls<R: Read, W: Write> {
    pub writer: RecordWriter<W>,
    pub reader: RecordReader<R>,
    pub rng: OsRng,
}

impl<R: Read, W: Write> Tls<R, W> {
    pub fn new(reader: R, writer: W, rng: OsRng) -> Tls<R, W> {
        let writer = RecordWriter::new(writer);
        let reader = RecordReader::new(reader);
        Tls {
            writer: writer,
            reader: reader,
            rng: rng,
        }
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
