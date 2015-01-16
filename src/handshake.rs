use std::io::MemReader;

use tls::TLS_VERSION;
use tls_result::TlsResult;
use tls_result::TlsErrorKind::{InternalError, UnexpectedMessage};
use tls_item::{TlsItem, DummyItem, ObscureData};
use signature::SignatureAndHashAlgorithmVec;
use cipher::CipherSuite;

// This is actually `struct { gmt_unix_time: u32, random_bytes: [u8, ..28] }`
// cf: http://tools.ietf.org/html/draft-mathewson-no-gmtunixtime-00
tls_array!(Random = [u8, ..32]);

tls_vec!(CipherSuiteVec = CipherSuite(2, (1 << 16) - 2));

tls_enum!(u8, enum CompressionMethod {
    null(0),
    DEFLATE(1) // RFC 3749
});
tls_vec!(CompressionMethodVec = CompressionMethod(1, (1 << 8) - 1));

tls_struct!(struct ProtocolVersion { major: u8, minor: u8 });

tls_vec!(SessionId = u8(0, 32));

tls_vec!(Asn1Cert = u8(1, (1 << 24) - 1));

// RFC 4492

tls_enum!(u16, enum NamedCurve {
    sect163k1 (1), sect163r1 (2), sect163r2 (3),
    sect193r1 (4), sect193r2 (5), sect233k1 (6),
    sect233r1 (7), sect239k1 (8), sect283k1 (9),
    sect283r1 (10), sect409k1 (11), sect409r1 (12),
    sect571k1 (13), sect571r1 (14), secp160k1 (15),
    secp160r1 (16), secp160r2 (17), secp192k1 (18),
    secp192r1 (19), secp224k1 (20), secp224r1 (21),
    secp256k1 (22), secp256r1 (23), secp384r1 (24),
    secp521r1 (25),
    arbitrary_explicit_prime_curves(0xFF01),
    arbitrary_explicit_char2_curves(0xFF02)
});
tls_vec!(EllipticCurveList = NamedCurve(1, (1 << 16) - 1));

tls_enum!(u8, enum ECPointFormat {
    uncompressed (0), ansiX962_compressed_prime (1),
    ansiX962_compressed_char2 (2)
});
tls_vec!(ECPointFormatList = ECPointFormat(1, (1 << 8) - 1));

// FIXME: Extension has the following structure:
// struct Extension {
//     extension_type: u8,
//     extension_data: opaque<1..2^16-1>,
// }
// and actual structure of `extension_data` depends on `extension_type`.
// Note that this is not exactly what `tls_enum_struct` wants!
// It's why we define horrible structs here.
tls_vec!(EllipticCurveListList = EllipticCurveList(1, (1 << 16) - 1));
tls_vec!(ECPointFormatListList = ECPointFormatList(1, (1 << 16) - 1));

tls_enum_struct!(u16, enum Extension {
    // RFC 6066
    //server_name(0),
    //max_fragment_length(1),
    //client_certificate_url(2),
    //trusted_ca_keys(3),
    //truncated_hmac(4),
    //status_request(5),
    // RFC 4492
    elliptic_curves(EllipticCurveListList) = 10,
    ec_point_formats(ECPointFormatListList) = 11
    // RFC 5246
    //signature_algorithms(13)
});
impl Extension {
    pub fn new_elliptic_curve_list(list: Vec<NamedCurve>) -> TlsResult<Extension> {
        let list = try!(EllipticCurveList::new(list));
        let list = try!(EllipticCurveListList::new(vec!(list)));
        let list = Extension::elliptic_curves(list);
        Ok(list)
    }

    pub fn new_ec_point_formats(list: Vec<ECPointFormat>) -> TlsResult<Extension> {
        let list = try!(ECPointFormatList::new(list));
        let list = try!(ECPointFormatListList::new(vec!(list)));
        let list = Extension::ec_point_formats(list);
        Ok(list)
    }
}

tls_vec!(ExtensionVec = Extension(0, (1 << 16) - 1));
tls_option!(ExtensionVec);

// struct Handshake {
//     msg_type: u8,
//     len: u24,
//     data: <depends on msg_type>
// }
macro_rules! tls_handshake(
    (
        $(
            $name:ident($body_ty:ty) = $num:tt, // $num: integer literal
        )+
    ) => (
        #[allow(non_camel_case_types)]
        pub enum Handshake {
            $(
                $name($body_ty),
            )+
        }

        impl TlsItem for Handshake {
            fn tls_write<W: Writer>(&self, writer: &mut W) -> TlsResult<()> {
                match *self {
                    $(
                        Handshake::$name(ref body) => {
                            try!(writer.write_u8(tt_to_expr!($num)));

                            let len = body.tls_size();
                            try!(writer.write_u8((len >> 16) as u8));
                            try!(writer.write_u8((len >> 8) as u8));
                            try!(writer.write_u8(len as u8));

                            try!(body.tls_write(writer));
                        }
                    )+
                }

                Ok(())
            }

            fn tls_read<R: Reader>(reader: &mut R) -> TlsResult<Handshake> {
                let ty = try!(reader.read_u8());

                // HandshakeBuffer already checked validity of length
                let _len = {
                    let n1 = try!(reader.read_u8()) as u32;
                    let n2 = try!(reader.read_u8()) as u32;
                    let n3 = try!(reader.read_u8()) as u32;
                    (n1 << 16) | (n2 << 8) | n3
                };

                let ret = match ty {
                    $(
                        tt_to_pat!($num) => {
                            let body: $body_ty = try!(TlsItem::tls_read(reader));
                            Handshake::$name(body)
                        }
                    )+
                    _ => return tls_err!(UnexpectedMessage,
                                         "unexpected Handshake message: type {}",
                                         ty),
                };

                let should_be_err = reader.read_u8();
                match should_be_err {
                    Err(_) => {},
                    Ok(_) => return tls_err!(InternalError, "expected EOF but found not"),
                }

                Ok(ret)
            }

            fn tls_size(&self) -> u64 {
                let body_len = match *self {
                    $(
                        Handshake::$name(ref body) => body.tls_size(),
                    )+
                };
                // msg_type 1 byte, length 3 bytes
                1 + 3 + body_len
            }
        }
    )
);

tls_handshake!(
    hello_request(DummyItem) = 0,
    client_hello(ClientHello) = 1,
    server_hello(ServerHello) = 2,
    // hello_verify_request(..) = 3, RFC 6347: DTLS
    // NewSessionTicket(..) = 4, RFC 5077: session resumption w/o server-side state
    certificate(CertificateList) = 11,
    server_key_exchange(ObscureData) = 12,
    certificate_request(CertificateRequest) = 13,
    server_hello_done(DummyItem) = 14,
    // certificate_verify = 15,
    client_key_exchange(ObscureData) = 16,
    finished(VerifyData) = 20,
);

tls_struct!(struct ClientHello {
    client_version: ProtocolVersion,
    random: Random,
    session_id: SessionId,
    cipher_suites: CipherSuiteVec,
    compression_methods: CompressionMethodVec,
    extensions: Option<ExtensionVec>
});

tls_struct!(struct ServerHello {
    server_version: ProtocolVersion,
    random: Random,
    session_id: SessionId,
    cipher_suite: CipherSuite,
    compression_method: CompressionMethod,
    extensions: Option<ExtensionVec>
});

tls_vec!(CertificateList = Asn1Cert(0, (1 << 24) - 1));

tls_enum!(u8, enum ClientCertificateType {
      rsa_sign(1), dss_sign(2), rsa_fixed_dh(3), dss_fixed_dh(4),
      rsa_ephemeral_dh_RESERVED(5), dss_ephemeral_dh_RESERVED(6),
      fortezza_dms_RESERVED(20)
});
tls_vec!(CertificiateTypeVec = ClientCertificateType(1, (1 << 8) - 1));

tls_vec!(DistinguishedName = u8(1, (1 << 16) - 1));
tls_vec!(DistinguishedNameVec = DistinguishedName(0, (1 << 16) - 1));

tls_struct!(struct CertificateRequest {
    certificate_types: CertificiateTypeVec,
    supported_signature_algorithms: SignatureAndHashAlgorithmVec,
    certificate_authorities: DistinguishedNameVec
});

// FIXME TLS 1.2 says the length can be longer for future ciphe suites.
tls_array!(VerifyData = [u8, ..12]);

// buffer for handshake protocol
pub struct HandshakeBuffer {
    buf: Vec<u8>,
}

impl HandshakeBuffer {
    pub fn new() -> HandshakeBuffer {
        HandshakeBuffer { buf: Vec::new() }
    }

    pub fn add_record(&mut self, fragment: Vec<u8>) {
        self.buf.push_all(&fragment[]);
    }

    // if message is arrived but has unknown type, the message is discarded and returns error.
    pub fn get_message(&mut self) -> TlsResult<Option<Handshake>> {
        let len = self.buf.len();
        // we need to read at least ty and length
        if len < 4 {
            return Ok(None);
        }

        let n1 = self.buf[1] as usize;
        let n2 = self.buf[2] as usize;
        let n3 = self.buf[3] as usize;
        let wanted_len: usize = (n1 << 16) | (n2 << 8) | n3;
        let wanted_len = wanted_len + 4;

        if len < wanted_len {
            return Ok(None);
        }

        // FIXME bad clone?
        let (message, remaining) = {
            let (message, remaining) = self.buf.split_at_mut(wanted_len);
            let message = message.to_vec();
            let remaining = remaining.to_vec();
            (message, remaining)
        };
        self.buf = remaining;

        let mut reader = MemReader::new(message);
        let message: Handshake = try!(TlsItem::tls_read(&mut reader));
        let ret = Ok(Some(message));

        ret
    }
}

impl Handshake {
    pub fn new_client_hello(random: Random,
                            cipher_suite: CipherSuite,
                            extensions: Vec<Extension>) -> TlsResult<Handshake> {
        let client_hello_body = {
            let client_version = {
                let (major, minor) = TLS_VERSION;

                ProtocolVersion {
                    major: major,
                    minor: minor,
                }
            };

            // TODO support session resumption
            let session_id = {
                let data = Vec::new();
                try!(SessionId::new(data))
            };

            let cipher_suites = {
                let data = vec!(cipher_suite);
                try!(CipherSuiteVec::new(data))
            };

            let compression_methods = {
                let data = vec!(CompressionMethod::null);
                try!(CompressionMethodVec::new(data))
            };

            let extensions = if extensions.len() == 0 {
                None
            } else {
                let ext = try!(ExtensionVec::new(extensions));
                Some(ext)
            };
            ClientHello {
                client_version: client_version,
                random: random,
                session_id: session_id,
                cipher_suites: cipher_suites,
                compression_methods: compression_methods,
                extensions: extensions,
            }
        };

        Ok(Handshake::client_hello(client_hello_body))
    }

    pub fn new_client_key_exchange(data: Vec<u8>) -> TlsResult<Handshake> {
        let data = ObscureData::new(data);
        Ok(Handshake::client_key_exchange(data))
    }

    pub fn new_finished(data: Vec<u8>) -> TlsResult<Handshake> {
        let data = try!(VerifyData::new(data));
        Ok(Handshake::finished(data))
    }
}

#[cfg(test)]
mod test {
    use std::io::MemReader;
    use tls_item::TlsItem;
    use cipher::CipherSuite;

    use super::{ProtocolVersion, SessionId, CipherSuiteVec, CompressionMethod,
                CompressionMethodVec, ClientHello, Handshake, Random};

    #[test]
    fn test_parse_client_hello() {
        let client_hello_msg = {
            let client_hello_body = {
                let client_version = {
                    let (major, minor) = (3, 3);

                    ProtocolVersion {
                        major: major,
                        minor: minor,
                    }
                };

                let random = {
                    let random_bytes = [0u8; 32].to_vec();
                    Random::new(random_bytes).unwrap()
                };

                let session_id = {
                    let data = Vec::new();
                    SessionId::new(data).unwrap()
                };

                let cipher_suites = {
                    let data = vec!(CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
                    CipherSuiteVec::new(data).unwrap()
                };

                let compression_methods = {
                    let data = vec!(CompressionMethod::null);
                    CompressionMethodVec::new(data).unwrap()
                };

                ClientHello {
                    client_version: client_version,
                    random: random,
                    session_id: session_id,
                    cipher_suites: cipher_suites,
                    compression_methods: compression_methods,
                    extensions: None,
                }
            };

            Handshake::client_hello(client_hello_body)
        };

        let mut packet = Vec::new();
        client_hello_msg.tls_write(&mut packet).unwrap();

        let mut reader = MemReader::new(packet.clone());
        let client_hello_msg_2: Handshake = TlsItem::tls_read(&mut reader).unwrap();

        let mut packet_2 = Vec::new();
        client_hello_msg_2.tls_write(&mut packet_2).unwrap();

        assert_eq!(packet, packet_2);
    }
}
