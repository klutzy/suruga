use std::rand::OsRng;

use tls_result::TlsResult;
use tls_result::TlsErrorKind::UnexpectedMessage;
use tls_item::TlsItem;
use self::chacha20_poly1305::ChaCha20Poly1305;
use self::ecdhe::EllipticDiffieHellman;

pub mod prf;
pub mod ecdhe;
pub mod chacha20_poly1305;

pub trait Aead {
    fn key_size(&self) -> usize;
    fn fixed_iv_len(&self) -> usize;
    fn mac_len(&self) -> usize;
    fn new_encryptor(&self, key: Vec<u8>) -> Box<Encryptor + 'static>;
    fn new_decryptor(&self, key: Vec<u8>) -> Box<Decryptor + 'static>;
}

pub trait Encryptor {
    fn encrypt(&mut self, nonce: &[u8], plain: &[u8], ad: &[u8]) -> Vec<u8>;
}

// Note: Enctryptor and Decryptor should be separated because there exists a state that
// client encrypts data but server does not.
pub trait Decryptor {
    fn decrypt(&mut self, nonce: &[u8], encrypted: &[u8], ad: &[u8]) -> TlsResult<Vec<u8>>;
    // FIXME: copied from Aead since record::RecordReader wants this
    fn mac_len(&self) -> usize;
}

pub trait KeyExchange {
    // return (client_key_exchange_data, pre_master_secret)
    fn compute_keys(&self, data: &[u8], rng: &mut OsRng) -> TlsResult<(Vec<u8>, Vec<u8>)>;
}

macro_rules! cipher_suite {
    ($(
        $id:ident = $kex:ident, $cipher:ident, $mac:ident, $v1:expr, $v2:expr;
    )+) => (
        #[allow(non_camel_case_types)]
        #[derive(Copy, PartialEq, Show)]
        pub enum CipherSuite {
            $(
                $id,
            )+
            UnknownCipherSuite,
        }

        impl CipherSuite {
            pub fn new_aead(&self) -> Box<Aead> {
                match *self {
                    $(
                        CipherSuite::$id => box $cipher as Box<Aead>,
                    )+
                    CipherSuite::UnknownCipherSuite => unreachable!(),
                }
            }

            pub fn new_kex(&self) -> Box<KeyExchange> {
                match *self {
                    $(
                        CipherSuite::$id => box $kex as Box<KeyExchange>,
                    )+
                    CipherSuite::UnknownCipherSuite => unreachable!(),
                }
            }

            // this can be different for some cipher suites
            pub fn verify_data_len(&self) -> usize { 12 }
        }

        impl TlsItem for CipherSuite {
            fn tls_write<W: Writer>(&self, writer: &mut W) -> TlsResult<()> {
                $(
                    if *self == CipherSuite::$id {
                        try!(writer.write_u8($v1));
                        try!(writer.write_u8($v2));
                        return Ok(());
                    }
                )+

                return tls_err!(UnexpectedMessage, "unexpected CipherSuite: {:?}", self);
            }

            fn tls_read<R: Reader>(reader: &mut R) -> TlsResult<CipherSuite> {
                let id1 = try!(reader.read_u8());
                let id2 = try!(reader.read_u8());
                $(
                    if id1 == $v1 && id2 == $v2 {
                        return Ok(CipherSuite::$id);
                    }
                )+
                // client may send cipher suites we don't know
                return Ok(CipherSuite::UnknownCipherSuite);
            }

            fn tls_size(&self) -> u64 {
                2
            }
        }
    )
}

// TODO RSA/ECDSA signs
cipher_suite!(
    // http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 =
    EllipticDiffieHellman, ChaCha20Poly1305, MAC_SHA256, 0xcc, 0x13;
    // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 =
    // EllipticDiffieHellman ChaCha20Poly1305 MAC_SHA256 0xcc 0x14;
);
