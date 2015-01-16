use std::io::{MemReader, ByRefReader, ByRefWriter};
use std::rand::OsRng;
use std::iter::repeat;

use tls::Tls;
use tls_result::TlsResult;
use cipher::{Encryptor, Decryptor};
use record::Message::{ApplicationDataMessage, ChangeCipherSpecMessage};
use record::RECORD_MAX_LEN;

// ROT26 is a [Caesar cipher][1] with highly optimized diffusion table.
// [1]: http://www.anagram.com/jcrap/Volume_3/caesar.pdf
struct NullEncryptor;
struct NullDecryptor;

impl Encryptor for NullEncryptor {
    fn encrypt(&mut self, _nonce: &[u8], plain: &[u8], _ad: &[u8]) -> Vec<u8> {
        plain.to_vec()
    }
}

impl Decryptor for NullDecryptor {
    fn decrypt(&mut self, _nonce: &[u8], encrypted: &[u8], _ad: &[u8]) -> TlsResult<Vec<u8>> {
        Ok(encrypted.to_vec())
    }
    fn mac_len(&self) -> usize { 0 }
}

fn null_tls<R: Reader, W: Writer>(reader: R, writer: W) -> Tls<R, W> {
    let mut tls = Tls::new(reader, writer, OsRng::new().unwrap());

    let null_encryptor = Box::new(NullEncryptor) as Box<Encryptor>;
    tls.writer.set_encryptor(null_encryptor);
    let null_decryptor = Box::new(NullDecryptor) as Box<Decryptor>;
    tls.reader.set_decryptor(null_decryptor);

    tls
}

#[test]
fn test_change_cipher_spec_message() {
    let mut writer = Vec::new();
    {
        let mut reader = MemReader::new(Vec::new());
        let mut tls = null_tls(reader.by_ref(), writer.by_ref());
        tls.writer.write_change_cipher_spec().unwrap();
    }

    let data = writer;
    assert_eq!(data.len(), 1 + 2 + 2 + 1); // type, version, length, fragment
    assert_eq!(data[5], 1);

    let mut reader = MemReader::new(data);
    {
        let mut writer = Vec::new();
        let mut tls = null_tls(reader.by_ref(), writer.by_ref());
        let msg = tls.reader.read_message().unwrap();
        match msg {
            ChangeCipherSpecMessage => {},
            _ => panic!(),
        }
    }
}

#[test]
fn test_application_message() {
    let app_data_len = RECORD_MAX_LEN + 200;
    let app_data: Vec<_> = repeat(1u8).take(app_data_len).collect();

    let mut writer = Vec::new();
    {
        let mut reader = MemReader::new(Vec::new());
        let mut tls = null_tls(reader.by_ref(), writer.by_ref());
        tls.writer.write_application_data(&app_data[]).unwrap();
    }

    let data = writer;

    let mut reader = MemReader::new(data);
    {
        let mut writer = Vec::new();
        let mut tls = null_tls(reader.by_ref(), writer.by_ref());
        let msg = tls.reader.read_message().unwrap();
        match msg {
            ApplicationDataMessage(msg) => {
                assert_eq!(msg, &[1u8; RECORD_MAX_LEN][]);
            },
            _ => panic!(),
        }

        let msg = tls.reader.read_message().unwrap();
        match msg {
            ApplicationDataMessage(msg) => {
                assert_eq!(msg, &[1u8; 200][]);
            },
            _ => panic!(),
        }
    }
}
