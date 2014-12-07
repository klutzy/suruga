use std::io::{MemReader, ByRefReader, ByRefWriter};
use std::rand::OsRng;

use super::Tls;
use record::Message::{ApplicationDataMessage, ChangeCipherSpecMessage};
use record::RECORD_MAX_LEN;

#[test]
fn test_change_cipher_spec_message() {
    let mut writer = Vec::new();
    {
        let mut reader = MemReader::new(Vec::new());
        let mut tls = Tls::new(reader.by_ref(), writer.by_ref(), OsRng::new().unwrap());
        // null cipher
        tls.writer.write_change_cipher_spec().unwrap();
    }

    let data = writer;
    assert_eq!(data.len(), 1 + 2 + 2 + 1); // type, version, length, fragment
    assert_eq!(data[5], 1);

    let mut reader = MemReader::new(data);
    {
        let mut writer = Vec::new();
        let mut tls = Tls::new(reader.by_ref(), writer.by_ref(), OsRng::new().unwrap());
        // null cipher
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
    let app_data = Vec::from_elem(app_data_len, 1u8);
    let mut writer = Vec::new();
    {
        let mut reader = MemReader::new(Vec::new());
        let mut tls = Tls::new(reader.by_ref(), writer.by_ref(), OsRng::new().unwrap());
        // null cipher
        tls.writer.write_application_data(app_data.as_slice()).unwrap();
    }

    let data = writer;

    let mut reader = MemReader::new(data);
    {
        let mut writer = Vec::new();
        let mut tls = Tls::new(reader.by_ref(), writer.by_ref(), OsRng::new().unwrap());
        let msg = tls.reader.read_message().unwrap();
        match msg {
            ApplicationDataMessage(msg) => {
                assert_eq!(msg, Vec::from_elem(RECORD_MAX_LEN, 1u8));
            },
            _ => panic!(),
        }

        let msg = tls.reader.read_message().unwrap();
        match msg {
            ApplicationDataMessage(msg) => {
                assert_eq!(msg, Vec::from_elem(200, 1u8));
            },
            _ => panic!(),
        }
    }
}
