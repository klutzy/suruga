use std::num::FromPrimitive;

use tls_result::TlsResult;
use tls_result::TlsErrorKind::{UnexpectedMessage, RecordOverflow, BadRecordMac, AlertReceived};
use alert::Alert;
use handshake::{Handshake, HandshakeBuffer};
use util::u64_be_array;
use cipher::{Encryptor, Decryptor};
use tls_item::TlsItem;
use tls::TLS_VERSION;

use self::ContentType::{ChangeCipherSpecTy, AlertTy, HandshakeTy, ApplicationDataTy};
use self::Message::{HandshakeMessage, ChangeCipherSpecMessage, AlertMessage,
                    ApplicationDataMessage};

#[repr(u8)]
#[derive(Copy, PartialEq, FromPrimitive, Show)]
pub enum ContentType {
    ChangeCipherSpecTy = 20,
    AlertTy = 21,
    HandshakeTy = 22,
    ApplicationDataTy = 23,
    // HeartBeat = 24, RFC 6520 extension :-)
}

/// maximum length of Record (excluding content_type, version, length fields)
pub const RECORD_MAX_LEN: uint = 1 << 14;

/// maximum length of EncryptedRecord (excluding content_type, version, length fields)
pub const ENC_RECORD_MAX_LEN: uint = (1 << 14) + 2048;

/// corresponds to `TLSPlaintext` in Section 6.2.1.
pub struct Record {
    pub content_type: ContentType,
    pub ver_major: u8,
    pub ver_minor: u8,
    // fragment length < 2^14
    pub fragment: Vec<u8>,
}

impl Record {
    pub fn new(content_type: ContentType, ver_major: u8, ver_minor: u8, fragment: Vec<u8>) -> Record {
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

/// corresponds to `TLSCiphertext` in Section 6.2.3.
pub struct EncryptedRecord {
    pub content_type: ContentType,
    pub ver_major: u8,
    pub ver_minor: u8,
    // fragment length < 2^14 + 2048
    pub fragment: Vec<u8>,
}

impl EncryptedRecord {
    pub fn new(content_type: ContentType, ver_major: u8, ver_minor: u8, fragment: Vec<u8>) -> EncryptedRecord {
        let len = fragment.len();
        if len > ENC_RECORD_MAX_LEN {
            panic!("record too long: {} > 2^14 + 2048", len);
        }

        EncryptedRecord {
            content_type: content_type,
            ver_major: ver_major,
            ver_minor: ver_minor,
            fragment: fragment,
        }
    }
}

pub struct RecordWriter<W: Writer> {
    writer: W,
    // if encryptor is None, handshake is not done yet.
    encryptor: Option<Box<Encryptor + 'static>>,
    write_count: u64,
}

impl<W: Writer> RecordWriter<W> {
    pub fn new(writer: W) -> RecordWriter<W> {
        RecordWriter {
            writer: writer,
            encryptor: None,
            write_count: 0,
        }
    }

    pub fn set_encryptor(&mut self, encryptor: Box<Encryptor + 'static>) {
        self.encryptor = Some(encryptor);
        self.write_count = 0;
    }

    pub fn write_record(&mut self, record: Record) -> TlsResult<()> {
        let enc_record = match self.encryptor {
            None => EncryptedRecord::new(record.content_type,
                                         record.ver_major,
                                         record.ver_minor,
                                         record.fragment),
            Some(ref mut encryptor) => {
                let seq_num = u64_be_array(self.write_count);

                let mut ad = Vec::new();
                ad.push_all(seq_num.as_slice());
                ad.push(record.content_type as u8);
                ad.push(record.ver_major);
                ad.push(record.ver_minor);
                let frag_len = record.fragment.len() as u16;
                ad.push((frag_len >> 8) as u8);
                ad.push(frag_len as u8);

                let encrypted_fragment = encryptor.encrypt(seq_num.as_slice(),
                                                           record.fragment.as_slice(),
                                                           ad.as_slice());
                EncryptedRecord::new(record.content_type,
                                     record.ver_major,
                                     record.ver_minor,
                                     encrypted_fragment)
            }
        };
        let fragment_len = enc_record.fragment.len() as u16;

        try!(self.writer.write_u8(enc_record.content_type as u8));

        let (major, minor) = TLS_VERSION;
        try!(self.writer.write_u8(major));
        try!(self.writer.write_u8(minor));

        try!(self.writer.write_be_u16(fragment_len));
        try!(self.writer.write(enc_record.fragment.as_slice()));

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
        self.write_data(HandshakeTy, data.as_slice())
    }

    pub fn write_alert(&mut self, alert: &Alert) -> TlsResult<()> {
        let mut data = Vec::new();
        try!(alert.tls_write(&mut data));
        self.write_data(AlertTy, data.as_slice())
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

pub enum Message {
    HandshakeMessage(Handshake),
    ChangeCipherSpecMessage,
    AlertMessage(Alert),
    ApplicationDataMessage(Vec<u8>),
}

pub struct RecordReader<R: Reader> {
    reader: R,
    // if decryptor is none, handshake is not done yet.
    decryptor: Option<Box<Decryptor + 'static>>,
    read_count: u64,
    handshake_buffer: HandshakeBuffer,
}

impl<R: Reader> RecordReader<R> {
    pub fn new(reader: R) -> RecordReader<R> {
        RecordReader {
            reader: reader,
            decryptor: None,
            read_count: 0,
            handshake_buffer: HandshakeBuffer::new(),
        }
    }

    pub fn set_decryptor(&mut self, decryptor: Box<Decryptor + 'static>) {
        self.decryptor = Some(decryptor);
        self.read_count = 0;
    }

    fn read_record(&mut self) -> TlsResult<Record> {
        let ty = try!(self.reader.read_u8());
        let ty = {
            let ct: Option<ContentType> = FromPrimitive::from_u8(ty);
            match ct {
                Some(ty) => ty,
                None => return tls_err!(UnexpectedMessage, "unexpected ContentType: {}", ty),
            }
        };

        let major = try!(self.reader.read_u8());
        let minor = try!(self.reader.read_u8());

        let len = {
            let len = try!(self.reader.read_be_u16()) as uint;
            if len > ENC_RECORD_MAX_LEN {
                return tls_err!(RecordOverflow, "TLSEncryptedText too long: {}", len);
            }
            len
        };

        let fragment = try!(self.reader.read_exact(len as uint));
        let enc_record = EncryptedRecord::new(ty, major, minor, fragment);

        let record = match self.decryptor {
            None => Record::new(enc_record.content_type,
                                enc_record.ver_major,
                                enc_record.ver_minor,
                                enc_record.fragment),
            Some(ref mut decryptor) => {
                let seq_num = u64_be_array(self.read_count);

                let mut ad = Vec::new();
                ad.push_all(seq_num.as_slice());
                ad.push(enc_record.content_type as u8); // TLSCompressed.type
                ad.push(enc_record.ver_major);
                ad.push(enc_record.ver_minor);

                let mac_len = decryptor.mac_len();
                let total_len = enc_record.fragment.len();
                if total_len < mac_len {
                    return tls_err!(BadRecordMac, "encrypted message too short: {}", total_len);
                }
                let frag_len = (total_len - mac_len) as u16;
                ad.push((frag_len >> 8) as u8);
                ad.push(frag_len as u8);

                // TODO: "seq_num as nonce" is chacha20poly1305-specific
                let data = try!(decryptor.decrypt(seq_num.as_slice(),
                                                   enc_record.fragment.as_slice(),
                                                   ad.as_slice()));

                Record::new(enc_record.content_type,
                            enc_record.ver_major,
                            enc_record.ver_minor,
                            data)
            }
        };

        self.read_count += 1;

        Ok(record)
    }

    /// read records until a "complete" message is found, and return the message.
    /// if invalid ChangeCipherSpec/Alert/Handshake message is found, return Err.
    /// (application record is always considered "complete" and "valid"
    /// since it is opaque to TLS layer.)
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
                        // alert packet can be broken into several records,
                        // buf it is rarely used and may cause alert attack
                        // if carelessly implemented:
                        // http://www.mitls.org/wsgi/alert-attack
                        // we just don't accept such record for simplicity.
                        // If alert messages are long, use the first two bytes.
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
                    self.handshake_buffer.add_record(record.fragment);

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
