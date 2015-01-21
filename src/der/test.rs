use der::{Tag, FromTlv, FromValue, DerResult, DerErrorKind};
use der::reader::DerReader;

macro_rules! assert_err {
    ($e:expr, $expected:expr) => (
        match $e {
            Err(ref e) if e.kind == $expected => {}
            actual => {
                panic!("expected {:?}, found {:?}", $expected, actual);
            }
        }
    )
}

#[derive(Debug, PartialEq)]
pub struct OctetString(Vec<u8>);
from_value!(OctetString: Tag::OctetString);
impl FromValue for OctetString {
    fn from_value(value: &[u8]) -> DerResult<OctetString> {
        Ok(OctetString(value.to_vec()))
    }
}

sequence_opts!(#[derive(PartialEq)] struct DefaultOptional {
    default(DEFAULT, false, Tag::Boolean): bool,
    optional(OPTIONAL, Tag::OctetString): Option<OctetString>,
    null(): (),
});

#[test]
fn test_default_optional() {
    let ders: Vec<(Vec<u8>, DefaultOptional)> = vec![
        (vec![0x30, 0x02, 0x05, 0x00], DefaultOptional {
            default: false,
            optional: None,
            null: (),
        }),
        (vec![0x30, 0x05, 0x01, 0x01, 0xFF, 0x05, 0x00], DefaultOptional {
            default: true,
            optional: None,
            null: (),
        }),
        (vec![0x30, 0x05, 0x04, 0x01, 0x12, 0x05, 0x00], DefaultOptional {
            default: false,
            optional: Some(OctetString(vec!(0x12))),
            null: (),
        }),
        (vec![0x30, 0x08, 0x01, 0x01, 0xFF, 0x04, 0x01, 0x12, 0x05, 0x00], DefaultOptional {
            default: true,
            optional: Some(OctetString(vec!(0x12))),
            null: (),
        }),
    ];

    for &(ref der, ref expected) in ders.iter() {
        let mut reader = DerReader::new(&der);
        let (tag, value) = reader.next_tlv().unwrap();
        let actual: DefaultOptional = FromTlv::from_tlv(tag, value).unwrap();
        assert_eq!(expected, &actual);
        assert!(reader.is_eof());
    }
}

// http://www.intelsecurity.com/advanced-threat-research/berserk.html
// http://www.intelsecurity.com/resources/wp-berserk-analysis-part-2.pdf
#[test]
fn test_length_overflow() {
    let mut der = vec![0x05];
    // 0x80 | 0x59, length is represented as 0x59-bytes.
    let len = 0xd9;
    der.push(len);
    for _ in 0..(len - 4) {
        der.push(0xff);
    }
    der.push_all(&[0x00, 0x00, 0x00, 0x02]);
    // null
    der.push_all(&[0x05, 0x00]);

    let mut reader = DerReader::new(&der);
    let next = reader.next_tlv();
    assert_err!(next, DerErrorKind::InvalidLen);
}

// null should be null.
#[test]
fn test_null() {
    let der = [0x05, 0x01, 0x01];

    let mut reader = DerReader::new(&der);
    let (tag, value) = reader.next_tlv().unwrap();
    let null_or_err: DerResult<()> = FromTlv::from_tlv(tag, value);
    assert_err!(null_or_err, DerErrorKind::InvalidVal);
}
