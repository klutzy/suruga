// DER reader

use std::fmt;

pub use self::reader::DerReader;
pub use self::bit_string::BitString;
pub use self::obj_id::ObjId;
pub use self::time::Time;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum DerErrorKind {
    /// length field is too big or invalid
    InvalidLen,
    /// unknown or unsupported tag value found
    InvalidTag,
    /// unexpected eof while reading tlv
    Eof,
    /// value field has invalid data
    InvalidVal,
}

#[derive(Debug)]
pub struct DerError {
    pub kind: DerErrorKind,
    pub desc: String,
}

impl fmt::Display for DerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        self.desc.fmt(f)
    }
}

impl DerError {
    pub fn new<T>(kind: DerErrorKind, desc: String) -> DerResult<T> {
        Err(DerError {
            kind: kind,
            desc: desc,
        })
    }
}

pub type DerResult<T> = Result<T, DerError>;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum TagClass {
    Universal = 0b00,
    Application = 0b01,
    ContextSpecific = 0b10,
    Private = 0b11,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Tag {
    // primitives
    Boolean, // 0x01
    Integer, // 0x02
    BitString, // 0x03
    OctetString, // 0x04
    Null, // 0x05
    ObjectIdentifier, // 0x06
    ObjectDescriptor, // 0x07
    External, // 0x08
    Real, // 0x09
    Enumerated, // 0x0a
    EmbeddedPdv, // 0x0b

    // wow much string
    Utf8String, // 0x0c
    NumericString, // 0x12
    PrintableString, // 0x13
    TeletexString, // 0x14
    VideotexString, // 0x15
    Ia5String, // 0x16
    GraphicString, // 0x19
    VisibleString, // 0x1a
    GeneralString, // 0x1b
    UniversalString, // 0x1c
    BmpString, // 0x1e

    UtcTime, // 0x17
    GeneralizedTime, // 0x18

    // constructed
    Sequence, // 0x10
    Set, // 0x11

    Primitive(u8, TagClass), // tag, tag_class
    Constructed(u8, TagClass), //tag, tag_class
}

pub trait FromTlv {
    fn from_tlv(tag: Tag, value: &[u8]) -> DerResult<Self>;
}

pub trait FromValue: FromTlv {
    fn from_value(value: &[u8]) -> DerResult<Self>;
}

#[macro_use] pub mod macros;
pub mod reader;

// basic primitive types

pub mod bit_string;
pub mod obj_id;
pub mod string;
pub mod time;

from_value!((): Tag::Null);
impl FromValue for () {
    fn from_value(value: &[u8]) -> DerResult<()> {
        if value.len() != 0 {
            return der_err!(DerErrorKind::InvalidVal, "Null with non-zero length");
        }
        Ok(())
    }
}

from_value!(bool: Tag::Boolean);
impl FromValue for bool {
    fn from_value(value: &[u8]) -> DerResult<bool> {
        if value.len() != 1 {
            return der_err!(DerErrorKind::InvalidVal, "boolean with wrong length");
        }
        match value[0] {
            0 => Ok(false),
            255 => Ok(true),
            _val => {
                return der_err!(DerErrorKind::InvalidVal, "boolean with wrong value: {}", _val);
            }
        }
    }
}

from_value!(Vec<u8>: Tag::OctetString);
impl FromValue for Vec<u8> {
    fn from_value(value: &[u8]) -> DerResult<Vec<u8>> {
        Ok(value.to_vec())
    }
}

#[derive(Debug)]
pub struct Any(pub Tag, pub Vec<u8>);
impl FromTlv for Any {
    fn from_tlv(tag: Tag, value: &[u8]) -> DerResult<Any> {
        Ok(Any(tag, value.to_vec()))
    }
}

#[derive(Debug)]
pub struct Integer(pub Vec<u8>);
from_value!(Integer: Tag::Integer);
impl FromValue for Integer {
    fn from_value(value: &[u8]) -> DerResult<Integer> {
        Ok(Integer(value.to_vec()))
    }
}

#[cfg(test)] mod test;
