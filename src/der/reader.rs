// # Notes
//
// -   DER only!
// -   Tag must be `< 31` (long tag is not supported) and length must be `< 65536`.

// TODO use Cell<usize> for pos; this allows the following pattern:
//
// ```
// let a = try!(reader.next_tlv());
// match a {
//     something => {
//         let b = try!(reader.next_tlv());
//     }
// }
// ```
//
// this is currently impossible because `a` freezes `reader`.
// (yes, I don't like Cell because it's bogus to add unnecessary check but it's better than
// unnecessary slice clones.)

use super::{Tag, TagClass};
use super::DerResult;
use super::DerErrorKind::{InvalidLen, InvalidTag, Eof};

pub struct DerReader<'a> {
    buf: &'a [u8],
    pos: usize,
    cur: Option<(Tag, &'a [u8])>,
}

impl<'a> DerReader<'a> {
    pub fn new(buf: &'a [u8]) -> DerReader<'a> {
        DerReader {
            buf: buf,
            pos: 0,
            cur: None,
        }
    }
}

// internal utilities
impl<'a> DerReader<'a> {
    fn read_u8(&mut self) -> DerResult<u8> {
        match self.buf.get(self.pos) {
            Some(&val) => {
                self.pos += 1;
                Ok(val)
            }
            None => return der_err!(Eof, "out-of-range"),
        }
    }

    fn read_tag(&mut self) -> DerResult<Tag> {
        let (tag_class, is_constructed, tag) = {
            let b0 = try!(self.read_u8());
            let class = match b0 >> 6 {
                0b00 => TagClass::Universal,
                0b01 => TagClass::Application,
                0b10 => TagClass::ContextSpecific,
                0b11 => TagClass::Private,
                _ => unreachable!(),
            };
            let is_constructed = (b0 >> 5) & 0b1 == 0b1;

            let tag = if b0 & 0b1_1111 == 0b1_1111 {
                // tag can be > 31, but we just don't support it.
                return der_err!(InvalidTag, "unsupported tag value > 31");
            } else {
                b0 & 0b1_1111
            };

            (class, is_constructed, tag)
        };

        let tag = if !is_constructed {
            // primitives
            if tag_class != TagClass::Universal {
                Tag::Primitive(tag, tag_class)
            } else {
                match tag {
                    0x00 => return der_err!(InvalidTag, "EndOfContents found in DER"),

                    0x01 => Tag::Boolean,
                    0x02 => Tag::Integer,
                    0x03 => Tag::BitString,
                    0x04 => Tag::OctetString,
                    0x05 => Tag::Null,
                    0x06 => Tag::ObjectIdentifier,
                    0x07 => Tag::ObjectDescriptor,
                    0x09 => Tag::Real,
                    0x0a => Tag::Enumerated,
                    0x0c => Tag::Utf8String,
                    0x12 => Tag::NumericString,
                    0x13 => Tag::PrintableString,
                    0x14 => Tag::TeletexString,
                    0x15 => Tag::VideotexString,
                    0x16 => Tag::Ia5String,
                    0x17 => Tag::UtcTime,
                    0x18 => Tag::GeneralizedTime,
                    0x19 => Tag::GraphicString,
                    0x1a => Tag::VisibleString,
                    0x1b => Tag::GeneralString,
                    0x1c => Tag::UniversalString,
                    0x1e => Tag::BmpString,

                    0x08 | 0x0b | 0x10 | 0x11 => {
                        return der_err!(InvalidTag, "Constructed tag found in Primitive: {}", tag);
                    }
                    _ => return der_err!(InvalidTag, "Unexpected tag in Primitive: {}", tag),
                }
            }
        } else {
            if tag_class != TagClass::Universal {
                Tag::Constructed(tag, tag_class)
            } else {
                match tag {
                    0x08 => Tag::External,
                    0x0b => Tag::EmbeddedPdv,
                    0x10 => Tag::Sequence,
                    0x11 => Tag::Set,

                    0x00 ... 0x0c | 0x12 ... 0x1e => {
                        return der_err!(InvalidTag, "Primitive tag found in Constructed: {}", tag);
                    }

                    _ => return der_err!(InvalidTag, "Unexpected tag in Constructed: {}", tag),
                }
            }
        };

        Ok(tag)
    }

    // length is actually u16
    fn read_len(&mut self) -> DerResult<usize> {
        let len = {
            let b0 = try!(self.read_u8());
            if b0 == 0b1000_0000 {
                return der_err!(InvalidLen, "indefinite length found in DER");
            } else if b0 >> 7 == 1 {
                // long form.
                // FIXME: check "overlong" bytes e.g. 0x82 0x00 0x01
                // I guess DER prohibits such one..
                let lenlen = b0 & 0b111_1111;
                if lenlen == 0b111_1111 {
                    return der_err!(InvalidLen, "illegal length");
                }
                // we just don't expect >= 2^16 bytes.
                if lenlen > 2 {
                    return der_err!(InvalidLen, "unsupported length: {}", lenlen);
                }
                let mut len: u32 = 0;
                for _i in 0..lenlen {
                    let next = try!(self.read_u8());
                    len = (len << 8) | (next as u32);
                }
                len as usize
            } else {
                b0 as usize
            }
        };

        Ok(len)
    }

    fn read_value(&mut self, len: usize) -> DerResult<&'a [u8]> {
        let new_pos = self.pos + len;
        if new_pos > self.buf.len() {
            return der_err!(Eof, "length too large: {}", len);
        }

        let slice = &self.buf[self.pos ..new_pos];
        self.pos += len;
        Ok(slice)
    }
}

// basic methods
impl<'a> DerReader<'a> {
    pub fn is_eof(&self) -> bool {
        self.cur == None && (self.buf.len() == self.pos)
    }

    // may return Ok(None) if eof
    // call `.bump()` if returned tlv has been consumed
    pub fn peek_tlv(&mut self) -> DerResult<Option<(Tag, &'a [u8])>> {
        if self.is_eof() {
            return Ok(None);
        }
        let (tag, len) = match self.cur {
            None => {
                let tag = try!(self.read_tag());
                let len = try!(self.read_len());
                let val = try!(self.read_value(len));
                self.cur = Some((tag, val));
                debug!("peek_tlv: tag {:?} val {:?}", tag, val);
                (tag, val)
            }
            Some(tag_len) => tag_len
        };
        Ok(Some((tag, len)))
    }

    pub fn bump(&mut self) {
        self.cur = None;
    }

    pub fn next_tlv(&mut self) -> DerResult<(Tag, &'a [u8])> {
        match try!(self.peek_tlv()) {
            None => der_err!(Eof, "end of stream when reading TLV"),
            Some(next) => {
                self.bump();
                Ok(next)
            }
        }
    }
}

// helpers
impl<'a> DerReader<'a> {
    pub fn explicit<T, F1, F2>(&mut self,
                               expected_tag: Tag,
                               mut matched: F1,
                               mut unmatched: F2) -> DerResult<T> where
        F1: FnMut(Tag, &[u8]) -> DerResult<T>,
        F2: FnMut() -> DerResult<T>,
    {
        match try!(self.peek_tlv()) {
            None => unmatched(),
            Some((tag, value)) => {
                if tag == expected_tag {
                    self.bump();

                    // actual data is wrapped in Constructed tag.
                    let mut exp_parser = DerReader::new(value);

                    let (tag, value) = try!(exp_parser.next_tlv());
                    let result = try!(matched(tag, value));

                    // only one should be packed?
                    if let Some(some) = try!(exp_parser.peek_tlv()) {
                        return der_err!(InvalidTag,
                                        "unexpected tag {:?} inside {:?}",
                                        some,
                                        expected_tag);
                    }

                    Ok(result)
                } else {
                    unmatched()
                }
            }
        }
    }

    pub fn default<T, F1, F2>(&mut self,
                              expected_tag: Tag,
                              mut matched: F1,
                              mut unmatched: F2) -> DerResult<T> where
        F1: FnMut(&[u8]) -> DerResult<T>,
        F2: FnMut() -> DerResult<T>,
    {
        match try!(self.peek_tlv()) {
            None => unmatched(),
            Some((tag, value)) => {
                if expected_tag == tag {
                    self.bump();
                    matched(value)
                } else {
                    unmatched()
                }
            }
        }
    }
}
