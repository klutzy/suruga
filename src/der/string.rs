use std::str;
use std::borrow::ToOwned;

use der::{Tag, FromTlv, DerResult};
use der::DerErrorKind::{InvalidTag, InvalidVal};

// ASN.1 strings are jokes. there are so many string types with their own subtle rules
// and some of the rules are ignored in wild.
//
// PrintableString doesn't allow '*' but some certs contain such values.
// https://code.google.com/p/go/issues/detail?id=850
// (mozilla pkix also accepts '*'.)
//
// PrintableString also doesn't allow '@', so you cannot print e-mail address.
// Due to this, some legacy certs used IA5String where it cannot occur.
//
// there are *three* unicode strings. UniversalString and Utf8String are
// basically same in ASN.1 but differently encoded in DER.
// BMPString is.. BMP subset. encoded as ucs2.
// (did you know ucs2 is big endian in spec?)
//
// also keep in mind that Rust doesn't accept invalid surrogates.
// we will just treat such string as "invalid".

// FIXME: I'm going to live with the std String for now.
// I'm not saying this is unimportant; just saying that I'm tired right now and
// I'll revise this in other day.

impl FromTlv for String {
    fn from_tlv(tag: Tag, value: &[u8]) -> DerResult<String> {
        match tag {
            Tag::Utf8String | Tag::PrintableString | Tag::Ia5String |
            Tag::TeletexString | Tag::VisibleString => {
                match str::from_utf8(value) {
                    Ok(value) => Ok(value.to_owned()),
                    Err(err) => return der_err!(InvalidVal, "invalid utf-8: {}, \"{:?}\"", err, value),
                }
            }
            // TODO: UniversalString, BmpString
            _ => return der_err!(InvalidTag, "unexpected tag \"{:?}\" for String", tag),
        }
    }
}

// TODO

// pub struct PrintableString<'a>(&'a [u8]);

// impl<'a> PrintableString<'a> {
//     pub fn from_bytes(bytes: &'a [u8]) -> Option<PrintableString<'a>> {
//         for b in bytes.iter() {
//             match b {
//                 b'A'...b'Z' | b'a'...b'z' | b'0'...b'9' | b' ' |
//                 b'\'' | b'(' | b')' | b'+' | b',' | b'-' | b'.' | b'/' |
//                 b':' | b'=' | b'?' => {}
//                 _ => return None,
//             }
//         }
//         Some(PrintableString(bytes))
//     }
// }

// // TODO
// #[derive(Debug)]
// pub struct Ia5String(pub Vec<u8>);
// from_value!(Ia5String: Tag::Ia5String);

// impl FromValue for Ia5String {
//     fn from_value(value: &[u8]) -> DerResult<Ia5String> {
//         Ok(Ia5String(value.to_vec()))
//     }
// }
