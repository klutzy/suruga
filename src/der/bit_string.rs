use der::{Tag, FromValue, DerResult};
use super::DerErrorKind::InvalidVal;

// there are *two* BIT STRING types.
// the first one is, well, bit vector.
// all bits except for unused ones are meaningful:
// for example, `0000_0000` != `0000` since the first one has 8 bits
// but the second one has 4 bits.
//
// the second one is bitfield structure. this works in a different way!
// for example, in the following structure:
// ```
// example ::= BIT STRING {
//     first (0),
//     second (1),
//     third (2)
// }
// ```
//
// `{ first = false, second = true, third = false }` is encoded to `01`,
// not `010`. that is, all trailing zeros are removed.
// it is specified in x.680 (22.7) and x.690 (11.2.2) in a horrible way.
//
// this module only defines the first bit vector type. for the second one,
// use `bit_string_fields` macro.

#[derive(Clone, PartialEq, Debug)]
pub struct BitString {
    pub unused_bits: u8,
    pub data: Vec<u8>,
}

from_value!(BitString: Tag::BitString);

/// Parse DER value and return (unused bits, bitstring value).
pub fn from_der<'a>(value: &'a [u8]) -> DerResult<(u8, &'a [u8])> {
    let len = value.len();
    if len == 0 {
        return der_err!(InvalidVal, "found zero-length BitString");
    }

    let unused_bits = value[0];
    if unused_bits >= 8 {
        return der_err!(InvalidVal, "unused bits >= 8 found");
    }
    if unused_bits > 0 && len == 1 {
        return der_err!(InvalidVal, "unused bits != 0 but no bits found");
    }

    Ok((unused_bits, &value[1..]))
}

impl FromValue for BitString {
    fn from_value(value: &[u8]) -> DerResult<BitString> {
        let (unused_bits, data) = try!(from_der(value));
        let data = data.to_vec();

        Ok(BitString {
            unused_bits: unused_bits,
            data: data,
        })
    }
}
