use super::{Tag, FromValue, DerResult};
use super::DerErrorKind::InvalidVal;

#[derive(PartialEq, Debug)]
pub struct ObjId {
    // DER encdoing of object identifier.
    pub value: Vec<u8>,
}

from_value!(ObjId: Tag::ObjectIdentifier);

impl FromValue for ObjId {
    fn from_value(value: &[u8]) -> DerResult<ObjId> {
        let len = value.len();

        if len == 0 {
            return der_err!(InvalidVal, "ObjectIdentifier with zero length");
        }

        Ok(ObjId {
            value: value.to_vec()
        })
    }
}
