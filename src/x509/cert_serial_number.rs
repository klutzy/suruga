use der::{Tag, FromValue, DerResult};
use der::DerErrorKind::InvalidVal;

// For some reason I will never understand, SerialNumber is packed into Integer.
// This means serial number can be negative!
#[derive(Debug)]
pub struct CertificateSerialNumber {
    pub val: Vec<u8>
}

from_value!(CertificateSerialNumber: Tag::Integer);

impl FromValue for CertificateSerialNumber {
    fn from_value(val: &[u8]) -> DerResult<CertificateSerialNumber> {
        if val.len() == 0 {
            return der_err!(InvalidVal, "zero-length CertificateSerialNumber");
        }

        if val.len() > 1 {
            let v0 = val[0];
            let v1 = val[1];

            if (v0 == 0 && (v1 >> 7) == 0) || (v0 == 0xFF && (v1 >> 7) == 1) {
                return der_err!(InvalidVal, "overlong bits");
            }
        }

        Ok(CertificateSerialNumber {
            val: val.to_vec()
        })
    }
}
