use std::error::Error;
use std::fmt;
use der;

#[derive(PartialEq, Debug)]
pub enum CertErrorKind {
    ParseError,
    InvalidField,
    InvalidPeriod,
}

#[derive(Debug)]
pub struct CertError {
    pub kind: CertErrorKind,
    pub desc: String,
}

impl CertError {
    pub fn new<T>(kind: CertErrorKind, desc: String) -> CertResult<T> {
        Err(CertError {
            kind: kind,
            desc: desc,
        })
    }
}

impl Error for CertError {
    fn description(&self) -> &str {
        match self.kind {
            CertErrorKind::ParseError => "DER parse error",
            CertErrorKind::InvalidField => "field has invalid value",
            CertErrorKind::InvalidPeriod => "cert from past or future", // TODO horrible desc
        }
    }
}

impl fmt::Display for CertError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        self.desc.fmt(f)
    }
}

impl From<der::DerError> for CertError {
    fn from(err: der::DerError) -> CertError {
        CertError {
            kind: CertErrorKind::ParseError,
            desc: format!("{:?}", err),
        }
    }
}

pub type CertResult<T> = Result<T, CertError>;

#[macro_use]
pub mod macros;

pub mod cert_serial_number;
pub mod version;
pub mod alg_id;
pub mod name;
pub mod validity;
pub mod extension;
pub mod certificate;

pub mod crl;
