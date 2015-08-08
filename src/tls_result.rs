use std::error::Error;
use std::io;
use std::fmt;

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum TlsErrorKind {
    // corresponds to alert messages

    UnexpectedMessage,
    BadRecordMac,
    RecordOverflow,
    IllegalParameter,
    DecodeError,
    DecryptError,
    InternalError,

    // we probably can't even send alert?
    IoFailure,
    AlertReceived,
}

#[derive(Debug)]
pub struct TlsError {
    pub kind: TlsErrorKind,
    pub desc: String,
}

impl TlsError {
    pub fn new<T>(kind: TlsErrorKind, desc: String) -> TlsResult<T> {
        Err(TlsError {
            kind: kind,
            desc: desc,
        })
    }
}

impl Error for TlsError {
    fn description(&self) -> &str {
        match self.kind {
            TlsErrorKind::UnexpectedMessage => "unexpected message",
            TlsErrorKind::BadRecordMac => "record has bad mac and/or encryption",
            TlsErrorKind::RecordOverflow => "record too long",
            TlsErrorKind::IllegalParameter => "illegal parameter during handshake",
            TlsErrorKind::DecodeError => "cannot decode message",
            TlsErrorKind::DecryptError => "failed to verify signature/message",
            TlsErrorKind::InternalError => "internal error",

            // UnsupportedExtension,

            // we probably can't even send alert?
            TlsErrorKind::IoFailure => "i/o error",
            TlsErrorKind::AlertReceived => "received an alert",
        }
    }
}

impl From<io::Error> for TlsError {
    fn from(err: io::Error) -> TlsError {
        TlsError {
            kind: TlsErrorKind::IoFailure,
            desc: format!("io error: {}", err),
        }
    }
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        <Self as fmt::Debug>::fmt(self, f)
    }
}

pub type TlsResult<T> = Result<T, TlsError>;
