use std::error::{Error, FromError};
use std::io::IoError;

#[derive(Copy, PartialEq, Show)]
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

#[derive(Show)]
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

    fn detail(&self) -> Option<String> {
        Some(self.desc.clone())
    }
}

impl FromError<IoError> for TlsError {
    fn from_error(err: IoError) -> TlsError {
        TlsError {
            kind: TlsErrorKind::IoFailure,
            desc: format!("io error: {}", err),
        }
    }
}

pub type TlsResult<T> = Result<T, TlsError>;
