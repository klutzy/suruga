#[deriving(Show)]
#[deriving(PartialEq)]
pub enum TlsErrorKind {
    UnexpectedMessage,
    BadRecordMac,
    RecordOverflow,
    IllegalParameter,
    DecodeError,
    DecryptError,
    InternalError,

    // UnsupportedExtension,

    // we probably can't even send alert?
    IoFailure,
    AlertReceived,
}

#[deriving(Show)]
pub struct TlsError {
    pub kind: TlsErrorKind,
    pub desc: String,

    // track where the error occurred
    #[cfg(debug)]
    file: &'static str,
    #[cfg(debug)]
    line: uint,
}

impl TlsError {
    #[cfg(not(debug))]
    pub fn new<T>(kind: TlsErrorKind, desc: String) -> TlsResult<T> {
        Err(TlsError {
            kind: kind,
            desc: desc,
        })
    }

    #[cfg(debug)]
    pub fn new<T>(kind: TlsErrorKind, desc: String, file: &'static str, line: uint)
    -> TlsResult<T> {
        Err(TlsError {
            kind: kind,
            desc: desc,
            file: file,
            line: line,
        })
    }
}

pub type TlsResult<T> = Result<T, TlsError>;
