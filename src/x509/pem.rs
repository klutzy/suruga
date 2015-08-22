use std::error::Error;
use std::fmt;
use std::io::{self, Read, BufRead, BufReader};
use std::fs::File;
use rustc_serialize::base64::{self, FromBase64};

use util::ReadExt;

#[derive(Debug)]
pub enum PemError {
    IoError(io::Error),
    FormatError,
    Base64Error(base64::FromBase64Error),
}

impl fmt::Display for PemError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Error for PemError {
    fn description(&self) -> &str {
        match *self {
            PemError::IoError(..) => "io failure",
            PemError::FormatError => "cannot parse PEM header or footer",
            PemError::Base64Error(..) => "cannot decode base64",
        }
    }
}

impl From<io::Error> for PemError {
    fn from(err: io::Error) -> PemError {
        PemError::IoError(err)
    }
}

impl From<base64::FromBase64Error> for PemError {
    fn from(err: base64::FromBase64Error) -> PemError {
        PemError::Base64Error(err)
    }
}

pub type PemResult<T> = Result<T, PemError>;

pub struct PemReader {
    inner: BufReader<File>,
}

impl PemReader {
    pub fn new(file: File) -> PemReader {
        PemReader {
            inner: BufReader::new(file),
        }
    }
}

impl Iterator for PemReader {
    type Item = PemResult<(Vec<u8>, Vec<u8>)>;

    fn next(&mut self) -> Option<PemResult<(Vec<u8>, Vec<u8>)>> {
        // return Err(PemError::FormatError) if expectation fails.
        macro_rules! pem_expect {
            ($actual:expr, $exp:expr) => ({
                if $exp != $actual {
                    return Some(Err(PemError::FormatError));
                }
            })
        }

        macro_rules! try_opt {
            ($e:expr) => ({
                match $e {
                    Ok(e) => e,
                    Err(e) => return Some(Err(From::from(e))),
                }
            })
        }

        // try to read one byte to check EOF..
        let mut buf = [0u8];
        let read = try_opt!(self.inner.read(&mut buf));
        if read == 0 {
            return None;
        } else {
            pem_expect!(buf[0], b'-');
        }

        let mut buf = [0u8; 4];
        try_opt!(self.inner.fill_exact(&mut buf));
        pem_expect!(buf[..], b"----"[..]);

        let kind = {
            let mut buf = vec![];
            try_opt!(self.inner.read_until(b'-', &mut buf));
            let len = buf.len();

            // buf == b"BEGIN <SOMETHING>-"
            pem_expect!(buf[..6], b"BEGIN "[..]);
            pem_expect!(buf[len - 1], b'-');
            buf[6..(len - 1)].to_vec()
        };

        let mut buf = [0u8; 5];
        try_opt!(self.inner.fill_exact(&mut buf));
        pem_expect!(buf[..], b"----\n"[..]);

        let body = {
            let mut body = vec![];
            try_opt!(self.inner.read_until(b'-', &mut body));
            let len = body.len();
            if len == 0 {
                return Some(Err(PemError::FormatError));
            }
            pem_expect!(body[len - 1], b'-');
            body.truncate(len - 1);
            try_opt!(body.from_base64())
        };

        let mut buf = [0u8; 4];
        try_opt!(self.inner.fill_exact(&mut buf));
        pem_expect!(buf[..], b"----"[..]);

        let mut buf = vec![];
        try_opt!(self.inner.read_until(b'-', &mut buf));
        let len = buf.len();

        // buf == b"END <SOMETHING>-"
        pem_expect!(buf[..4], b"END "[..]);
        pem_expect!(buf[len - 1], b'-');
        pem_expect!(buf[4..(len - 1)], kind[..]);

        let mut buf = [0u8; 5];
        try_opt!(self.inner.fill_exact(&mut buf));
        pem_expect!(buf[..], b"----\n"[..]);

        Some(Ok((kind, body)))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, None)
    }
}
