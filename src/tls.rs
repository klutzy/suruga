use std::rand::OsRng;

use tls_result::{TlsResult, TlsError, TlsErrorKind};
use record::{RecordWriter, RecordReader};
use alert::{self, Alert};

pub static TLS_VERSION: (u8, u8) = (3, 3);

pub struct Tls<R: Reader, W: Writer> {
    pub writer: RecordWriter<W>,
    pub reader: RecordReader<R>,
    pub rng: OsRng,
}

impl<R: Reader, W: Writer> Tls<R, W> {
    pub fn new(reader: R, writer: W, rng: OsRng) -> Tls<R, W> {
        let writer = RecordWriter::new(writer);
        let reader = RecordReader::new(reader);
        Tls {
            writer: writer,
            reader: reader,
            rng: rng,
        }
    }

    pub fn close(&mut self) -> TlsResult<()> {
        let alert_data = alert::Alert {
            level: alert::AlertLevel::fatal,
            description: alert::AlertDescription::close_notify,
        };
        try!(self.writer.write_alert(&alert_data));
        Ok(())
    }

    // send fatal alert and return error
    // (it may be different to `err`, because writing alert can fail)
    pub fn send_tls_alert(&mut self, err: TlsError) -> TlsError {
        match err.kind {
            TlsErrorKind::IoFailure => return err,
            _ => {
                let alert = alert::Alert::from_tls_err(&err);
                let result = self.writer.write_alert(&alert);
                match result {
                    Ok(()) => return err,
                    Err(err) => return err,
                }
            }
        }
    }
}
