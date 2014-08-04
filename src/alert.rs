use tls_result::{TlsResult, TlsError, TlsErrorKind};
use tls_result;
use tls_item::TlsItem;

// we treat every alert as fatal.
tls_enum!(u8 enum AlertLevel {
    warning(1),
    fatal(2)
})

// A.3. Alert Messages
// http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
tls_enum!(u8 #[deriving(Show)] enum AlertDescription {
    close_notify(0),
    unexpected_message(10),
    bad_record_mac(20),
    decryption_failed_RESERVED(21),
    record_overflow(22),
    decompression_failure(30),
    handshake_failure(40),
    no_certificate_RESERVED(41),
    bad_certificate(42),
    unsupported_certificate(43),
    certificate_revoked(44),
    certificate_expired(45),
    certificate_unknown(46),
    illegal_parameter(47),
    unknown_ca(48),
    access_denied(49),
    decode_error(50),
    decrypt_error(51),
    export_restriction_RESERVED(60),
    protocol_version(70),
    insufficient_security(71),
    internal_error(80),
    user_canceled(90),
    no_renegotiation(100),
    unsupported_extension(110)

    // RFC 6066
    // certificate_unobtainable(111),
    // unrecognized_name(112),
    // bad_certificate_status_response(113),
    // bad_certificate_hash_value(114),
})

impl AlertDescription {
    fn from_err(kind: TlsErrorKind) -> AlertDescription {
        match kind {
            tls_result::UnexpectedMessage => unexpected_message,
            tls_result::BadRecordMac => bad_record_mac,
            tls_result::RecordOverflow => record_overflow,
            tls_result::IllegalParameter => illegal_parameter,
            tls_result::DecodeError => decode_error,
            tls_result::DecryptError => decrypt_error,
            tls_result::InternalError => internal_error,

            // FIXME: we probably can't even send alert?
            tls_result::IoFailure => internal_error,
            tls_result::AlertReceived => close_notify,
        }

    }
}

tls_struct!(struct Alert {
    level: AlertLevel,
    description: AlertDescription
})

impl Alert {
    pub fn new(level: AlertLevel, desc: AlertDescription) -> TlsResult<Alert> {
        // TODO filter out some rfc-invalid alerts
        Ok(Alert {
            level: level,
            description: desc,
        })
    }

    pub fn from_tls_err(err: &TlsError) -> Alert {
        Alert {
            level: fatal,
            description: AlertDescription::from_err(err.kind),
        }
    }
}
