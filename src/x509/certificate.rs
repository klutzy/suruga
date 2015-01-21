use der::{Tag, FromTlv, DerReader, BitString};

use super::CertResult;
use super::alg_id::AlgId;
use super::version::Version;
use super::name::Name;
use super::validity::Validity;
use super::extension::ExtensionList;
use super::cert_serial_number::CertificateSerialNumber;

sequence!(struct SubjectPublicKeyInfo {
    alg: AlgId,
    subject_pub_key: BitString,
});

sequence_opts!(struct TbsCertificate {
    version(EXPLICIT_DEFAULT[C:0], Version::Version1): Version,
    serial_number(): CertificateSerialNumber,
    signature(): AlgId,
    issuer(): Name,
    validity(): Validity,
    subject(): Name,
    subject_pub_key_info(): SubjectPublicKeyInfo,

    // If present, version MUST be v2 or v3
    issuer_unique_id(IMPLICIT_OPTIONAL[P:1], Tag::BitString): Option<BitString>,
    subject_unique_id(IMPLICIT_OPTIONAL[P:2], Tag::BitString):  Option<BitString>,

    extensions(EXPLICIT_OPTIONAL[C:3]): Option<ExtensionList>,
});

sequence!(struct Certificate {
    cert: TbsCertificate,
    sig_alg: AlgId,
    sig_val: BitString,
});

impl Certificate {
    /// Parse Certificate from DER bytes.
    pub fn parse(cert: &[u8]) -> CertResult<Certificate> {
        let mut parser = DerReader::new(cert);
        let (tag, value) = try!(parser.next_tlv());
        let cert = try!(FromTlv::from_tlv(tag, value));
        Ok(cert)
    }

    // pub fn validate(&self, context: &ValidationContext) -> CertResult<()> {
    // }
}
