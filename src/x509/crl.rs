use der::{Tag, FromTlv, DerReader, BitString, Time};

use super::alg_id::AlgId;
use super::CertResult;
use super::version::Version;
use super::name::Name;
use super::cert_serial_number::CertificateSerialNumber;
use super::extension::ExtensionList;

sequence_opts!(struct RevokedCert {
    user_cert(): CertificateSerialNumber,
    revoke_date(): Time,
    // if Some, version must be v2
    extensions(OPTIONAL, Tag::Sequence): Option<ExtensionList>,
});

sequence_of!(struct RevokedCertList = RevokedCert(0));

sequence_opts!(struct TbsCertList {
    // if Some, must be v2
    version(OPTIONAL, Tag::Integer): Option<Version>,
    signature(): AlgId,
    issuer(): Name,
    this_update(): Time,
    next_update(OPTIONAL, Tag::UtcTime, Tag::GeneralizedTime): Option<Time>,
    revoked_certs(OPTIONAL, Tag::Sequence): Option<RevokedCertList>,
    // if Some, version must be v2
    extensions(EXPLICIT_OPTIONAL[C:0]): Option<ExtensionList>,
});

sequence!(struct CertificateList {
    cert_list: TbsCertList,
    sig_alg: AlgId,
    sig_val: BitString,
});

impl CertificateList {
    /// Parse Certificate from DER bytes.
    pub fn parse(cert: &[u8]) -> CertResult<CertificateList> {
        let mut parser = DerReader::new(cert);
        let (tag, value) = try!(parser.next_tlv());
        let output = try!(FromTlv::from_tlv(tag, value));
        Ok(output)
    }
}
