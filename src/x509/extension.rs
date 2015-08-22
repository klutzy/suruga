use der::{Tag, FromTlv, FromValue, DerResult};
use der::{ObjId, Any, Integer};
use der::reader::DerReader;
use der::DerErrorKind::{InvalidVal, InvalidTag};

use super::cert_serial_number::CertificateSerialNumber;
use super::name::{Name, RelativeDistinguishedName};

macro_rules! id_ce {
    // 0x55 (joint-iso-ccitt(2) ds(5)) 29
    ($($e:expr),*) => ([0x55, 29, $($e),*])
}

macro_rules! id_pkix {
    // 0x2b (iso(1) identified-organization(3)) 6 1 5 5 7
    ($($e:expr),*) => ([0x2b, 6, 1, 5, 5, 7, $($e),*])
}

macro_rules! id_pe {
    ($($e:expr),*) => (id_pkix!(1, $($e),*))
}

macro_rules! id_qt {
    ($($e:expr),*) => (id_pkix!(2, $($e),*))
}

// TODO all tagged typed should be reviewed again since most of them are
// implicit but some of them are automatically forced to be explicit (wat)

pub type Ia5String = String;

// DisplayText ::= CHOICE {
//     ia5String        IA5String      (SIZE (1..200)),
//     visibleString    VisibleString  (SIZE (1..200)),
//     bmpString        BMPString      (SIZE (1..200)),
//     utf8String       UTF8String     (SIZE (1..200))
// }
pub type DisplayText = String;

pub type KeyIdentifier = Vec<u8>;

sequence_opts!(struct AuthorityKeyIdentifier {
    key_identifier(IMPLICIT_OPTIONAL[P:0], Tag::OctetString): Option<KeyIdentifier>,
    authority_cert_issuer(IMPLICIT_OPTIONAL[C:1], Tag::Sequence): Option<GeneralNames>,
    authority_cert_serial_number(IMPLICIT_OPTIONAL[P:2], Tag::Integer):
        Option<CertificateSerialNumber>,
});

bit_string_fields!(struct KeyUsage {
    digital_signature(0),
    // also known as non_repudiation.
    content_commitment(1),
    key_encipherment(2),
    data_encipherment(3),
    key_agreement(4),
    key_cert_sign(5),
    crl_sign(6),
    encipher_only(7),
    decipher_only(8),
});

sequence_opts!(struct UserNotice {
    notice_ref(OPTIONAL, Tag::Sequence): Option<NoticeReference>,
    explicit_text(OPTIONAL, Tag::Ia5String, Tag::VisibleString): Option<DisplayText>,
});

sequence_of!(struct IntegerSequence = Integer(0));

sequence!(struct NoticeReference {
    organization: DisplayText,
    notice_numbers: IntegerSequence,
});

enum_obj_id!(enum PolicyQualifierInfo {
    Cps(Ia5String) = id_qt!(1),
    Unotice(UserNotice) = id_qt!(2),
});

sequence_of!(struct PolicyQualifiers = PolicyQualifierInfo(1));

// Go x509 ignores qualifiers.
sequence_opts!(struct PolicyInformation {
    policy_identifier(): ObjId,
    policy_qualifiers(OPTIONAL, Tag::Sequence): Option<PolicyQualifiers>,
});

sequence_of!(struct CertificatePolicies = PolicyInformation(1));

// TODO see 4.2.1.6 for commented fields
choice_tagged!(enum GeneralName {
    [C:0] OtherName(IMPLICIT, Tag::Sequence): Any,
    [P:1] Rfc822Name(IMPLICIT, Tag::Ia5String): Ia5String,
    [P:2] DnsName(IMPLICIT, Tag::Ia5String): Ia5String,
    // [3] X400Address(ORAddress),
    // `Name` is CHOICE, so cannot be IMPLICIT. sigh
    [C:4] DirectoryName(EXPLICIT): Name,
    // [5] EdiPartyName(EDIPartyName),
    [P:6] UniformResourceIdentifier(IMPLICIT, Tag::Ia5String): Ia5String,
    // [7] IpAddress(OctetString),
    // [8] RegisteredId(ObjId),
});
sequence_of!(struct GeneralNames = GeneralName(1));

// sequence_of!(SubjectDirectoryAttributes = Attribute(1));

// TODO it's silly to accept >1 bytes
#[derive(Debug)]
pub struct PathLenConstraints(Vec<u8>);
from_value!(PathLenConstraints: Tag::Integer);

impl FromValue for PathLenConstraints {
    fn from_value(value: &[u8]) -> DerResult<PathLenConstraints> {
        Ok(PathLenConstraints(value.to_vec()))
    }
}

sequence_opts!(struct BasicConstraints {
    ca(DEFAULT, false, Tag::Boolean): bool,
    path_len_constraints(OPTIONAL, Tag::Integer): Option<PathLenConstraints>,
});

// 4.2.1.12 Extended Key Usage
sequence_of!(struct ExtKeyUsageSyntax = ObjId(1));

choice_tagged!(enum DistributionPointName {
    [C:0] FullName(IMPLICIT, Tag::Sequence): GeneralNames,
    [C:1] NameRelativeToCrlIssuer(IMPLICIT, Tag::Set): RelativeDistinguishedName,
});
bit_string_fields!(struct ReasonFlags {
    unused(0),
    key_compromise(1),
    ca_compromise(2),
    affiliation_changed(3),
    superseded(4),
    cessation_of_operation(5),
    certificate_hold(6),
    privilege_withdrawn(7),
    aa_compromise(8),
});
// even if distributionPoint is implicit in the spec, DistributionPointName is
// CHOICE which cannot be implicit, so it is *implicitly* explicit. sigh
sequence_opts!(struct DistrubitionPoint {
    distribution_point(EXPLICIT_OPTIONAL[C:0]): Option<DistributionPointName>,
    reasons(IMPLICIT_OPTIONAL[P:1], Tag::BitString): Option<ReasonFlags>,
    crl_issuer(IMPLICIT_OPTIONAL[C:2], Tag::Sequence): Option<GeneralNames>,
});
sequence_of!(struct CrlDistrubitionPoints = DistrubitionPoint(1));

// 4.2.2.1
sequence!(struct AccessDescription {
    access_method: ObjId,
    access_location: GeneralName,
});
sequence_of!(struct AuthorityInfoAccessSyntax = AccessDescription(1));

// Extension ::= SEQUENCE {
//     extn_id OBJECT IDENTIFIER,
//     critical BOOLEAN DEFAULT FALSE,
//     extn_value OCTET STRING
// }
// where `extn_value` is DER blob determined by extn_id.
// note that this is different to `ANY` since it is wrapped in OctetString.
macro_rules! extensions {
    (
        $(
            $name:ident($t:ty) = $val:pat,
        )+
    ) => (
        #[derive(Debug)]
        pub enum Extension {
            $(
                $name($t),
            )+

            // .0: extension id
            // .1: critical bit
            // TODO: this may not a good design at all.. revisit this later
            Unknown(Vec<u8>, bool),
        }

        from_sequence!(Extension);
        impl Extension {
            fn from_seq(mut reader: DerReader) -> DerResult<Extension> {
                // FIXME: this exists only because `extn_id` freezes reader.
                #[derive(Debug)]
                enum ExtensionId {
                    $(
                        $name,
                    )+

                    Unknown(Vec<u8>),
                }

                let ext = {
                    let (tag, extn_id) = try!(reader.next_tlv());
                    if tag != Tag::ObjectIdentifier {
                        return der_err!(InvalidTag, "expected ObjectIdentifier");
                    }
                    let ext = match extn_id {
                        $(
                            $val => ExtensionId::$name,
                        )+
                        unknown_id => ExtensionId::Unknown(unknown_id.to_vec()),
                    };
                    debug!("extension id: {:?} -> {:?}", extn_id, ext);
                    ext
                };

                let critical = sequence_item!(bool, reader, DEFAULT, false, Tag::Boolean);
                if let ExtensionId::Unknown(id) = ext {
                    return Ok(Extension::Unknown(id, critical));
                }

                let (tag, extn_value) = try!(reader.next_tlv());
                if tag != Tag::OctetString {
                    return der_err!(InvalidTag, "expected OctetString");
                }

                match ext {
                    $(
                        ExtensionId::$name => {
                            let mut ext_reader = DerReader::new(extn_value);
                            let (ext_tag, ext_value) = try!(ext_reader.next_tlv());
                            debug!("ext tag {:?} value {:?}", ext_tag, ext_value);
                            let result: $t = try!(FromTlv::from_tlv(ext_tag, ext_value));
                            if !ext_reader.is_eof() {
                                return der_err!(InvalidTag, "too many TLV elements");
                            }
                            debug!("extension result: {}, {:?}", stringify!($name), result);
                            return Ok(Extension::$name(result));
                        }
                    )+
                    ExtensionId::Unknown(..) => unreachable!(),
                }
            }
        }
    )
}

extensions! {
    // 4.2.1.1
    AuthorityKeyIdentifier(AuthorityKeyIdentifier) = id_ce!(35),
    // 4.2.1.2
    SubjectKeyIdentifier(KeyIdentifier) = id_ce!(14),
    // 4.2.1.3
    KeyUsage(KeyUsage) = id_ce!(15),
    // 4.2.1.4
    CertificatePolicies(CertificatePolicies) = id_ce!(32),
    // 4.2.1.5
    // PolicyMappings(PolicyMappings) = id_ce!(33),
    // 4.2.1.6
    SubjectAltName(GeneralNames) = id_ce!(17),
    // 4.2.1.7
    IssuerAltName(GeneralNames) = id_ce!(18),
    // 4.2.1.8
    // SubjectDirectoryAttributes(SubjectDirectoryAttributes) = id_ce!(9),
    // 4.2.1.9
    BasicConstraints(BasicConstraints) = id_ce!(19),
    // 4.2.1.10
    // NameConstraints(NameConstraints) = id_ce!(30),
    // 4.2.1.11
    // PolicyConstraints(PolicyConstraints) = id_ce!(36),
    // 4.2.1.12
    ExtendedKeyUsage(ExtKeyUsageSyntax) = id_ce!(37),
    // 4.2.1.13
    CrlDistrubitionPoints(CrlDistrubitionPoints) = id_ce!(31),
    // 4.2.1.14
    // InhibitAnyPolicy(InhibitAnyPolicy) = id_ce!(54),
    // 4.2.1.15
    // FreshestCrl(CrlDistrubitionPoints) = id_ce!(46),

    // 4.2.2.1
    AuthorityInfoAccess(AuthorityInfoAccessSyntax) = id_pe!(1),
    // 4.2.2.2
    // SubjectInfoAccess(SubjectInfoAccess) = id_pe!(11),

    // RFC 3709: Logotype, id_pe!(12)
}

// seems that some OCSP responses contain empty ExtensionList.
// https://bugzilla.mozilla.org/show_bug.cgi?id=997994
sequence_of!(struct ExtensionList = Extension(1));
