use der::{Tag, FromTlv, DerResult, DerReader};

// iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1
macro_rules! id_pkcs1 {
    ($($e:expr),*) => ([42u8, 134, 72, 134, 247, 13, 1, 1, $($e),*])
}

enum_obj_id!(enum AlgId {
    // RFC 3279
    Rsa(()) = id_pkcs1!(1),
    // RsaMd2(()) = id_pkcs1!(2),
    // RsaMd5(()) = id_pkcs1!(4),
    RsaSha1(()) = id_pkcs1!(5),

    // RFC 4055
    // "sha###WithRSAEncryption"
    RsaSha224(()) = id_pkcs1!(14),
    RsaSha256(()) = id_pkcs1!(11),
});
