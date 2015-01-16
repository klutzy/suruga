// 7.4.1.4.1 Signature algorithm

use tls_item::TlsItem;

tls_enum!(u8, enum HashAlgorithm {
   none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
   sha512(6)
});

tls_enum!(u8, enum SignatureAlgorithm {
  anonymous(0), rsa(1), dsa(2), ecdsa(3)
});

tls_struct!(struct SignatureAndHashAlgorithm {
    hash: HashAlgorithm,
    signature: SignatureAlgorithm
});
tls_vec!(SignatureAndHashAlgorithmVec = SignatureAndHashAlgorithm(2, (1 << 16) - 2));

tls_vec!(Signature = u8(0, (1 << 16) - 1));
tls_struct!(struct DigitallySigned {
    algorithm: SignatureAndHashAlgorithm,
    signature: Signature
});
