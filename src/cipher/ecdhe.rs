use std::io::Cursor;
use rand::{Rng, OsRng};

use crypto::wrapping::Wrapping as W;
use util::{ReadExt, WriteExt};
use tls_result::TlsResult;
use tls_result::TlsErrorKind::IllegalParameter;
use tls_item::TlsItem;
use crypto::p256;
use handshake::NamedCurve;
use signature::DigitallySigned;
use super::KeyExchange;

tls_vec!(EcData = u8(1, (1 << 8) - 1));
tls_struct!(struct EcCurve {
    a: EcData,
    b: EcData
});

// usage:
// struct {
//     Type type;
//     "opaque" {
//         select (type) {
//             case TypeVariant1:
//                 ...
//             case TypeVariant2:
//                 ...
//         }
//     }
// } Struct;
macro_rules! tls_enum_struct {
    (
        $repr_ty:ident,
        $(#[$a:meta])*
        enum $enum_name:ident {
            $(
                $name:ident($body_ty:ident) = $num:tt // $num: integer literal
            ),+
        }
    ) => (
        #[allow(non_camel_case_types)]
        $(#[$a])*
        pub enum $enum_name {
            $(
                $name($body_ty),
            )+
        }

        impl TlsItem for $enum_name {
            fn tls_write<W: WriteExt>(&self, writer: &mut W) -> ::tls_result::TlsResult<()> {
                match *self {
                    $(
                        $enum_name::$name(ref body) => {
                            try_write_num!($repr_ty, writer, tt_to_expr!($num));
                            try!(body.tls_write(writer));
                        }
                    )+
                }
                Ok(())
            }

            fn tls_read<R: ReadExt>(reader: &mut R) -> ::tls_result::TlsResult<$enum_name> {
                let num = try_read_num!($repr_ty, reader);
                match num {
                    $(
                        tt_to_pat!($num) => {
                            let body: $body_ty = try!(TlsItem::tls_read(reader));
                            Ok($enum_name::$name(body))
                        }
                    )+
                    _ => return tls_err!(::tls_result::TlsErrorKind::DecodeError,
                                         "unexpected value: {}", num),
                }
            }

            fn tls_size(&self) -> u64 {
                let prefix_size = num_size!($repr_ty);
                let body_size = match *self {
                    $(
                        $enum_name::$name(ref body) => body.tls_size(),
                    )+
                };
                prefix_size + body_size
            }
        }
    )
}


tls_enum_struct!(u8, enum EcParameters {
    // explicit_prime(...) = 1,
    // explicit_char2(...) = 2,
    named_curve(NamedCurve) = 3
});

tls_struct!(struct ServerEcdhParams {
    curve_params: EcParameters,
    public: EcData
});

tls_struct!(struct EcdheServerKeyExchange {
    params: ServerEcdhParams,
    signed_params: DigitallySigned
});

pub struct EllipticDiffieHellman;

impl KeyExchange for EllipticDiffieHellman {
    fn compute_keys(&self, data: &[u8], rng: &mut OsRng) -> TlsResult<(Vec<u8>, Vec<u8>)> {
        let mut reader = Cursor::new(data);
        let ecdh_params: EcdheServerKeyExchange = try!(TlsItem::tls_read(&mut reader));

        let gy = &ecdh_params.params.public;
        let gy = p256::NPoint256::from_uncompressed_bytes(gy);
        let gy = match gy {
            None => {
                return tls_err!(IllegalParameter, "server sent strange public key");
            }
            Some(gy) => gy,
        };
        let gy = gy.to_point();

        fn get_random_x(rng: &mut OsRng) -> p256::int256::Int256 {
            loop {
                let mut x = p256::int256::ZERO;
                for i in 0..8 {
                    x.v[i] = W(rng.next_u32());
                }
                let xx = x.reduce_once(W(0));
                let x_is_okay = xx.compare(&x);
                if x_is_okay == W(0) {
                    return x;
                }
            }
        }

        let x = get_random_x(rng);
        let gx = p256::G.mult_scalar(&x).normalize().to_uncompressed_bytes();
        let gxy = gy.mult_scalar(&x).normalize();
        let pre_master_secret = gxy.x.to_bytes();

        // we don't support client cert. send public key explicitly.
        let public = try!(EcData::new(gx));

        let mut data = Vec::new();
        try!(public.tls_write(&mut data));
        let public = data;

        Ok((public, pre_master_secret))
    }
}
