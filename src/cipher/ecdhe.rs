use std::rand::{Rng, OsRng};
use std::old_io::BufReader;

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
        let mut reader = BufReader::new(data);
        let ecdh_params: EcdheServerKeyExchange = try!(TlsItem::tls_read(&mut reader));

        let gy = &*ecdh_params.params.public;
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
                for i in 0us..8 {
                    x.v[i] = rng.next_u32();
                }
                let xx = x.reduce_once(0);
                let x_is_okay = xx.compare(&x);
                if x_is_okay == 0 {
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
