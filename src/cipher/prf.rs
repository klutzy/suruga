// In AEAD setting, PRF is only used for key calculation.
// SHA-256 only for now.

use std::mem;
use crypto::sha2::sha256;

// key is SECRET, but the length is publicly known.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const B: usize = 64;

    if key.len() > B {
        // FIXME
        unimplemented!();
    }

    let mut i_msg = [0x36u8; B].to_vec();
    let mut o_msg = [0x5cu8; B].to_vec();
    {
        let i_msg = i_msg.as_mut_slice();
        let o_msg = o_msg.as_mut_slice();
        for i in (0us..key.len()) {
            i_msg[i] ^= key[i];
            o_msg[i] ^= key[i];
        }
    }

    i_msg.push_all(msg);
    let h_i = sha256(i_msg.as_slice());
    o_msg.push_all(h_i.as_slice());
    let h_o = sha256(o_msg.as_slice());

    h_o
}

pub struct Prf {
    secret: Vec<u8>, // SECRET
    seed: Vec<u8>,
    a: [u8; 32],
    buf: Vec<u8>,
}

impl Prf {
    pub fn new(secret: &[u8], seed: &[u8]) -> Prf {
        let a1 = hmac_sha256(secret, seed);

        Prf {
            secret: secret.to_vec(),
            seed: seed.to_vec(),
            a: a1,
            buf: Vec::new(),
        }
    }

    // get 32-byte pseudorandom number.
    fn next_block(&mut self) -> [u8; 32] {
        let mut input = self.a.to_vec();
        input.push_all(self.seed.as_slice());
        let next = hmac_sha256(self.secret.as_slice(), input.as_slice());
        self.a = hmac_sha256(self.secret.as_slice(), self.a.as_slice());

        next
    }

    pub fn get_bytes(&mut self, size: usize) -> Vec<u8> {
        let mut ret = {
            let buflen = self.buf.len();
            if buflen > 0 {
                if buflen <= size {
                    mem::replace(&mut self.buf, Vec::new())
                } else {
                    let rest = self.buf.slice_from(size).to_vec();
                    let mut buf = mem::replace(&mut self.buf, rest);
                    buf.truncate(size);
                    buf
                }
            } else {
                Vec::new()
            }
        };

        while ret.len() < size {
            let next_block = self.next_block();
            let slice_len = size - ret.len();
            if slice_len > 32 {
                ret.push_all(next_block.as_slice());
            } else {
                ret.push_all(next_block.slice_to(slice_len));
                self.buf = next_block.slice_from(slice_len).to_vec();
                break;
            };
        }

        ret
    }
}

#[cfg(test)]
mod test {
    use super::{hmac_sha256, Prf};

    #[test]
    fn test_hmac_sha256() {
        // some test vectors from RFC 4231
        static VALUES: &'static [(&'static [u8], &'static [u8], &'static [u8])] = &[
            (b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\
               \x0b\x0b\x0b\x0b",
             b"\x48\x69\x20\x54\x68\x65\x72\x65",
             b"\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b\
               \x88\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37\x6c\x2e\x32\xcf\xf7"),
            (b"\x4a\x65\x66\x65",
             b"\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61\x20\x77\x61\x6e\x74\x20\
               \x66\x6f\x72\x20\x6e\x6f\x74\x68\x69\x6e\x67\x3f",
             b"\x5b\xdc\xc1\x46\xbf\x60\x75\x4e\x6a\x04\x24\x26\x08\x95\x75\xc7\
               \x5a\x00\x3f\x08\x9d\x27\x39\x83\x9d\xec\x58\xb9\x64\xec\x38\x43"),
            (b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\
               \xaa\xaa\xaa\xaa",
             b"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
               \xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
               \xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\
               \xdd\xdd",
             b"\x77\x3e\xa9\x1e\x36\x80\x0e\x46\x85\x4d\xb8\xeb\xd0\x91\x81\xa7\
               \x29\x59\x09\x8b\x3e\xf8\xc1\x22\xd9\x63\x55\x14\xce\xd5\x65\xfe"),
            (b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\
               \x11\x12\x13\x14\x15\x16\x17\x18\x19",
             b"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
               \xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
               \xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\
               \xcd\xcd",
             b"\x82\x55\x8a\x38\x9a\x44\x3c\x0e\xa4\xcc\x81\x98\x99\xf2\x08\x3a\
               \x85\xf0\xfa\xa3\xe5\x78\xf8\x07\x7a\x2e\x3f\xf4\x67\x29\x66\x5b"),
        ];

        for &(key, input, expected) in VALUES.iter() {
            let actual = hmac_sha256(key, input);
            assert_eq!(actual.as_slice(), expected);
        }
    }

    #[test]
    fn test_get_bytes() {
        let ret1 = {
            let mut prf = Prf::new(b"", b"");
            let mut ret = Vec::new();
            for _ in 0us..100 {
                ret.push_all(&prf.get_bytes(1)[]);
            }
            ret
        };

        let ret2 = {
            let mut prf = Prf::new(b"", b"");
            prf.get_bytes(100)
        };

        assert_eq!(ret1, ret2);

        let ret3 = {
            let mut prf = Prf::new(b"", b"");
            let mut b = prf.get_bytes(33);
            b.push_all(&prf.get_bytes(33)[]);
            b.push_all(&prf.get_bytes(100 - 33 * 2)[]);
            b
        };

        assert_eq!(ret1, ret3);
    }
}
