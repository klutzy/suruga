// http://cr.yp.to/chacha/chacha-20080128.pdf
// http://cr.yp.to/chacha.html

// convert $e.slice($i, $i + 4) into u32
macro_rules! to_le_u32 {
    ($e:ident[$i:expr]) => ({
        let i: usize = $i;
        let v1 = $e[i + 0] as u32;
        let v2 = $e[i + 1] as u32;
        let v3 = $e[i + 2] as u32;
        let v4 = $e[i + 3] as u32;
        v1 | (v2 << 8) | (v3 << 16) | (v4 << 24)
    })
}

pub struct ChaCha20 {
    // SECRET
    vals: [u32; 16],
}

impl ChaCha20 {
    // key: SECRET
    pub fn new(key: &[u8], nonce: &[u8]) -> ChaCha20 {
        assert_eq!(key.len(), 32);
        assert_eq!(nonce.len(), 8);

        let mut vals = [0u32; 16];

        // "expand 32-byte k"
        vals[0] = 0x61707865;
        vals[1] = 0x3320646e;
        vals[2] = 0x79622d32;
        vals[3] = 0x6b206574;

        for i in (0us..8) {
            vals[4 + i] = to_le_u32!(key[4 * i]);
        }

        // counter
        vals[12] = 0;
        vals[13] = 0;

        vals[14] = to_le_u32!(nonce[0]);
        vals[15] = to_le_u32!(nonce[4]);

        ChaCha20 {
            vals: vals,
        }
    }

    fn round20(&self) -> [u32; 16] {
        // $e must be > 0 and < 32
        macro_rules! rot {
            ($a:expr, $e:expr) => ({
                let a: u32 = $a;
                let e: usize = $e;
                (a << e) | (a >> (32 - e))
            })
        }

        macro_rules! quarter_round {
            ($a:expr, $b:expr, $c:expr, $d:expr) => ({
                $a += $b;
                $d ^= $a;
                $d = rot!($d, 16);

                $c += $d;
                $b ^= $c;
                $b = rot!($b, 12);

                $a += $b;
                $d ^= $a;
                $d = rot!($d, 8);

                $c += $d;
                $b ^= $c;
                $b = rot!($b, 7);
            })
        }

        macro_rules! quarter_round_idx {
            ($e:expr, $a:expr, $b:expr, $c:expr, $d:expr) => (
                quarter_round!($e[$a], $e[$b], $e[$c], $e[$d])
            )
        }

        let mut vals = self.vals;
        for _ in (0us..10) {
            // column round
            quarter_round_idx!(vals, 0, 4, 8, 12);
            quarter_round_idx!(vals, 1, 5, 9, 13);
            quarter_round_idx!(vals, 2, 6, 10, 14);
            quarter_round_idx!(vals, 3, 7, 11, 15);

            // diagonal round
            quarter_round_idx!(vals, 0, 5, 10, 15);
            quarter_round_idx!(vals, 1, 6, 11, 12);
            quarter_round_idx!(vals, 2, 7, 8, 13);
            quarter_round_idx!(vals, 3, 4, 9, 14);
        }

        for i in (0us..16) {
            vals[i] += self.vals[i];
        }

        vals
    }

    pub fn next(&mut self) -> [u8; 64] {
        let next = self.round20();

        // in TLS, vals[13] never increases
        {
            self.vals[12] += 1;
            //let mut count = (self.vals[12] as u64) | (self.vals[13] as u64 << 32);
            //count += 1;
            //self.vals[12] = count as u32;
            //self.vals[13] = (count >> 32) as u32;
        }

        let next_bytes = {
            let mut next_bytes = [0u8; 64];
            for i in (0us..16) {
                next_bytes[4 * i + 0] = next[i] as u8;
                next_bytes[4 * i + 1] = (next[i] >> 8) as u8;
                next_bytes[4 * i + 2] = (next[i] >> 16) as u8;
                next_bytes[4 * i + 3] = (next[i] >> 24) as u8;
            }
            next_bytes
        };

        next_bytes
    }

    // Do not use same nonce for more than 2^70 bytes.
    //
    // if data is 1 byte, it still produces 64 bytes then 63 bytes are just discarded.
    // so this is not suitable for "byte-streaming" mode.
    //
    // data: SECRET
    pub fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut ret: Vec<u8> = Vec::new();

        for chunk in data.chunks(64) {
            let next = self.next();
            let xor_iter = next.iter().zip(chunk.iter()).map(|(&x, &y)| x ^ y);
            ret.extend(xor_iter);
        }

        ret
    }
}

#[cfg(test)]
mod test {
    use std::iter::repeat;

    use super::ChaCha20;

    fn check_keystream(key: &[u8], nonce: &[u8], keystream: &[u8]) {
        let mut chacha = ChaCha20::new(key, nonce);
        let input: Vec<_> = repeat(0u8).take(keystream.len()).collect();
        let output = chacha.encrypt(&input[]);
        assert_eq!(&output[], keystream);
    }

    #[test]
    fn test_chacha20() {
        // from https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04

        let mut key = [0u8; 32];
        let mut nonce = [0u8; 8];
        let keystream = b"\x76\xb8\xe0\xad\xa0\xf1\x3d\x90\x40\x5d\x6a\xe5\x53\x86\xbd\x28\
                          \xbd\xd2\x19\xb8\xa0\x8d\xed\x1a\xa8\x36\xef\xcc\x8b\x77\x0d\xc7\
                          \xda\x41\x59\x7c\x51\x57\x48\x8d\x77\x24\xe0\x3f\xb8\xd8\x4a\x37\
                          \x6a\x43\xb8\xf4\x15\x18\xa1\x1c\xc3\x87\xb6\x69\xb2\xee\x65\x86";
        check_keystream(&key, &nonce, keystream);

        key[31] = 1;
        let keystream = b"\x45\x40\xf0\x5a\x9f\x1f\xb2\x96\xd7\x73\x6e\x7b\x20\x8e\x3c\x96\
                          \xeb\x4f\xe1\x83\x46\x88\xd2\x60\x4f\x45\x09\x52\xed\x43\x2d\x41\
                          \xbb\xe2\xa0\xb6\xea\x75\x66\xd2\xa5\xd1\xe7\xe2\x0d\x42\xaf\x2c\
                          \x53\xd7\x92\xb1\xc4\x3f\xea\x81\x7e\x9a\xd2\x75\xae\x54\x69\x63";
        check_keystream(&key, &nonce, keystream);

        key[31] = 0;
        nonce[7] = 1;
        let keystream = b"\xde\x9c\xba\x7b\xf3\xd6\x9e\xf5\xe7\x86\xdc\x63\x97\x3f\x65\x3a\
                          \x0b\x49\xe0\x15\xad\xbf\xf7\x13\x4f\xcb\x7d\xf1\x37\x82\x10\x31\
                          \xe8\x5a\x05\x02\x78\xa7\x08\x45\x27\x21\x4f\x73\xef\xc7\xfa\x5b\
                          \x52\x77\x06\x2e\xb7\xa0\x43\x3e\x44\x5f\x41\xe3";
        check_keystream(&key, &nonce, keystream);

        key[31] = 0;
        nonce[7] = 0;
        nonce[0] = 1;
        let keystream = b"\xef\x3f\xdf\xd6\xc6\x15\x78\xfb\xf5\xcf\x35\xbd\x3d\xd3\x3b\x80\
                          \x09\x63\x16\x34\xd2\x1e\x42\xac\x33\x96\x0b\xd1\x38\xe5\x0d\x32\
                          \x11\x1e\x4c\xaf\x23\x7e\xe5\x3c\xa8\xad\x64\x26\x19\x4a\x88\x54\
                          \x5d\xdc\x49\x7a\x0b\x46\x6e\x7d\x6b\xbd\xb0\x04\x1b\x2f\x58\x6b";
        check_keystream(&key, &nonce, keystream);

        for i in (0us..0x20) {
            key[i] = i as u8;
        }
        for i in (0us..0x08) {
            nonce[i] = i as u8;
        }
        let keystream = b"\xf7\x98\xa1\x89\xf1\x95\xe6\x69\x82\x10\x5f\xfb\x64\x0b\xb7\x75\
                          \x7f\x57\x9d\xa3\x16\x02\xfc\x93\xec\x01\xac\x56\xf8\x5a\xc3\xc1\
                          \x34\xa4\x54\x7b\x73\x3b\x46\x41\x30\x42\xc9\x44\x00\x49\x17\x69\
                          \x05\xd3\xbe\x59\xea\x1c\x53\xf1\x59\x16\x15\x5c\x2b\xe8\x24\x1a\
                          \x38\x00\x8b\x9a\x26\xbc\x35\x94\x1e\x24\x44\x17\x7c\x8a\xde\x66\
                          \x89\xde\x95\x26\x49\x86\xd9\x58\x89\xfb\x60\xe8\x46\x29\xc9\xbd\
                          \x9a\x5a\xcb\x1c\xc1\x18\xbe\x56\x3e\xb9\xb3\xa4\xa4\x72\xf8\x2e\
                          \x09\xa7\xe7\x78\x49\x2b\x56\x2e\xf7\x13\x0e\x88\xdf\xe0\x31\xc7\
                          \x9d\xb9\xd4\xf7\xc7\xa8\x99\x15\x1b\x9a\x47\x50\x32\xb6\x3f\xc3\
                          \x85\x24\x5f\xe0\x54\xe3\xdd\x5a\x97\xa5\xf5\x76\xfe\x06\x40\x25\
                          \xd3\xce\x04\x2c\x56\x6a\xb2\xc5\x07\xb1\x38\xdb\x85\x3e\x3d\x69\
                          \x59\x66\x09\x96\x54\x6c\xc9\xc4\xa6\xea\xfd\xc7\x77\xc0\x40\xd7\
                          \x0e\xaf\x46\xf7\x6d\xad\x39\x79\xe5\xc5\x36\x0c\x33\x17\x16\x6a\
                          \x1c\x89\x4c\x94\xa3\x71\x87\x6a\x94\xdf\x76\x28\xfe\x4e\xaa\xf2\
                          \xcc\xb2\x7d\x5a\xaa\xe0\xad\x7a\xd0\xf9\xd4\xb6\xad\x3b\x54\x09\
                          \x87\x46\xd4\x52\x4d\x38\x40\x7a\x6d\xeb\x3a\xb7\x8f\xab\x78\xc9";
        check_keystream(&key, &nonce, keystream);
    }
}
