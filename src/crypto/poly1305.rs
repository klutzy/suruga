// http://cr.yp.to/mac/poly1305-20050329.pdf

macro_rules! choose_impl {
    ($s: ident, $t:ty, $($a:expr)+) => (
        impl $s {
            fn choose(flag: $t, a: &$s, b: &$s) -> $s {
                $s {
                    v: [
                        $(
                            a.v[$a] ^ (flag * (a.v[$a] ^ b.v[$a])),
                        )+
                    ]
                }
            }
        }
    )
}

// radix-2^26 (26 == 130/5)
// value = v[0] + 2^26 v[1] + 2^52 v[2] + 2^78 v[3] + 2^104 v[4]
// lazy normalization: v[i] <= 2^32 - 1
// http://cr.yp.to/highspeed/neoncrypto-20120320.pdf
pub struct Int1305 {
    v: [u32; 5],
}

pub const ZERO: Int1305 = Int1305 { v: [0; 5] };

choose_impl! {Int1305, u32, 0 1 2 3 4}

impl Int1305 {
    // no reduction.
    fn add(&self, b: &Int1305) -> Int1305 {
        macro_rules! add_digit {
            ($a:expr, $b:expr, $c:expr, $($i:expr)+) => ({
                $(
                    $c[$i] = $a[$i] + $b[$i];
                )+
            })
        }

        let mut ret = [0; 5];

        add_digit!(self.v, b.v, ret, 0 1 2 3 4);

        Int1305 { v: ret }
    }

    fn mult(&self, b: &Int1305) -> Int1305 {
        let b5 = [b.v[0] * 5, b.v[1] * 5, b.v[2] * 5, b.v[3] * 5, b.v[4] * 5];

        macro_rules! m {
            ($i:expr, $j:expr) => ((self.v[$i] as u64) * (b.v[$j] as u64))
        }
        macro_rules! m5 {
            ($i:expr, $j:expr) => ((self.v[$i] as u64) * (b5[$j] as u64))
        }

        let mut v: [u64; 5] = [
            m!(0, 0) + m5!(1, 4) + m5!(2, 3) + m5!(3, 2) + m5!(4, 1),
            m!(0, 1) + m!(1, 0) + m5!(2, 4) + m5!(3, 3) + m5!(4, 2),
            m!(0, 2) + m!(1, 1) + m!(2, 0) + m5!(3, 4) + m5!(4, 3),
            m!(0, 3) + m!(1, 2) + m!(2, 1) + m!(3, 0) + m5!(4, 4),
            m!(0, 4) + m!(1, 3) + m!(2, 2) + m!(3, 1) + m!(4, 0),
        ];

        // if self and b is reduced, v[i] <= 25 * (2^26 - 1)^2

        let mut carry = 0;

        macro_rules! reduce_digit {
            ($i:expr) => ({
                v[$i] += carry;
                carry = v[$i] >> 26;
                v[$i] &= (1 << 26) - 1;
            })
        }

        reduce_digit!(0); // carry <= 25 * (2^26 - 1)
        reduce_digit!(1); // again, carry <= 25 * (2^26 - 1)
        reduce_digit!(2);
        reduce_digit!(3);
        reduce_digit!(4);

        debug_assert_eq!(v[0] >> 32, 0);
        debug_assert_eq!(v[1] >> 32, 0);
        debug_assert_eq!(v[2] >> 32, 0);
        debug_assert_eq!(v[3] >> 32, 0);
        debug_assert_eq!(v[4] >> 32, 0);

        debug_assert!(carry <= 25 * ((1 << 26) - 1));

        carry *= 5; // carry <= 125 * (2^26 - 1)

        reduce_digit!(0); // carry <= 125
        reduce_digit!(1); // carry <= 1
        reduce_digit!(2);
        reduce_digit!(3);
        reduce_digit!(4);

        debug_assert_eq!(v[0] >> 32, 0);
        debug_assert_eq!(v[1] >> 32, 0);
        debug_assert_eq!(v[2] >> 32, 0);
        debug_assert_eq!(v[3] >> 32, 0);
        debug_assert_eq!(v[4] >> 32, 0);

        debug_assert!(carry <= 1);

        carry *= 5; // carry <= 5

        reduce_digit!(0);
        reduce_digit!(1);
        reduce_digit!(2);
        reduce_digit!(3);
        reduce_digit!(4);

        debug_assert_eq!(v[0] >> 32, 0);
        debug_assert_eq!(v[1] >> 32, 0);
        debug_assert_eq!(v[2] >> 32, 0);
        debug_assert_eq!(v[3] >> 32, 0);
        debug_assert_eq!(v[4] >> 32, 0);

        debug_assert_eq!(carry, 0);

        Int1305 { v: [v[0] as u32, v[1] as u32, v[2] as u32, v[3] as u32, v[4] as u32] }
    }

    fn from_bytes(msg: &[u8; 16]) -> Int1305 {
        macro_rules! b4 {
            ($i:expr, $n:expr) => (
                ((msg[$i] as u32) >> $n) |
                ((msg[$i+1] as u32) << (8 - $n)) |
                ((msg[$i+2] as u32) << (16 - $n)) |
                (((msg[$i+3] as u32) & ((1 << (2 + $n)) - 1)) << (24 - $n))
            )
        }
        macro_rules! b3 {
            ($i:expr, $n:expr) => (
                ((msg[$i] as u32) >> $n) |
                ((msg[$i+1] as u32) << (8 - $n)) |
                ((msg[$i+2] as u32) << (16 - $n))
            )
        }

        let v = [
            b4!(0, 0),
            b4!(3, 26 * 1 - 8 * 3),
            b4!(6, 26 * 2 - 8 * 6),
            b4!(9, 26 * 3 - 8 * 9),
            b3!(13, 0),
        ];

        debug_assert_eq!(v[0] >> 26, 0);
        debug_assert_eq!(v[1] >> 26, 0);
        debug_assert_eq!(v[2] >> 26, 0);
        debug_assert_eq!(v[3] >> 26, 0);
        debug_assert_eq!(v[4] >> 26, 0);

        Int1305 { v: v }
    }

    // self must be reduced
    fn normalize(&self) -> Int1305 {
        // we have two possibilities: (a) 0 <= self <= p - 1, (b) p <= self <= 2 * p - 1
        // we must return self - p in case of (b)
        // if 2^130 - 5 <= a + b <= 2^131 - 11, 2^130 <= a + b + 5 <= 2^131 - 6
        // therefore (a + b + 5) >> 130 == 1 and (a + b - p) == (a + b + 5) & !(1 << 130)
        // here we compute a + b + 5 + (0b111...111 << 130) to eliminate `& !(1 << 130)` part

        static P5: [u64; 5] = [5, 0, 0, 0, ((1 << 6) - 1) << 26];

        let mut ret_b = Int1305 { v: [0; 5] };
        let mut carry = 0;

        macro_rules! add_digit {
            ($($i:expr)+) => ({
                $(
                    let v = (self.v[$i] as u64) + P5[$i] + carry;
                    carry = v >> 26;
                    ret_b.v[$i] = (v & ((1 << 26) - 1)) as u32;
                )+
            })
        }
        add_digit! {0 1 2 3}
        ret_b.v[4] = ((self.v[4] as u64) + P5[4] + carry) as u32;

        let is_case_b = ret_b.v[4] >> 31;

        Int1305::choose(is_case_b, &ret_b, self)
    }
}

pub fn authenticate(msg: &[u8], r: &[u8; 16], aes: &[u8; 16]) -> [u8; 16] {
    let mut r = *r;
    r[3] &= 15;
    r[4] &= 252;
    r[7] &= 15;
    r[8] &= 252;
    r[11] &= 15;
    r[12] &= 252;
    r[15] &= 15;

    let r = Int1305::from_bytes(&r);

    // c[0] * r^q + c[1] * r^(q-1) + ... + c[q-1] * r
    // = (((c[0] * r + c[1]) * r) + ... + c[q-1]) * r
    let mut h = ZERO;

    let len = msg.len();
    let chunks = (len + 15) / 16;
    for i in (0..chunks) {
        // c[i] = sum_i (m[16*i] * 2^8) + 2^128

        let mut m = [0u8; 16];
        let m_len = if i < chunks - 1 { 16 } else { len - 16 * i };
        for j in (0..m_len) {
            m[j] = msg[i * 16 + j];
        }
        let mut c = Int1305::from_bytes(&m);

        // append 1 to the chunk
        let flag_pos = m_len * 8;
        c.v[flag_pos / 26] |= 1 << (flag_pos % 26);

        h = c.add(&h).mult(&r);
    }

    let h = h.normalize();
    let h = {
        macro_rules! b {
            ($i:expr, $n:expr) => (
                (h.v[$i] >> $n) as u8
            );
            ($i:expr, $n:expr, $m:expr) => (
                ((h.v[$i] >> $n) | (h.v[$i+1] & ((1 << $m) - 1)) << (8 - $m)) as u8
            );
        }

        [
            b!(0, 0 + 0),
            b!(0, 0 + 8),
            b!(0, 0 + 16),
            b!(0, 0 + 24, 6), // 6 == 8 * 4 - 26 * 1

            b!(1, 6 + 0),
            b!(1, 6 + 8),
            b!(1, 6 + 16, 4), // 4 == 8 * 7 - 26 * 2

            b!(2, 4 + 0),
            b!(2, 4 + 8),
            b!(2, 4 + 16, 2), // 2 == 8 * 10 - 26 * 3

            b!(3, 2 + 0),
            b!(3, 2 + 8),
            b!(3, 2 + 16),

            b!(4, 0 + 0),
            b!(4, 0 + 8),
            b!(4, 0 + 16),
            //b!(4, 0 + 24), // discard 2 bits: mod 2^128
        ]
    };

    // h + aes (mod 2^128)
    let ret = {
        let mut ret = [0; 16];

        macro_rules! to_u32 {
            ($a:expr, $i:expr) => (
                ($a[$i] as u32) | ($a[$i + 1] as u32) << 8 |
                ($a[$i + 2] as u32) << 16 | ($a[$i + 3] as u32) << 24
            )
        }

        let h32 = [to_u32!(h, 0), to_u32!(h, 4), to_u32!(h, 8), to_u32!(h, 12)];
        let aes32 = [to_u32!(aes, 0), to_u32!(aes, 4), to_u32!(aes, 8), to_u32!(aes, 12)];

        let mut carry = 0;

        let sum = (h32[0] as u64) + (aes32[0] as u64) + carry;
        let ret0 = sum as u32;
        carry = sum >> 32;

        let sum = (h32[1] as u64) + (aes32[1] as u64) + carry;
        let ret1 = sum as u32;
        carry = sum >> 32;

        let sum = (h32[2] as u64) + (aes32[2] as u64) + carry;
        let ret2 = sum as u32;
        carry = sum >> 32;

        let sum = (h32[3] as u64) + (aes32[3] as u64) + carry;
        let ret3 = sum as u32;

        macro_rules! to_u8 {
            ($a:expr, $r:expr, $i:expr) => ({
                $a[$i] = $r as u8;
                $a[$i+1] = ($r >> 8) as u8;
                $a[$i+2] = ($r >> 16) as u8;
                $a[$i+3] = ($r >> 24) as u8;
            })
        }

        to_u8!(ret, ret0, 0);
        to_u8!(ret, ret1, 4);
        to_u8!(ret, ret2, 8);
        to_u8!(ret, ret3, 12);

        ret
    };

    ret
}

#[cfg(test)]
mod test {
    use super::Int1305;

    static COEFFS: &'static [Int1305] = &[
        super::ZERO,
        Int1305 { v: [1, 0, 0, 0, 0] },
        Int1305 { v: [1, 1, 1, 1, 1] },
        Int1305 { v: [
            (1 << 26) - 1,
            (1 << 26) - 1,
            (1 << 26) - 1,
            (1 << 26) - 1,
            (1 << 25) - 1,
        ] },

        Int1305 { v: [0, 1, 2, 3, 4] },
        Int1305 { v: [5, 6, 7, 8, 9] },
        Int1305 { v: [1 << 23, 3 << 20, 0, 5 << 21, 0] },
        Int1305 { v: [1 << 20; 5] },
        Int1305 { v: [1 << 24; 5] },
        Int1305 { v: [(1 << 25) - 1; 5] },
        Int1305 { v: [0x3fffffb - 1, 0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff] }, // p - 1
    ];

    impl PartialEq for Int1305 {
        fn eq(&self, b: &Int1305) -> bool {
            self.normalize().v[] == b.normalize().v[]
        }
    }

    impl ::std::fmt::Show for Int1305 {
        fn fmt(&self, a: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
            (self.v[]).fmt(a)
        }
    }

    #[test]
    fn test_add() {
        // (a + b) + c == a + (b + c)
        for a in COEFFS.iter() {
            for b in COEFFS.iter() {
                for c in COEFFS.iter() {
                    let abc = a.add(b).add(c);

                    let bca = b.add(c).add(a);
                    assert_eq!(abc, bca);

                    let acb = a.add(c).add(b);
                    assert_eq!(abc, acb);
                }
            }
        }
    }

    #[test]
    fn test_normalize() {
        let p = Int1305 { v: [0x3fffffb, 0x3ffffff, 0x3ffffff, 0x3ffffff, 0x3ffffff] };
        assert_eq!(&p.normalize().v[], &super::ZERO.v[]);

        let large = Int1305 { v: [0, 10, 5, 10, 1 << 26] };
        let small = Int1305 { v: [5, 10, 5, 10, 0] };

        assert_eq!(&large.normalize().v[], &small.v[]);
        assert_eq!(&small.normalize().v[], &small.v[]);

        for a in COEFFS.iter() {
            assert_eq!(a.normalize(), *a);
        }
    }

    #[test]
    fn test_mult() {
        // (a * b) * c == a * (b * c)
        for a in COEFFS.iter() {
            for b in COEFFS.iter() {
                for c in COEFFS.iter() {
                    let abc = a.mult(b).mult(c).normalize();

                    let bca = b.mult(c).mult(a).normalize();
                    assert_eq!(abc, bca);

                    let acb = a.mult(c).mult(b).normalize();
                    assert_eq!(abc, acb);
                }
            }
        }
    }

    #[test]
    fn test_poly1305_examples() {
        // from Appendix B of reference paper
        static VALUES: &'static [(&'static [u8], [u8; 16], [u8; 16], [u8; 16])] = &[
            // (msg, r, aes, result)
            (&[0xf3, 0xf6],
             [0x85, 0x1f, 0xc4, 0x0c, 0x34, 0x67, 0xac, 0x0b,
              0xe0, 0x5c, 0xc2, 0x04, 0x04, 0xf3, 0xf7, 0x00],
             [0x58, 0x0b, 0x3b, 0x0f, 0x94, 0x47, 0xbb, 0x1e,
              0x69, 0xd0, 0x95, 0xb5, 0x92, 0x8b, 0x6d, 0xbc],
             [0xf4, 0xc6, 0x33, 0xc3, 0x04, 0x4f, 0xc1, 0x45,
              0xf8, 0x4f, 0x33, 0x5c, 0xb8, 0x19, 0x53, 0xde]),

            (&[],
             [0xa0, 0xf3, 0x08, 0x00, 0x00, 0xf4, 0x64, 0x00,
              0xd0, 0xc7, 0xe9, 0x07, 0x6c, 0x83, 0x44, 0x03],
             [0xdd, 0x3f, 0xab, 0x22, 0x51, 0xf1, 0x1a, 0xc7,
              0x59, 0xf0, 0x88, 0x71, 0x29, 0xcc, 0x2e, 0xe7],
             [0xdd, 0x3f, 0xab, 0x22, 0x51, 0xf1, 0x1a, 0xc7,
              0x59, 0xf0, 0x88, 0x71, 0x29, 0xcc, 0x2e, 0xe7]),

            (&[0x66, 0x3c, 0xea, 0x19, 0x0f, 0xfb, 0x83, 0xd8,
               0x95, 0x93, 0xf3, 0xf4, 0x76, 0xb6, 0xbc, 0x24,
               0xd7, 0xe6, 0x79, 0x10, 0x7e, 0xa2, 0x6a, 0xdb,
               0x8c, 0xaf, 0x66, 0x52, 0xd0, 0x65, 0x61, 0x36],
             [0x48, 0x44, 0x3d, 0x0b, 0xb0, 0xd2, 0x11, 0x09,
              0xc8, 0x9a, 0x10, 0x0b, 0x5c, 0xe2, 0xc2, 0x08],
             [0x83, 0x14, 0x9c, 0x69, 0xb5, 0x61, 0xdd, 0x88,
              0x29, 0x8a, 0x17, 0x98, 0xb1, 0x07, 0x16, 0xef],
             [0x0e, 0xe1, 0xc1, 0x6b, 0xb7, 0x3f, 0x0f, 0x4f,
              0xd1, 0x98, 0x81, 0x75, 0x3c, 0x01, 0xcd, 0xbe]),

            (&[0xab, 0x08, 0x12, 0x72, 0x4a, 0x7f, 0x1e, 0x34,
               0x27, 0x42, 0xcb, 0xed, 0x37, 0x4d, 0x94, 0xd1,
               0x36, 0xc6, 0xb8, 0x79, 0x5d, 0x45, 0xb3, 0x81,
               0x98, 0x30, 0xf2, 0xc0, 0x44, 0x91, 0xfa, 0xf0,
               0x99, 0x0c, 0x62, 0xe4, 0x8b, 0x80, 0x18, 0xb2,
               0xc3, 0xe4, 0xa0, 0xfa, 0x31, 0x34, 0xcb, 0x67,
               0xfa, 0x83, 0xe1, 0x58, 0xc9, 0x94, 0xd9, 0x61,
               0xc4, 0xcb, 0x21, 0x09, 0x5c, 0x1b, 0xf9],
             [0x12, 0x97, 0x6a, 0x08, 0xc4, 0x42, 0x6d, 0x0c,
              0xe8, 0xa8, 0x24, 0x07, 0xc4, 0xf4, 0x82, 0x07],
             [0x80, 0xf8, 0xc2, 0x0a, 0xa7, 0x12, 0x02, 0xd1,
              0xe2, 0x91, 0x79, 0xcb, 0xcb, 0x55, 0x5a, 0x57],
             [0x51, 0x54, 0xad, 0x0d, 0x2c, 0xb2, 0x6e, 0x01,
              0x27, 0x4f, 0xc5, 0x11, 0x48, 0x49, 0x1f, 0x1b]),
        ];

        for &(msg, ref r, ref aes, ref expected) in VALUES.iter() {
            let output = super::authenticate(msg, r, aes);
            assert_eq!(&output[], &expected[]);
        }
    }
}
