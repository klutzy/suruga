// constantly slow implementation of NIST P-256
// http://www.nsa.gov/ia/_files/nist-routines.pdf
// http://point-at-infinity.org/ecc/nisttv

use self::int256::{Int256, ZERO, ONE};

// Point on Y^2 = X^3 - 3 * X + B mod P256 where B is some obscure big number
// (x, y, z): (X, Y) = (x/z^2, y/z^3) is point of Y^2 = X^3 - 3 * X + c
// identity (INFTY) is (1, 1, 0)
#[derive(Copy)]
pub struct Point256 {
    x: Int256,
    y: Int256,
    z: Int256,
}

pub const G: Point256 = Point256 {
    x: Int256 {
        v: [0xd898c296, 0xf4a13945, 0x2deb33a0, 0x77037d81,
            0x63a440f2, 0xf8bce6e5, 0xe12c4247, 0x6b17d1f2]
    },
    y: Int256 {
        v: [0x37bf51f5, 0xcbb64068, 0x6b315ece, 0x2bce3357,
            0x7c0f9e16, 0x8ee7eb4a, 0xfe1a7f9b, 0x4fe342e2]
    },
    z: ONE,
};

pub const B: Int256 = Int256 {
    v: [0x27d2604b, 0x3bce3c3e, 0xcc53b0f6, 0x651d06b0,
        0x769886bc, 0xb3ebbd55, 0xaa3a93e7, 0x5ac635d8]
};

const INFTY: Point256 = Point256 {
    x: ONE,
    y: ONE,
    z: ZERO,
};

impl Clone for Point256 {
    fn clone(&self) -> Point256 {
        Point256 {
            x: self.x.clone(),
            y: self.y.clone(),
            z: self.z.clone(),
        }
    }
}

impl Point256 {
    pub fn normalize(&self) -> NPoint256 {
        let z2 = self.z.square();
        let z3 = self.z.mult(&z2);
        let x = self.x.mult(&z2.inverse());
        let y = self.y.mult(&z3.inverse());

        NPoint256 {
            x: x,
            y: y,
        }
    }

    fn choose(flag: u32, a: &Point256, b: &Point256) -> Point256 {
        let x = Int256::choose(flag, &a.x, &b.x);
        let y = Int256::choose(flag, &a.y, &b.y);
        let z = Int256::choose(flag, &a.z, &b.z);

        Point256 {
            x: x,
            y: y,
            z: z,
        }
    }

    // compute `self + self`
    // self.z must not zero.
    fn double(&self) -> Point256 {
        let z2 = self.z.square();
        let y2 = self.y.square();

        // a = 3 * (x - z^2) * (x + z^2)
        let a = {
            let x_sub_z2 = self.x.sub(&z2);
            let x_add_z2 = self.x.add(&z2);
            let mult = x_add_z2.mult(&x_sub_z2); // (x - z^2) (x + z^2)
            mult.add(&mult).add(&mult)
        };

        // b = x * y^2
        let b = self.x.mult(&y2);
        let b2 = b.add(&b);
        let b4 = b2.add(&b2);
        let b8 = b4.add(&b4);

        // x_new = a^2 - 8 * x * y^2
        let x_new = a.square().sub(&b8);

        // y_new = (4 * b - x_new) * a - 8 * y^4
        let y_new = {
            let y4 = y2.square();
            let y4_2 = y4.add(&y4);
            let y4_4 = y4_2.add(&y4_2);
            let y4_8 = y4_4.add(&y4_4);

            a.mult(&b4.sub(&x_new)).sub(&y4_8)
        };

        // z_new = 2 * z * y = (z + y)^2 - (z^2 + y^2)
        let z_new = self.y.add(&self.z).square().sub(&z2.add(&y2));

        let ret = Point256 {
            x: x_new,
            y: y_new,
            z: z_new,
        };

        // if z is zero, ret is (nonzero, nonzero, zero).
        // return normalized INFTY for easy comparison
        let self_not_infty = self.z.compare(&ZERO);
        let ret = Point256::choose(self_not_infty, &INFTY, &ret);

        ret
    }

    fn add(&self, b: &Point256) -> Point256 {
        let self_is_zero = self.z.compare(&ZERO);
        let b_is_zero = b.z.compare(&ZERO);

        let z2 = self.z.square(); // z^2
        let z3 = self.z.mult(&z2); // z^3
        let bz2 = b.z.square();
        let bz3 = b.z.mult(&bz2);

        let x = self.x.mult(&bz2);
        let y = self.y.mult(&bz3);
        let bx = b.x.mult(&z2);
        let by = b.y.mult(&z3);

        let xdiff = x.sub(&bx);
        let xdiff2 = xdiff.square();
        let xdiff3 = xdiff.mult(&xdiff2);

        let ydiff = y.sub(&by);
        let ydiff2 = ydiff.square();

        let xsum = x.add(&bx);
        let ysum = y.add(&by);

        // e = (x + x') * (x - x')^3
        let e = xsum.mult(&xdiff2);

        // x_new = (y - y')^2 - e
        let x_new = ydiff2.sub(&e);
        let x_new_2 = x_new.add(&x_new);

        // y_new = ((y - y') * (e - 2 * x_new) - (y + y') * (x - x')^3) / 2
        let y_new = {
            let t4 = ysum.mult(&xdiff3);
            let t5 = ydiff.mult(&e.sub(&x_new_2));
            let y_new = t5.sub(&t4).divide_by_2();
            y_new
        };

        // z_new = z * z' * (x - x')
        let z_new = self.z.mult(&b.z).mult(&xdiff);

        let xdiff_nonzero = xdiff.compare(&ZERO); // 0 if zero
        let ydiff_nonzero = ydiff.compare(&ZERO); // 0 if zero

        // if `self == b`, unfortunately, this is `(0, 0, 0)`.
        let ret = Point256 {
            x: x_new,
            y: y_new,
            z: z_new,
        };

        // if self == b, return self.double() since ret is (0, 0, 0)
        let double = self.double();
        let ret = Point256::choose(xdiff_nonzero | ydiff_nonzero, &double, &ret);
        // if self == -b, return INFTY
        let ret = Point256::choose(xdiff_nonzero | (1 - ydiff_nonzero), &INFTY, &ret);
        // if self == INFTY, return b
        let ret = Point256::choose(self_is_zero, b, &ret);
        // if b == INFTY, return self
        let ret = Point256::choose(b_is_zero, self, &ret);

        ret
    }

    pub fn mult_scalar(&self, n: &Int256) -> Point256 {
        let mut ret = INFTY.clone();
        for i in range(0u, 7).rev() {
            for j in range(0u, 8).rev() {
                let bit = (n.v[i] >> j) & 1;

                let ret2 = ret.double();
                let ret3 = ret2.add(self);

                ret = Point256::choose(bit, &ret2, &ret3);
            }
        }

        ret
    }
}

// normalized
pub struct NPoint256 {
    pub x: Int256,
    pub y: Int256,
}

impl NPoint256 {
    pub fn to_point(self) -> Point256 {
        Point256 {
            x: self.x,
            y: self.y,
            z: ONE,
        }
    }

    pub fn from_uncompressed_bytes(data: &[u8]) -> Option<NPoint256> {
        if data.len() != 1 + 32 * 2 {
            return None;
        }
        if data[0] != 0x04 {
            return None;
        }

        let x = Int256::from_bytes(data.slice(1, 32 + 1));
        let y = Int256::from_bytes(data.slice(1 + 32, 1 + 32 * 2));

        let (x, y) = match (x, y) {
            (Some(x), Some(y)) => (x, y),
            _ => return None,
        };

        let p = NPoint256 {
            x: x,
            y: y,
        };

        // wait, but is p on the curve?
        // check if y^2 + 3 * x == x^3 + B

        let y2 = y.square();
        let lhs = y2.add(&x.double().add(&x));

        let x3 = x.square().mult(&x);
        let rhs = x3.add(&B);

        let zero_if_same = lhs.compare(&rhs);

        if zero_if_same != 0 {
            return None;
        }

        Some(p)
    }

    pub fn to_uncompressed_bytes(&self) -> Vec<u8> {
        // 0x04 || self.x (big endian) || self.y (big endian)
        let mut b = Vec::with_capacity(1 + (256 / 8) * 2);
        b.push(0x04); // uncompressed
        b.push_all(&self.x.to_bytes()[]);
        b.push_all(&self.y.to_bytes()[]);
        b
    }
}

pub mod int256 {
    const LIMBS: uint = 8;

    // 2^32-radix: value = v[0] + 2^32 v[1] + ... + 2^124 v[7]
    // value must be < P256
    #[derive(Copy)]
    pub struct Int256 {
        pub v: [u32; LIMBS]
    }

    // P256 = 2^256 - 2^224 + 2^192 + 2^96 - 1
    pub const P256: Int256 = Int256 {
        v: [0xffffffff, 0xffffffff, 0xffffffff, 0x00000000,
            0x00000000, 0x00000000, 0x00000001, 0xffffffff]
    };
    pub const ZERO: Int256 = Int256 { v: [0; LIMBS] };
    pub const ONE: Int256 = Int256 { v: [1, 0, 0, 0, 0, 0, 0, 0] };

    impl Clone for Int256 {
        fn clone(&self) -> Int256 {
            Int256 { v: self.v }
        }
    }

    impl Int256 {
        // return 0 if self == b.
        // otherwise return 1.
        pub fn compare(&self, b: &Int256) -> u32 {
            let mut diff = 0u32;
            for i in range(0u, LIMBS) {
                diff |= self.v[i] ^ b.v[i];
            }
            diff |= diff >> 16;
            diff |= diff >> 8;
            diff |= diff >> 4;
            diff |= diff >> 2;
            diff |= diff >> 1;
            diff & 1
        }

        // if flag == 0, returns a
        // if flag == 1, returns b
        pub fn choose(flag: u32, a: &Int256, b: &Int256) -> Int256 {
            let mut v = [0; LIMBS];
            for i in range(0u, LIMBS) {
                v[i] = a.v[i] ^ (flag * (a.v[i] ^ b.v[i]));
            }
            Int256 { v: v }
        }

        // return (value, carry) where
        // value = self + b mod 2^256
        // carry = if self + b < P256 { 0 } else { 1 }
        // i.e. self + b == value + 2^256 * carry
        fn add_no_reduce(&self, b: &Int256) -> (Int256, u32) {
            let mut v = Int256 { v: [0u32; LIMBS] };

            // invariant: carry <= 1
            let mut carry = 0u64;
            for i in range(0u, LIMBS) {
                // add <= 2^33
                let add = (self.v[i] as u64) + (b.v[i] as u64) + carry;
                v.v[i] = add as u32;
                carry = add >> 32;
            }
            (v, carry as u32)
        }

        // return (value, carry) where
        // value = self - b mod 2^256
        // carry = if self > b { 0 } else { 1 }
        // i.e. self - b == value - 2^256 * carry
        fn sub_no_reduce(&self, b: &Int256) -> (Int256, u32) {
            let mut v = Int256 { v: [0u32; LIMBS] };

            // invariant: carry_sub <= 1
            let mut carry_sub = 0u64;
            for i in range(0u, LIMBS) {
                // -2^32 <= sub <= 2^32
                let sub = (self.v[i] as u64) - (b.v[i] as u64) - carry_sub;
                // if sub < 0, set carry_sub = 1 and sub += 2^32
                carry_sub = sub >> 63;
                v.v[i] = sub as u32;
            }

            (v, carry_sub as u32)
        }

        // input may not be reduced
        // precondition: `self + carry * 2^256 < 2 * P256`
        // return `(self + carry * 2^256) mod P256`
        pub fn reduce_once(&self, carry: u32) -> Int256 {
            let (v, carry_sub) = self.sub_no_reduce(&P256);
            debug_assert!(!(carry_sub == 0 && carry == 1)); // precondition violated
            let choose_new = carry ^ (carry_sub as u32);
            Int256::choose(choose_new, &v, self)
        }

        pub fn add(&self, b: &Int256) -> Int256 {
            let (v, carry) = self.add_no_reduce(b);
            let v = v.reduce_once(carry);
            v
        }

        pub fn double(&self) -> Int256 {
            // FIXME can be more efficient
            self.add(self)
        }

        pub fn sub(&self, b: &Int256) -> Int256 {
            let (v, carry_sub) = self.sub_no_reduce(b);
            // if self - b < 0, carry_sub == 1 and v == 2^256 + self - b
            let (v2, _carry_add) = v.add_no_reduce(&P256);
            debug_assert!(!(_carry_add == 0 && carry_sub == 1));
            Int256::choose(carry_sub as u32, &v, &v2)
        }

        pub fn mult(&self, b: &Int256) -> Int256 {
            let mut w = [0u64; LIMBS * 2];
            for i in range(0u, LIMBS) {
                for j in range(0u, LIMBS) {
                    let ij = i + j;
                    let v_ij = (self.v[i] as u64) * (b.v[j] as u64);
                    let v_ij_low = (v_ij as u32) as u64;
                    let v_ij_high = v_ij >> 32;
                    let w_ij = w[ij] + v_ij_low;
                    let w_ij_low = (w_ij as u32) as u64;
                    let w_ij_high = v_ij_high + (w_ij >> 32);
                    w[ij] = w_ij_low;
                    w[ij + 1] += w_ij_high;
                }
            }

            let mut v = [0u32; LIMBS * 2];
            let mut carry = 0u64;
            for i in range(0u, LIMBS * 2) {
                let a = w[i] + carry;
                v[i] = a as u32;
                carry = a >> 32;
            }
            debug_assert_eq!(carry, 0);

            let mut buf = ZERO;
            for i in range(0u, LIMBS) {
                buf.v[i] = v[i];
            }
            let t = buf.reduce_once(0);

            let mut buf = ZERO;
            for i in range(0u, 5) {
                buf.v[i + 3] = v[i + 11];
            }
            let s1 = buf.reduce_once(0);

            let mut buf = ZERO;
            for i in range(0u, 4) {
                buf.v[i + 3] = v[i + 12];
            }
            let s2 = buf.reduce_once(0);

            let mut buf = ZERO;
            for i in range(0u, 3) {
                buf.v[i] = v[i + 8];
            }
            buf.v[6] = v[14];
            buf.v[7] = v[15];
            let s3 = buf.reduce_once(0);

            let mut buf = ZERO;
            for i in range(0u, 3) {
                buf.v[i] = v[i + 9];
                buf.v[i + 3] = v[i + 13];
            }
            buf.v[6] = v[13];
            buf.v[7] = v[8];
            let s4 = buf.reduce_once(0);

            let mut buf = ZERO;
            for i in range(0u, 3) {
                buf.v[i] = v[i + 11];
            }
            buf.v[6] = v[8];
            buf.v[7] = v[10];
            let d1 = buf.reduce_once(0);

            let mut buf = ZERO;
            for i in range(0u, 4) {
                buf.v[i] = v[i + 12];
            }
            buf.v[6] = v[9];
            buf.v[7] = v[11];
            let d2 = buf.reduce_once(0);

            let mut buf = ZERO;
            for i in range(0u, 3) {
                buf.v[i] = v[i + 13];
                buf.v[i + 3] = v[i + 8];
            }
            buf.v[7] = v[12];
            let d3 = buf.reduce_once(0);

            let mut buf = ZERO;
            for i in range(0u, 3) {
                buf.v[i + 3] = v[i + 9];
            }
            buf.v[7] = v[13];
            buf.v[0] = v[14];
            buf.v[1] = v[15];
            let d4 = buf.reduce_once(0);

            let r = t.add(&s1.double()).add(&s2.double()).add(&s3).add(&s4);
            let r = r.sub(&d1.add(&d2).add(&d3).add(&d4));
            r
        }

        pub fn square(&self) -> Int256 {
            // FIXME can be more efficient
            self.mult(self)
        }

        // return self^-1 = self^(P256 - 2)
        pub fn inverse(&self) -> Int256 {
            // 2^256 - 2^224 + 2^192 + 2^96 - 3
            // 2^224 (2^32 - 1) + (2^192 - 1) + 2 (2^95 - 1)
            // 2^256 = (2^32)^8
            // 2^224 = (2^32)^7

            // compute a^(2^n)
            fn square_n(a: &Int256, n: uint) -> Int256 {
                let mut y = a.clone();
                for _ in range(0, n) {
                    y = y.square();
                }
                y
            }

            // compute z^(2^n + 1)
            // if z == self^(2^n - 1), it returns self^(2^(2n) - 1)
            fn z_n(z: &Int256, n: uint) -> Int256 {
                let y = square_n(z, n);
                y.mult(z)
            }

            // for given z_n = a^(2^n - 1), return z_{n+1} = a^(2^(n+1) - 1)
            fn z_1(z: &Int256, a: &Int256) -> Int256 {
                z.square().mult(a)
            }

            // FIXME this routine seems far from optimal

            let z2 = z_n(self, 1);
            let z4 = z_n(&z2, 2);
            let z8 = z_n(&z4, 4);
            let z16 = z_n(&z8, 8);
            let z32 = z_n(&z16, 16);

            let z5 = z_1(&z4, self);

            let z10 = z_n(&z5, 5);
            let z11 = z_1(&z10, self);

            let z22 = z_n(&z11, 11);
            let z23 = z_1(&z22, self);

            let z46 = z_n(&z23, 23);
            let z47 = z_1(&z46, self);

            let z94 = z_n(&z47, 47);
            let z95 = z_1(&z94, self);

            let y96_2 = z95.square();
            let z96 = y96_2.mult(self);

            let z192 = z_n(&z96, 96);

            let y256_224 = square_n(&z32, 224);

            y256_224.mult(&z192).mult(&y96_2)
        }

        pub fn divide_by_2(&self) -> Int256 {
            let is_odd = self.v[0] & 1;

            let mut half_even = ZERO;
            for i in range(0u, LIMBS - 1) {
                half_even.v[i] = (self.v[i] >> 1) | ((self.v[i + 1] & 1) << 31);
            }
            half_even.v[LIMBS - 1] = self.v[LIMBS - 1] >> 1;

            let mut half_odd = ZERO;
            let (self_p, carry) = self.add_no_reduce(&P256);
            for i in range(0u, LIMBS - 1) {
                half_odd.v[i] = (self_p.v[i] >> 1) | ((self_p.v[i + 1] & 1) << 31);
            }
            half_odd.v[LIMBS - 1] = (self_p.v[LIMBS - 1] >> 1) | (carry << 31);
            // we can assume half_odd < P256 since (self + P256) < P256 * 2

            Int256::choose(is_odd, &half_even, &half_odd)
        }

        // big-endian.
        pub fn to_bytes(&self) -> Vec<u8> {
            let mut b = [0u8; 256 / 8];
            for i in range(0u, LIMBS) {
                let vi = self.v[LIMBS - 1 - i];
                for j in range(0u, 4) {
                    b[i * 4 + j] = (vi >> ((3 - j) * 8)) as u8;
                }
            }

            b.to_vec()
        }

        // big-endian.
        pub fn from_bytes(b: &[u8]) -> Option<Int256> {
            if b.len() != 32 {
                return None;
            }

            let mut x = ZERO;
            for i in range(0u, LIMBS) {
                let mut vi = 0u32;
                for j in range(0u, 4) {
                    vi |= (b[i * 4 + j] as u32) << ((3 - j) * 8);
                }
                x.v[LIMBS - 1 - i] = vi;
            }

            Some(x)
        }
    }

    #[cfg(test)]
    mod test {
        use super::{Int256, P256, ZERO, ONE};

        impl PartialEq for Int256 {
            fn eq(&self, b: &Int256) -> bool {
                self.v[] == b.v[]
            }
        }

        impl ::std::fmt::Show for Int256 {
            fn fmt(&self, a: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                self.v[].fmt(a)
            }
        }

        // FIXME more values
        static VALUES_256: &'static [Int256] = &[
            ZERO,
            ONE,
            Int256 { v: [2, 0, 0, 0, 0, 0, 0, 0] },
            Int256 { v: [1; 8] },
            Int256 { v: [0, 2, 0, 2, 0, 0, 0, 0] },
            Int256 { v: [1, 2, 3, 4, 5, 6, 7, 8] },
            Int256 { v: [0x0, 0x0, 0x0, 0x0, 0xffffffff, 0xffffffff, 0, 0xffffffff] },
            Int256 { v: [0xfffffffe; 8] },
        ];

        #[test]
        fn test_int256_compare() {
            for a in VALUES_256.iter() {
                for b in VALUES_256.iter() {
                    if a == b {
                        assert_eq!(a.compare(b), 0);
                    } else {
                        assert_eq!(a.compare(b), 1);
                    }
                }
            }
        }

        #[test]
        fn test_int256_reduce_once() {
            // FIXME more tests

            assert_eq!(ZERO.reduce_once(0), ZERO);
            assert_eq!(P256.reduce_once(0), ZERO);

            static P256P1: Int256 = Int256 {
                v: [0, 0, 0, 1, 0, 0, 1, 0xffffffff]
            };
            assert_eq!(P256P1.reduce_once(0), ONE);

            // 2^256 == 2^224 - 2^192 - 2^96 + 1
            let v = Int256 {
                v: [1, 0, 0, 0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe, 0]
            };
            assert_eq!(ZERO.reduce_once(1), v);
        }

        #[test]
        fn test_int256_add() {
            for a in VALUES_256.iter() {
                assert_eq!(a.add(&ZERO), *a);

                for b in VALUES_256.iter() {
                    let ab = a.add(b);
                    assert_eq!(ab, b.add(a));
                    for c in VALUES_256.iter() {
                        let abc = ab.add(c);
                        let acb = a.add(c).add(b);
                        assert_eq!(abc, acb);

                        let bca = b.add(c).add(a);
                        assert_eq!(abc, bca);
                    }
                }
            }
        }

        #[test]
        fn test_int256_sub() {
            for a in VALUES_256.iter() {
                assert_eq!(a.sub(&ZERO), *a);
                assert_eq!(a.sub(a), ZERO);

                for b in VALUES_256.iter() {
                    assert_eq!(a.sub(b).add(b), *a);

                    let ab = a.sub(b);
                    assert_eq!(ab.reduce_once(0), ab);

                    for c in VALUES_256.iter() {
                        let abc = ab.sub(c);
                        let ac = a.sub(c);
                        let acb = ac.sub(b);
                        assert_eq!(abc, acb);

                        let bc = b.add(c);
                        let a_bc = a.sub(&bc);
                        assert_eq!(abc, a_bc);
                    }
                }
            }
        }

        #[test]
        fn test_int256_mult() {
            for a in VALUES_256.iter() {
                assert_eq!(a.mult(&ONE), *a);
                assert_eq!(a.mult(&ZERO), ZERO);

                for b in VALUES_256.iter() {
                    let ab = a.mult(b);
                    assert_eq!(ab, b.mult(a));
                    for c in VALUES_256.iter() {
                        let ac = a.mult(c);

                        let abc = ab.mult(c);
                        let acb = ac.mult(b);
                        assert_eq!(abc, acb);

                        let bca = b.mult(c).mult(a);
                        assert_eq!(abc, bca);

                        let abac = ab.add(&ac);
                        let bc = b.add(c);
                        let abc = a.mult(&bc);
                        assert_eq!(abac, abc);
                    }
                }
            }
        }

        #[test]
        fn test_int256_inverse() {
            assert_eq!(ONE.inverse(), ONE);

            for a in VALUES_256.iter() {
                if *a == ZERO {
                    continue;
                }

                let a_inv = a.inverse();
                let a_inv_a = a_inv.mult(a);
                assert_eq!(a_inv_a, ONE);

                let a_inv_inv = a_inv.inverse();
                assert_eq!(a_inv_inv, *a);
            }
        }

        #[test]
        fn test_int256_divide_by_2() {
            for a in VALUES_256.iter() {
                let a_half = a.divide_by_2();
                assert_eq!(a_half, a_half.reduce_once(0));
                let a_half_2 = a_half.add(&a_half);
                assert_eq!(*a, a_half_2);
            }
        }

        #[test]
        fn test_from_bytes() {
            for a in VALUES_256.iter() {
                let b = a.to_bytes();
                let aa = Int256::from_bytes(&b[]).expect("to_bytes failed");
                assert_eq!(*a, aa);
            }
        }
    }
}
