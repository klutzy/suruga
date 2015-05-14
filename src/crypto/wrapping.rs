#![allow(non_camel_case_types)]

// NOTE: since there is no const fn (yet), you can't use `w32(100)` function
// for consts and statics. (workaround: use `Wrapping(100)`.)

pub use std::num::Wrapping;

pub trait ToWrapping {
    fn to_w64(self) -> w64;
    fn to_w32(self) -> w32;
    fn to_w16(self) -> w16;
    fn to_w8(self) -> w8;
}

macro_rules! to_wrapping_impl_fn {
    ($name:ident, $ut:ty, $wt:ty, $size:expr) => (
        #[inline(always)]
        fn $name(self) -> $wt {
            // NOTE: `WrappingOps::wrapping_as_u64()` can be used when implemented
            let val: u64 = self.0 as u64;
            let val: u64 = val & ((1 << $size) - 1);
            let val: $ut = val as $ut;
            Wrapping(val)
        }
    )
}

macro_rules! wrapping_type {
    ($wt:ident, $ut:ident) => (
        pub type $wt = Wrapping<$ut>;

        #[inline(always)]
        pub fn $wt(val: $ut) -> $wt {
            Wrapping(val)
        }

        impl ToWrapping for Wrapping<$ut> {
            #[inline(always)]
            fn to_w64(self) -> w64 {
                Wrapping(self.0 as u64)
            }

            to_wrapping_impl_fn!(to_w8, u8, w8, 8);
            to_wrapping_impl_fn!(to_w16, u16, w16, 16);
            to_wrapping_impl_fn!(to_w32, u32, w32, 32);
        }

    )
}

wrapping_type!(w64, u64);
wrapping_type!(w32, u32);
wrapping_type!(w16, u16);
wrapping_type!(w8, u8);

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_to_wrapping() {
        const V: w64 = Wrapping(0x12345678_87654321);
        assert_eq!(V.to_w32().0, 0x87654321);
        assert_eq!(V.to_w16().0, 0x4321);
        assert_eq!(V.to_w8().0, 0x21);
    }
}
