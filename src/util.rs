use std::mem;
use std::num::Int;

/// constant-time compare function.
/// `a` and `b` may be SECRET, but the length is known.
/// precondition: `a.len() == b.len()`
pub fn crypto_compare(a: &[u8], b: &[u8]) -> bool {
    debug_assert_eq!(a.len(), b.len());

    let mut diff = 0u8;
    for i in (0..a.len()) {
        diff |= a[i] ^ b[i];
    }
    diff = diff | (diff >> 4);
    diff = diff | (diff >> 2);
    diff = diff | (diff >> 1);
    diff = diff & 1;
    return diff == 0;
}

pub fn u64_be_array(x: u64) -> [u8; 8] {
    unsafe { mem::transmute(x.to_be()) }
}

pub fn u64_le_array(x: u64) -> [u8; 8] {
    unsafe { mem::transmute(x.to_le()) }
}
