/// constant-time compare function.
/// `a` and `b` may be SECRET, but the length is known.
/// precondition: `a.len() == b.len()`
pub fn crypto_compare(a: &[u8], b: &[u8]) -> bool {
    debug_assert_eq!(a.len(), b.len());

    let mut diff = 0u8;
    for i in range(0u, a.len()) {
        diff |= a[i] ^ b[i];
    }
    diff = diff | (diff >> 4);
    diff = diff | (diff >> 2);
    diff = diff | (diff >> 1);
    diff = diff & 1;
    return diff == 0;
}

pub fn u64_be_vec(len: u64) -> Vec<u8> {
    let mut v = Vec::new();
    for i in range(0u, 8).rev() {
        v.push((len >> (8 * i)) as u8);
    }
    v
}

pub fn u64_le_vec(len: u64) -> Vec<u8> {
    let mut v = Vec::new();
    for i in range(0u, 8) {
        v.push((len >> (8 * i)) as u8);
    }
    v
}
