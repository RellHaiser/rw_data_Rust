//! The archives' cipher and checksum.

/// XORs every byte with the byte of the 64-bit key (little endian) at the same position
/// modulo 8. The original works on 8-byte words from the end of the buffer (writing them as
/// `!(!word ^ key)`) and then on the remaining bytes; the result is the same. The cipher is
/// its own inverse.
pub fn decrypt(data: &mut [u8], key: u64) {
    let key = key.to_le_bytes();
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= key[i & 7];
    }
}

/// The 16-bit checksum of the ISD1 archives and FQL files.
pub fn checksum16(data: &[u8], seed: u16) -> u16 {
    let mut sum = seed;
    for &b in data {
        sum = sum.wrapping_add(b as u16);
        sum ^= (!b) as u16;
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cipher_is_its_own_inverse() {
        let original: Vec<u8> = (0..37u8).collect();
        let mut data = original.clone();
        decrypt(&mut data, 0x0123_4567_89AB_CDEF);
        assert_ne!(data, original);
        assert_eq!(data[0], 0xEF);
        decrypt(&mut data, 0x0123_4567_89AB_CDEF);
        assert_eq!(data, original);
    }

    #[test]
    fn checksum_matches_reference() {
        // sum = 0xFF; byte 0x41: sum = 0x140 ^ 0xBE = 0x1FE
        assert_eq!(checksum16(b"A", 0xFF), 0x1FE);
        assert_eq!(checksum16(b"", 0xFF), 0xFF);
    }
}
