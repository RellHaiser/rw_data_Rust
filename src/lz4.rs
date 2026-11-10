//! LZ4 decoder of the archive blocks (an addition of the port: the original only knew LZSS).
//!
//! A block of type DTA_BLOCK_LZ4 holds one LZ4 *block* (<https://github.com/lz4/lz4>,
//! doc/lz4_Block_format.md) as written by LZ4_compress_default: no frame, no size header (a
//! block always decodes to 32 KB, the last one of a file to the rest). The stream is a list of
//! sequences:
//!   token     high nibble = literal length, low nibble = match length - 4; a nibble of 15 is
//!             continued by bytes added to it, up to and including the first one that is not 255
//!   literals  the literal bytes
//!   offset    u16 little endian, 1..65535: the match starts this many bytes back in the output
//!   match     (length + 4 bytes, copied byte by byte: it may overlap its own output)
//! The last sequence has only the token and the literals; the stream ends with them.

const MIN_MATCH: usize = 4;

/// Reads a length continued past its nibble of 15. None if the input ends first.
fn read_length(src: &[u8], i: &mut usize, mut length: usize) -> Option<usize> {
    loop {
        let byte = *src.get(*i)?;
        *i += 1;
        length += byte as usize;
        // (anything past 16 MB is damage)
        if byte != 255 || length >= 0x0100_0000 {
            return Some(length);
        }
    }
}

/// Decodes one LZ4 block into `dst`; returns the decoded size, at most `dst.len()`.
///
/// Like the other decoders it never fails: a damaged stream (a length or offset past the
/// input, a reference before the start of the output) ends the decoding there, and the
/// output stops at the end of `dst`. A valid block decodes exactly as LZ4_decompress_safe.
pub fn decompress(src: &[u8], dst: &mut [u8]) -> usize {
    let src_size = src.len();
    let capacity = dst.len();
    let mut i = 0usize;
    let mut out = 0usize;
    while i < src_size {
        let token = src[i];
        i += 1;

        let mut literals = (token >> 4) as usize;
        if literals == 15 {
            match read_length(src, &mut i, literals) {
                Some(l) => literals = l,
                None => return out,
            }
        }
        literals = literals.min(src_size - i); // cut off: keep what is there
        let copied = literals.min(capacity - out);
        dst[out..out + copied].copy_from_slice(&src[i..i + copied]);
        i += literals;
        out += copied;
        if copied != literals || i >= src_size {
            return out; // the room is full, or this was the last sequence
        }

        if src_size - i < 2 {
            return out;
        }
        let offset = src[i] as usize | (src[i + 1] as usize) << 8;
        i += 2;
        if offset == 0 || offset > out {
            return out;
        }

        let mut length = (token & 0xF) as usize;
        if length == 15 {
            match read_length(src, &mut i, length) {
                Some(l) => length = l,
                None => return out,
            }
        }
        length += MIN_MATCH;
        let n = length.min(capacity - out);
        for k in 0..n {
            // byte by byte: the copy may overlap
            dst[out + k] = dst[out + k - offset];
        }
        out += n;
        if n != length {
            return out;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_literals_and_overlapping_match() {
        // "abc" then a match of 9 bytes at offset 3, then the last literals "xy".
        let block = [0x35, b'a', b'b', b'c', 3, 0, 0x20, b'x', b'y'];
        let mut out = [0u8; 64];
        let n = decompress(&block, &mut out);
        assert_eq!(&out[..n], b"abcabcabcabcxy");
    }

    #[test]
    fn stops_at_the_room() {
        let block = [0x35, b'a', b'b', b'c', 3, 0, 0x20, b'x', b'y'];
        let mut out = [0u8; 5];
        assert_eq!(decompress(&block, &mut out), 5);
        assert_eq!(&out, b"abcab");
    }

    #[test]
    fn rejects_offsets_before_the_output() {
        let block = [0x10, b'a', 9, 0];
        let mut out = [0u8; 16];
        assert_eq!(decompress(&block, &mut out), 1);
    }
}
