//! LZSS codec of the archive blocks and FQL files.
//!
//! Stream: byte 0 = 0 (stored: the data follows) or 1 (compressed). A compressed stream is
//! a sequence of groups of 16 items, each group preceded by a big-endian 16-bit flag word
//! (most significant bit first; the first one is at bytes 1..2):
//!   flag 0: a literal byte
//!   flag 1: two bytes DDDD DDDD DDDD LLLL: copy L + 3 bytes from D bytes back (D != 0), or
//!           D == 0: four bytes 00 0H LL BB: H:LL + 16 copies of byte BB

const WINDOW_SIZE: u32 = 0x1000;
const MAX_MATCH: u16 = 0x12;
const MAX_RUN: u16 = 0xFFF;
const MIN_RUN: u16 = 0x10;

/// A byte of `src`, or 0 past its end (the original read whatever followed the data).
#[inline]
fn at(src: &[u8], i: usize) -> u8 {
    src.get(i).copied().unwrap_or(0)
}

/// Decodes a stream into `dst`; returns the decoded size.
///
/// Valid streams decode exactly as in the original. On anything else (a damaged block, or
/// bytes past the end of a file) the original wrote past `dst`, read before it and past
/// `src`; here the output stops at the end of `dst`, a reference before the start of the
/// output reads zeros and a token cut off by the end of the input ends the stream.
pub fn decompress(src: &[u8], dst: &mut [u8]) -> usize {
    let src_size = src.len();
    let capacity = dst.len();
    if src_size == 0 {
        return 0;
    }
    if src[0] == 0 {
        let size = (src_size - 1).min(capacity);
        dst[..size].copy_from_slice(&src[1..1 + size]);
        return size;
    }
    if src_size < 3 {
        return 0;
    }

    let mut out = 0usize;
    let mut i = 3usize;
    let mut flags = u16::from_be_bytes([src[1], src[2]]);
    let mut flags_left = 16u8;
    while i < src_size {
        if flags_left == 0 {
            if i + 2 > src_size {
                break;
            }
            flags = u16::from_be_bytes([src[i], src[i + 1]]);
            flags_left = 16;
            i += 2;
            if i >= src_size {
                break;
            }
        }
        if flags & 0x8000 == 0 {
            if out >= capacity {
                return out;
            }
            dst[out] = src[i];
            out += 1;
            i += 1;
        } else {
            if i + 2 > src_size {
                break;
            }
            let distance = src[i] as usize * 16 + (src[i + 1] >> 4) as usize;
            if distance == 0 {
                if i + 4 > src_size {
                    break;
                }
                let count = ((src[i + 1] as usize) << 8) + 0xF + src[i + 2] as usize + 1;
                let n = count.min(capacity - out);
                dst[out..out + n].fill(src[i + 3]);
                i += 4;
                out += n;
                if n != count {
                    return out;
                }
            } else {
                let length = (src[i + 1] & 0xF) as usize + 3;
                let n = length.min(capacity - out);
                for k in 0..n {
                    // byte by byte: the copy may overlap
                    let a = out + k;
                    dst[a] = if a >= distance { dst[a - distance] } else { 0 };
                }
                i += 2;
                out += n;
                if n != length {
                    return out;
                }
            }
        }
        flags <<= 1;
        flags_left -= 1;
    }
    out
}

/// dtaRead's decoder: unlike [`decompress`] it does not stop at the room or at a cut-off
/// token. The original over-read the input (zeros here), read back-references from before
/// the output (zeros here) and wrote past it (dropped). The stream is the first `src_size`
/// bytes of `src`; `out` = where the output starts in `dst` (the wave path's references can
/// reach its header). Returns the output count, which can exceed `dst.len()`.
pub fn decompress_retail(src: &[u8], src_size: usize, dst: &mut [u8], mut out: usize) -> usize {
    let capacity = dst.len();
    let put = |dst: &mut [u8], a: usize, value: u8| {
        if a < capacity {
            dst[a] = value;
        }
    };
    if at(src, 0) == 0 {
        for k in 1..src_size {
            put(dst, out, at(src, k));
            out += 1;
        }
        return out;
    }
    let mut flags = u16::from_be_bytes([at(src, 1), at(src, 2)]);
    let mut flags_left = 16u8;
    let mut i = 3usize;
    while i < src_size {
        if flags_left == 0 {
            flags = u16::from_be_bytes([at(src, i), at(src, i + 1)]);
            flags_left = 16;
            i += 2;
        }
        if flags & 0x8000 == 0 {
            put(dst, out, at(src, i));
            out += 1;
            i += 1;
        } else {
            let distance = at(src, i) as usize * 16 + (at(src, i + 1) >> 4) as usize;
            if distance == 0 {
                let count = at(src, i + 1) as usize * 0x100 + 0x10 + at(src, i + 2) as usize;
                let value = at(src, i + 3);
                for _ in 0..count {
                    put(dst, out, value);
                    out += 1;
                }
                i += 4;
            } else {
                let length = (at(src, i + 1) & 0xF) as usize + 3;
                for _ in 0..length {
                    let value = if out >= distance && out - distance < capacity {
                        dst[out - distance]
                    } else {
                        0
                    };
                    put(dst, out, value);
                    out += 1;
                }
                i += 2;
            }
        }
        flags <<= 1;
        flags_left -= 1;
    }
    out
}

/// Looks for an earlier occurrence of the bytes at `pos` through the hash table and records
/// `pos` in it. On success `length` (3..18) and `match_pos` describe the match.
fn find_match(
    hash_table: &mut [i32; 0x1000],
    data: &[u8],
    pos: u32,
    size: u32,
    length: &mut u16,
    match_pos: &mut i32,
) -> bool {
    let p = pos as usize;
    // Reads up to two bytes past the end of the data, like the original.
    let mixed =
        ((((at(data, p) as i32) << 4) ^ at(data, p + 1) as i32) << 4) ^ at(data, p + 2) as i32;
    let hash = ((mixed as u32).wrapping_mul(0x9E5F) >> 4 & 0xFFF) as usize;
    let mut found = false;
    let candidate = hash_table[hash];
    if candidate != -1 && pos.wrapping_sub(candidate as u32) < WINDOW_SIZE {
        *match_pos = candidate;
        *length = 0;
        let m = candidate as usize;
        while *length < MAX_MATCH
            && at(data, p + *length as usize) == at(data, m + *length as usize)
            && pos + (*length as u32) < size
        {
            *length += 1;
        }
        found = *length > 2;
    }
    hash_table[hash] = pos as i32;
    found
}

/// Compresses the first `size` bytes of `src` into `dst` (resized as needed); returns the
/// stream's size. Falls back to a stored stream when compressing does not pay.
///
/// Like the original it looks at up to two bytes after the data (zeros past the end of
/// `src`), so pass the data followed by what came after it for byte-identical output.
pub fn compress(src: &[u8], size: usize, dst: &mut Vec<u8>) -> usize {
    let mut hash_table = [-1i32; 0x1000];
    dst.clear();
    dst.resize(size + 16, 0);
    let size32 = size as u32;
    dst[0] = 1;
    let mut i = 0u32;
    let mut out = 3usize;
    let mut flags_pos = 1usize;
    let mut flag_count = 0u16;
    let mut flags = 0u16;
    let mut match_pos = 0i32;
    while i < size32 && out <= size {
        if flag_count > 15 {
            dst[flags_pos..flags_pos + 2].copy_from_slice(&flags.to_be_bytes());
            flags_pos = out;
            flag_count = 0;
            out += 2;
        }

        // Reads one byte past the end of the data, like the original.
        let mut length = 1u16;
        while at(src, i as usize) == at(src, (i + length as u32) as usize)
            && length < MAX_RUN
            && i + (length as u32) < size32
        {
            length += 1;
        }

        if length < MIN_RUN {
            if !find_match(&mut hash_table, src, i, size32, &mut length, &mut match_pos) {
                dst[out] = at(src, i as usize);
                out += 1;
                i += 1;
                flags <<= 1;
            } else {
                let code = ((i.wrapping_sub(match_pos as u32) as u16).wrapping_mul(16))
                    .wrapping_sub(3)
                    .wrapping_add(length);
                dst[out..out + 2].copy_from_slice(&code.to_be_bytes());
                out += 2;
                i += length as u32;
                flags = flags.wrapping_mul(2).wrapping_add(1);
            }
        } else {
            let count = length - MIN_RUN;
            dst[out] = 0;
            dst[out + 1..out + 3].copy_from_slice(&count.to_be_bytes());
            dst[out + 3] = at(src, i as usize);
            out += 4;
            i += length as u32;
            flags = flags.wrapping_mul(2).wrapping_add(1);
        }
        flag_count += 1;
    }
    let flags = ((flags as u32) << ((16 - flag_count as u32) & 0x1F)) as u16;
    dst[flags_pos..flags_pos + 2].copy_from_slice(&flags.to_be_bytes());

    if size < out {
        dst[1..1 + size].copy_from_slice(&src[..size]);
        dst[0] = 0;
        out = size + 1;
    }
    dst.truncate(out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<u8> {
        let mut data = Vec::new();
        for i in 0..20000u32 {
            data.push((i % 251) as u8);
            if i % 7 == 0 {
                data.extend_from_slice(b"hello hello hello");
            }
            if i % 1000 == 0 {
                data.extend(std::iter::repeat(0xAB).take(300));
            }
        }
        data.truncate(0x8000);
        data
    }

    #[test]
    fn round_trip() {
        let data = sample();
        let mut packed = Vec::new();
        let n = compress(&data, data.len(), &mut packed);
        assert_eq!(n, packed.len());
        assert_eq!(packed[0], 1, "the sample compresses");
        let mut out = vec![0u8; data.len()];
        assert_eq!(decompress(&packed, &mut out), data.len());
        assert_eq!(out, data);

        let mut out = vec![0u8; data.len()];
        assert_eq!(
            decompress_retail(&packed, packed.len(), &mut out, 0),
            data.len()
        );
        assert_eq!(out, data);
    }

    #[test]
    fn incompressible_is_stored() {
        let mut seed = 12345u32;
        let data: Vec<u8> = (0..1000)
            .map(|_| {
                seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
                (seed >> 16) as u8
            })
            .collect();
        let mut packed = Vec::new();
        let n = compress(&data, data.len(), &mut packed);
        assert_eq!(packed[0], 0);
        assert_eq!(n, data.len() + 1);
        let mut out = vec![0u8; data.len()];
        assert_eq!(decompress(&packed, &mut out), data.len());
        assert_eq!(out, data);
    }

    #[test]
    fn damaged_streams_stay_in_bounds() {
        let mut out = [0u8; 16];
        // a run of 0x10 + 0xFFF bytes into 16 bytes of room
        assert_eq!(decompress(&[1, 0x80, 0, 0, 0x0F, 0xFF, 7], &mut out), 16);
        assert_eq!(out, [7; 16]);
        assert!(decompress_retail(&[1, 0x80, 0, 0, 0x0F, 0xFF, 7], 7, &mut out, 0) > 16);
    }
}
