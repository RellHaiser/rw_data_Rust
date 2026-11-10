//! Decoder of compressed WAV blocks: 16-bit PCM stored as one byte per sample, the delta to
//! the previous sample of the channel (bit 7 = sign, bits 0..6 = index in a quadratic table).
//! The first sample of every channel is stored as is.

use crate::lzss;
use crate::state::DTA_WAV_HEADER_SIZE;
use crate::wav_tables::WAV_DELTAS;

const HEADER: usize = DTA_WAV_HEADER_SIZE as usize;

fn delta_table(block_type: u8) -> &'static [i16; 128] {
    &WAV_DELTAS[match block_type {
        0x0C => 1,
        0x10 => 2,
        0x14 => 3,
        0x18 => 4,
        0x1C => 5,
        0x20 => 6,
        _ => 0,
    }]
}

/// A byte of `src`, or 0 past its end (the original read whatever followed the block).
#[inline]
fn at(src: &[u8], i: usize) -> u8 {
    src.get(i).copied().unwrap_or(0)
}

fn read32(p: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([at(p, i), at(p, i + 1), at(p, i + 2), at(p, i + 3)])
}

fn read16(p: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([at(p, i), at(p, i + 1)])
}

fn sample(p: &[u8], i: usize) -> i16 {
    read16(p, i) as i16
}

fn delta(table: &[i16; 128], code: u8) -> i16 {
    let d = table[(code & 0x7F) as usize];
    if code & 0x80 != 0 {
        d.wrapping_neg()
    } else {
        d
    }
}

/// "RIFF", "fmt " and "data" at the same places as in the file's header.
fn starts_with_header(src: &[u8], header: &[u8]) -> bool {
    read32(src, 1) == read32(header, 0)
        && read32(src, 0xD) == read32(header, 0xC)
        && read32(src, 0x25) == read32(header, 0x24)
}

/// Decodes the block in the first `src_size` bytes of `src` (which starts with the block type
/// byte; the first block of a file then repeats the file's RIFF header `wav_header`, which is
/// copied to the output). Returns the decoded size. The output stops at the end of `dst`
/// (only damaged data gets there; the original went on).
pub fn decompress(src: &[u8], src_size: usize, wav_header: Option<&[u8]>, dst: &mut [u8]) -> usize {
    let capacity = dst.len();
    let table = delta_table(at(src, 0));
    let src_size = src_size.min(src.len());
    let mut out = 0usize;
    let mut i = 1usize;

    // The original read the header unconditionally (a null header crashed it).
    let Some(header) = wav_header else {
        if i < src_size {
            out += lzss::decompress(&src[i..src_size], &mut dst[out..]);
        }
        return out;
    };

    if starts_with_header(src, header) && capacity >= HEADER {
        for (k, d) in dst[..HEADER].iter_mut().enumerate() {
            *d = at(src, 1 + k);
        }
        out += HEADER;
        i += HEADER;
    }
    if i >= src_size {
        return out;
    }

    let channels = read16(header, 0x16);
    let block_align = read16(header, 0x20);
    // The original divided by a zero channel count too.
    if channels == 0 || block_align / channels != 2 {
        out += lzss::decompress(&src[i..src_size], &mut dst[out..]);
        return out;
    }

    // Like the original, a sample pair at the end of the data may use the byte after it.
    if channels == 2 {
        if capacity - out < 4 {
            return out;
        }
        for _ in 0..4 {
            dst[out] = at(src, i);
            out += 1;
            i += 1;
        }
        if i < src_size {
            let mut left = sample(dst, out - 4);
            let mut right = sample(dst, out - 2);
            loop {
                if capacity - out < 4 {
                    return out;
                }
                let s = out;
                out += 4;
                left = left.wrapping_add(delta(table, at(src, i)));
                dst[s..s + 2].copy_from_slice(&left.to_le_bytes());
                right = right.wrapping_add(delta(table, at(src, i + 1)));
                i += 2;
                dst[s + 2..s + 4].copy_from_slice(&right.to_le_bytes());
                if i >= src_size {
                    break;
                }
            }
        }
    } else {
        if capacity - out < 2 {
            return out;
        }
        for _ in 0..2 {
            dst[out] = at(src, i);
            out += 1;
            i += 1;
        }
        if i < src_size {
            let mut value = sample(dst, out - 2);
            loop {
                if capacity - out < 2 {
                    return out;
                }
                let s = out;
                out += 2;
                value = value.wrapping_add(delta(table, at(src, i)));
                i += 1;
                dst[s..s + 2].copy_from_slice(&value.to_le_bytes());
                if i >= src_size {
                    break;
                }
            }
        }
    }
    out
}

/// dtaRead's decoder: no stop at the room, stereo consumes byte pairs (an odd tail decodes
/// one pad byte), the LZ branch runs the original's LZ with back-references into the copied
/// header. Returns at most `dst.len()`.
pub fn decompress_retail(src: &[u8], src_size: usize, wav_header: &[u8], dst: &mut [u8]) -> usize {
    let capacity = dst.len();
    let put = |dst: &mut [u8], a: usize, value: u8| {
        if a < capacity {
            dst[a] = value;
        }
    };
    let table = delta_table(at(src, 0));
    let mut out = 0usize;
    let mut i = 1usize;
    if starts_with_header(src, wav_header) {
        while out < HEADER {
            put(dst, out, at(src, 1 + out));
            out += 1;
        }
        i += HEADER;
    }
    if i < src_size {
        let channels = read16(wav_header, 0x16);
        let block_align = read16(wav_header, 0x20);
        if channels != 0 && block_align / channels == 2 {
            let n = if channels == 2 { 2 } else { 1 };
            let mut value = [sample(src, i), sample(src, i + 2)];
            for _ in 0..2 * n {
                put(dst, out, at(src, i));
                out += 1;
                i += 1;
            }
            while i < src_size {
                for v in value.iter_mut().take(n) {
                    *v = v.wrapping_add(delta(table, at(src, i)));
                    i += 1;
                    let bytes = v.to_le_bytes();
                    put(dst, out, bytes[0]);
                    put(dst, out + 1, bytes[1]);
                    out += 2;
                }
            }
        } else {
            let rest = if i < src.len() { &src[i..] } else { &[][..] };
            out = lzss::decompress_retail(rest, src_size - i, dst, out);
        }
    }
    out.min(capacity)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(channels: u16) -> Vec<u8> {
        let mut h = vec![0u8; HEADER];
        h[0..4].copy_from_slice(b"RIFF");
        h[0xC..0x10].copy_from_slice(b"fmt ");
        h[0x16..0x18].copy_from_slice(&channels.to_le_bytes());
        h[0x20..0x22].copy_from_slice(&(2 * channels).to_le_bytes());
        h[0x24..0x28].copy_from_slice(b"data");
        h
    }

    #[test]
    fn mono_deltas() {
        let h = header(1);
        // type 8, header, first sample 100, then +1 (code 1), -2 (code 0x82)
        let mut src = vec![8u8];
        src.extend_from_slice(&h);
        src.extend_from_slice(&100i16.to_le_bytes());
        src.extend_from_slice(&[1, 0x82]);
        let mut dst = vec![0u8; 0x8000];
        let n = decompress(&src, src.len(), Some(&h), &mut dst);
        assert_eq!(n, HEADER + 6);
        assert_eq!(&dst[..HEADER], &h[..]);
        let samples: Vec<i16> = dst[HEADER..n]
            .chunks(2)
            .map(|c| i16::from_le_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(samples, [100, 101, 99]);

        let mut dst2 = vec![0u8; 0x8000];
        let n2 = decompress_retail(&src, src.len(), &h, &mut dst2);
        assert_eq!(n2, n);
        assert_eq!(dst2[..n2], dst[..n]);
    }

    #[test]
    fn stereo_deltas() {
        let h = header(2);
        let mut src = vec![0x0Cu8]; // table 1, no header in this block
        src.extend_from_slice(&10i16.to_le_bytes());
        src.extend_from_slice(&(-10i16).to_le_bytes());
        src.extend_from_slice(&[2, 0x82]);
        let mut dst = vec![0u8; 64];
        let n = decompress(&src, src.len(), Some(&h), &mut dst);
        let samples: Vec<i16> = dst[..n]
            .chunks(2)
            .map(|c| i16::from_le_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(samples, [10, -10, 13, -13]);
        let mut dst2 = vec![0u8; 64];
        assert_eq!(decompress_retail(&src, src.len(), &h, &mut dst2), n);
        assert_eq!(dst2[..n], dst[..n]);
    }
}
