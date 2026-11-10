//! Reading and seeking: dtaRead, dtaSeek, dtaGetTime.

use std::fs::File;
use std::sync::Arc;

use crate::crypt::{checksum16, decrypt};
use crate::open::report_archive_error;
use crate::state::*;
use crate::{fql, lz4, lzss, platform, wav};

/// The original's decoders run to the end of the input, which is zero-padded by this many
/// bytes, and may read that far past it.
const DECODE_PAD: usize = 0x40;

/// A stored block is at most 0xFFFF bytes plus the type byte. (The original decoded into a
/// 0x8008-byte stack buffer, too small for the largest blocks a 16-bit size allows.)
const RAW_BLOCK_SIZE: usize = 0x10000 + 8 + DECODE_PAD;

/// The original read a block's stored size into its 0x8008-byte stack buffer. Larger ISD0
/// blocks (and empty ones, which left a stale type byte) make dtaRead fail with -1; for ISD1 a
/// block past the table or of 0x8008 bytes or more fails as a read error (6).
const RETAIL_BLOCK_LIMIT: u32 = 0x8008;

/// What dtaRead copies out of the open file at the start.
struct ReadContext {
    handle: usize,
    file: Arc<File>,
    archive: u32,
    size: u32,
    data_offset: u32,
    block_count: u32,
    key: u64,
    encrypted: bool,
    info: Arc<BlockInfo>,
}

impl ReadContext {
    /// ISD1: block sizes, checksums and types are in tables
    fn tables(&self) -> bool {
        self.info.block_tables
    }

    fn table_count(&self) -> u32 {
        self.info.block_sizes.len() as u32
    }

    // (The original read one entry past the tables when reading up to the end of a file.)
    fn size_of(&self, block: u32) -> u32 {
        self.info
            .block_sizes
            .get(block as usize)
            .map_or(0, |&s| s as u32)
    }

    fn type_of(&self, block: u32) -> u8 {
        self.info
            .block_types
            .get(block as usize)
            .copied()
            .unwrap_or(0)
    }

    /// Offset of a block from data_offset: the sum of the sizes before it.
    fn offset_of(&self, block: u32) -> u32 {
        (0..block).fold(0u32, |o, i| o.wrapping_add(self.size_of(i)))
    }

    fn seek(&self, offset: u32) -> bool {
        platform::seek(&self.file, offset)
    }

    fn invalidate(&self, st: &mut State) {
        st.open_files[self.handle].buffer_valid = false;
    }
}

/// ISD0: reads the u32 in front of a block (stored size | size of the previous block << 16).
fn read_block_header(file: &File, c: &mut Cursor) -> bool {
    let mut value = [0u8; 4];
    if !platform::read_exact(file, &mut value) {
        return false;
    }
    let value = u32::from_le_bytes(value);
    c.previous_block_size = value >> 16;
    c.block_size = value & 0xFFFF;
    true
}

/// Reads the stored block at the current file position into `raw` (raw[0] = the type),
/// checks and decrypts it. For ISD1 the type comes from the table and `block_size` grows by
/// it. On failure reports the error (some callers first invalidate the buffer, as the
/// original did).
fn read_block(
    st: &mut State,
    ctx: &ReadContext,
    raw: &mut [u8],
    block_size: &mut u32,
    block: u32,
    invalidate_on_error: bool,
) -> bool {
    let tables = ctx.tables();
    let start = tables as usize;
    let size = *block_size;
    let bad = if tables {
        block >= ctx.table_count() || size >= RETAIL_BLOCK_LIMIT
    } else {
        size == 0 || size > RETAIL_BLOCK_LIMIT
    };
    let fail = |st: &mut State, error: Option<i32>| {
        if invalidate_on_error {
            ctx.invalidate(st);
        }
        if let Some(error) = error {
            report_archive_error(st, ctx.archive, error);
        }
        false
    };
    if bad {
        return fail(st, tables.then_some(DTA_ERROR_READ));
    }
    let size = size as usize;
    let data = &mut raw[start..start + size];
    match platform::read(&ctx.file, data) {
        Err(_) => return fail(st, tables.then_some(DTA_ERROR_READ)),
        Ok(n) if n != size => return fail(st, Some(DTA_ERROR_SIZE)),
        Ok(_) => {}
    }
    if tables
        && st.error_callback.is_some()
        && block < ctx.table_count()
        && ctx.info.block_checksums[block as usize] != checksum16(data, CHECKSUM_SEED)
    {
        report_archive_error(st, ctx.archive, DTA_ERROR_CHECKSUM);
    }
    if ctx.encrypted {
        decrypt(data, ctx.key); // the cipher is its own inverse
    }
    if tables {
        raw[0] = ctx.type_of(block);
        *block_size += 1;
    }
    // The original's decoders read past the block (stale stack bytes); zeros here.
    let end = *block_size as usize;
    raw[end..end + DECODE_PAD].fill(0);
    true
}

/// Decodes a stored block (raw[0] = type) into `dst` (a valid block decodes to at most
/// 32 KB); returns the decoded size, or -1. Damaged blocks decode as in the original, which
/// never compared the result with the expected size; a stored block larger than the room
/// fails.
fn decode_block(
    ctx: &ReadContext,
    raw: &mut [u8],
    block_size: u32,
    block: u32,
    dst: &mut [u8],
) -> i32 {
    let capacity = dst.len();
    let size = block_size as usize;
    match raw[0] {
        DTA_BLOCK_LZSS => {
            lzss::decompress_retail(&raw[..size + DECODE_PAD], size, dst, 0).min(capacity) as i32
        }
        DTA_BLOCK_LZ4 => lz4::decompress(&raw[1..size], dst) as i32,
        t if t < DTA_BLOCK_WAV => {
            if size - 1 > capacity {
                return -1;
            }
            dst[..size - 1].copy_from_slice(&raw[1..size]);
            (size - 1) as i32
        }
        _ => {
            // Unless the whole block is encrypted, only the first block's RIFF header is.
            if block == 0 && !ctx.encrypted {
                decrypt(&mut raw[1..1 + DTA_WAV_HEADER_SIZE as usize], ctx.key);
            }
            let src = &raw[..size + DECODE_PAD];
            let header = &ctx.info.wav_header;
            if header.is_empty() {
                // (the original crashed on the missing header)
                wav::decompress(src, size, None, dst) as i32
            } else {
                wav::decompress_retail(src, size, header, dst) as i32
            }
        }
    }
}

/// A file in an archive. Returns the bytes read or -1.
fn read_archived(
    st: &mut State,
    ctx: &ReadContext,
    c: &mut Cursor,
    dst: &mut [u8],
    decoded: &mut [u8],
    raw: &mut [u8],
) -> i32 {
    let count = dst.len() as u32;
    let tables = ctx.tables();
    let file = &*ctx.file;
    let at = |offset: u32| ctx.data_offset.wrapping_add(offset);

    // Move to the block of the position.
    let target = c.position >> 15;
    if c.block != target {
        if tables {
            c.block_size = ctx.size_of(target);
            c.block_offset = ctx.offset_of(target);
            c.block = target;
        } else if c.block < target {
            while c.block != target {
                c.block_offset = c.block_offset.wrapping_add(4 + c.block_size);
                c.block += 1;
                if !ctx.seek(at(c.block_offset)) || !read_block_header(file, c) {
                    return -1;
                }
            }
        } else if target < c.block >> 1 {
            // Nearer to the start: walk forward from the first block.
            if !ctx.seek(ctx.data_offset) {
                return -1;
            }
            c.block = 0;
            c.block_offset = 0;
            if !read_block_header(file, c) {
                return -1;
            }
            while c.block != target {
                c.block_offset = c.block_offset.wrapping_add(4 + c.block_size);
                c.block += 1;
                if !ctx.seek(at(c.block_offset)) || !read_block_header(file, c) {
                    return -1;
                }
            }
        } else {
            // Walk back through the sizes of the previous blocks.
            while c.block != target {
                c.block_offset = c.block_offset.wrapping_sub(c.previous_block_size + 4);
                c.block -= 1;
                if !ctx.seek(at(c.block_offset)) || !read_block_header(file, c) {
                    return -1;
                }
            }
        }
        c.block_position = c
            .position
            .wrapping_sub(c.block.wrapping_mul(DTA_BLOCK_SIZE));
        ctx.invalidate(st);
    }

    // Decode the block.
    if !st.open_files[ctx.handle].buffer_valid {
        if !ctx.seek(at(c.block_offset.wrapping_add(if tables { 0 } else { 4 }))) {
            return -1;
        }
        if !read_block(st, ctx, raw, &mut c.block_size, c.block, false) {
            return -1;
        }
        let n = decode_block(ctx, raw, c.block_size, c.block, decoded);
        if n < 0 {
            return -1;
        }
        c.buffer_size = n as u32;
        st.open_files[ctx.handle].buffer_valid = true;
    }

    // (Only damaged data leaves the position past the decoded bytes; the original then
    // copied from past the buffer.)
    let available = c.buffer_size.saturating_sub(c.block_position);
    let bp = c.block_position as usize;
    if count <= available {
        dst.copy_from_slice(&decoded[bp..bp + count as usize]);
        c.position += count;
        c.block_position += count;
        // At the end of the block, step to the next one.
        if c.block_position == c.buffer_size && c.block + 1 < ctx.block_count {
            if !tables {
                c.block_offset = c.block_offset.wrapping_add(c.block_size + 4);
                c.block += 1;
                if !ctx.seek(at(c.block_offset)) || !read_block_header(file, c) {
                    return -1;
                }
            } else {
                c.block += 1;
                c.block_offset = ctx.offset_of(c.block);
                c.block_size = ctx.size_of(c.block);
            }
            ctx.invalidate(st);
            c.block_position = 0;
        }
        return count as i32;
    }

    // The rest of this block ...
    dst[..available as usize].copy_from_slice(&decoded[bp..bp + available as usize]);
    c.position += available;
    c.block_position = 0;
    let mut done = available;
    let remaining = count - available;
    if !tables {
        c.block_offset = c.block_offset.wrapping_add(c.block_size + 4);
    } else {
        c.block_offset = ctx.offset_of(c.block + 1);
    }
    if !ctx.seek(at(c.block_offset)) {
        return -1;
    }

    // ... whole blocks, decoded straight into the caller's buffer ...
    let whole_blocks = remaining >> 15;
    let tail = remaining - whole_blocks * DTA_BLOCK_SIZE;
    for _ in 0..whole_blocks {
        c.block += 1;
        if !tables {
            if !read_block_header(file, c) {
                ctx.invalidate(st);
                return -1;
            }
        } else {
            c.block_size = ctx.size_of(c.block);
        }
        if !read_block(st, ctx, raw, &mut c.block_size, c.block, true) {
            return -1;
        }
        let n = decode_block(ctx, raw, c.block_size, c.block, &mut dst[done as usize..]);
        if n < 0 {
            ctx.invalidate(st);
            return -1;
        }
        c.buffer_size = n as u32;
        done += c.buffer_size;
        c.position += c.buffer_size;
        if !tables {
            c.block_offset = c.block_offset.wrapping_add(4 + c.block_size);
        } else {
            c.block_offset = ctx.offset_of(c.block + 1);
        }
    }

    // ... and the start of the next block through the file's buffer.
    c.block += 1;
    if !tables {
        if !read_block_header(file, c) {
            ctx.invalidate(st);
            return -1;
        }
    } else {
        c.block_offset = ctx.offset_of(c.block);
        c.block_size = ctx.size_of(c.block);
    }
    if tail == 0 {
        ctx.invalidate(st);
        return done as i32;
    }
    if !read_block(st, ctx, raw, &mut c.block_size, c.block, true) {
        return -1;
    }
    let n = decode_block(ctx, raw, c.block_size, c.block, decoded);
    if n < 0 {
        ctx.invalidate(st);
        return -1;
    }
    c.buffer_size = n as u32;
    // (Like the original, a damaged block that decodes to less than the tail leaves the
    // rest of the copy to the buffer's earlier contents. Damaged whole blocks that decoded to
    // more than 32 KB leave less room than the tail: the original (and the C++ port) then
    // wrote past the caller's buffer and returned more than was asked for; the copy stops at
    // the end of the buffer here.)
    let tail = tail.min(count - done);
    let bp = c.block_position as usize; // 0 here, and tail < 32 KB
    dst[done as usize..(done + tail) as usize].copy_from_slice(&decoded[bp..bp + tail as usize]);
    c.position += tail;
    c.block_position += tail;
    (done + tail) as i32
}

/// A file on disk, read through its 32 KB buffer. Returns the bytes read or -1.
fn read_disk(
    st: &mut State,
    ctx: &ReadContext,
    c: &mut Cursor,
    dst: &mut [u8],
    decoded: &mut [u8],
) -> i32 {
    let count = dst.len() as u32;
    let file = &*ctx.file;
    if !st.open_files[ctx.handle].buffer_valid
        || c.position < c.block_offset
        || c.block_offset.wrapping_add(c.buffer_size) <= c.position
    {
        c.block_offset = c.position & !(DTA_BLOCK_SIZE - 1);
        if !ctx.seek(c.block_offset) {
            return -1;
        }
        c.buffer_size = ctx.size.wrapping_sub(c.block_offset).min(DTA_BLOCK_SIZE);
        if !platform::read_exact(file, &mut decoded[..c.buffer_size as usize]) {
            return -1;
        }
        st.open_files[ctx.handle].buffer_valid = true;
        c.block_position = c.position - c.block_offset;
    }

    let available = c.buffer_size.saturating_sub(c.block_position);
    let bp = c.block_position as usize;
    if count <= available {
        dst.copy_from_slice(&decoded[bp..bp + count as usize]);
        c.position += count;
        c.block_position += count;
        if c.block_position == c.buffer_size && c.position < ctx.size {
            c.block_offset = c.block_offset.wrapping_add(c.buffer_size);
            ctx.invalidate(st);
        }
        return count as i32;
    }

    dst[..available as usize].copy_from_slice(&decoded[bp..bp + available as usize]);
    c.position += available;
    c.block_position = 0;
    let mut done = available as usize;
    let remaining = (count - available) as usize;
    ctx.invalidate(st);
    c.block_offset = c.block_offset.wrapping_add(c.buffer_size);
    if !ctx.seek(c.block_offset) {
        return -1;
    }
    c.buffer_size = ctx.size.wrapping_sub(c.block_offset).min(DTA_BLOCK_SIZE);
    if remaining < c.buffer_size as usize {
        // Refill the buffer and copy from it.
        if !platform::read_exact(file, &mut decoded[..c.buffer_size as usize]) {
            return -1;
        }
        dst[done..done + remaining].copy_from_slice(&decoded[..remaining]);
        done += remaining;
        c.position += remaining as u32;
        c.block_position += remaining as u32;
        st.open_files[ctx.handle].buffer_valid = true;
    } else {
        // Read the rest straight into the caller's buffer.
        if !platform::read_exact(file, &mut dst[done..done + remaining]) {
            return -1;
        }
        done += remaining;
        c.position += remaining as u32;
    }
    done as i32
}

/// dtaRead
///
/// # Safety
/// `buffer` must be null or valid for writes of `size` bytes (the bytes left in the file
/// when `size` is negative, as in the original).
pub unsafe fn read(handle: i32, buffer: *mut u8, size: i32) -> i32 {
    with_state(|st| {
        if buffer.is_null() || handle as u32 as usize >= st.open_files.len() {
            return -1;
        }
        let h = handle as usize;
        let file = &st.open_files[h];
        if file.is_free() || file.flags & DTA_FILE_WRITE != 0 {
            return -1;
        }
        let ctx = ReadContext {
            handle: h,
            file: file.file.clone().expect("not free"),
            archive: file.archive,
            size: file.size,
            data_offset: file.data_offset,
            block_count: file.block_count,
            key: file.key,
            encrypted: file.blocks_encrypted,
            info: file.info.clone(),
        };
        let flags = file.flags;
        let mut cursor = file.cursor;

        // Reads of ISD1 files opened while recording / playing back go through the FQL file.
        let recorded = ctx.tables() && st.fql.active() && st.fql_handles.contains(&handle);

        // dtaSeek accepts one byte past the end. The original then computed the remaining
        // size as 0xFFFFFFFF and copied `size` bytes from past its buffers; this reads nothing.
        if cursor.position > ctx.size {
            return 0;
        }
        let count = (size as u32).min(ctx.size - cursor.position);
        // SAFETY: the caller's buffer holds `count` bytes (see above).
        let dst = std::slice::from_raw_parts_mut(buffer, count as usize);

        let result;
        if flags & DTA_FILE_DISK == 0 && recorded && st.fql.read_file.is_some() {
            fql::read(st, dst);
            result = count as i32;
            cursor = Cursor {
                position: cursor.position + count,
                ..Cursor::default()
            };
        } else {
            let mut decoded = std::mem::take(&mut st.open_files[h].buffer);
            decoded.resize(DTA_BLOCK_SIZE as usize, 0);
            if flags & DTA_FILE_DISK == 0 {
                let mut raw = std::mem::take(&mut st.raw_block);
                raw.resize(RAW_BLOCK_SIZE, 0);
                result = read_archived(st, &ctx, &mut cursor, dst, &mut decoded, &mut raw);
                st.raw_block = raw;
            } else {
                result = read_disk(st, &ctx, &mut cursor, dst, &mut decoded);
            }
            st.open_files[h].buffer = decoded;
            if result < 0 {
                return -1;
            }
            if flags & DTA_FILE_DISK == 0 && recorded && st.fql.write_file.is_some() {
                fql::write(st, &dst[..result as usize]);
            }
        }
        st.open_files[h].cursor = cursor;
        result
    })
}

/// dtaSeek. origin: 0 = SEEK_SET, 1 = SEEK_CUR, 2 = SEEK_END. Returns the new position or -1.
pub fn seek(handle: i32, position: i32, origin: i32) -> i32 {
    with_state(|st| {
        let Some(file) = st.open_files.get_mut(handle as u32 as usize) else {
            return -1;
        };
        if file.is_free() {
            return -1;
        }
        let size = file.size;
        let cursor = &mut file.cursor;

        // Files being read: only the position moves; dtaRead finds the block.
        if file.flags & DTA_FILE_WRITE == 0 {
            let target = match origin {
                0 => {
                    if position < 0 || size < position as u32 {
                        return -1;
                    }
                    position as u32
                }
                1 => {
                    let target = cursor.position.wrapping_add(position as u32);
                    if size < target || (target as i32) < 0 {
                        return -1;
                    }
                    target
                }
                2 => {
                    // (The test is position < 2, so one byte past the end is accepted.)
                    let target = size.wrapping_add(position as u32);
                    if position < 2 && target as i32 >= 0 {
                        target
                    } else {
                        return -1;
                    }
                }
                _ => return -1,
            };
            cursor.position = target;
            cursor.block_position = target % DTA_BLOCK_SIZE;
            return target as i32;
        }

        // Files being written: the file pointer. The original's switch has no breaks, so a
        // failed seek is retried with the next origins.
        if !(0..=2).contains(&origin) {
            return -1;
        }
        let os_file = file.file.clone().expect("not free");
        for o in origin..=2 {
            match platform::seek_from(&os_file, position, o) {
                Some(p) if p != u32::MAX => {
                    cursor.position = p;
                    cursor.block_position = p % DTA_BLOCK_SIZE;
                    return p as i32;
                }
                _ => cursor.position = u32::MAX, // INVALID_SET_FILE_POINTER
            }
        }
        -1
    })
}

/// dtaGetTime: the last-write time (a FILETIME) of the archived file itself, or
/// (`container_time`, and for disk files) of the file on disk.
pub fn get_time(handle: i32, container_time: bool) -> Option<u64> {
    with_state(|st| {
        let file = st.open_files.get(handle as u32 as usize)?;
        let os_file = file.file.as_ref()?;
        if file.flags & DTA_FILE_DISK == 0 && !container_time {
            return Some(file.time);
        }
        platform::last_write_time(os_file)
    })
}
