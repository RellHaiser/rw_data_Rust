//! FQL files: the archive data read during a load, recorded in order into one file
//! (dtaCreateFQL .. dtaCloseFQL) and played back from it (dtaFQLBegin .. dtaFQLEnd), so a
//! later load reads one file sequentially instead of seeking through the archives.
//!
//! File: u32 file size, u16 checksum of that u32, then blocks. A block is a u32 stored
//! size and LZSS chunks (u32 size + stream) that decompress to up to 128 KB:
//!   u32 used size (including this 8-byte header), u32 checksum (computed with it zeroed),
//!   then records: u32 size + data (a record may continue in the next blocks).
//! Only ISD1 archives are recorded: the file headers, names, block tables and WAV headers
//! read by the archive lookup, and the data read by dtaRead.

use std::io::{Seek, SeekFrom};
use std::ptr;

use crate::crypt::checksum16;
use crate::state::*;
use crate::{lzss, platform};

const CHUNK_SIZE: u32 = 0x8000;
const BLOCK_SIZE: u32 = Fql::BLOCK_SIZE;
const HEADER_SIZE: u32 = Fql::BLOCK_HEADER_SIZE;
const BLOCK_PAYLOAD: u32 = BLOCK_SIZE - HEADER_SIZE;

fn load32(b: &[u8], at: usize) -> u32 {
    match b.get(at..at + 4) {
        Some(s) => u32::from_le_bytes([s[0], s[1], s[2], s[3]]),
        None => 0,
    }
}

fn store32(b: &mut [u8], at: usize, value: u32) {
    b[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn report_fql_error(st: &mut State, error: i32) {
    let name = st.fql.file_name.clone();
    st.report(ptr::null_mut(), &name, error);
}

/// Compresses the recording buffer into the file as one block. Returns the result of the
/// last write.
fn flush_block(st: &mut State) -> bool {
    let fql = &mut st.fql;
    let used = fql.write_position;
    let block = &mut fql.write_buffer;
    store32(block, 0, used);
    store32(block, 4, 0);
    let checksum = checksum16(&block[..used as usize], CHECKSUM_SEED) as u32;
    store32(block, 4, checksum);

    let Some(mut file) = fql.write_file.as_ref() else {
        return false;
    };
    let start = file.stream_position().unwrap_or(0);
    let mut total = 0u32;
    let mut ok = platform::write(file, &total.to_le_bytes()); // patched below

    // LzssCompress looks at the bytes after each chunk, like the original.
    let mut chunk = Vec::new();
    let mut write_chunk = |offset: u32, size: u32| {
        let packed = lzss::compress(&block[offset as usize..], size as usize, &mut chunk) as u32;
        platform::write(file, &packed.to_le_bytes());
        ok = platform::write(file, &chunk);
        total += 4 + packed;
    };
    let chunks = used / CHUNK_SIZE;
    let rest = used - chunks * CHUNK_SIZE;
    let mut offset = 0;
    for _ in 0..chunks {
        write_chunk(offset, CHUNK_SIZE);
        offset += CHUNK_SIZE;
    }
    if rest != 0 {
        write_chunk(offset, rest);
    }

    let _ = file.seek(SeekFrom::Start(start));
    ok = platform::write(file, &total.to_le_bytes());
    let _ = file.seek(SeekFrom::End(0));
    fql.write_total = fql.write_total.wrapping_add(4 + total);
    fql.write_position = HEADER_SIZE;
    ok
}

/// Reads and decompresses the next block. Errors are reported but the block is used anyway.
fn read_block(st: &mut State) -> bool {
    let mut ok = true;
    let Some(file) = st.fql.read_file.take() else {
        return false;
    };

    let mut stored = [0u8; 4];
    let read = match platform::read(&file, &mut stored) {
        Ok(n) => n,
        Err(_) => {
            ok = false;
            report_fql_error(st, DTA_ERROR_READ);
            0
        }
    };
    if read != 4 {
        ok = false;
        report_fql_error(st, DTA_ERROR_SIZE);
    }
    let stored = u32::from_le_bytes(stored);
    // (The original read `stored` bytes whatever the size of the buffer.)
    let wanted = stored.min(Fql::COMPRESSED_BUFFER_SIZE) as usize;
    let mut compressed = std::mem::take(&mut st.fql.compressed_buffer);
    compressed.resize(Fql::COMPRESSED_BUFFER_SIZE as usize, 0);
    let read = match platform::read(&file, &mut compressed[..wanted]) {
        Ok(n) => n,
        Err(_) => {
            ok = false;
            report_fql_error(st, DTA_ERROR_READ);
            0
        }
    };
    if read as u32 != stored {
        ok = false;
        report_fql_error(st, DTA_ERROR_SIZE);
    }
    st.fql.read_file = Some(file);

    let fql = &mut st.fql;
    fql.read_buffer.resize((BLOCK_SIZE + 0x10000) as usize, 0);
    let block = &mut fql.read_buffer;
    let mut out = 0usize;
    let mut i = 0usize;
    while i < wanted {
        // (Bounds checks on corrupt data are additions of the port.)
        if i + 4 > wanted || out > BLOCK_SIZE as usize {
            break;
        }
        let length = load32(&compressed, i) as usize;
        i += 4;
        if length == 0 || length > wanted - i {
            break;
        }
        let chunk = &compressed[i..i + length];
        if chunk[0] == 1 {
            out += lzss::decompress(chunk, &mut block[out..]);
        } else {
            let size = (length - 1).min(block.len() - out);
            block[out..out + size].copy_from_slice(&chunk[1..1 + size]);
            out += size;
        }
        i += length;
    }
    fql.compressed_buffer = compressed;

    fql.read_size = load32(block, 0) as i32;
    let checksum = load32(block, 4);
    store32(block, 4, 0);
    let used = (fql.read_size as u32).min(BLOCK_SIZE) as usize;
    let mismatch = checksum != checksum16(&block[..used], CHECKSUM_SEED) as u32;
    fql.read_position = HEADER_SIZE as i32;
    if mismatch {
        // (The original called the callback without checking it for null.)
        report_fql_error(st, DTA_ERROR_CHECKSUM);
    }
    ok
}

/// Bytes left in the current playback block (never past the buffer).
fn available(fql: &Fql) -> usize {
    let end = (fql.read_size.max(0) as usize).min(fql.read_buffer.len());
    end.saturating_sub(fql.read_position.max(0) as usize)
}

/// Plays back one record into `data`, which must have the recorded size.
pub fn read(st: &mut State, data: &mut [u8]) -> bool {
    let size = data.len();
    let mut ok = true;
    if st.fql.read_size.wrapping_sub(st.fql.read_position) < 1 {
        ok = read_block(st);
    }
    let fql = &mut st.fql;
    let recorded = load32(&fql.read_buffer, fql.read_position.max(0) as usize);
    fql.read_position = fql.read_position.wrapping_add(4);
    // The playback must ask for exactly what was recorded ("temp==buff_size", rw_data.cpp
    // line 306; an assert of the debug build).
    debug_assert_eq!(recorded as usize, size, "temp==buff_size");

    let avail = available(fql);
    let pos = fql.read_position.max(0) as usize;
    if size <= avail {
        data.copy_from_slice(&fql.read_buffer[pos..pos + size]);
        fql.read_position += size as i32;
        return ok;
    }

    data[..avail].copy_from_slice(&fql.read_buffer[pos..pos + avail]);
    let mut done = avail;
    let mut left = size - avail;
    while left != 0 {
        ok = read_block(st);
        let fql = &mut st.fql;
        let avail = available(fql);
        let pos = fql.read_position as usize;
        if avail == 0 {
            // (The original looped forever at the end of the file; zeros stand for the rest.)
            data[done..].fill(0);
            break;
        }
        if avail < left {
            data[done..done + avail].copy_from_slice(&fql.read_buffer[pos..pos + avail]);
            done += avail;
            left -= avail;
        } else {
            data[done..].copy_from_slice(&fql.read_buffer[pos..pos + left]);
            fql.read_position += left as i32;
            left = 0;
        }
    }
    ok
}

/// Records `data` as one record.
pub fn write(st: &mut State, data: &[u8]) -> bool {
    let size = data.len() as u32;
    let mut ok = true;
    // The record's size never straddles two blocks.
    if BLOCK_SIZE - st.fql.write_position < 4 {
        ok = flush_block(st);
    }
    let pos = st.fql.write_position as usize;
    store32(&mut st.fql.write_buffer, pos, size);
    st.fql.write_position += 4;

    let room = BLOCK_SIZE - st.fql.write_position;
    let put = |st: &mut State, from: u32, n: u32| {
        let pos = st.fql.write_position as usize;
        st.fql.write_buffer[pos..pos + n as usize]
            .copy_from_slice(&data[from as usize..(from + n) as usize]);
        st.fql.write_position += n;
    };
    if size <= room {
        put(st, 0, size);
        return ok;
    }

    put(st, 0, room);
    ok = flush_block(st);
    let mut done = room;
    let mut left = size - room;
    for _ in 0..left / BLOCK_PAYLOAD {
        put(st, done, BLOCK_PAYLOAD);
        done += BLOCK_PAYLOAD;
        ok = flush_block(st);
    }
    left %= BLOCK_PAYLOAD;
    if left != 0 {
        put(st, done, left);
    }
    ok
}

pub fn is_extension_filtered(st: &State, file_name: &[u8]) -> bool {
    st.fql_extension_filter
        .contains(&pack_extension(c_str(file_name)))
}

/// Marks an open file as recorded / played back (`file_name` is upper case).
pub fn record_open(st: &mut State, handle: i32, file_name: &[u8]) {
    if is_extension_filtered(st, file_name) {
        return;
    }
    if !st.fql_handles.contains(&handle) {
        st.fql_handles.push(handle);
    }
}

fn free_read_buffers(fql: &mut Fql) {
    fql.read_buffer = Vec::new();
    fql.compressed_buffer = Vec::new();
}

/// dtaFQLBegin: starts playing back an FQL file: archive reads come from it instead of the
/// archives. (Unlike the other functions, the original did not take the lock here.)
pub fn begin(file_name: Option<&[u8]>) -> bool {
    with_state(|st| {
        let Some(file_name) = file_name else {
            return false;
        };
        if st.fql.read_file.is_some() {
            return false;
        }
        // (The original strcpy'd the name into a 260-byte buffer.)
        st.fql.file_name = file_name[..file_name.len().min(259)].to_vec();
        st.fql.read_position = 0;
        st.fql.read_size = 0;

        let file = match platform::open_read(file_name, false) {
            Ok(f) => f,
            Err(_) => {
                st.report(ptr::null_mut(), file_name, DTA_ERROR_OPEN);
                return false;
            }
        };
        // Slack after the block: the decoder of a corrupt chunk may run past 128 KB.
        st.fql.read_buffer = vec![0u8; (BLOCK_SIZE + 0x10000) as usize];
        st.fql.compressed_buffer = vec![0u8; Fql::COMPRESSED_BUFFER_SIZE as usize];

        // The error callbacks below were not checked for null in the original.
        let fail = |st: &mut State, error: i32| {
            st.report(ptr::null_mut(), file_name, error);
            st.fql.read_file = None;
            free_read_buffers(&mut st.fql);
            false
        };
        let file_size = platform::seek_end(&file).unwrap_or(u32::MAX);
        platform::seek(&file, 0);
        let mut total = [0u8; 4];
        match platform::read(&file, &mut total) {
            Err(_) => return fail(st, DTA_ERROR_READ),
            Ok(n) if n != 4 => return fail(st, DTA_ERROR_SIZE),
            Ok(_) => {}
        }
        let mut checksum = [0u8; 2];
        match platform::read(&file, &mut checksum) {
            Err(_) => return fail(st, DTA_ERROR_READ),
            Ok(n) if n != 2 => return fail(st, DTA_ERROR_SIZE),
            Ok(_) => {}
        }
        if checksum16(&total, CHECKSUM_SEED) != u16::from_le_bytes(checksum) {
            st.report(ptr::null_mut(), file_name, DTA_ERROR_CHECKSUM);
        }
        if u32::from_le_bytes(total) != file_size {
            st.report(ptr::null_mut(), file_name, DTA_ERROR_SIZE);
        }
        st.fql.read_file = Some(file);
        true
    })
}

/// dtaFQLEnd
pub fn end() {
    with_state(|st| {
        st.fql.read_file = None;
        st.fql_handles.clear();
        free_read_buffers(&mut st.fql);
        st.fql.read_position = 0;
        st.fql.read_size = 0;
    })
}

/// dtaCreateFQL: starts recording into a new FQL file.
pub fn create(file_name: &[u8]) -> bool {
    with_state(|st| {
        if st.fql.write_file.is_some() {
            return false;
        }
        st.fql.write_total = 0;
        st.fql.write_position = HEADER_SIZE;
        let Ok(file) = platform::open_write(file_name, true, false) else {
            return false;
        };
        // Two bytes of slack: the compressor reads past the end of the data it compresses.
        st.fql.write_buffer = vec![0u8; (BLOCK_SIZE + 2) as usize];
        // Room for the header (the size and its checksum), written by dtaCloseFQL.
        if platform::write(&file, &[0u8; 6]) {
            st.fql.write_total = 6;
        }
        st.fql.write_file = Some(file);
        true
    })
}

/// dtaCloseFQL: finishes the recording.
pub fn close() {
    with_state(|st| {
        if st.fql.write_file.is_none() {
            return;
        }
        if st.fql.write_position != HEADER_SIZE {
            flush_block(st);
        }
        if let Some(file) = st.fql.write_file.take() {
            let total = st.fql.write_total.to_le_bytes();
            platform::seek(&file, 0);
            platform::write(&file, &total);
            platform::write(&file, &checksum16(&total, CHECKSUM_SEED).to_le_bytes());
        }
        st.fql_handles.clear();
        st.fql.write_buffer = Vec::new();
        st.fql.write_position = HEADER_SIZE;
    })
}

/// dtaAddFQLExtensionFilter: files with these extensions are not recorded.
pub fn add_extension_filter(ext: Option<&[u8]>) -> bool {
    with_state(|st| {
        let Some(packed) = ext.and_then(pack_extension_argument) else {
            return false;
        };
        if !st.fql_extension_filter.contains(&packed) {
            st.fql_extension_filter.push(packed);
        }
        true
    })
}

/// dtaClearFQLExtensionFilter
pub fn clear_extension_filter() {
    with_state(|st| st.fql_extension_filter.clear())
}
