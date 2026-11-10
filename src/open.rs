//! Opening and closing files: the archive lookup, disk files, dtaOpen / dtaClose.

use std::ffi::c_void;
use std::ptr;
use std::sync::Arc;

use crate::archive::find_archive_table;
use crate::crypt::{checksum16, decrypt};
use crate::state::*;
use crate::{filelog, fql, platform};

/// OpenEntry results besides a handle.
const ENTRY_NO_MATCH: i32 = -2; // another file with the same hash: try the next entry
const ENTRY_ERROR: i32 = -1; // stop the lookup

/// First index of the entries with this hash in an archive's (sorted) table, or -1.
fn archive_find_entry(entries: &[FileEntry], hash: u32) -> i32 {
    let count = entries.len() as i32;
    if count < 1 {
        return -1;
    }

    // The original compares the hashes through their signed difference.
    let compare = |index: i32| hash.wrapping_sub(entries[index as usize].hash) as i32;
    let mut low = 0;
    let mut high = count - 1;
    let mut middle = count / 2;
    loop {
        let difference = compare(middle);
        if difference == 0 {
            break;
        }
        if difference > 0 {
            low = middle + 1;
        } else {
            high = middle - 1;
        }
        if high < low {
            return -1;
        }
        middle = (high - low) / 2 + low;
    }
    while middle >= 1 && entries[middle as usize - 1].hash == hash {
        middle -= 1;
    }
    middle
}

/// Reports an error of the archive in a search slot (or of the FQL file during playback).
fn report_slot_error(st: &mut State, slot: usize, error: i32) {
    if st.error_callback.is_none() {
        return;
    }
    if st.fql.read_file.is_none() {
        let Some(s) = st.search_order.get(slot) else {
            return;
        };
        let archive = s.archive;
        // SAFETY: archives in the search order are alive.
        let name = unsafe { (*archive).name_bytes().to_vec() };
        st.report(archive, &name, error);
    } else {
        let name = st.fql.file_name.clone();
        st.report(ptr::null_mut(), &name, error);
    }
}

/// Calls the error callback for an error in an archived file.
pub fn report_archive_error(st: &mut State, archive: u32, error: i32) {
    if st.error_callback.is_none() {
        return;
    }
    let slot = st.search_order.iter().rposition(|s| {
        st.archive_tables
            .get(s.table as usize)
            .is_some_and(|t| t.id == archive)
    });
    if let Some(slot) = slot {
        report_slot_error(st, slot, error);
    }
}

/// Reads from the archive, or from the FQL file during playback when the file is recorded.
/// The byte count, or Err when the read fails.
fn read_archive_data(
    st: &mut State,
    file: &std::fs::File,
    data: &mut [u8],
    recorded: bool,
) -> Result<usize, ()> {
    if recorded && st.fql.read_file.is_some() {
        fql::read(st, data);
        return Ok(data.len());
    }
    platform::read(file, data).map_err(|_| ())
}

fn record_archive_data(st: &mut State, data: &[u8], recorded: bool) {
    if recorded && st.fql.write_file.is_some() {
        fql::write(st, data);
    }
}

/// Opens the file of one table entry if its full name matches.
fn open_entry(
    st: &mut State,
    slot: usize,
    table: usize,
    entry: &FileEntry,
    upper_name: &[u8],
    recorded: bool,
) -> i32 {
    let file = st.archive_tables[table].file.clone();
    let key = st.archive_tables[table].key;
    let version = st.archive_tables[table].version;
    let archive_id = st.archive_tables[table].id;

    // The table holds the last 16 characters of the name.
    let name_length = (entry.hash >> 16) as u16 as usize;
    let tail_offset = name_length.saturating_sub(16);
    if strncmp(
        &entry.name_tail,
        upper_name.get(tail_offset..).unwrap_or(&[]),
        16,
    ) != 0
    {
        return ENTRY_NO_MATCH;
    }

    if !platform::seek(&file, entry.header_offset) {
        return ENTRY_ERROR;
    }

    // Header (0x20 bytes): u32 ?, u32 ?, FILETIME, size, block count, then
    // ISD0: u16 name length at +0x18; ISD1: +0x18 header checksum (of the header with it
    // zeroed), +0x1C name length, +0x1E checksum of the name and the block tables.
    // ISD0 archives are never played back from an FQL file.
    let mut header = [0u8; 0x20];
    let mut name_field = 0u16;
    let mut tables_checksum = 0u16;
    if version == 0 {
        if !platform::read_exact(&file, &mut header) {
            return ENTRY_ERROR;
        }
        decrypt(&mut header, key);
        name_field = le16(&header, 0x18);
    } else if version == 1 {
        match read_archive_data(st, &file, &mut header, recorded) {
            Err(()) => {
                report_slot_error(st, slot, DTA_ERROR_READ);
                return ENTRY_ERROR;
            }
            Ok(n) if n != header.len() => {
                report_slot_error(st, slot, DTA_ERROR_SIZE);
                return ENTRY_ERROR;
            }
            Ok(_) => {}
        }
        record_archive_data(st, &header, recorded);
        decrypt(&mut header, key);
        name_field = le16(&header, 0x1C);
        tables_checksum = le16(&header, 0x1E);
        if st.error_callback.is_some() {
            let stored = le32(&header, 0x18);
            header[0x18..0x1C].fill(0);
            if stored != checksum16(&header, CHECKSUM_SEED) as u32 {
                report_slot_error(st, slot, DTA_ERROR_CHECKSUM);
            }
        }
    }

    // Full name. The original read it into a 264-byte stack buffer whatever its length.
    let name_size = (name_field & 0x7FFF) as usize;
    let mut name = vec![0u8; name_size + 1];
    let read;
    if version == 1 {
        read = match read_archive_data(st, &file, &mut name[..name_size], recorded) {
            Ok(n) => n,
            Err(()) => {
                report_slot_error(st, slot, DTA_ERROR_READ);
                return ENTRY_ERROR;
            }
        };
        record_archive_data(st, &name[..read], recorded);
    } else {
        read = match platform::read(&file, &mut name[..name_size]) {
            Ok(n) => n,
            Err(_) => return ENTRY_ERROR,
        };
    }
    if read != name_size {
        report_slot_error(st, slot, DTA_ERROR_SIZE);
        return ENTRY_ERROR;
    }
    decrypt(&mut name[..name_size], key);
    let mut checksum = 0u16;
    if version != 0 && st.error_callback.is_some() {
        checksum = checksum16(&name[..name_size], CHECKSUM_SEED);
    }
    name[read] = 0;
    upper_case(&mut name);
    if c_str(upper_name) != c_str(&name) {
        return ENTRY_NO_MATCH;
    }

    let size = le32(&header, 0x10);
    let mut open = OpenFile {
        file: Some(file.clone()),
        archive: archive_id,
        flags: 0,
        time: u64::from(le32(&header, 8)) | u64::from(le32(&header, 12)) << 32,
        size,
        data_offset: entry.data_offset,
        block_count: le32(&header, 0x14),
        key,
        blocks_encrypted: name_field & DTA_NAME_ENCRYPTED_BLOCKS != 0,
        ..OpenFile::default()
    };
    open.cursor.buffer_size = size.min(DTA_BLOCK_SIZE);
    let mut info = BlockInfo::default();

    if version == 0 {
        // The first block's header: its stored size in the low 16 bits.
        let mut block_header = [0u8; 4];
        if !platform::read_exact(&file, &mut block_header) {
            return ENTRY_ERROR;
        }
        open.cursor.block_size = u32::from_le_bytes(block_header) & 0xFFFF;
    } else if version == 1 {
        // Block tables: u32 per block (size | checksum << 16), then a type byte per block.
        let block_count = open.block_count as usize;
        let sizes_bytes = (open.block_count.wrapping_mul(4)) as usize;
        // (A damaged header gives any count; the original then failed to allocate and crashed.)
        let mut sizes: Vec<u8> = Vec::new();
        if sizes
            .try_reserve_exact(sizes_bytes.max(block_count))
            .is_err()
        {
            report_slot_error(st, slot, DTA_ERROR_MEMORY);
            return ENTRY_ERROR;
        }
        sizes.resize(sizes_bytes, 0);
        let read = match read_archive_data(st, &file, &mut sizes, recorded) {
            Ok(n) => n,
            Err(()) => {
                report_slot_error(st, slot, DTA_ERROR_READ);
                return ENTRY_ERROR;
            }
        };
        record_archive_data(st, &sizes[..read], recorded);
        if read != sizes_bytes {
            report_slot_error(st, slot, DTA_ERROR_SIZE); // (unchecked callback in the original)
            return ENTRY_ERROR;
        }
        if st.error_callback.is_some() {
            checksum = checksum16(&sizes, checksum);
        }
        info.block_tables = true;
        info.block_sizes = sizes.chunks_exact(4).map(|c| le16(c, 0)).collect();
        info.block_checksums = sizes.chunks_exact(4).map(|c| le16(c, 2)).collect();
        // (The original read the first size of an empty table too.)
        open.cursor.block_size = info.block_sizes.first().map_or(0, |&s| s as u32);

        info.block_types = vec![0u8; block_count];
        let read = match read_archive_data(st, &file, &mut info.block_types, recorded) {
            Ok(n) => n,
            Err(()) => {
                report_slot_error(st, slot, DTA_ERROR_READ);
                return ENTRY_ERROR;
            }
        };
        record_archive_data(st, &info.block_types[..read], recorded);
        if read != block_count {
            report_slot_error(st, slot, DTA_ERROR_SIZE); // (unchecked callback in the original)
            return ENTRY_ERROR;
        }
        if st.error_callback.is_some() && tables_checksum != checksum16(&info.block_types, checksum)
        {
            report_slot_error(st, slot, DTA_ERROR_CHECKSUM);
        }
        decrypt(&mut info.block_types, key);
    }

    // Type of the first block; compressed WAV files keep their RIFF header.
    let mut block = [0u8; 1 + DTA_WAV_HEADER_SIZE as usize];
    if version == 0 {
        if !platform::read_exact(&file, &mut block[..1]) {
            return ENTRY_ERROR;
        }
        if open.blocks_encrypted {
            decrypt(&mut block[..1], key);
        }
    } else {
        block[0] = info.block_types.first().copied().unwrap_or(0);
    }
    if block[0] > 7 {
        let read = match read_archive_data(st, &file, &mut block[1..], recorded) {
            Ok(n) => n,
            Err(()) => {
                report_slot_error(st, slot, DTA_ERROR_READ);
                return ENTRY_ERROR;
            }
        };
        record_archive_data(st, &block[1..1 + read], recorded);
        if read != DTA_WAV_HEADER_SIZE as usize {
            report_slot_error(st, slot, DTA_ERROR_SIZE); // (unchecked callback in the original)
            return ENTRY_ERROR;
        }
        if version == 0 && open.blocks_encrypted {
            decrypt(&mut block, key); // encrypted together with the type byte
        } else {
            decrypt(&mut block[1..], key);
        }
        info.wav_header = block[1..].to_vec();
    }

    open.info = Arc::new(info);
    open.buffer = vec![0u8; DTA_BLOCK_SIZE as usize];
    store_open_file(st, open)
}

/// Puts an open file in the first free slot (or a new one); returns its handle.
pub fn store_open_file(st: &mut State, file: OpenFile) -> i32 {
    if let Some(handle) = st.open_files.iter().position(OpenFile::is_free) {
        st.open_files[handle] = file;
        return handle as i32;
    }
    st.open_files.push(file);
    st.open_files.len() as i32 - 1
}

/// Upper-case copy of a name and its hash: (length << 16) | 16-bit sum of its bytes.
fn name_hash(file_name: &[u8]) -> (Vec<u8>, u32) {
    let mut upper = file_name.to_vec();
    upper_case(&mut upper);
    let length = upper.len() as u32;
    let sum = upper
        .iter()
        .rev()
        .fold(0u16, |s, &b| s.wrapping_add(b as u16));
    (upper, length.wrapping_shl(16) | sum as u32)
}

pub fn open_from_archives(st: &mut State, file_name: &[u8]) -> i32 {
    let (upper_name, hash) = name_hash(file_name);

    let recorded = st.fql.active() && !fql::is_extension_filtered(st, &upper_name);

    let slot_count = st.search_order.len();
    for slot in 0..slot_count {
        let table = st.search_order[slot].table as usize;
        let Some(t) = st.archive_tables.get(table) else {
            continue;
        };
        let entry_count = t.entries.len();
        let first = archive_find_entry(&t.entries, hash);
        if first == -1 {
            continue;
        }
        for index in first as usize..entry_count {
            let entry = st.archive_tables[table].entries[index];
            if entry.hash != hash {
                break;
            }
            let handle = open_entry(st, slot, table, &entry, &upper_name, recorded);
            if handle == ENTRY_NO_MATCH {
                continue;
            }
            return handle; // a handle or an error (-1)
        }
    }
    -1
}

pub fn open_from_disk(st: &mut State, file_name: &[u8]) -> i32 {
    let Ok(file) = platform::open_read(file_name, false) else {
        return -1;
    };
    let Ok(size) = platform::seek_end(&file) else {
        return -1;
    };

    let mut open = OpenFile {
        file: Some(Arc::new(file)),
        flags: DTA_FILE_DISK,
        size,
        block_count: 1,
        buffer: vec![0u8; DTA_BLOCK_SIZE as usize],
        ..OpenFile::default()
    };
    open.cursor.buffer_size = size.min(DTA_BLOCK_SIZE);
    store_open_file(st, open)
}

/// dtaOpen
pub fn open(file_name: &[u8], archives_first: bool) -> i32 {
    with_state(|st| {
        let handle = if !archives_first && !st.prefer_archives {
            match open_from_disk(st, file_name) {
                -1 => open_from_archives(st, file_name),
                h => h,
            }
        } else {
            match open_from_archives(st, file_name) {
                -1 => open_from_disk(st, file_name),
                h => h,
            }
        };

        if handle >= 0 {
            let mut upper_name = file_name.to_vec();
            upper_case(&mut upper_name);
            if st.fql.active() {
                fql::record_open(st, handle, &upper_name);
            }
            filelog::record(st, &upper_name);
        }
        handle
    })
}

/// dtaClose
pub fn close(st: &mut State, handle: i32) -> bool {
    if handle as u32 as usize >= st.open_files.len() {
        return false;
    }
    let h = handle as usize;
    if st.open_files[h].is_free() {
        return true;
    }

    if st.fql.active() {
        let mut i = st.fql_handles.len();
        while i > 0 {
            i -= 1;
            if st.fql_handles[i] == handle {
                st.fql_handles.swap_remove(i);
            }
        }
    }

    let file = std::mem::take(&mut st.open_files[h]);
    if file.flags & DTA_FILE_DISK != 0 {
        drop(file.file); // closes it
        if file.flags & DTA_FILE_TEMP != 0 {
            let temp = &file.temp_file_name;
            if file.flags & DTA_FILE_WRITE_ERROR == 0 {
                // Replace the target ("<name>.tmp" without ".tmp") by the temporary file.
                let target = &temp[..temp.len() - 4];
                if !platform::delete(target) && platform::clear_read_only(target) {
                    platform::delete(target);
                }
                platform::rename(temp, target);
            } else {
                platform::delete(temp);
            }
        }
    }
    true
}

/// dtaGetPackDirectAccess: opens the .dta containing `file_name` for direct access and stores
/// the offset of the file's data in it; for a file that is not in an archive, opens the file
/// itself (offset 0). Returns the OS handle (a file descriptor on Unix) or -1.
///
/// # Safety
/// `offset` must be null or valid for a write.
pub unsafe fn get_pack_direct_access(file_name: Option<&[u8]>, offset: *mut i32) -> *mut c_void {
    let (result, handle) = with_state(|st| {
        let mut result = platform::INVALID_RAW_HANDLE;
        let mut handle = -1;
        if let (Some(file_name), false) = (file_name, offset.is_null()) {
            // Look the file up without recording it.
            let fql_read = st.fql.read_file.take();
            let fql_write = st.fql.write_file.take();
            handle = open_from_archives(st, file_name);
            st.fql.read_file = fql_read;
            st.fql.write_file = fql_write;

            if handle < 0 {
                if let Ok(f) = platform::open_read(file_name, true) {
                    result = platform::into_raw_handle(f);
                }
                *offset = 0;
            } else {
                let open = &st.open_files[handle as usize];
                *offset = open.data_offset as i32;
                let table = find_archive_table(st, open.archive);
                if table >= 0 {
                    let name = st.archive_tables[table as usize].file_name.clone();
                    if let Ok(f) = platform::open_read(&name, true) {
                        result = platform::into_raw_handle(f);
                    }
                }
            }
        }
        (result, handle)
    });
    // Quirk kept from the original: the test is != 0, so a lookup that got handle 0 leaves
    // that file open.
    if handle != 0 {
        with_state(|st| close(st, handle));
    }
    result
}
