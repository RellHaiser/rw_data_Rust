//! Writing files: dtaOpenWrite, dtaWrite, dtaFlush, and dtaBin2Text.

use std::sync::Arc;

use crate::open::store_open_file;
use crate::platform;
use crate::state::*;

/// dtaOpenWrite flags.
pub const DTA_WRITE_HIDDEN: i32 = 0x1; // create the file hidden (Windows)
pub const DTA_WRITE_TEMP_FILE: i32 = 0x100; // write "<name>.tmp"; dtaClose renames it over <name>
pub const DTA_WRITE_CREATE_ALWAYS: i32 = 0x10000; // truncate instead of opening as it is
pub const DTA_WRITE_CLEAR_READONLY: i32 = 0x100000; // on failure, clear read-only and retry

/// dtaOpenWrite: opens a file on disk for writing; -1 on failure.
pub fn open_write(st: &mut State, file_name: &[u8], flags: i32) -> i32 {
    let hidden = flags & DTA_WRITE_HIDDEN != 0;
    let truncate = flags & DTA_WRITE_CREATE_ALWAYS != 0;

    // With DTA_WRITE_TEMP_FILE the data goes to "<name>.tmp", which starts as a copy of the
    // file unless it is recreated. (The original built the name in a 512-byte buffer.)
    let mut temp_name = Vec::new();
    let path: &[u8] = if flags & DTA_WRITE_TEMP_FILE != 0 {
        temp_name = [file_name, b".tmp"].concat();
        if truncate {
            platform::delete(&temp_name);
        } else {
            platform::copy(file_name, &temp_name);
        }
        &temp_name
    } else {
        file_name
    };

    let file = match platform::open_write(path, truncate, hidden) {
        Ok(f) => f,
        Err(_) => {
            if flags & DTA_WRITE_CLEAR_READONLY == 0 || !platform::clear_read_only(path) {
                return -1;
            }
            match platform::open_write(path, truncate, hidden) {
                Ok(f) => f,
                Err(_) => return -1,
            }
        }
    };

    let mut open = OpenFile {
        file: Some(Arc::new(file)),
        flags: DTA_FILE_WRITE | DTA_FILE_DISK,
        block_count: 1,
        buffer: vec![0u8; DTA_BLOCK_SIZE as usize], // allocated by the original too, though unused
        ..OpenFile::default()
    };
    if flags & DTA_WRITE_TEMP_FILE != 0 {
        open.flags |= DTA_FILE_TEMP;
        open.temp_file_name = temp_name;
    }
    open.cursor.buffer_size = DTA_BLOCK_SIZE;
    store_open_file(st, open)
}

/// dtaWrite: `data` is None for a negative size (which fails, as WriteFile did).
pub fn write(st: &mut State, handle: i32, data: Option<&[u8]>) -> i32 {
    let Some(file) = st.open_files.get_mut(handle as u32 as usize) else {
        return -1;
    };
    if file.is_free() || file.flags & DTA_FILE_WRITE == 0 || file.flags & DTA_FILE_DISK == 0 {
        return -1;
    }
    let ok = match (data, &file.file) {
        (Some(data), Some(f)) => platform::write(f, data),
        _ => false,
    };
    if !ok {
        // A failed write keeps the temporary file from replacing the target.
        if file.flags & DTA_FILE_TEMP != 0 {
            file.flags |= DTA_FILE_WRITE_ERROR;
        }
        return -1;
    }
    data.map_or(-1, |d| d.len() as i32)
}

/// dtaFlush
pub fn flush(handle: i32) -> bool {
    with_state(|st| {
        let Some(file) = st.open_files.get(handle as u32 as usize) else {
            return false;
        };
        if file.is_free() || file.flags & DTA_FILE_WRITE == 0 || file.flags & DTA_FILE_DISK == 0 {
            return false;
        }
        file.file.as_ref().is_some_and(|f| f.sync_all().is_ok())
    })
}

/// dtaBin2Text: removes the '\r' characters of a buffer in place (except a trailing one);
/// returns the new size.
pub fn bin2text(buffer: &mut [u8]) -> usize {
    let mut size = buffer.len();
    if size == 0 {
        return 0;
    }
    // Positions of the '\r' characters, from the end; the last character is not checked.
    let positions: Vec<usize> = (0..size - 1)
        .rev()
        .filter(|&i| buffer[i] == b'\r')
        .collect();
    for p in positions {
        buffer.copy_within(p + 1..size, p);
        size -= 1;
    }
    size
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bin2text_keeps_a_trailing_cr() {
        let mut text = *b"a\r\nb\r\n\r";
        let n = bin2text(&mut text);
        assert_eq!(&text[..n], b"a\nb\n\r");
    }
}
