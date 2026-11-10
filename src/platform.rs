//! The operating-system side, on the standard library only.
//!
//! The original called the Win32 API directly; this module maps each call onto `std`:
//!
//! | original                         | here                                              |
//! |----------------------------------|---------------------------------------------------|
//! | CreateFileA / CloseHandle        | `std::fs::OpenOptions` / dropping the `File`      |
//! | ReadFile / WriteFile             | `std::io::Read` / `Write` on `&File`              |
//! | SetFilePointer                   | `std::io::Seek`                                   |
//! | FlushFileBuffers                 | `File::sync_all`                                  |
//! | GetFileTime (last write)         | `Metadata::modified`, converted to a FILETIME     |
//! | DeleteFileA / MoveFileA / CopyFileA | `fs::remove_file` / `fs::rename` / `fs::copy`  |
//! | Get/SetFileAttributesA (read-only) | `fs::metadata` / `fs::set_permissions`          |
//! | CRITICAL_SECTION                 | `std::sync::Mutex` + `Condvar` (see state.rs)     |
//! | MessageBoxA (leak report)        | standard error                                    |
//!
//! On Windows the sharing modes and attributes of the original (exclusive writes, hidden
//! files, ...) are kept through `std::os::windows::fs::OpenOptionsExt`, which is part of the
//! standard library; on other systems they have no equivalent and are left out.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(windows)]
mod win {
    pub const FILE_SHARE_READ: u32 = 0x1;
    pub const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
    pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    pub const FILE_FLAG_RANDOM_ACCESS: u32 = 0x1000_0000;
}

/// Converts a file name from the C interface into a path.
///
/// The names are byte strings in the system's narrow encoding. On Unix they are used as they
/// are, with the game's `\` separators turned into `/`. On Windows they are read as UTF-8,
/// and bytes that are not valid UTF-8 as Latin-1 (the ANSI code page cannot be queried
/// without the Win32 API; plain ASCII names, which is what the game uses, are unaffected).
pub fn to_path(name: &[u8]) -> PathBuf {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let converted: Vec<u8> = name
            .iter()
            .map(|&b| if b == b'\\' { b'/' } else { b })
            .collect();
        PathBuf::from(std::ffi::OsStr::from_bytes(&converted))
    }
    #[cfg(not(unix))]
    {
        match std::str::from_utf8(name) {
            Ok(s) => PathBuf::from(s),
            Err(_) => PathBuf::from(name.iter().map(|&b| b as char).collect::<String>()),
        }
    }
}

/// CreateFileA(GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING).
pub fn open_read(name: &[u8], random_access: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(win::FILE_SHARE_READ);
        if random_access {
            options.custom_flags(win::FILE_FLAG_RANDOM_ACCESS);
        }
    }
    #[cfg(not(windows))]
    let _ = random_access;
    options.open(to_path(name))
}

/// CreateFileA(GENERIC_WRITE, no sharing, CREATE_ALWAYS or OPEN_ALWAYS).
pub fn open_write(name: &[u8], truncate: bool, hidden: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(truncate);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(0);
        options.attributes(if hidden {
            win::FILE_ATTRIBUTE_HIDDEN
        } else {
            win::FILE_ATTRIBUTE_NORMAL
        });
    }
    #[cfg(not(windows))]
    let _ = hidden;
    options.open(to_path(name))
}

/// ReadFile: reads until `buf` is full or the file ends; the byte count.
pub fn read(mut file: &File, buf: &mut [u8]) -> io::Result<usize> {
    let mut done = 0;
    while done < buf.len() {
        match file.read(&mut buf[done..]) {
            Ok(0) => break,
            Ok(n) => done += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(done)
}

/// Reads exactly `buf.len()` bytes; false on an error or a short read.
pub fn read_exact(file: &File, buf: &mut [u8]) -> bool {
    matches!(read(file, buf), Ok(n) if n == buf.len())
}

/// WriteFile of the whole buffer.
pub fn write(mut file: &File, buf: &[u8]) -> bool {
    file.write_all(buf).is_ok()
}

/// SetFilePointer(FILE_BEGIN).
pub fn seek(mut file: &File, offset: u32) -> bool {
    file.seek(SeekFrom::Start(offset as u64)).is_ok()
}

/// SetFilePointer with a signed 32-bit distance; the new position (low 32 bits, like the
/// original's DWORD) or None.
pub fn seek_from(mut file: &File, distance: i32, origin: i32) -> Option<u32> {
    let from = match origin {
        0 => {
            if distance < 0 {
                return None;
            }
            SeekFrom::Start(distance as u64)
        }
        1 => SeekFrom::Current(distance as i64),
        _ => SeekFrom::End(distance as i64),
    };
    file.seek(from).ok().map(|p| p as u32)
}

/// The size of a file (low 32 bits, like SetFilePointer(FILE_END)); leaves the file
/// pointer at the end, like the original.
pub fn seek_end(mut file: &File) -> io::Result<u32> {
    file.seek(SeekFrom::End(0)).map(|p| p as u32)
}

/// FILETIME of a system time: 100-nanosecond intervals since 1601-01-01 (UTC).
pub fn file_time(time: SystemTime) -> u64 {
    const UNIX_EPOCH_AS_FILETIME: i128 = 116_444_736_000_000_000;
    let intervals: i128 = match time.duration_since(UNIX_EPOCH) {
        Ok(after) => after.as_nanos() as i128 / 100,
        Err(before) => -(before.duration().as_nanos() as i128 / 100),
    };
    (intervals + UNIX_EPOCH_AS_FILETIME).clamp(0, u64::MAX as i128) as u64
}

/// GetFileTime: the last-write time of an open file.
pub fn last_write_time(file: &File) -> Option<u64> {
    file.metadata()
        .and_then(|m| m.modified())
        .ok()
        .map(file_time)
}

pub fn delete(name: &[u8]) -> bool {
    fs::remove_file(to_path(name)).is_ok()
}

pub fn exists(name: &[u8]) -> bool {
    fs::symlink_metadata(to_path(name)).is_ok()
}

/// MoveFileA: fails when the target exists.
pub fn rename(from: &[u8], to: &[u8]) -> bool {
    if exists(to) {
        return false;
    }
    fs::rename(to_path(from), to_path(to)).is_ok()
}

/// CopyFileA(bFailIfExists = FALSE).
pub fn copy(from: &[u8], to: &[u8]) -> bool {
    fs::copy(to_path(from), to_path(to)).is_ok()
}

/// Clears the read-only attribute (on Unix: gives the owner write permission). False when
/// the file's attributes cannot be read.
pub fn clear_read_only(name: &[u8]) -> bool {
    let path = to_path(name);
    let Ok(metadata) = fs::metadata(&path) else {
        return false;
    };
    let mut permissions = metadata.permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(permissions.mode() | 0o200);
    }
    #[cfg(not(unix))]
    #[allow(clippy::permissions_set_readonly_false)] // Windows: clears FILE_ATTRIBUTE_READONLY
    permissions.set_readonly(false);
    let _ = fs::set_permissions(&path, permissions);
    true
}

/// The value of an invalid handle (INVALID_HANDLE_VALUE / -1).
pub const INVALID_RAW_HANDLE: *mut std::ffi::c_void = -1isize as *mut std::ffi::c_void;

/// Gives up ownership of a file and returns its OS handle (a HANDLE on Windows, a file
/// descriptor elsewhere), as dtaGetPackDirectAccess returns it.
pub fn into_raw_handle(file: File) -> *mut std::ffi::c_void {
    #[cfg(windows)]
    {
        use std::os::windows::io::IntoRawHandle;
        file.into_raw_handle()
    }
    #[cfg(unix)]
    {
        use std::os::unix::io::IntoRawFd;
        file.into_raw_fd() as isize as *mut std::ffi::c_void
    }
    #[cfg(not(any(windows, unix)))]
    {
        drop(file);
        INVALID_RAW_HANDLE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn file_time_epoch() {
        assert_eq!(file_time(UNIX_EPOCH), 116_444_736_000_000_000);
        assert_eq!(
            file_time(UNIX_EPOCH + Duration::from_secs(1)),
            116_444_736_010_000_000
        );
    }
}
