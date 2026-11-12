//! Rust port of `rw_data.dll`, the data-file layer of Hidden & Dangerous 2: the virtual file
//! system over the `.dta` archives (lookup, decryption, LZSS / LZ4 / WAV block
//! decompression), plain file writing, file logs and FQL load recordings.
//!
//! The crate builds into a drop-in replacement of the DLL: the same 26 functions with the
//! same C interface (see `include/rw_data.h`). On 32-bit Windows they are `__stdcall` and
//! exported under the original's decorated names and ordinals (see build.rs), and the archive
//! object keeps the MSVC 6 virtual-table layout (see archive.rs). On other targets the same
//! functions use the platform's C calling convention, so the library also builds as a shared
//! library for Linux or macOS.
//!
//! It depends on the standard library only: the Win32 calls of the original are replaced by
//! their `std` equivalents (see platform.rs).
//!
//! Rust callers can use the same functions directly (they are `pub`); the C strings they take
//! are NUL-terminated byte strings.

#![allow(clippy::missing_safety_doc)]

use std::ffi::{c_char, c_int, c_void, CStr};

mod archive;
mod crypt;
mod filelog;
mod fql;
mod lz4;
mod lzss;
mod mods;
mod open;
mod platform;
mod read;
mod state;
mod wav;
mod wav_tables;
mod write;

pub use archive::{DtaRead, VTable};
pub use state::{
    DTA_ERROR_CHECKSUM, DTA_ERROR_FORMAT, DTA_ERROR_MEMORY, DTA_ERROR_OPEN, DTA_ERROR_READ,
    DTA_ERROR_SIZE,
};
pub use write::{
    DTA_WRITE_CLEAR_READONLY, DTA_WRITE_CREATE_ALWAYS, DTA_WRITE_HIDDEN, DTA_WRITE_TEMP_FILE,
};

/// Codecs and the cipher, for tools and tests.
pub mod codec {
    pub use crate::crypt::{checksum16, decrypt};
    pub mod lzss {
        pub use crate::lzss::{compress, decompress};
    }
    pub mod lz4 {
        pub use crate::lz4::decompress;
    }
}

/// Called for archive errors. `archive` is null for errors that happen while an archive is
/// being opened and for errors of the FQL file (then `file_name` is the FQL file's name).
/// `__cdecl` in the original.
pub type ErrorCallback =
    unsafe extern "C" fn(archive: *mut c_void, file_name: *const c_char, error: c_int);

/// Windows' FILETIME: 100-nanosecond intervals since 1601-01-01 (UTC).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileTime {
    pub low: u32,
    pub high: u32,
}

pub const DTA_INVALID_HANDLE: c_int = -1;

/// The bytes of a C string, None for a null pointer.
unsafe fn bytes<'a>(text: *const c_char) -> Option<&'a [u8]> {
    if text.is_null() {
        None
    } else {
        Some(CStr::from_ptr(text).to_bytes())
    }
}

// Archives ------------------------------------------------------------------------------

/// Mounts an archive and appends it to the search order; null when the file is missing or
/// is not an archive. The archive is unusable until its key is set (XorKey / SetKey).
#[no_mangle]
#[allow(improper_ctypes_definitions)]
pub unsafe extern "system" fn dtaCreate(file_name: *const c_char) -> *mut DtaRead {
    archive::create(bytes(file_name).unwrap_or_default())
}

/// Opens the .dta containing `file_name` for direct access and stores the offset of the
/// file's data in it; for a file that is not in an archive, opens the file itself (offset
/// 0). Returns the OS file handle (a file descriptor outside Windows), -1 on failure; the
/// caller closes it.
#[no_mangle]
pub unsafe extern "system" fn dtaGetPackDirectAccess(
    file_name: *const c_char,
    offset: *mut c_int,
) -> *mut c_void {
    open::get_pack_direct_access(bytes(file_name), offset)
}

/// Installs the error callback; returns the previous one.
#[no_mangle]
pub extern "system" fn dtaSetCallbackERR(callback: Option<ErrorCallback>) -> Option<ErrorCallback> {
    state::with_state(|st| std::mem::replace(&mut st.error_callback, callback))
}

/// (port) The number of mod archives mounted from the Mods folder now (see mods.rs). They
/// are mounted by the host's first dtaCreate and released with its last archive. The export
/// also tells a host that this DLL mounts the mods itself, so the host need not.
#[no_mangle]
pub extern "system" fn dtaModsMounted() -> c_int {
    state::with_state(|st| st.mods.len() as c_int)
}

/// Enables the "Not released ..." report (written to standard error) when the library
/// unloads with archives alive (the mod archives, which the library owns, are left out).
#[no_mangle]
pub extern "system" fn dtaDumpMemoryLeaks(enable: bool) {
    state::LEAK_REPORT.store(enable, std::sync::atomic::Ordering::Relaxed);
}

// Files ---------------------------------------------------------------------------------

/// Opens a file for reading; -1 on failure. The disk is searched before the archives unless
/// `archives_first` (or C_DtaArchive::SetPreferArchives) is set.
#[no_mangle]
pub unsafe extern "system" fn dtaOpen(file_name: *const c_char, archives_first: bool) -> c_int {
    match bytes(file_name) {
        Some(name) => open::open(name, archives_first),
        None => -1,
    }
}

/// Opens a file on disk for writing (DTA_WRITE_* flags); -1 on failure.
#[no_mangle]
pub unsafe extern "system" fn dtaOpenWrite(file_name: *const c_char, flags: c_int) -> c_int {
    match bytes(file_name) {
        Some(name) => state::with_state(|st| write::open_write(st, name, flags)),
        None => -1,
    }
}

#[no_mangle]
pub unsafe extern "system" fn dtaRead(handle: c_int, buffer: *mut c_void, size: c_int) -> c_int {
    read::read(handle, buffer.cast(), size)
}

#[no_mangle]
pub unsafe extern "system" fn dtaWrite(handle: c_int, buffer: *const c_void, size: c_int) -> c_int {
    let data = if buffer.is_null() {
        return -1;
    } else if size < 0 {
        None
    } else {
        Some(std::slice::from_raw_parts(
            buffer.cast::<u8>(),
            size as usize,
        ))
    };
    state::with_state(|st| write::write(st, handle, data))
}

/// origin: 0 = SEEK_SET, 1 = SEEK_CUR, 2 = SEEK_END. Returns the new position or -1.
#[no_mangle]
pub extern "system" fn dtaSeek(handle: c_int, position: c_int, origin: c_int) -> c_int {
    read::seek(handle, position, origin)
}

#[no_mangle]
pub extern "system" fn dtaClose(handle: c_int) -> bool {
    state::with_state(|st| open::close(st, handle))
}

#[no_mangle]
pub extern "system" fn dtaFlush(handle: c_int) -> bool {
    write::flush(handle)
}

/// Last-write time: of the archived file itself, or (`container_time`, and for disk files)
/// of the file on disk.
#[no_mangle]
pub unsafe extern "system" fn dtaGetTime(
    handle: c_int,
    time: *mut FileTime,
    container_time: bool,
) -> bool {
    if time.is_null() {
        return false;
    }
    match read::get_time(handle, container_time) {
        Some(t) => {
            *time = FileTime {
                low: t as u32,
                high: (t >> 32) as u32,
            };
            true
        }
        None => false,
    }
}

#[no_mangle]
pub unsafe extern "system" fn dtaDelete(file_name: *const c_char) -> bool {
    bytes(file_name).is_some_and(platform::delete)
}

/// Removes the '\r' characters of a buffer in place (except a trailing one); returns the new
/// size.
#[no_mangle]
pub unsafe extern "system" fn dtaBin2Text(buffer: *mut c_char, size: c_int) -> c_int {
    // (A negative size made the original run over the whole address space.)
    if buffer.is_null() || size <= 0 {
        return 0;
    }
    let text = std::slice::from_raw_parts_mut(buffer.cast::<u8>(), size as usize);
    write::bin2text(text) as c_int
}

// File logs: text files listing the names opened with dtaOpen ---------------------------

/// Opens a log (dtaOpenWrite flags); returns the log's index or -1.
#[no_mangle]
pub unsafe extern "system" fn dtaOpenFileLog(file_name: *const c_char, flags: c_int) -> c_int {
    match bytes(file_name) {
        Some(name) => filelog::open_file_log(name, flags),
        None => -1,
    }
}

#[no_mangle]
pub extern "system" fn dtaCloseFileLog(log: c_int) -> bool {
    filelog::close_file_log(log)
}

/// A log lists the names starting with one of its directories ...
#[no_mangle]
pub unsafe extern "system" fn dtaAddDir(log: c_int, dir: *const c_char) -> bool {
    filelog::add_dir(log, bytes(dir))
}

/// ... or with one of its extensions (at most 3 characters).
#[no_mangle]
pub unsafe extern "system" fn dtaAddExtension(log: c_int, ext: *const c_char) -> bool {
    filelog::add_extension(log, bytes(ext))
}

/// Prefix written before every name of the log.
#[no_mangle]
pub unsafe extern "system" fn dtaSetPathBeforeLogItems(log: c_int, path: *const c_char) -> bool {
    filelog::set_path_before(log, bytes(path))
}

// FQL: record the archive reads of a load into one file and play them back --------------

/// Starts recording into a new FQL file.
#[no_mangle]
pub unsafe extern "system" fn dtaCreateFQL(file_name: *const c_char) -> bool {
    bytes(file_name).is_some_and(fql::create)
}

/// Finishes the recording.
#[no_mangle]
pub extern "system" fn dtaCloseFQL() {
    fql::close()
}

/// Starts playing back an FQL file: archive reads come from it instead of the archives.
#[no_mangle]
pub unsafe extern "system" fn dtaFQLBegin(file_name: *const c_char) -> bool {
    fql::begin(bytes(file_name))
}

#[no_mangle]
pub extern "system" fn dtaFQLEnd() {
    fql::end()
}

/// Files with these extensions are not recorded.
#[no_mangle]
pub unsafe extern "system" fn dtaAddFQLExtensionFilter(ext: *const c_char) -> bool {
    fql::add_extension_filter(bytes(ext))
}

#[no_mangle]
pub extern "system" fn dtaClearFQLExtensionFilter() {
    fql::clear_extension_filter()
}

/// Does nothing in this build.
#[no_mangle]
pub extern "system" fn dtaSetDebugFQLExt(_value: c_int) {}

// Unloading -------------------------------------------------------------------------------
//
// The original reported leaked archives from a global destructor. Rust has none, so the
// report runs from the library's unload hook: DllMain on Windows, the ELF finalizer array
// elsewhere.

#[cfg(windows)]
#[no_mangle]
#[allow(non_snake_case)]
extern "system" fn DllMain(_instance: *mut c_void, reason: u32, _reserved: *mut c_void) -> i32 {
    const DLL_PROCESS_DETACH: u32 = 0;
    if reason == DLL_PROCESS_DETACH {
        state::report_leaks();
    }
    1
}

#[cfg(all(unix, not(target_vendor = "apple")))]
#[used]
#[link_section = ".fini_array"]
static REPORT_LEAKS_AT_UNLOAD: extern "C" fn() = {
    extern "C" fn report() {
        state::report_leaks();
    }
    report
};
