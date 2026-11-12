//! Global state of the library and the lock that serialises every call.
//!
//! The original kept its state in globals guarded by one (recursive) critical section. Here
//! the state lives in a [`RefCell`] guarded by a re-entrant mutex built on `std::sync`: the
//! same thread may enter again (the error callback may call back into the library), other
//! threads wait.
//!
//! Errors are not reported while the state is borrowed: they are queued and the callback is
//! called once the call's work is done (still under the lock, like most of the original's
//! reports), so a callback can safely call any function of the library.

use std::cell::RefCell;
use std::ffi::{c_char, c_int, CString};
use std::fs::File;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, ThreadId};

use crate::archive::DtaRead;
use crate::ErrorCallback;

// Archive formats ----------------------------------------------------------------------
//
// ISD0 / ISD1 archive:
//   +0  magic "ISD0" or "ISD1"
//   ISD0: +4  16-byte table header (encrypted): u32 ?, u32 table offset, u32 table size, u32 ?
//   ISD1: +4  20 bytes (encrypted): u32 ?, u32 table offset, u32 table size,
//             u32 table checksum, u32 header checksum (of these 24 bytes with it zeroed)
//   table: file entries (0x1C bytes each), sorted by hash, encrypted
//   file:  file header (0x20 bytes, encrypted), the name (encrypted), then
//          ISD0: blocks, each a u32 (low 16 bits = stored size, high 16 = size of the
//                previous block) and the block (first byte = type, see below)
//          ISD1: u32[blockCount] (low 16 bits = stored size, high 16 = checksum),
//                u8[blockCount] block types (encrypted), then the blocks without the type byte
//   Every file is split in 32 KB blocks. Block types: 1 = LZSS, 2 = LZ4 (an addition of the
//   port; the original stores those bytes as they are), 0 and 3..7 = stored, >= 8 =
//   compressed 16-bit WAV (the first block starts with the 0x2C-byte RIFF header).
//   The key is a 64-bit XOR key (see crypt::decrypt); a header flag says whether the
//   blocks are encrypted too or only the WAV header.

pub const DTA_MAGIC_ISD0: u32 = 0x3044_5349; // "ISD0"
pub const DTA_MAGIC_ISD1: u32 = 0x3144_5349; // "ISD1"
pub const DTA_BLOCK_SIZE: u32 = 0x8000; // decoded size of a block
pub const DTA_WAV_HEADER_SIZE: u32 = 0x2C;
pub const DTA_BLOCK_LZSS: u8 = 1;
pub const DTA_BLOCK_LZ4: u8 = 2; // port only (see lz4.rs)
pub const DTA_BLOCK_WAV: u8 = 8; // and up
pub const DTA_NAME_ENCRYPTED_BLOCKS: u16 = 0x8000; // file header name-length flag

pub const CHECKSUM_SEED: u16 = 0xFF;

/// Error codes passed to the error callback.
pub const DTA_ERROR_OPEN: c_int = 1;
pub const DTA_ERROR_SIZE: c_int = 2;
pub const DTA_ERROR_CHECKSUM: c_int = 3;
pub const DTA_ERROR_FORMAT: c_int = 4;
pub const DTA_ERROR_MEMORY: c_int = 5;
pub const DTA_ERROR_READ: c_int = 6;

/// Entry of an archive's file table (0x1C bytes in the archive).
#[derive(Clone, Copy, Default)]
pub struct FileEntry {
    /// (name length << 16) | 16-bit sum of the upper-case name's bytes
    pub hash: u32,
    /// the file's header, followed by its name
    pub header_offset: u32,
    /// the first block
    pub data_offset: u32,
    /// the last 16 characters of the upper-case name (not terminated)
    pub name_tail: [u8; 16],
}

pub const FILE_ENTRY_SIZE: usize = 0x1C;

impl FileEntry {
    pub fn from_bytes(b: &[u8]) -> Self {
        let mut name_tail = [0u8; 16];
        name_tail.copy_from_slice(&b[12..28]);
        FileEntry {
            hash: le32(b, 0),
            header_offset: le32(b, 4),
            data_offset: le32(b, 8),
            name_tail,
        }
    }

    pub fn write_to(&self, b: &mut [u8]) {
        b[0..4].copy_from_slice(&self.hash.to_le_bytes());
        b[4..8].copy_from_slice(&self.header_offset.to_le_bytes());
        b[8..12].copy_from_slice(&self.data_offset.to_le_bytes());
        b[12..28].copy_from_slice(&self.name_tail);
    }
}

/// A mounted archive's table.
pub struct ArchiveTable {
    /// Identifies the archive (the original compared file handles).
    pub id: u32,
    pub file: Arc<File>,
    pub key: u64,
    pub file_name: Vec<u8>,
    pub entries: Vec<FileEntry>,
    /// 0 = ISD0, 1 = ISD1
    pub version: i32,
}

/// Entry of the archive search order.
#[derive(Clone, Copy)]
pub struct SearchSlot {
    pub archive: *mut DtaRead,
    /// index in `archive_tables`
    pub table: i32,
    /// (port) searched before the disk even when archives are not preferred (a mod archive
    /// marked with '+' in Mods/load_order.txt; see mods.rs)
    pub prefer: bool,
}

// OpenFile::flags
pub const DTA_FILE_DISK: u32 = 0x1; // a file on disk (else in an archive)
pub const DTA_FILE_WRITE: u32 = 0x2; // opened by dtaOpenWrite
pub const DTA_FILE_TEMP: u32 = 0x4; // written through "<name>.tmp"
pub const DTA_FILE_WRITE_ERROR: u32 = 0x80; // a write failed: the temporary file is discarded

/// Read position of an open file; dtaRead works on a copy and stores it back on success.
#[derive(Clone, Copy, Default)]
pub struct Cursor {
    /// archive: offset of the current block from data_offset; disk: file offset of the buffer
    pub block_offset: u32,
    pub position: u32,
    /// read position in the decoded block / buffer
    pub block_position: u32,
    /// archive: current block
    pub block: u32,
    /// archive: stored size of the current block
    pub block_size: u32,
    /// ISD0: stored size of the block before it
    pub previous_block_size: u32,
    /// bytes in the buffer
    pub buffer_size: u32,
}

/// The parts of an archived file that do not change once it is open.
#[derive(Default)]
pub struct BlockInfo {
    /// RIFF header of compressed WAV files (else empty)
    pub wav_header: Vec<u8>,
    /// ISD1: the block sizes are in the tables below
    pub block_tables: bool,
    pub block_sizes: Vec<u16>,
    pub block_checksums: Vec<u16>,
    pub block_types: Vec<u8>,
}

/// An open file. `file == None` marks a free slot.
#[derive(Default)]
pub struct OpenFile {
    /// For archived files the archive's file.
    pub file: Option<Arc<File>>,
    /// For archived files the archive's id, else 0.
    pub archive: u32,
    pub flags: u32,
    /// archived files: the time stored in the archive (FILETIME)
    pub time: u64,
    pub size: u32,
    /// archived files: offset of the first block
    pub data_offset: u32,
    pub block_count: u32,
    pub cursor: Cursor,
    /// archived files: the archive's key
    pub key: u64,
    /// DTA_FILE_TEMP: "<name>.tmp"
    pub temp_file_name: Vec<u8>,
    /// 32 KB: the decoded block / the file data
    pub buffer: Vec<u8>,
    pub info: Arc<BlockInfo>,
    pub buffer_valid: bool,
    /// whole blocks are encrypted, not only the WAV header
    pub blocks_encrypted: bool,
}

impl OpenFile {
    pub fn is_free(&self) -> bool {
        self.file.is_none()
    }
}

/// A file log.
pub struct FileLog {
    /// dta write handle, -1 once closed
    pub handle: i32,
    /// packed upper-case extensions (see pack_extension)
    pub extensions: Vec<i32>,
    /// upper-case directory prefixes
    pub dirs: Vec<Vec<u8>>,
    /// written before every name
    pub path_before: Vec<u8>,
}

/// State of FQL recording and playback.
pub struct Fql {
    // playback (dtaFQLBegin)
    pub read_file: Option<File>,
    /// the current block, decompressed
    pub read_buffer: Vec<u8>,
    pub read_size: i32,
    pub read_position: i32,
    /// the current block as stored
    pub compressed_buffer: Vec<u8>,
    /// reported to the error callback
    pub file_name: Vec<u8>,
    // recording (dtaCreateFQL)
    pub write_file: Option<File>,
    pub write_buffer: Vec<u8>,
    pub write_position: u32,
    /// bytes written to the file
    pub write_total: u32,
}

impl Fql {
    pub const BLOCK_SIZE: u32 = 0x20000; // uncompressed block, 8-byte header
    pub const BLOCK_HEADER_SIZE: u32 = 8;
    pub const COMPRESSED_BUFFER_SIZE: u32 = 0x20028;

    const fn new() -> Self {
        Fql {
            read_file: None,
            read_buffer: Vec::new(),
            read_size: 0,
            read_position: 0,
            compressed_buffer: Vec::new(),
            file_name: Vec::new(),
            write_file: None,
            write_buffer: Vec::new(),
            write_position: Self::BLOCK_HEADER_SIZE,
            write_total: 0,
        }
    }

    pub fn active(&self) -> bool {
        self.read_file.is_some() || self.write_file.is_some()
    }
}

/// An error waiting for the callback.
pub struct PendingError {
    callback: ErrorCallback,
    archive: *mut DtaRead,
    name: CString,
    error: c_int,
}

pub struct State {
    /// indexed by handle
    pub open_files: Vec<OpenFile>,
    pub archive_tables: Vec<ArchiveTable>,
    pub search_order: Vec<SearchSlot>,
    pub file_logs: Vec<FileLog>,
    pub fql_extension_filter: Vec<i32>,
    /// open files being recorded / played back
    pub fql_handles: Vec<i32>,
    pub error_callback: Option<ErrorCallback>,
    pub prefer_archives: bool,
    pub fql: Fql,
    /// Scratch buffer for one stored block (dtaRead).
    pub raw_block: Vec<u8>,
    pub next_archive_id: u32,
    pending_errors: Vec<PendingError>,
    /// While Some, errors are collected here instead of going to the callback (mods.rs).
    pub captured_errors: Option<Vec<c_int>>,
    /// (port) The mod archives mounted from the Mods folder, owned by the library (mods.rs).
    pub mods: Vec<*mut DtaRead>,
    /// The Mods folder was looked at for the archives mounted now.
    pub mods_mounted: bool,
    /// Mods/mods.log was started in this process (later mounts append to it).
    pub mods_log_started: bool,
    /// prefer_archives before Mods/load_order.txt set it, restored when the mods go.
    pub mods_saved_prefer: Option<bool>,
}

impl State {
    const fn new() -> Self {
        State {
            open_files: Vec::new(),
            archive_tables: Vec::new(),
            search_order: Vec::new(),
            file_logs: Vec::new(),
            fql_extension_filter: Vec::new(),
            fql_handles: Vec::new(),
            error_callback: None,
            prefer_archives: false,
            fql: Fql::new(),
            raw_block: Vec::new(),
            next_archive_id: 1,
            pending_errors: Vec::new(),
            captured_errors: None,
            mods: Vec::new(),
            mods_mounted: false,
            mods_log_started: false,
            mods_saved_prefer: None,
        }
    }

    /// Whether errors go anywhere (the callback, or the capture of mods.rs): the original
    /// only computed the checksums when an error callback was installed.
    pub fn reporting(&self) -> bool {
        self.error_callback.is_some() || self.captured_errors.is_some()
    }

    /// Queues an error for the callback (if one is installed).
    pub fn report(&mut self, archive: *mut DtaRead, name: &[u8], error: c_int) {
        if let Some(captured) = &mut self.captured_errors {
            captured.push(error);
        } else if let Some(callback) = self.error_callback {
            self.pending_errors.push(PendingError {
                callback,
                archive,
                name: c_string(name),
                error,
            });
        }
    }
}

// Re-entrant lock -----------------------------------------------------------------------

struct ReentrantMutex {
    state: Mutex<(Option<ThreadId>, u32)>,
    released: Condvar,
}

impl ReentrantMutex {
    const fn new() -> Self {
        ReentrantMutex {
            state: Mutex::new((None, 0)),
            released: Condvar::new(),
        }
    }

    fn lock(&self) {
        let me = thread::current().id();
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            match s.0 {
                None => {
                    *s = (Some(me), 1);
                    return;
                }
                Some(owner) if owner == me => {
                    s.1 += 1;
                    return;
                }
                Some(_) => s = self.released.wait(s).unwrap_or_else(|e| e.into_inner()),
            }
        }
    }

    fn unlock(&self) {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        s.1 -= 1;
        if s.1 == 0 {
            s.0 = None;
            self.released.notify_one();
        }
    }
}

struct Global {
    lock: ReentrantMutex,
    state: RefCell<State>,
}

// SAFETY: `state` is only touched by the thread that holds `lock` (see `with_state`), and the
// raw archive pointers in it are only dereferenced under that lock too.
unsafe impl Sync for Global {}

static GLOBAL: Global = Global {
    lock: ReentrantMutex::new(),
    state: RefCell::new(State::new()),
};

/// Holds the global lock; released on drop.
struct LockGuard;

impl LockGuard {
    fn acquire() -> Self {
        GLOBAL.lock.lock();
        LockGuard
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        GLOBAL.lock.unlock();
    }
}

/// Runs `f` on the global state under the lock, then reports the errors it queued.
///
/// `f` must not call back into the library's public functions (it would find the state
/// borrowed); internal code passes the `&mut State` along instead.
pub fn with_state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    let _guard = LockGuard::acquire();
    let (result, errors) = {
        let mut state = GLOBAL.state.borrow_mut();
        let result = f(&mut state);
        (result, std::mem::take(&mut state.pending_errors))
    };
    for e in errors {
        // SAFETY: the callback is a function pointer installed by the host.
        unsafe { (e.callback)(e.archive.cast(), e.name.as_ptr() as *const c_char, e.error) };
    }
    result
}

// Leak counter ---------------------------------------------------------------------------

/// Counts the archives and their references; reported when the library unloads.
pub static LEAK_REFERENCES: AtomicI32 = AtomicI32::new(0);
pub static LEAK_OBJECTS: AtomicI32 = AtomicI32::new(0);
pub static LEAK_REPORT: AtomicBool = AtomicBool::new(false);
/// The mod archives mounted now (one object and one reference each): they belong to the
/// library, not the host, so the report leaves them out.
pub static MOD_ARCHIVES: AtomicI32 = AtomicI32::new(0);

/// The "Not released ..." report (a message box in the original; standard error here).
/// (macOS has no unload hook for it, see lib.rs.)
#[cfg_attr(target_vendor = "apple", allow(dead_code))]
pub fn report_leaks() {
    if !LEAK_REPORT.load(Ordering::Relaxed) {
        return;
    }
    let mut message = String::new();
    let mods = MOD_ARCHIVES.load(Ordering::Relaxed);
    let references = LEAK_REFERENCES.load(Ordering::Relaxed) - mods;
    if references != 0 {
        message += &format!("Not released:  {references}  reference(s) of Dta_read.\n");
    }
    let objects = LEAK_OBJECTS.load(Ordering::Relaxed) - mods;
    if objects != 0 {
        message += &format!("Not released:  {objects}  Dta_read(s).\n");
    }
    if !message.is_empty() {
        use std::io::Write;
        let _ = write!(std::io::stderr(), "Dta_read error message: {message}");
    }
}

// Small helpers ---------------------------------------------------------------------------

pub fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

pub fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

/// A C string of the bytes up to the first NUL.
pub fn c_string(bytes: &[u8]) -> CString {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    CString::new(&bytes[..end]).unwrap_or_default()
}

/// MSVC's rand() (the DLL had its own copy of the C runtime): per thread, seeded with 1.
pub fn dta_rand() -> i32 {
    thread_local!(static SEED: std::cell::Cell<u32> = const { std::cell::Cell::new(1) });
    SEED.with(|seed| {
        let s = seed.get().wrapping_mul(214_013).wrapping_add(2_531_011);
        seed.set(s);
        ((s >> 16) & 0x7FFF) as i32
    })
}

/// _strupr of the C locale, up to the first NUL.
pub fn upper_case(text: &mut [u8]) {
    for c in text.iter_mut() {
        if *c == 0 {
            break;
        }
        c.make_ascii_uppercase();
    }
}

/// The bytes of a C string, up to (not including) its NUL.
pub fn c_str(bytes: &[u8]) -> &[u8] {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    &bytes[..end]
}

/// strncmp of two byte strings that end at their first NUL or at their end.
pub fn strncmp(a: &[u8], b: &[u8], n: usize) -> i32 {
    for i in 0..n {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        if x != y {
            return x as i32 - y as i32;
        }
        if x == 0 {
            return 0;
        }
    }
    0
}

/// Packs the extension of a name (up to the last 3 characters after the last '.') into an
/// int.
pub fn pack_extension(name: &[u8]) -> i32 {
    let length = name.len();
    // (The original read the byte before an empty name.)
    if length == 0 {
        return 0;
    }
    // Start of the extension: after the last '.' among the last 3 characters, else the
    // last 3 characters.
    let mut end = length;
    let start;
    loop {
        let s = end - 1;
        if (length - s) as i32 > 2 || (s as i32) < 1 {
            start = s;
            break;
        }
        let before = name[end - 2];
        end = s;
        if before == b'.' {
            start = s;
            break;
        }
    }
    let mut packed = [0u8; 4];
    let n = (length - start).min(4);
    packed[..n].copy_from_slice(&name[start..start + n]);
    i32::from_le_bytes(packed)
}

/// Packs an extension argument (1..3 characters) the way pack_extension packs a name's.
pub fn pack_extension_argument(ext: &[u8]) -> Option<i32> {
    if ext.is_empty() || ext.len() > 3 {
        return None;
    }
    let mut packed = [0u8; 4];
    packed[..ext.len()].copy_from_slice(ext);
    upper_case(&mut packed);
    Some(i32::from_le_bytes(packed))
}
