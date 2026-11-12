//! Mounted archives: the archive object behind `C_DtaArchive` ("Dta_read" in the original)
//! and dtaCreate.
//!
//! The object is shared with C++ code built by any compiler, so it keeps the layout of the
//! original MSVC 6 class: a pointer to a table of ten functions, all `__thiscall` on 32-bit
//! x86 (on other targets there is one C calling convention, which `thiscall` maps onto).
//! Slot 0 is MSVC's scalar deleting destructor.

use std::ffi::{c_char, c_void, CString};
use std::fs::File;
use std::ptr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::crypt::{checksum16, decrypt};
use crate::platform;
use crate::state::*;

/// The archive object.
#[repr(C)]
pub struct DtaRead {
    vtable: *const VTable,
    /// The key is kept XOR-masked with a random value (inverted once the archive is open).
    key_mask: u64,
    key: u64,
    ref_count: u32,
    /// Identifies the archive's table and its open files (the original compared handles).
    id: u32,
    file: Option<Arc<File>>,
    /// 0 = ISD0, 1 = ISD1
    version: i32,
    file_name: CString,
}

impl DtaRead {
    pub fn name_bytes(&self) -> &[u8] {
        self.file_name.as_bytes()
    }

    pub fn name_ptr(&self) -> *const c_char {
        self.file_name.as_ptr()
    }
}

macro_rules! define_vtable {
    ($abi:literal) => {
        /// The virtual table of `C_DtaArchive` (see include/rw_data.h).
        #[repr(C)]
        pub struct VTable {
            pub deleting_destructor: unsafe extern $abi fn(*mut DtaRead, u32) -> *mut c_void,
            pub add_ref: unsafe extern $abi fn(*mut DtaRead) -> i32,
            pub release: unsafe extern $abi fn(*mut DtaRead) -> i32,
            pub xor_key: unsafe extern $abi fn(*mut DtaRead, u32, u32) -> bool,
            pub get_key: unsafe extern $abi fn(*mut DtaRead) -> u64,
            pub set_key: unsafe extern $abi fn(*mut DtaRead, u32, u32) -> bool,
            pub set_prefer_archives: unsafe extern $abi fn(*mut DtaRead, bool) -> bool,
            pub set_priority: unsafe extern $abi fn(*mut DtaRead, i32) -> i32,
            pub get_priority: unsafe extern $abi fn(*mut DtaRead) -> i32,
            pub get_name: unsafe extern $abi fn(*mut DtaRead) -> *const c_char,
        }

        unsafe extern $abi fn vt_deleting_destructor(this: *mut DtaRead, flags: u32) -> *mut c_void {
            deleting_destructor(this, flags)
        }
        unsafe extern $abi fn vt_add_ref(this: *mut DtaRead) -> i32 {
            add_ref(this)
        }
        unsafe extern $abi fn vt_release(this: *mut DtaRead) -> i32 {
            release(this)
        }
        unsafe extern $abi fn vt_xor_key(this: *mut DtaRead, low: u32, high: u32) -> bool {
            xor_key(this, low, high)
        }
        unsafe extern $abi fn vt_get_key(this: *mut DtaRead) -> u64 {
            get_key(this)
        }
        unsafe extern $abi fn vt_set_key(this: *mut DtaRead, low: u32, high: u32) -> bool {
            set_key(this, low, high)
        }
        unsafe extern $abi fn vt_set_prefer_archives(this: *mut DtaRead, prefer: bool) -> bool {
            set_prefer_archives(this, prefer)
        }
        unsafe extern $abi fn vt_set_priority(this: *mut DtaRead, priority: i32) -> i32 {
            set_priority(this, priority)
        }
        unsafe extern $abi fn vt_get_priority(this: *mut DtaRead) -> i32 {
            get_priority(this)
        }
        unsafe extern $abi fn vt_get_name(this: *mut DtaRead) -> *const c_char {
            get_name(this)
        }

        static VTABLE: VTable = VTable {
            deleting_destructor: vt_deleting_destructor,
            add_ref: vt_add_ref,
            release: vt_release,
            xor_key: vt_xor_key,
            get_key: vt_get_key,
            set_key: vt_set_key,
            set_prefer_archives: vt_set_prefer_archives,
            set_priority: vt_set_priority,
            get_priority: vt_get_priority,
            get_name: vt_get_name,
        };
    };
}

#[cfg(target_arch = "x86")]
define_vtable!("thiscall");
#[cfg(not(target_arch = "x86"))]
define_vtable!("C");

impl DtaRead {
    /// The virtual table, for callers in Rust.
    pub fn vtable(&self) -> &VTable {
        // SAFETY: always points at the static VTABLE.
        unsafe { &*self.vtable }
    }
}

fn make_key(low: u32, high: u32) -> u64 {
    (high as u64) << 32 | low as u64
}

/// Index in the search order of an archive, or -1.
fn find_search_slot(st: &State, archive: *mut DtaRead) -> i32 {
    st.search_order
        .iter()
        .rposition(|s| s.archive == archive)
        .map_or(-1, |i| i as i32)
}

/// Index in the archive tables of an archive's table (searched from the end), or -1.
pub fn find_archive_table(st: &State, id: u32) -> i32 {
    st.archive_tables
        .iter()
        .rposition(|t| t.id == id)
        .map_or(-1, |i| i as i32)
}

/// Opens the archive and reads its magic; on success registers its table and appends it
/// to the search order (with one reference). Returns whether it succeeded.
unsafe fn construct(st: &mut State, this: *mut DtaRead, file_name: &[u8]) -> bool {
    let a = &mut *this;
    // A random mask built from four rand() values.
    for _ in 0..4 {
        a.key_mask = (a.key_mask << 16) | (dta_rand() as u16 as u64);
    }

    let file = match platform::open_read(file_name, true) {
        Ok(f) => f,
        Err(_) => {
            st.report(ptr::null_mut(), file_name, DTA_ERROR_OPEN);
            return false;
        }
    };

    let mut magic = [0u8; 4];
    let read = match platform::read(&file, &mut magic) {
        Ok(n) => n,
        Err(_) => {
            st.report(ptr::null_mut(), file_name, DTA_ERROR_READ);
            return false;
        }
    };
    if read != magic.len() {
        st.report(ptr::null_mut(), file_name, DTA_ERROR_SIZE);
        return false;
    }

    let magic = u32::from_le_bytes(magic);
    a.version = match magic {
        DTA_MAGIC_ISD0 => 0,
        DTA_MAGIC_ISD1 => 1,
        _ => -1,
    };
    if a.version < 0 {
        st.report(ptr::null_mut(), file_name, DTA_ERROR_FORMAT);
        return false;
    }

    let file = Arc::new(file);
    a.id = st.next_archive_id;
    st.next_archive_id = st.next_archive_id.wrapping_add(1).max(1);
    a.file = Some(file.clone());
    st.archive_tables.push(ArchiveTable {
        id: a.id,
        file,
        key: 0,
        file_name: file_name.to_vec(),
        entries: Vec::new(),
        version: a.version,
    });
    st.search_order.push(SearchSlot {
        archive: this,
        table: st.archive_tables.len() as i32 - 1,
        prefer: false,
    });
    add_ref_locked(a);
    a.key_mask = !a.key_mask;
    a.file_name = c_string(file_name);
    LEAK_OBJECTS.fetch_add(1, Ordering::Relaxed);
    true
}

/// The destructor: unregisters the archive. Runs under the lock.
fn destroy(st: &mut State, this: *mut DtaRead) {
    // SAFETY: `this` is a live archive object.
    let a = unsafe { &mut *this };
    // (closes the archive's file once its open files are gone too)
    a.file = None;

    let table = if a.id != 0 {
        find_archive_table(st, a.id)
    } else {
        -1
    };
    if table >= 0 {
        st.archive_tables.remove(table as usize);
    }
    // When the table was not found every index is decremented, like the original did.
    for slot in (0..st.search_order.len()).rev() {
        if st.search_order[slot].archive == this {
            st.search_order.remove(slot);
        } else if table < st.search_order[slot].table {
            st.search_order[slot].table -= 1;
        }
    }
    // Files still open in the archive become free slots.
    if a.id != 0 {
        for open in st.open_files.iter_mut().rev() {
            if !open.is_free() && open.archive == a.id {
                *open = OpenFile::default();
            }
        }
    }
    LEAK_OBJECTS.fetch_sub(1, Ordering::Relaxed);

    // (port) The mod archives live as long as the host keeps an archive of its own: once
    // the last one is gone they are released too (and mounted again by the next dtaCreate).
    if st.mods_mounted
        && !st
            .search_order
            .iter()
            .any(|s| !st.mods.contains(&s.archive))
    {
        crate::mods::unmount(st);
    }
}

/// MSVC's scalar deleting destructor, kept for the layout of the virtual table.
unsafe fn deleting_destructor(this: *mut DtaRead, flags: u32) -> *mut c_void {
    with_state(|st| destroy(st, this));
    if flags & 1 != 0 {
        drop(Box::from_raw(this));
    }
    this.cast()
}

fn add_ref_locked(a: &mut DtaRead) -> i32 {
    LEAK_REFERENCES.fetch_add(1, Ordering::Relaxed);
    a.ref_count = a.ref_count.wrapping_add(1);
    a.ref_count as i32
}

unsafe fn add_ref(this: *mut DtaRead) -> i32 {
    with_state(|_| add_ref_locked(&mut *this))
}

/// The count is unsigned: releasing an archive that was never referenced (a failed
/// dtaCreate) wraps it around and leaks the object, as in the original.
unsafe fn release(this: *mut DtaRead) -> i32 {
    with_state(|st| release_locked(st, this))
}

/// Release under the lock.
///
/// # Safety
/// `this` must be a live archive object.
pub unsafe fn release_locked(st: &mut State, this: *mut DtaRead) -> i32 {
    LEAK_REFERENCES.fetch_sub(1, Ordering::Relaxed);
    let a = &mut *this;
    a.ref_count = a.ref_count.wrapping_sub(1);
    let remaining = a.ref_count as i32;
    if a.ref_count < 1 {
        destroy(st, this);
        drop(Box::from_raw(this));
    }
    remaining
}

/// The game applies its key in two steps: XorKey(key ^ r) with a random r, then
/// XorKey(GetKey() ^ key). The first call only stores the masked value; the second one
/// recovers the key ((key ^ r ^ mask) ^ key ^ (mask ^ key ^ r) = key) and loads the table.
unsafe fn xor_key(this: *mut DtaRead, low: u32, high: u32) -> bool {
    with_state(|st| {
        let a = &mut *this;
        let value = make_key(low, high);
        if a.key == 0 {
            a.key = value ^ a.key_mask;
            a.key_mask ^= value;
            return true;
        }
        let key = value ^ a.key_mask;
        a.key_mask = 0;
        load_file_table(st, a, this, key)
    })
}

unsafe fn get_key(this: *mut DtaRead) -> u64 {
    (*this).key
}

/// Decrypts the file table with a plain key.
unsafe fn set_key(this: *mut DtaRead, low: u32, high: u32) -> bool {
    with_state(|st| load_file_table(st, &mut *this, this, make_key(low, high)))
}

/// Reads and decrypts the file table (the common part of XorKey and SetKey).
pub fn load_file_table(st: &mut State, a: &mut DtaRead, this: *mut DtaRead, key: u64) -> bool {
    let Some(file) = a.file.clone() else {
        return false;
    };
    let name = a.file_name.as_bytes().to_vec();
    if !platform::seek(&file, 4) {
        return false;
    }

    let mut table_offset = 0u32;
    let mut table_size = 0u32;
    let mut table_checksum = 0u32;
    if a.version == 0 {
        let mut header = [0u8; 16];
        if !platform::read_exact(&file, &mut header) {
            return false;
        }
        decrypt(&mut header, key);
        table_offset = le32(&header, 4);
        table_size = le32(&header, 8);
    } else if a.version == 1 {
        let file_size = platform::seek_end(&file).unwrap_or(u32::MAX);
        if file_size < 0x18 {
            st.report(this, &name, DTA_ERROR_SIZE);
        }
        platform::seek(&file, 0);

        // magic, then 20 encrypted bytes: ?, table offset, table size, table checksum,
        // and the checksum of all 24 bytes (decrypted, with this field zeroed).
        let mut header = [0u8; 0x18];
        match platform::read(&file, &mut header) {
            Err(_) => {
                st.report(this, &name, DTA_ERROR_READ);
                return false;
            }
            Ok(n) if n != header.len() => {
                st.report(this, &name, DTA_ERROR_SIZE);
                return false;
            }
            Ok(_) => {}
        }
        decrypt(&mut header[4..], key);
        let header_checksum = le32(&header, 0x14);
        header[0x14..0x18].fill(0);
        if st.reporting() && header_checksum != checksum16(&header, CHECKSUM_SEED) as u32 {
            st.report(this, &name, DTA_ERROR_CHECKSUM);
        }
        table_offset = le32(&header, 8);
        table_size = le32(&header, 12);
        table_checksum = le32(&header, 16);
        if file_size != table_size.wrapping_add(table_offset) {
            st.report(this, &name, DTA_ERROR_SIZE);
        }
    }

    let table = find_archive_table(st, a.id);
    if table < 0 {
        return false;
    }
    let size = table_size as usize;
    let count = size / FILE_ENTRY_SIZE;

    // (A wrong key gives any size; the original then failed to allocate and crashed.)
    let mut raw: Vec<u8> = Vec::new();
    let archive = &mut st.archive_tables[table as usize];
    archive.key = key;
    if raw.try_reserve_exact(size).is_err()
        || archive
            .entries
            .try_reserve(count.saturating_sub(archive.entries.len()))
            .is_err()
    {
        st.report(this, &name, DTA_ERROR_MEMORY);
        return false;
    }
    archive.entries.resize(count, FileEntry::default());

    // The original read `table_size` bytes straight into the entries, past their end when
    // the size is not a multiple of an entry; this reads into a buffer of the full size
    // that starts with the current entries (what a short read leaves in place).
    raw.resize(size, 0);
    for (i, entry) in archive.entries.iter().enumerate() {
        entry.write_to(&mut raw[i * FILE_ENTRY_SIZE..(i + 1) * FILE_ENTRY_SIZE]);
    }
    platform::seek(&file, table_offset);
    let read = match platform::read(&file, &mut raw) {
        Ok(n) => n,
        Err(_) => {
            st.report(this, &name, DTA_ERROR_READ);
            0
        }
    };
    if read != size {
        st.report(this, &name, DTA_ERROR_SIZE);
    }
    if a.version != 0 && st.reporting() && table_checksum != checksum16(&raw, CHECKSUM_SEED) as u32
    {
        st.report(this, &name, DTA_ERROR_CHECKSUM);
    }
    decrypt(&mut raw, key);
    let archive = &mut st.archive_tables[table as usize];
    for (i, entry) in archive.entries.iter_mut().enumerate() {
        *entry = FileEntry::from_bytes(&raw[i * FILE_ENTRY_SIZE..(i + 1) * FILE_ENTRY_SIZE]);
    }
    true
}

/// Global switch: dtaOpen looks in the archives before the disk. Returns the old value.
unsafe fn set_prefer_archives(_this: *mut DtaRead, prefer: bool) -> bool {
    with_state(|st| std::mem::replace(&mut st.prefer_archives, prefer))
}

/// Position in the archive search order (0 = searched first); returns the new position.
unsafe fn set_priority(this: *mut DtaRead, priority: i32) -> i32 {
    with_state(|st| {
        let mut priority = priority;
        if priority < 0 {
            priority = 0;
        } else if !st.search_order.is_empty() && priority as usize > st.search_order.len() - 1 {
            priority = st.search_order.len() as i32 - 1;
        }

        let slot = find_search_slot(st, this);
        // The original also moved a slot when the archive was not in the search order (-1),
        // reading and erasing outside the vector.
        if slot >= 0 && slot != priority {
            let entry = st.search_order.remove(slot as usize);
            st.search_order.insert(priority as usize, entry);
        }
        priority
    })
}

unsafe fn get_priority(this: *mut DtaRead) -> i32 {
    with_state(|st| find_search_slot(st, this))
}

unsafe fn get_name(this: *mut DtaRead) -> *const c_char {
    (*this).file_name.as_ptr()
}

/// dtaCreate: mounts an archive and appends it to the search order; null when the file is
/// missing or is not an archive.
///
/// (port) The host's first archive also mounts the archives of the Mods folder, ahead of it
/// in the search order (see mods.rs).
pub fn create(file_name: &[u8]) -> *mut DtaRead {
    with_state(|st| {
        let archive = create_locked(st, file_name);
        if !archive.is_null() && !st.mods_mounted {
            let host_slot = st.search_order.len() - 1;
            crate::mods::mount(st);
            st.search_order[host_slot..].rotate_left(1);
        }
        archive
    })
}

/// dtaCreate under the lock (without the mods).
pub fn create_locked(st: &mut State, file_name: &[u8]) -> *mut DtaRead {
    let archive = Box::into_raw(Box::new(DtaRead {
        vtable: &VTABLE,
        key_mask: 0,
        key: 0,
        ref_count: 0,
        id: 0,
        file: None,
        version: -1,
        file_name: CString::default(),
    }));
    // SAFETY: `archive` was just allocated.
    if unsafe { construct(st, archive, file_name) } {
        return archive;
    }
    // SAFETY: the object is alive (it leaks, see release).
    unsafe { release_locked(st, archive) };
    ptr::null_mut()
}
