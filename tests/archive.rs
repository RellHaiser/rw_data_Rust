//! End-to-end tests: archives packed by tools/dta_pack.py (the packer of the C++ port) are
//! mounted and read through the library's C interface, and the results compared with the
//! packed files. Needs Python 3.9+ on the PATH (`python` or `python3`); without it the
//! archive tests are skipped with a message.

use std::ffi::{c_char, c_int, c_void, CString};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Mutex;

use rw_data::*;

/// The library's state is global: the tests run one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

const LOW: u32 = 0x1234_5678;
const HIGH: u32 = 0x9ABC_DEF0;

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn path_c(p: &Path) -> CString {
    c(p.to_str().unwrap())
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rw_data_test_{}_{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Deterministic test data: text-like (compressible) or noise.
fn data(len: usize, seed: u32, compressible: bool) -> Vec<u8> {
    let mut s = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
    let words: [&[u8]; 6] = [
        b"soldier ",
        b"mission ",
        b"\r\n",
        b"weapon=",
        b"12345 ",
        b"Tables\\",
    ];
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        if compressible {
            out.extend_from_slice(words[(s % 6) as usize]);
        } else {
            out.push(s as u8);
        }
    }
    out.truncate(len);
    out
}

/// The files packed into the test archives: (name in the archive, contents).
fn files() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("readme.txt", b"Hello, archive!\r\n".to_vec()),
        ("Tables\\items.sav", data(100_000, 1, true)),
        ("Tables\\exact.bin", data(0x8000, 2, true)),
        ("Maps\\noise.bin", data(70_000, 3, false)),
        (
            "Maps\\Sub\\a_rather_long_file_name_for_the_tail.dat",
            data(0x8000 * 5 + 17, 4, true),
        ),
        ("empty.txt", Vec::new()),
    ]
}

fn python() -> Option<&'static str> {
    ["python", "python3"].into_iter().find(|p| {
        Command::new(p)
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
    })
}

/// Packs `files()` into `<dir>/<name>`; None when Python is missing.
fn pack(dir: &Path, name: &str, compression: &str) -> Option<PathBuf> {
    let Some(python) = python() else {
        eprintln!("skipped: Python is needed to pack the test archives");
        return None;
    };
    let folder = dir.join(format!("src_{compression}"));
    for (file, contents) in files() {
        let path = folder.join(file.replace('\\', "/"));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }
    let archive = dir.join(name);
    let packer = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tools")
        .join("dta_pack.py");
    let output = Command::new(python)
        .arg("-I")
        .arg(packer)
        .arg(&folder)
        .arg(&archive)
        .args([
            "--key",
            &format!("{LOW:#x}:{HIGH:#x}"),
            "--compression",
            compression,
            "--workers",
            "1",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "dta_pack.py failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Some(archive)
}

static ERRORS: AtomicI32 = AtomicI32::new(0);

unsafe extern "C" fn count_errors(_archive: *mut c_void, name: *const c_char, error: c_int) {
    eprintln!("error {error} for {:?}", std::ffi::CStr::from_ptr(name));
    ERRORS.fetch_add(1, Ordering::SeqCst);
}

fn vt(archive: *mut DtaRead) -> &'static VTable {
    unsafe { (*archive).vtable() }
}

fn mount(path: &Path) -> *mut DtaRead {
    let archive = unsafe { dtaCreate(path_c(path).as_ptr()) };
    assert!(!archive.is_null(), "dtaCreate failed");
    archive
}

fn release(archive: *mut DtaRead) {
    assert_eq!(unsafe { (vt(archive).release)(archive) }, 0);
}

fn read_all(handle: c_int, size: usize) -> Vec<u8> {
    let mut out = vec![0u8; size + 10];
    let n = unsafe { dtaRead(handle, out.as_mut_ptr().cast(), out.len() as c_int) };
    assert_eq!(n, size as c_int);
    out.truncate(size);
    out
}

/// Reads at many positions with many sizes (crossing blocks, whole blocks, backwards).
fn check_random_access(handle: c_int, expected: &[u8]) {
    let len = expected.len();
    let mut s = 0x2468_ACE1u32;
    for _ in 0..300 {
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        let pos = if len == 0 { 0 } else { s as usize % len };
        let size = match s % 4 {
            0 => (s >> 8) as usize % 64,
            1 => (s >> 8) as usize % 0x9000,
            2 => (s >> 8) as usize % (0x8000 * 3),
            _ => 0x8000,
        };
        assert_eq!(dtaSeek(handle, pos as c_int, 0), pos as c_int);
        let mut buf = vec![0u8; size];
        let n = unsafe { dtaRead(handle, buf.as_mut_ptr().cast(), size as c_int) };
        let want = size.min(len - pos);
        assert_eq!(n, want as c_int, "read of {size} at {pos}");
        assert_eq!(
            &buf[..want],
            &expected[pos..pos + want],
            "data of {size} at {pos}"
        );
        // and a sequential read after it. (Not an empty one at the end: like the original,
        // that fails for an archived file whose size is a multiple of 32 KB, as it looks for
        // the block after the last one.)
        let next = (len - pos - want).min(1000);
        if next == 0 {
            continue;
        }
        let mut buf = vec![0u8; next];
        let n = unsafe { dtaRead(handle, buf.as_mut_ptr().cast(), next as c_int) };
        assert_eq!(n, next as c_int);
        assert_eq!(&buf[..], &expected[pos + want..pos + want + next]);
    }
    // the end: one byte past it is accepted and reads nothing
    assert_eq!(dtaSeek(handle, 0, 2), len as c_int);
    assert_eq!(dtaSeek(handle, 1, 2), len as c_int + 1);
    assert_eq!(dtaSeek(handle, 2, 2), -1);
    let mut b = [0u8; 4];
    assert_eq!(unsafe { dtaRead(handle, b.as_mut_ptr().cast(), 4) }, 0);
}

fn check_archive(compression: &str) {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = scratch(compression);
    let Some(path) = pack(&dir, "Test.dta", compression) else {
        return;
    };
    ERRORS.store(0, Ordering::SeqCst);
    let previous = dtaSetCallbackERR(Some(count_errors));

    let archive = mount(&path);
    assert!(unsafe { (vt(archive).set_key)(archive, LOW, HIGH) });
    let name = unsafe { std::ffi::CStr::from_ptr((vt(archive).get_name)(archive)) };
    assert_eq!(name.to_str().unwrap(), path.to_str().unwrap());
    assert_eq!(unsafe { (vt(archive).get_priority)(archive) }, 0);

    for (file, contents) in files() {
        // Any case: the lookup is case-insensitive.
        let handle = unsafe { dtaOpen(c(&file.to_lowercase()).as_ptr(), true) };
        assert!(handle >= 0, "{file} not found");
        assert_eq!(read_all(handle, contents.len()), contents, "{file}");
        check_random_access(handle, &contents);

        let mut time = FileTime::default();
        assert!(unsafe { dtaGetTime(handle, &mut time, false) });
        assert_ne!(time, FileTime::default());
        assert!(unsafe { dtaGetTime(handle, &mut time, true) });
        assert!(dtaClose(handle));
    }
    assert_eq!(
        unsafe { dtaOpen(c("Tables\\missing.sav").as_ptr(), true) },
        -1
    );
    assert_eq!(unsafe { dtaOpen(c("Tables\\items.sa").as_ptr(), true) }, -1);

    // Direct access: the archive file and the offset of the file's first block.
    let mut offset = -1;
    let raw = unsafe { dtaGetPackDirectAccess(c("readme.txt").as_ptr(), &mut offset) };
    assert_ne!(raw as isize, -1);
    assert!(offset > 0);
    close_raw(raw);

    assert_eq!(
        ERRORS.load(Ordering::SeqCst),
        0,
        "errors reported for a valid archive"
    );
    release(archive);
    dtaSetCallbackERR(previous);
    let _ = std::fs::remove_dir_all(dir);
}

fn close_raw(raw: *mut c_void) {
    #[cfg(windows)]
    {
        use std::os::windows::io::FromRawHandle;
        drop(unsafe { std::fs::File::from_raw_handle(raw) });
    }
    #[cfg(unix)]
    {
        use std::os::unix::io::FromRawFd;
        drop(unsafe { std::fs::File::from_raw_fd(raw as isize as i32) });
    }
}

#[test]
fn lzss_archive() {
    check_archive("lzss");
}

#[test]
fn lz4_archive() {
    check_archive("lz4");
}

#[test]
fn stored_archive() {
    check_archive("none");
}

#[test]
fn xor_key_in_two_steps_and_wrong_keys() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = scratch("xor");
    let Some(path) = pack(&dir, "Xor.dta", "lzss") else {
        return;
    };
    // The game's way: XorKey(key ^ r), then XorKey(GetKey() ^ key).
    let archive = mount(&path);
    let key = (HIGH as u64) << 32 | LOW as u64;
    let r = 0x0F0F_1234_5555_AAAAu64;
    let v = vt(archive);
    unsafe {
        assert!((v.xor_key)(
            archive,
            (key ^ r) as u32,
            ((key ^ r) >> 32) as u32
        ));
        let second = (v.get_key)(archive) ^ key;
        assert!((v.xor_key)(archive, second as u32, (second >> 32) as u32));
        let handle = dtaOpen(c("Tables\\items.sav").as_ptr(), true);
        assert!(handle >= 0);
        assert_eq!(read_all(handle, 100_000), files()[1].1);
        dtaClose(handle);
    }
    release(archive);

    // A wrong key: checksum errors, and the files are not found.
    ERRORS.store(0, Ordering::SeqCst);
    let previous = dtaSetCallbackERR(Some(count_errors));
    let archive = mount(&path);
    unsafe {
        (vt(archive).set_key)(archive, 1, 2);
        assert_eq!(dtaOpen(c("readme.txt").as_ptr(), true), -1);
    }
    assert!(ERRORS.load(Ordering::SeqCst) > 0);
    release(archive);
    dtaSetCallbackERR(previous);

    // Not an archive / missing.
    std::fs::write(dir.join("not.dta"), b"PK\x03\x04 something").unwrap();
    ERRORS.store(0, Ordering::SeqCst);
    let previous = dtaSetCallbackERR(Some(count_errors));
    assert!(unsafe { dtaCreate(path_c(&dir.join("not.dta")).as_ptr()) }.is_null());
    assert!(unsafe { dtaCreate(path_c(&dir.join("missing.dta")).as_ptr()) }.is_null());
    assert_eq!(ERRORS.load(Ordering::SeqCst), 2);
    dtaSetCallbackERR(previous);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn priorities_and_disk_first() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = scratch("prio");
    let Some(a) = pack(&dir, "A.dta", "lzss") else {
        return;
    };
    let b = pack(&dir, "B.dta", "lz4").unwrap();
    let first = mount(&a);
    let second = mount(&b);
    unsafe {
        (vt(first).set_key)(first, LOW, HIGH);
        (vt(second).set_key)(second, LOW, HIGH);
        assert_eq!((vt(second).get_priority)(second), 1);
        assert_eq!((vt(second).set_priority)(second, 0), 0);
        assert_eq!((vt(first).get_priority)(first), 1);
        assert_eq!((vt(first).set_priority)(first, 99), 1);

        // A file on disk with the same name wins unless the archives come first.
        let disk_dir = dir.join("disk");
        std::fs::create_dir_all(&disk_dir).unwrap();
        let disk_file = disk_dir.join("readme.txt");
        std::fs::write(&disk_file, b"from disk").unwrap();
        let name = path_c(&disk_file);
        let h = dtaOpen(name.as_ptr(), false);
        assert_eq!(read_all(h, 9), b"from disk");
        dtaClose(h);

        assert!(!(vt(first).set_prefer_archives)(first, true));
        assert!((vt(first).set_prefer_archives)(first, false));
    }
    release(second);
    // The archive's open files become invalid when it is released.
    let h = unsafe { dtaOpen(c("readme.txt").as_ptr(), true) };
    assert!(h >= 0);
    release(first);
    let mut b1 = [0u8; 1];
    assert_eq!(unsafe { dtaRead(h, b1.as_mut_ptr().cast(), 1) }, -1);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn fql_record_and_playback() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = scratch("fql");
    let Some(path) = pack(&dir, "Fql.dta", "lzss") else {
        return;
    };
    let archive = mount(&path);
    unsafe { (vt(archive).set_key)(archive, LOW, HIGH) };
    let fql = path_c(&dir.join("load.fql"));
    let script: Vec<(&str, usize, usize)> = vec![
        ("Tables\\items.sav", 0, 100_000),
        ("readme.txt", 0, 17),
        ("Maps\\noise.bin", 1000, 50_000),
        (
            "Maps\\Sub\\a_rather_long_file_name_for_the_tail.dat",
            0x8000 * 2 + 3,
            0x8000 * 3,
        ),
    ];
    let run = |expect_from_archive: bool| -> Vec<Vec<u8>> {
        let mut results = Vec::new();
        for &(name, pos, size) in &script {
            unsafe {
                let h = dtaOpen(c(name).as_ptr(), true);
                assert!(h >= 0, "{name}");
                if pos != 0 {
                    dtaSeek(h, pos as c_int, 0);
                }
                let mut buf = vec![0u8; size];
                assert_eq!(
                    dtaRead(h, buf.as_mut_ptr().cast(), size as c_int),
                    size as c_int
                );
                results.push(buf);
                dtaClose(h);
            }
        }
        if expect_from_archive {
            let all = files();
            for (i, &(name, pos, size)) in script.iter().enumerate() {
                let contents = &all.iter().find(|f| f.0 == name).unwrap().1;
                assert_eq!(results[i], contents[pos..pos + size], "{name}");
            }
        }
        results
    };

    unsafe { assert!(dtaCreateFQL(fql.as_ptr())) };
    let recorded = run(true);
    dtaCloseFQL();
    assert!(std::fs::metadata(dir.join("load.fql")).unwrap().len() > 6);

    // Play back with the archive gone: everything comes from the FQL file.
    ERRORS.store(0, Ordering::SeqCst);
    let previous = dtaSetCallbackERR(Some(count_errors));
    unsafe { assert!(dtaFQLBegin(fql.as_ptr())) };
    let played = run(false);
    dtaFQLEnd();
    assert_eq!(played, recorded);
    assert_eq!(ERRORS.load(Ordering::SeqCst), 0);
    dtaSetCallbackERR(previous);
    release(archive);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn writing_logs_and_disk_files() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let dir = scratch("write");
    let target = dir.join("out.txt");
    let name = path_c(&target);
    std::fs::write(&target, b"old contents").unwrap();
    unsafe {
        // Through a temporary file that replaces the target on close.
        let h = dtaOpenWrite(name.as_ptr(), DTA_WRITE_TEMP_FILE | DTA_WRITE_CREATE_ALWAYS);
        assert!(h >= 0);
        assert!(dir.join("out.txt.tmp").exists());
        assert_eq!(dtaWrite(h, b"new\r\ntext".as_ptr().cast(), 9), 9);
        assert!(dtaFlush(h));
        assert_eq!(std::fs::read(&target).unwrap(), b"old contents");
        assert!(dtaClose(h));
        assert_eq!(std::fs::read(&target).unwrap(), b"new\r\ntext");
        assert!(!dir.join("out.txt.tmp").exists());

        // Read it back from disk, with random access over several buffers.
        let big = data(200_000, 9, false);
        let big_path = dir.join("big.bin");
        std::fs::write(&big_path, &big).unwrap();
        let h = dtaOpen(path_c(&big_path).as_ptr(), false);
        assert!(h >= 0);
        check_random_access(h, &big);
        let mut time = FileTime::default();
        assert!(dtaGetTime(h, &mut time, false));
        assert!(time.high > 0x01D0_0000, "a 21st-century FILETIME");
        dtaClose(h);

        // Seeking a file being written moves the file pointer.
        let h = dtaOpenWrite(name.as_ptr(), 0);
        assert_eq!(dtaSeek(h, 0, 2), 9);
        assert_eq!(dtaWrite(h, b"!".as_ptr().cast(), 1), 1);
        assert_eq!(dtaSeek(h, 0, 0), 0);
        assert_eq!(dtaWrite(h, b"N".as_ptr().cast(), 1), 1);
        dtaClose(h);
        assert_eq!(std::fs::read(&target).unwrap(), b"New\r\ntext!");

        // Bin2Text
        let mut text = *b"a\r\nb\r\n";
        assert_eq!(dtaBin2Text(text.as_mut_ptr().cast(), 6), 4);
        assert_eq!(&text[..4], b"a\nb\n");

        // A file log of the names opened under a directory or with an extension.
        let log_path = dir.join("files.log");
        let log = dtaOpenFileLog(path_c(&log_path).as_ptr(), DTA_WRITE_CREATE_ALWAYS);
        assert!(log >= 0);
        let dir_prefix = c(&format!(
            "{}{}",
            dir.to_str().unwrap(),
            std::path::MAIN_SEPARATOR
        ));
        assert!(dtaAddDir(log, dir_prefix.as_ptr()));
        assert!(dtaAddExtension(log, c("sav").as_ptr()));
        assert!(!dtaAddExtension(log, c("long").as_ptr()));
        assert!(dtaSetPathBeforeLogItems(log, c("pre:").as_ptr()));
        let h = dtaOpen(name.as_ptr(), false);
        dtaClose(h);
        assert!(dtaCloseFileLog(log));
        let logged = std::fs::read_to_string(&log_path).unwrap();
        assert_eq!(
            logged,
            format!("PRE:{}\r\n", target.to_str().unwrap().to_uppercase())
        );

        assert!(dtaDelete(name.as_ptr()));
        assert!(!target.exists());
        assert_eq!(dtaOpen(name.as_ptr(), false), -1);
    }
    let _ = std::fs::remove_dir_all(dir);
}
