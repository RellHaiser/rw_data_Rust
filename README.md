# rw_data — Rust port

A Rust rewrite of the C++ source port of `rw_data.dll`, the data-file layer of Hidden & Dangerous 2.
It covers the virtual file system over the `.dta` archives (lookup, decryption, and LZSS / LZ4 / WAV
block decompression), plain file writing, file logs and FQL load recordings.

The crate builds into a drop-in replacement for the DLL:

* the same 26 functions with the same C interface ([include/rw_data.h](include/rw_data.h)), plus
  `dtaModsMounted` (ordinal 27) for the [mod archives](#mods);
* on 32-bit Windows they are `__stdcall` and exported under the original decorated names and
  ordinals (`_dtaOpen@8` @18, …; see [build.rs](build.rs));
* the archive object keeps the MSVC 6 virtual-table layout with `__thiscall` methods, so the
  game, `LS3DF.dll`, `LS3DRF.dll` and the dedicated server can use it unchanged.

The crate depends on the standard library only, with no other crates. Every Win32 call of the
original is replaced by its `std` equivalent (see the table in [src/platform.rs](src/platform.rs)).
On targets other than 32-bit x86 the same functions use the platform's C calling convention, so
the library also builds as `librw_data.so` / `.dylib`.

How the functions work, the archive and FQL file formats and the algorithms are described in
[docs/rw_data_functions.md](docs/rw_data_functions.md), the documentation of the C++ port. Its
function addresses and file names refer to the C++ sources.

## Building

```bash
cargo build --release --target i686-pc-windows-msvc
```

That is the game's 32-bit DLL: `target/i686-pc-windows-msvc/release/rw_data.dll`. A plain
`cargo build --release` builds for the host (64-bit Windows, Linux, macOS).

```bash
cargo test
```

The end-to-end tests in [tests/archive.rs](tests/archive.rs) pack archives with
[tools/dta_pack.py](tools/dta_pack.py) and need Python 3.9+ on the PATH (they are skipped
without it).

## Mods

The DLL mounts every `.dta` archive of the `Mods` folder next to the executable ahead of the
game's own archives, so a file in a mod replaces the game's copy. Nothing in the executable has
to change: the host's first `dtaCreate` mounts the mods before returning, and they are released
again with the host's last archive (a later `dtaCreate` mounts them again, reading the folder
afresh). Every program that uses the DLL gets the mods, the dedicated server included. The
environment variable `RW_DATA_MODS_DIR` names another folder.

Mod archives are not encrypted: pack them with a blank key.

```bash
python tools/dta_pack.py MyMod Mods/MyMod.dta --key blank
```

When two mods hold the same file, the archive mounted first wins. Archives are mounted in
alphabetical order (ignoring case), unless `Mods/load_order.txt` says otherwise:

```
# Comments start with '#'; blank lines are skipped.
prefer_archives = yes      # every archive is searched before loose files on disk (default: no)
HighestPriority.dta        # mounted first: wins over everything below
Second                     # ".dta" may be left out; names ignore case
+Textures.dta              # this archive is searched before loose files on disk
-Disabled.dta              # not mounted
```

Archives the file does not name are mounted after the named ones, in alphabetical order.

* `prefer_archives` is the global switch of `C_DtaArchive::SetPreferArchives`: with it every
  archive (the game's own too) is searched before loose files. Without it a loose file on disk
  overrides any archive, as in the original game. It is set back when the mods are released.
* `+` does the same for one mod archive only: `dtaOpen` searches the `+` archives, then the
  disk, then the other archives. (An explicit `archivesFirst` or `prefer_archives` still
  searches every archive first.)

What was mounted, and every problem (a named archive that is missing, a file that is not an
archive, an archive packed with a key), is written to `Mods/mods.log`. The first mount of a
process rewrites it; later ones append. Errors while mounting mods go to that log, not the
host's error callback. Errors reading a mod archive later go to the callback, like those of
any other archive.

An archive packed with a key is detected by its ISD1 checksums failing with the blank key. ISD0
archives have no checksums, so a keyed ISD0 mod may be mounted and read as garbage. `dta_pack.py`
writes ISD1.

Notes for hosts:

* `dtaModsMounted()` returns how many mod archives are mounted now. A host that mounts mods
  itself (for use with the original DLL) can look the export up and skip its own mounting
  when it exists.
* The leak report of `dtaDumpMemoryLeaks` leaves the mod archives out: they belong to the DLL.
* A host that moves its own archive to position 0 with `SetPriority` puts it ahead of the mods.
* The folder is found next to the executable, not next to the DLL, because the DLL's own path
  cannot be found without the Win32 API. The game, its dedicated server and `rw_data.dll` share
  one folder.

## Layout

| file | contents (C++ port file) |
|---|---|
| `src/lib.rs` | the exported functions |
| `src/state.rs` | global state, the re-entrant lock, formats (`dta_globals.cpp`, `dta_internal.h`) |
| `src/archive.rs` | the archive object, its virtual table, `dtaCreate` (`dta_archive.cpp`) |
| `src/open.rs` | archive lookup, `dtaOpen`, `dtaClose`, `dtaGetPackDirectAccess` (`dta_open.cpp`) |
| `src/read.rs` | `dtaRead`, `dtaSeek`, `dtaGetTime` (`dta_read.cpp`) |
| `src/write.rs` | `dtaOpenWrite`, `dtaWrite`, `dtaFlush`, `dtaBin2Text` (`dta_write.cpp`) |
| `src/filelog.rs`, `src/fql.rs` | file logs, FQL recording / playback |
| `src/crypt.rs`, `src/lzss.rs`, `src/lz4.rs`, `src/wav.rs` | cipher, checksum and codecs |
| `src/platform.rs` | the operating-system side, on `std` only |
| `src/mods.rs` | the Mods folder (port only) |

## Differences from the C++ port

The port keeps the original's behaviour, quirks included (for example the inverted test in
`dtaOpenFileLog`, and handle 0 being left open by `dtaGetPackDirectAccess`). It differs in these
places:

* **Buffer overrun fixed.** When the whole blocks of a long `dtaRead` are damaged so that they
  decode to more than 32 KB, the original and the C++ port copy the last partial block past the
  caller's buffer and return more bytes than requested. The Rust port stops at the end of the
  buffer.
* **No crashes on wild sizes.** A wrong key or a damaged header gives a huge table size or
  block count. The original fails to allocate and crashes; this port reports
  `DTA_ERROR_MEMORY` (5) and fails the call.
* **FQL playback past the end** fills the rest with zeros. The original loops forever.
* **Error callbacks** fire at the end of the call that caused them, still under the lock and in
  the same order. This lets a callback call back into the library safely.
* `dtaFQLBegin` / `dtaFQLEnd` take the lock (the original did not).
* A failed `dtaCreate` closes the file it opened. The original leaked the handle, though it
  still leaks the small object, as before.
* The leak report of `dtaDumpMemoryLeaks` goes to standard error, not a message box. It runs
  from `DllMain` on Windows and the ELF finalizer on Linux. macOS has no hook for it.
* Outside Windows: `dtaGetPackDirectAccess` returns a file descriptor. Sharing modes, the hidden
  attribute and random-access hints have no equivalent and are skipped. File names have their
  `\` separators turned into `/`. File-system lookups are case-sensitive, but archive lookups are
  not.
* On Windows, file names that are not valid UTF-8 are read as Latin-1, because the ANSI code
  page cannot be queried without the Win32 API. Plain ASCII names are unaffected.
* The 32-bit DLL also exports `DllMain`.
* The mod archives of the `Mods` folder ([above](#mods)) and `dtaModsMounted` are new.

## Verification

Besides `cargo test`, the port was compared with the C++ port. Both were built as 32-bit DLLs
and driven through the same scenarios. The scenarios covered 128 archives (LZSS, LZ4 and
stored), most with random damage to the block data or the block tables. They ran 95,000 random
seeks and reads with both key methods, plus an FQL recording and its playback. Return values,
read data and the sequence of error callbacks were identical, and the FQL files were
byte-identical. The only differences followed the buffer overruns described above.

Not covered: ISD0 archives and real compressed-WAV files, because the packer writes neither.
Those code paths are straight ports and are exercised only through damaged block-type tables.
