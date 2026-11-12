//! (port) Mod archives: every `.dta` archive of the `Mods` folder is mounted ahead of the
//! host's archives, so a file in a mod replaces the game's copy. Nothing in the host has to
//! change: the host's first `dtaCreate` mounts the mods, and they are released again with
//! the host's last archive.
//!
//! The `Mods` folder is the one next to the executable, or the folder named by the
//! `RW_DATA_MODS_DIR` environment variable. (The DLL's own folder cannot be found without
//! the Win32 API; the game, its dedicated server and rw_data.dll all sit in one folder.)
//!
//! Mod archives are not encrypted: they are packed with a blank key
//! (`dta_pack.py MyMod Mods/MyMod.dta --key blank`). One packed with a key is rejected: its
//! ISD1 header and table fail their checksums with the blank key. (ISD0 archives have no
//! checksums, so a wrong key goes unnoticed there; dta_pack.py writes ISD1.)
//!
//! The first archive mounted is searched first, so it wins when two mods hold the same file.
//! The order is alphabetical (ignoring case) unless `Mods/load_order.txt` says otherwise:
//!
//! ```text
//! # Comments start with '#'; blank lines are skipped.
//! prefer_archives = yes      every archive is searched before loose files on disk
//! HighestPriority.dta        archives in search order, the first one wins
//! Second                     (".dta" may be left out; names ignore case)
//! +Textures.dta              searched before loose files on disk (the other archives after)
//! -Disabled.dta              not mounted at all
//! ```
//!
//! Archives in the folder that the file does not name are mounted after the named ones, in
//! alphabetical order. `prefer_archives` is the global switch of
//! `C_DtaArchive::SetPreferArchives`: it applies to every archive, the game's own included.
//! Without it a loose file on disk overrides any archive except the ones marked '+'.
//!
//! What was mounted, and any problem, is written to `Mods/mods.log` (rewritten by the first
//! mount of a process, appended to by later ones). Errors of the mod archives while they are
//! mounted go to the log, not to the host's error callback.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use crate::archive;
use crate::state::*;

/// Overrides the location of the Mods folder.
pub const MODS_DIR_VARIABLE: &str = "RW_DATA_MODS_DIR";
const LOAD_ORDER: &str = "load_order.txt";
const LOG: &str = "mods.log";

/// The Mods folder: `RW_DATA_MODS_DIR`, or `Mods` next to the executable.
fn mods_dir() -> Option<PathBuf> {
    match std::env::var_os(MODS_DIR_VARIABLE) {
        Some(dir) if !dir.is_empty() => Some(PathBuf::from(dir)),
        _ => Some(std::env::current_exe().ok()?.parent()?.join("Mods")),
    }
}

/// Mods/mods.log; writing failures are ignored.
struct Log(Option<File>);

impl Log {
    fn open(st: &mut State, dir: &Path) -> Log {
        let mut options = OpenOptions::new();
        if st.mods_log_started {
            options.append(true);
        } else {
            options.write(true).truncate(true);
        }
        st.mods_log_started = true;
        Log(options.create(true).open(dir.join(LOG)).ok())
    }

    fn line(&mut self, text: &str) {
        if let Some(file) = &mut self.0 {
            let _ = writeln!(file, "{text}");
        }
    }
}

#[derive(Default)]
struct LoadOrder {
    /// named archives in search order, and whether they are marked '+'
    order: Vec<(String, bool)>,
    /// archives named with a leading '-'
    disabled: Vec<String>,
    prefer_archives: Option<bool>,
}

fn same_name(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn contains_name(names: &[String], name: &str) -> bool {
    names.iter().any(|n| same_name(n, name))
}

/// "Name" -> "Name.dta"; a name that already ends with ".dta" is kept.
fn with_dta_extension(name: &str) -> String {
    let b = name.as_bytes();
    if b.len() >= 4 && b[b.len() - 4..].eq_ignore_ascii_case(b".dta") {
        name.to_string()
    } else {
        format!("{name}.dta")
    }
}

/// Parses Mods/load_order.txt (see the module comment).
fn parse_load_order(text: &str, log: &mut Log) -> LoadOrder {
    let mut config = LoadOrder::default();
    for (number, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        // Settings: "name = value". Only known setting names are taken as settings, so an
        // archive whose name holds '=' still works.
        if let Some((key, value)) = line.split_once('=') {
            if same_name(key.trim(), "prefer_archives") {
                let value = value.trim();
                match value.to_ascii_lowercase().as_str() {
                    "yes" | "true" | "on" | "1" => config.prefer_archives = Some(true),
                    "no" | "false" | "off" | "0" => config.prefer_archives = Some(false),
                    _ => log.line(&format!(
                        "ERROR: {LOAD_ORDER} line {}: prefer_archives must be yes or no, not '{value}'",
                        number + 1
                    )),
                }
                continue;
            }
        }

        if let Some(name) = line.strip_prefix('-') {
            let name = name.trim();
            if !name.is_empty() && !contains_name(&config.disabled, &with_dta_extension(name)) {
                config.disabled.push(with_dta_extension(name));
            }
            continue;
        }
        let (name, prefer) = match line.strip_prefix('+') {
            Some(name) => (name.trim(), true),
            None => (line, false),
        };
        if name.is_empty() {
            continue;
        }
        let name = with_dta_extension(name);
        match config.order.iter_mut().find(|(n, _)| same_name(n, &name)) {
            Some(entry) => entry.1 |= prefer,
            None => config.order.push((name, prefer)),
        }
    }
    config
}

/// The names of the .dta files in the folder, alphabetical ignoring case.
fn find_archives(dir: &Path, log: &mut Log) -> Vec<String> {
    let mut names = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return names;
    };
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|t| !t.is_dir()) {
            continue;
        }
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            log.line(&format!(
                "ERROR: '{}' skipped: the name is not valid Unicode",
                file_name.to_string_lossy()
            ));
            continue;
        };
        let b = name.as_bytes();
        if b.len() > 4 && b[b.len() - 4..].eq_ignore_ascii_case(b".dta") {
            names.push(name.to_string());
        }
    }
    names.sort_by_key(|n| n.to_ascii_lowercase());
    names
}

fn error_names(errors: &[i32]) -> String {
    let names: Vec<&str> = errors
        .iter()
        .map(|&e| match e {
            DTA_ERROR_OPEN => "open",
            DTA_ERROR_SIZE => "size",
            DTA_ERROR_CHECKSUM => "checksum",
            DTA_ERROR_FORMAT => "format",
            DTA_ERROR_MEMORY => "memory",
            DTA_ERROR_READ => "read",
            _ => "?",
        })
        .collect();
    names.join(", ")
}

/// Mounts the archives of the Mods folder, appended to the search order. Called under the
/// lock by the host's first dtaCreate (archive::create), which then moves them ahead of
/// the host's archive.
pub fn mount(st: &mut State) {
    st.mods_mounted = true;
    let Some(dir) = mods_dir() else {
        return;
    };
    if !dir.is_dir() {
        return;
    }
    let mut log = Log::open(st, &dir);
    log.line(&format!("Mods folder: {}", dir.display()));

    // Read from disk, not through the archives, so no archive can supply it.
    let config = match fs::read(dir.join(LOAD_ORDER)) {
        Ok(text) => parse_load_order(&String::from_utf8_lossy(&text), &mut log),
        Err(_) => LoadOrder::default(),
    };
    let found = find_archives(&dir, &mut log);

    // Named archives first, in the file's order, then the rest alphabetically.
    let mut order: Vec<(String, bool)> = Vec::new();
    for (name, prefer) in &config.order {
        if contains_name(&config.disabled, name) {
            continue;
        }
        match found.iter().find(|f| same_name(f, name)) {
            Some(file) => order.push((file.clone(), *prefer)),
            None => log.line(&format!(
                "ERROR: '{name}' is in {LOAD_ORDER} but not in the Mods folder"
            )),
        }
    }
    for file in &found {
        if !order.iter().any(|(n, _)| same_name(n, file)) && !contains_name(&config.disabled, file)
        {
            order.push((file.clone(), false));
        }
    }

    for (file, prefer) in order {
        let path = dir.join(&file);
        let Some(name) = path.to_str() else {
            log.line(&format!(
                "ERROR: '{}' skipped: the path is not valid Unicode",
                path.display()
            ));
            continue;
        };
        // The errors of the mod archives go to the log, not to the host's callback.
        st.captured_errors = Some(Vec::new());
        let a = archive::create_locked(st, name.as_bytes());
        if a.is_null() {
            let errors = st.captured_errors.take().unwrap_or_default();
            log.line(&format!(
                "ERROR: '{name}' is not a .dta archive ({})",
                error_names(&errors)
            ));
            continue;
        }
        // SAFETY: `a` is a live archive object.
        let loaded = unsafe { archive::load_file_table(st, &mut *a, a, 0) };
        let errors = st.captured_errors.take().unwrap_or_default();
        if !loaded || !errors.is_empty() {
            log.line(&format!(
                "ERROR: '{name}' could not be read: it must be packed with a blank key ({})",
                error_names(&errors)
            ));
            // SAFETY: `a` is live and holds the one reference of construct.
            unsafe { archive::release_locked(st, a) };
            continue;
        }
        if prefer {
            if let Some(slot) = st.search_order.iter_mut().find(|s| s.archive == a) {
                slot.prefer = true;
            }
        }
        st.mods.push(a);
        MOD_ARCHIVES.fetch_add(1, Ordering::Relaxed);
        log.line(&format!(
            "Mod archive {}: {name}{}",
            st.mods.len(),
            if prefer {
                " (searched before loose files)"
            } else {
                ""
            }
        ));
    }
    st.captured_errors = None;

    for file in &found {
        if contains_name(&config.disabled, file) {
            log.line(&format!(
                "Mod archive disabled: {}",
                dir.join(file).display()
            ));
        }
    }

    if let Some(prefer) = config.prefer_archives {
        st.mods_saved_prefer = Some(std::mem::replace(&mut st.prefer_archives, prefer));
        log.line(&format!(
            "prefer_archives = {}",
            if prefer { "yes" } else { "no" }
        ));
    }
}

/// Releases the mod archives (when the host's last archive is gone) and restores
/// prefer_archives. The next dtaCreate mounts them again.
pub fn unmount(st: &mut State) {
    st.mods_mounted = false;
    if let Some(prefer) = st.mods_saved_prefer.take() {
        st.prefer_archives = prefer;
    }
    for a in std::mem::take(&mut st.mods) {
        MOD_ARCHIVES.fetch_sub(1, Ordering::Relaxed);
        // SAFETY: the library holds one reference of each mod archive.
        unsafe { archive::release_locked(st, a) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_order_file() {
        let text = "# comment\r\n\
                    prefer_archives = Yes  # setting\r\n\
                    First.DTA\n\
                    second\n\
                    +Third\n\
                    \n\
                    -Off.dta\n\
                    -off\n\
                    first.dta\n\
                    +second.dta\n\
                    a=b.dta\n";
        let config = parse_load_order(text, &mut Log(None));
        assert_eq!(config.prefer_archives, Some(true));
        assert_eq!(
            config.order,
            vec![
                ("First.DTA".to_string(), false),
                ("second.dta".to_string(), true),
                ("Third.dta".to_string(), true),
                ("a=b.dta".to_string(), false),
            ]
        );
        assert_eq!(config.disabled, vec!["Off.dta".to_string()]);
    }
}
