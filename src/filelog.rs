//! File logs: text files listing the names opened with dtaOpen, filtered by directory
//! prefixes and extensions.

use crate::open::close;
use crate::state::*;
use crate::write::{open_write, write};

fn is_open_log(st: &State, log: i32) -> bool {
    st.file_logs
        .get(log as u32 as usize)
        .is_some_and(|l| l.handle >= 0)
}

fn write_log_line(st: &mut State, log: usize, file_name: &[u8]) {
    // (The original built the line in a 516-byte buffer.)
    let entry = &st.file_logs[log];
    let handle = entry.handle;
    let line = [c_str(&entry.path_before), c_str(file_name)].concat();
    write(st, handle, Some(&line));
    write(st, handle, Some(b"\r\n"));
}

/// Writes an opened name to the log that wants it. `file_name` is upper case.
pub fn record(st: &mut State, file_name: &[u8]) {
    let name = c_str(file_name);
    // The last log with a directory the name starts with ...
    let by_dir = st.file_logs.iter().rposition(|log| {
        log.dirs
            .iter()
            .any(|dir| name.len() >= dir.len() && strncmp(dir, name, dir.len()) == 0)
    });
    if let Some(log) = by_dir {
        write_log_line(st, log, name);
        return;
    }

    // ... else the last one with its extension.
    let extension = pack_extension(name);
    if let Some(log) = st
        .file_logs
        .iter()
        .rposition(|log| log.extensions.contains(&extension))
    {
        write_log_line(st, log, name);
    }
}

/// dtaOpenFileLog: opens a log (dtaOpenWrite flags); returns the log's index or -1.
pub fn open_file_log(file_name: &[u8], flags: i32) -> i32 {
    with_state(|st| {
        let handle = open_write(st, file_name, flags);
        if handle < 0 {
            return -1;
        }

        // Quirk kept from the original: the search from the end stops at the first log that is
        // still open (the test is inverted), so opening a second log takes over the last open
        // log's slot (and its filters) and leaves the old file open. Closed slots are not reused.
        match st.file_logs.iter().rposition(|log| log.handle != -1) {
            None => {
                st.file_logs.push(FileLog {
                    handle,
                    extensions: Vec::new(),
                    dirs: Vec::new(),
                    path_before: Vec::new(),
                });
                st.file_logs.len() as i32 - 1
            }
            Some(slot) => {
                st.file_logs[slot].handle = handle;
                slot as i32
            }
        }
    })
}

/// dtaCloseFileLog
pub fn close_file_log(log: i32) -> bool {
    with_state(|st| {
        if !is_open_log(st, log) {
            return false;
        }
        let handle = st.file_logs[log as usize].handle;
        close(st, handle);
        let entry = &mut st.file_logs[log as usize];
        entry.handle = -1;
        entry.extensions.clear();
        entry.dirs.clear();
        // (The original freed the prefix without clearing the pointer; setting a new prefix
        // on the closed log then freed it again.)
        entry.path_before.clear();
        true
    })
}

/// dtaAddDir: a log lists the names starting with one of its directories ...
pub fn add_dir(log: i32, dir: Option<&[u8]>) -> bool {
    with_state(|st| {
        let Some(dir) = dir else { return false };
        if !is_open_log(st, log) {
            return false;
        }
        let mut upper = dir.to_vec();
        upper_case(&mut upper);
        // Directories that are a prefix of the new one, or that it is a prefix of, are replaced.
        let dirs = &mut st.file_logs[log as usize].dirs;
        dirs.retain(|d| strncmp(d, &upper, d.len().min(upper.len())) != 0);
        dirs.push(upper);
        true
    })
}

/// dtaAddExtension: ... or with one of its extensions (at most 3 characters).
pub fn add_extension(log: i32, ext: Option<&[u8]>) -> bool {
    with_state(|st| {
        if !is_open_log(st, log) {
            return false;
        }
        let Some(packed) = ext.and_then(pack_extension_argument) else {
            return false;
        };
        let extensions = &mut st.file_logs[log as usize].extensions;
        if !extensions.contains(&packed) {
            extensions.push(packed);
        }
        true
    })
}

/// dtaSetPathBeforeLogItems: prefix written before every name of the log.
pub fn set_path_before(log: i32, path: Option<&[u8]>) -> bool {
    with_state(|st| {
        let Some(entry) = st.file_logs.get_mut(log as u32 as usize) else {
            return false;
        };
        entry.path_before.clear();
        if let Some(path) = path {
            entry.path_before = path.to_vec();
            upper_case(&mut entry.path_before);
        }
        true
    })
}
