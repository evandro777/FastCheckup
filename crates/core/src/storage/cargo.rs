//! Cargo's download folders. Cargo makes all of it again (`registry/src` from `registry/cache` without a network,
//! the others by downloading), so only the age tells whether a clean-up pays off. Never `bin`, `config.toml` or
//! `credentials.toml`: the folders are a fixed table, so a caller can only name a row, never a path.
use std::{
    fs, io,
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

use super::Item;
use crate::apps::{WALK_CAP, walk};

/// (id, folder under `~/.cargo`).
const FOLDERS: [(&str, &str); 3] = [
    ("registry-src", "registry/src"),
    ("registry-cache", "registry/cache"),
    ("git", "git"),
];

fn root(home: &Path) -> PathBuf {
    home.join(".cargo")
}

/// One row per folder that holds something. `newest` is the later of the files' dates and cargo's own record of the
/// last build (`.global-cache` is touched on every use), so a folder cargo still reads is not called old.
pub fn scan(home: &Path) -> Vec<Item> {
    let cargo = root(home);
    let used = fs::metadata(cargo.join(".global-cache"))
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs());
    FOLDERS
        .iter()
        .filter_map(|&(id, sub)| {
            let dir = cargo.join(sub);
            let (size, newest) = walk(&dir, &mut WALK_CAP.clone());
            (size > 0).then(|| Item {
                id: id.into(),
                size,
                newest: newest.max(used),
                path: dir.to_string_lossy().into_owned(),
            })
        })
        .collect()
}

/// The folder a row clears (for the command line the dialog shows).
pub fn path(home: &Path, id: &str) -> Option<PathBuf> {
    FOLDERS.iter().find(|f| f.0 == id).map(|f| root(home).join(f.1))
}

/// Deletes what is inside the folder, for good, and keeps the folder. Links are removed, never followed.
/// Keeps going after a failure and reports the first one.
pub fn clear(home: &Path, id: &str) -> io::Result<()> {
    let dir = path(home, id).ok_or_else(|| io::Error::other("unknown Cargo folder, scan again"))?;
    let mut first = Ok(());
    for e in fs::read_dir(&dir)?.flatten() {
        let p = e.path();
        let done = if fs::symlink_metadata(&p).is_ok_and(|m| m.is_dir()) {
            fs::remove_dir_all(&p)
        } else {
            fs::remove_file(&p)
        };
        if first.is_ok() {
            first = done;
        }
    }
    first
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_and_clear_touch_only_the_table() {
        let home = std::env::temp_dir().join(format!("fastcheckup-cargo-{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        let src = home.join(".cargo/registry/src/index-x/foo-1.0.0");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("lib.rs"), [0u8; 10]).unwrap();
        fs::create_dir_all(home.join(".cargo/bin")).unwrap();
        fs::write(home.join(".cargo/bin/tool"), [0u8; 10]).unwrap();
        fs::write(home.join(".cargo/credentials.toml"), "token").unwrap();

        let rows = scan(&home);
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0].id.as_str(), rows[0].size), ("registry-src", 10));

        assert!(clear(&home, "bin").is_err());
        clear(&home, "registry-src").unwrap();
        assert!(home.join(".cargo/registry/src").is_dir());
        assert!(!src.exists());
        assert!(home.join(".cargo/bin/tool").exists());
        assert!(home.join(".cargo/credentials.toml").exists());
        let _ = fs::remove_dir_all(&home);
    }
}
