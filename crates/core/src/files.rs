//! Files only the user can read, written atomically, and a bad file moved aside without losing an older backup.
//! The same file is in every Fast app (FastHello holds the master): change it there and copy it to the others.
use std::{
    fs,
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

/// `<file name>.bad.<nanoseconds>`: where an unreadable file is kept. A name that is already taken is skipped, so a
/// second bad file (even within the same clock tick) never replaces the first backup.
pub fn backup_path(path: &Path) -> PathBuf {
    let mut stamp = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    loop {
        let mut name = path.file_name().unwrap_or_default().to_os_string();
        name.push(format!(".bad.{stamp}"));
        let candidate = path.with_file_name(name);
        if !candidate.exists() {
            return candidate;
        }
        stamp += 1;
    }
}

/// Reads and parses `path`. A missing file gives the default; one that cannot be read (bad UTF-8, permissions) or parsed
/// is moved to `backup_path` and the default is used, so the next save never overwrites what the user wrote.
/// The flag says the file was read and parsed (false for a missing or backed-up one).
pub fn read_or_backup<T: Default>(path: &Path, parse: impl FnOnce(&str) -> Result<T, String>) -> (T, bool) {
    let read = match fs::read_to_string(path) {
        Ok(text) => parse(&text).map(|v| (v, true)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return (T::default(), false),
        Err(e) => Err(e.to_string()),
    };
    read.unwrap_or_else(|e| {
        let bad = backup_path(path);
        eprintln!(
            "{} is invalid ({e}); kept as {}, using defaults",
            path.display(),
            bad.display()
        );
        let _ = fs::rename(path, bad);
        (T::default(), false)
    })
}

/// Creates `dir` (and parents) readable only by the user, and tightens one made by an older version (0755): the
/// files in it can hold passwords and tokens.
pub fn create_private_dir(dir: &Path) -> io::Result<()> {
    fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
}

/// Writes `data` to a file only the user can read. The mode is also set on an existing file (a leftover `.tmp`).
pub fn write_private(path: &Path, data: impl AsRef<[u8]>) -> io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(data.as_ref())
}

/// Writes `data` to `path` through a private temp file and a rename, so a crash never leaves half a file. The folder
/// is created (0700) when missing. The pid in the temp name keeps two running copies from writing the same file.
pub fn write_atomic(path: &Path, data: impl AsRef<[u8]>) -> io::Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        create_private_dir(dir)?;
    }
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{}.tmp", std::process::id()));
    let tmp = path.with_file_name(name);
    write_private(&tmp, data)
        .and_then(|()| fs::rename(&tmp, path))
        .inspect_err(|_| {
            let _ = fs::remove_file(&tmp);
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "{}-files-{name}-{}",
            env!("CARGO_PKG_NAME"),
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn private_dir_and_file_are_tightened() {
        let dir = temp_dir("perm");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let file = dir.join("x.tmp");
        fs::write(&file, "old").unwrap(); // 0644 leftover
        create_private_dir(&dir).unwrap();
        write_private(&file, "new").unwrap();
        assert_eq!((mode(&dir), mode(&file)), (0o700, 0o600));
        assert_eq!(fs::read_to_string(&file).unwrap(), "new");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn atomic_write_is_private_replaces_the_file_and_leaves_no_temp() {
        let dir = temp_dir("atomic");
        let file = dir.join("sub/p.json");
        write_atomic(&file, "one").unwrap();
        write_atomic(&file, "two").unwrap();
        assert_eq!(fs::read_to_string(&file).unwrap(), "two");
        assert_eq!((mode(&file), mode(file.parent().unwrap())), (0o600, 0o700));
        assert_eq!(
            fs::read_dir(file.parent().unwrap()).unwrap().count(),
            1,
            "no .tmp left behind"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_second_bad_file_never_replaces_the_first_backup() {
        let dir = temp_dir("bad");
        let file = dir.join("p.json");
        let parse = |t: &str| t.parse::<u32>().map_err(|e| e.to_string());
        assert_eq!(read_or_backup(&file, parse), (0, false), "missing: default, no backup");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
        for text in ["first", "second"] {
            fs::write(&file, text).unwrap();
            assert_eq!(read_or_backup(&file, parse), (0, false));
            assert!(!file.exists(), "moved aside, so the next save cannot overwrite it");
        }
        let mut kept: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| fs::read_to_string(e.path()).unwrap())
            .collect();
        kept.sort();
        assert_eq!(kept, ["first", "second"]);
        let name = backup_path(Path::new("/x/p.json"));
        assert!(name.to_string_lossy().starts_with("/x/p.json.bad."));
        fs::write(&file, "7").unwrap();
        assert_eq!(read_or_backup(&file, parse), (7, true), "a good file still loads");
        let _ = fs::remove_dir_all(dir);
    }
}
