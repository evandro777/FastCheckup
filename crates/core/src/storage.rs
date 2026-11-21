//! Storage module: disk usage, the biggest folders and files in $HOME, build output, old installers in Downloads,
//! Trash, caches, the journal and Docker. Parsers take plain
//! text so tests need no journalctl or docker. Every action re-checks the target before it writes.
use std::{
    collections::HashMap,
    ffi::OsString,
    fs, io,
    path::{Component, Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicBool, Ordering::Relaxed},
    time::UNIX_EPOCH,
};

use walkdir::WalkDir;

pub mod browsers;
pub mod cargo;
pub mod flatpak;
mod steam;
pub use steam::{Keep, Version};
use steam::{all_old_versions, leftover_dirs, steam_games, steam_leftovers, steam_libraries, steam_roots};

use crate::{
    apps::{APT_GET, WALK_CAP, command_ok, command_read, now, parse_size, plain, trash_in, walk},
    services::{pkexec_output, pkexec_run},
};

const JOURNALCTL: &str = "/usr/bin/journalctl";
/// What `journalctl --vacuum-size` keeps.
pub const JOURNAL_KEEP: u64 = 100 * 1024 * 1024;
const INSTALLER_MIN: u64 = 20_000_000;
const CACHE_MIN: u64 = 1_000_000;
const CACHE_TOP: usize = 15;
const INSTALLER_EXT: [&str; 13] = [
    ".deb",
    ".appimage",
    ".run",
    ".iso",
    ".exe",
    ".msi",
    ".zip",
    ".7z",
    ".rar",
    ".tgz",
    ".tar.gz",
    ".tar.xz",
    ".tar.bz2",
];
/// Entries visited looking for build folders.
/// shortcut: a home with more files than this is only partly searched, when users complain add a progress stream.
const BUILD_CAP: u32 = 1_000_000;
/// Smallest file listed as one of the biggest, and how many are listed.
const BIG_MIN: u64 = 100_000_000;
const BIG_TOP: usize = 20;
const FOLDER_TOP: usize = 10;
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Item {
    /// Full path for build output, a plain file or folder name for the others. The UI hands it back to the actions.
    pub id: String,
    pub size: u64,
    pub newest: Option<u64>,
    /// Folder or file the "Open" button shows; empty when the row has none.
    pub path: String,
}

/// One row of `docker system df`; the strings are Docker's own (`1.2GB`).
#[derive(Clone, Debug, PartialEq)]
pub struct DockerRow {
    pub kind: String,
    pub size: String,
    pub reclaimable: String,
    pub reclaimable_bytes: u64,
}

/// One mounted filesystem from `df`.
#[derive(Clone, Debug, PartialEq)]
pub struct Mount {
    pub path: String,
    pub total: u64,
    pub used: u64,
}

#[derive(Default, Debug)]
pub struct Scan {
    /// Every version of a tool (`id` = `tool/version`) with why it stays; only `Keep::No` can go to the Trash.
    pub old_versions: Vec<Version>,
    /// Wine prefix and shader cache of an uninstalled Steam game (`id` = `#appid`, `path` = the prefix folder).
    pub steam_leftovers: Vec<Item>,
    pub mounts: Vec<Mount>,
    pub builds: Vec<Item>,
    /// `__pycache__` folders per project (`id` = `path` = the project folder, `size` = all its caches).
    pub pycaches: Vec<Item>,
    /// Cache, crash reports and AI models per installed browser (`id` = browser id, `path` = its profile folder).
    pub browsers: Vec<Item>,
    /// Cargo's registry source, registry downloads and git checkouts (`id` as in `cargo::FOLDERS`, `newest` = last use).
    pub cargo: Vec<Item>,
    /// `~/.var/app/<id>/cache` of Flatpak apps (`id` = app id, `path` = the cache folder), 1 MB and up.
    pub flatpak_caches: Vec<Item>,
    pub installers: Vec<Item>,
    pub caches: Vec<Item>,
    /// Home Trash entries deleted more than `usage_days` days ago (`id` = name in `Trash/files`, `newest` = deletion).
    pub old_trash: Vec<Item>,
    pub trash_size: u64,
    pub trash_count: usize,
    pub journal: u64,
    pub coredumps: Coredumps,
    /// Size and count of the rotated logs in `/var/log`.
    pub rotated_logs: (u64, usize),
    /// Package files APT keeps in `/var/cache/apt/archives`.
    pub apt_cache: u64,
    /// Timeshift snapshot names (their dates), oldest first. Empty when Timeshift is absent or its folder is not readable.
    pub snapshots: Vec<String>,
    /// Timeshift has a config file, so a snapshot folder that reads empty may just be unreadable without root.
    pub timeshift: bool,
    /// Empty when Docker is missing or the user may not talk to it.
    pub docker: Vec<DockerRow>,
}

/// `XDG_DOWNLOAD_DIR="$HOME/Transferências"` from `user-dirs.dirs`; only `$HOME/...` or absolute values are accepted.
fn parse_user_dir(text: &str, home: &Path) -> Option<PathBuf> {
    let value = text.lines().find_map(|l| l.trim().strip_prefix("XDG_DOWNLOAD_DIR="))?;
    let value = value.trim().trim_matches('"');
    match value.strip_prefix("$HOME/") {
        Some(rest) if plain_path(rest) => Some(home.join(rest)),
        _ if Path::new(value).is_absolute() && plain_path(value) => Some(PathBuf::from(value)),
        _ => None,
    }
}

fn plain_path(p: &str) -> bool {
    !p.is_empty() && !Path::new(p).components().any(|c| c == Component::ParentDir)
}

pub fn downloads(home: &Path) -> PathBuf {
    fs::read_to_string(home.join(".config/user-dirs.dirs"))
        .ok()
        .and_then(|t| parse_user_dir(&t, home))
        .unwrap_or_else(|| home.join("Downloads"))
}

fn cache_dir(home: &Path) -> PathBuf {
    home.join(".cache")
}

fn trash_files(home: &Path) -> PathBuf {
    home.join(".local/share/Trash/files")
}

fn trash_info(home: &Path) -> PathBuf {
    home.join(".local/share/Trash/info")
}

/// `DeletionDate=2026-11-09T11:17:04` of a `.trashinfo` as epoch seconds. `None` when missing or malformed, so such an
/// entry is never called old. shortcut: the local time is read as UTC (off by hours), harmless against a limit of days.
fn trash_date(info: &str) -> Option<u64> {
    let v = info.lines().find_map(|l| l.strip_prefix("DeletionDate="))?.trim();
    let (d, t) = v.split_once('T')?;
    stamp(d, t, '-', ':')
}

/// `2026-11-09` + `11:17:04` (separators given) as epoch seconds, local time read as UTC. Shared by Trash dates and
/// Timeshift snapshot names (`2026-11-09_11-17-04`).
fn stamp(d: &str, t: &str, dsep: char, tsep: char) -> Option<u64> {
    let num = |s: &str| s.parse::<i64>().ok();
    let mut d = d.split(dsep).map(num);
    let (y, m, day) = (d.next()??, d.next()??, d.next()??);
    let mut t = t.split(tsep).map(num);
    let (h, mi, s) = (t.next()??, t.next()??, t.next()??);
    if !(1..=12).contains(&m) || !(1..=31).contains(&day) || !(0..24).contains(&h) || !(0..60).contains(&mi) {
        return None;
    }
    // Days since 1970-01-01 (Howard Hinnant's civil-date algorithm).
    let y = if m <= 2 { y - 1 } else { y };
    let (era, month) = (y.div_euclid(400), if m > 2 { m - 3 } else { m + 9 });
    let yoe = y - era * 400;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + (153 * month + 2) / 5 + day - 1;
    u64::try_from((era * 146_097 + doe - 719_468) * 86_400 + h * 3600 + mi * 60 + s).ok()
}

fn old_cutoff(now: u64, days: u32) -> u64 {
    now.saturating_sub(u64::from(days) * 86_400)
}

/// Epoch second before which something is "old" (`days` ago).
pub fn cutoff(days: u32) -> u64 {
    old_cutoff(now(), days)
}

/// Trash entries deleted at or before the cutoff, biggest first. Names with a `/` cannot come from a real Trash and are skipped.
fn old_trash(home: &Path, now: u64, days: u32) -> Vec<Item> {
    let (cutoff, files) = (old_cutoff(now, days), trash_files(home));
    let mut out: Vec<Item> = fs::read_dir(trash_info(home))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().strip_suffix(".trashinfo")?.to_string();
            let secs = trash_date(&fs::read_to_string(e.path()).ok()?).filter(|s| *s <= cutoff)?;
            let meta = fs::symlink_metadata(files.join(&name)).ok().filter(|_| plain(&name))?;
            let size = if meta.is_dir() {
                walk(&files.join(&name), &mut WALK_CAP.clone()).0
            } else {
                meta.len()
            };
            Some(Item {
                id: name,
                size,
                newest: Some(secs),
                ..Default::default()
            })
        })
        .collect();
    out.sort_by_key(|i| std::cmp::Reverse(i.size));
    out
}

/// Deletes one old entry of the home Trash for good (its file and its `.trashinfo`). Re-checked: the date is read again,
/// so an entry trashed again under the same name since the scan stays. Links are removed, never followed.
pub fn delete_trash_entry(home: &Path, name: &str, days: u32) -> io::Result<()> {
    let info = trash_info(home).join(format!("{name}.trashinfo"));
    let old = plain(name)
        && fs::read_to_string(&info)
            .ok()
            .and_then(|t| trash_date(&t))
            .is_some_and(|s| s <= old_cutoff(now(), days));
    if !old {
        return Err(io::Error::other("not an old Trash entry any more, scan again"));
    }
    let path = trash_files(home).join(name);
    match fs::symlink_metadata(&path) {
        Ok(m) if m.is_dir() => fs::remove_dir_all(&path)?,
        Ok(_) => fs::remove_file(&path)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        // Any other error: keep the .trashinfo, or the file is left in Trash with no record.
        Err(e) => return Err(e),
    }
    fs::remove_file(info)
}

/// The Trash command line shown for `delete_trash_entry`.
pub fn trash_entry_command(home: &Path, name: &str) -> String {
    // Single quotes: Trash names can hold spaces and `$`; a `'` inside is closed, escaped and reopened.
    let quote = |p: PathBuf| format!("'{}'", p.to_string_lossy().replace('\'', r"'\''"));
    format!(
        "rm -r {} {}",
        quote(trash_files(home).join(name)),
        quote(trash_info(home).join(format!("{name}.trashinfo")))
    )
}

/// One root step of the bulk clean-up. Fixed text, no ids, so nothing needs quoting.
fn root_step(action: i32) -> Option<String> {
    Some(match action {
        3 => format!("{APT_GET} autoremove -y"),
        16 => format!("{APT_GET} clean"),
        10 => format!("{JOURNALCTL} --vacuum-size=100M"),
        // `\*` stays literal inside the single quotes of the shown command and reaches `find` as `*`.
        22 => format!("/usr/bin/find {COREDUMP_DIR} -maxdepth 1 -type f -name core.\\* -delete"),
        // Must select the same names as `is_rotated`. Same shell escaping as step 22.
        24 => format!(
            "/usr/bin/find {LOG_DIR} -maxdepth {LOG_DEPTH} -type f \\( -name \\*.gz -o -name \\*.xz -o -name \\*.\\[0-9\\] -o -name \\*.\\[0-9\\]\\[0-9\\] \\) -delete"
        ),
        _ => return None,
    })
}

/// Every step is followed by a marker line with its exit code, and none stops the next: a failed step must not hide
/// the rest. The `\n` keeps a marker on its own line when the program's output has no final newline.
pub fn root_script(actions: &[i32]) -> String {
    actions
        .iter()
        .filter_map(|a| Some(format!("{} 2>&1; printf \"\\n@@ {a} %s\\n\" $?", root_step(*a)?)))
        .collect::<Vec<_>>()
        .join("; ")
}

/// The line shown in the confirm dialog: built from the same script that `run_root` executes.
pub fn root_command(actions: &[i32]) -> String {
    format!("pkexec /bin/sh -c '{}'", root_script(actions))
}

/// Result per root step from the script's output; a missing marker is a failure. Each step's stderr is merged into its
/// stdout (`2>&1`), so the message of a failed step is the last line it printed, never another step's warnings.
/// `stderr` is only pkexec's own, for the case where no step ran.
fn parse_root(actions: &[i32], stdout: &str, stderr: &str) -> Vec<(i32, io::Result<()>)> {
    // (step, exit code, last non-empty line before its marker); a later marker for the same step wins.
    let mut done: Vec<(i32, &str, &str)> = vec![];
    let mut last = "";
    for line in stdout.lines() {
        match line.strip_prefix("@@ ").and_then(|m| m.split_once(' ')) {
            Some((n, code)) if n.parse::<i32>().is_ok() => {
                done.push((n.parse().unwrap_or_default(), code.trim(), last));
                last = "";
            }
            _ if !line.trim().is_empty() => last = line.trim(),
            _ => {}
        }
    }
    let stderr = stderr.trim();
    actions
        .iter()
        .map(|a| {
            let r = match done.iter().rev().find(|d| d.0 == *a) {
                Some((_, "0", _)) => Ok(()),
                Some((_, c, msg)) if !msg.is_empty() => Err(io::Error::other(format!("{msg} (exit {c})"))),
                Some((_, c, _)) => Err(io::Error::other(format!("failed (exit {c})"))),
                None if !stderr.is_empty() => Err(io::Error::other(stderr.to_string())),
                None => Err(io::Error::other("did not run")),
            };
            (*a, r)
        })
        .collect()
}

/// Runs the root steps of `actions` (3 autoremove, 16 apt clean, 10 journal) in one `pkexec`, so one password covers all.
pub fn run_root(actions: &[i32]) -> Vec<(i32, io::Result<()>)> {
    let script = root_script(actions);
    match pkexec_output("/bin/sh", &["-c", &script]) {
        Ok(out) => parse_root(
            actions,
            &String::from_utf8_lossy(&out.stdout),
            &String::from_utf8_lossy(&out.stderr),
        ),
        Err(e) => actions
            .iter()
            .map(|a| (*a, Err(io::Error::other(e.to_string()))))
            .collect(),
    }
}

/// What a Python project keeps next to its venv, so something can recreate it.
const VENV_MANIFESTS: [&str; 5] = ["pyproject.toml", "requirements.txt", "setup.py", "setup.cfg", "Pipfile"];

/// `target/` next to a Cargo.toml, `node_modules/` next to a package.json, a venv (`pyvenv.cfg` inside) next to a
/// Python project file. Anything else with that name is not ours.
fn is_build(path: &Path) -> bool {
    let manifests: &[&str] = match path.file_name().and_then(|n| n.to_str()) {
        Some("target") => &["Cargo.toml"],
        Some("node_modules") => &["package.json"],
        Some(".venv" | "venv" | "env") if path.join("pyvenv.cfg").is_file() => &VENV_MANIFESTS,
        _ => return false,
    };
    path.parent()
        .is_some_and(|p| manifests.iter().any(|m| p.join(m).is_file()))
}

const PROJECT_MARKERS: [&str; 5] = ["pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", ".git"];

/// A `__pycache__` that holds only `.pyc` files: Python rebuilds those, so anything else in there is not ours to delete.
fn is_pycache(path: &Path) -> bool {
    path.file_name().is_some_and(|n| n == "__pycache__")
        && fs::read_dir(path).is_ok_and(|mut r| {
            r.all(|e| {
                e.is_ok_and(|e| {
                    e.file_type().is_ok_and(|t| t.is_file()) && e.path().extension().is_some_and(|x| x == "pyc")
                })
            })
        })
}

/// Never entered when looking for caches: hidden folders, and the installed packages of any venv or system Python
/// (`site-packages`), whose caches belong to no project of yours.
fn is_skipped_dir(name: &std::ffi::OsStr) -> bool {
    let name = name.to_string_lossy();
    name.starts_with('.') || name == "site-packages" || name == "dist-packages"
}

/// The project a cache folder belongs to: the nearest folder below `home` with a project marker, else its parent.
/// `None` when that would be `home` itself (a cache right in $HOME is not a project).
fn pycache_project(home: &Path, cache: &Path) -> Option<PathBuf> {
    let parent = cache.parent()?;
    let found = parent
        .ancestors()
        .take_while(|a| *a != home)
        .find(|a| PROJECT_MARKERS.iter().any(|m| a.join(m).exists()));
    let project = found.unwrap_or(parent);
    (project != home && project.starts_with(home)).then(|| project.to_path_buf())
}

/// Build folders, and the projects' `__pycache__` folders grouped per project (one row each, never one per file).
fn builds(home: &Path, excluded: &[PathBuf], cancel: &AtomicBool) -> (Vec<Item>, Vec<Item>) {
    let mut caches = HashMap::<PathBuf, (u64, Option<u64>)>::new();
    let (mut out, mut visits) = (Vec::new(), BUILD_CAP);
    let mut it = WalkDir::new(home).same_file_system(true).into_iter();
    while let Some(entry) = it.next() {
        let Ok(e) = entry else { continue };
        if visits == 0 || cancel.load(Relaxed) {
            break;
        }
        visits -= 1;
        // `file_type` does not follow links, so a symlinked folder is never entered.
        if e.depth() == 0 || !e.file_type().is_dir() {
            continue;
        }
        // `is_build` comes before the hidden check so a `.venv` is found; hidden folders are otherwise never entered.
        if excluded.iter().any(|x| e.path().starts_with(x)) {
            it.skip_current_dir();
        } else if is_build(e.path()) {
            let (size, newest) = walk(e.path(), &mut WALK_CAP.clone());
            out.push(Item {
                id: e.path().to_string_lossy().into_owned(),
                size,
                newest,
                ..Default::default()
            });
            it.skip_current_dir();
        } else if is_skipped_dir(e.file_name()) {
            it.skip_current_dir();
        } else if is_pycache(e.path()) {
            if let Some(project) = pycache_project(home, e.path()) {
                let (size, newest) = walk(e.path(), &mut WALK_CAP.clone());
                let slot = caches.entry(project).or_default();
                slot.0 += size;
                slot.1 = slot.1.max(newest);
            }
            it.skip_current_dir();
        }
    }
    out.sort_by_key(|i| std::cmp::Reverse(i.size));
    let mut pycaches: Vec<Item> = caches
        .into_iter()
        .map(|(p, (size, newest))| {
            let id = p.to_string_lossy().into_owned();
            Item {
                path: id.clone(),
                id,
                size,
                newest,
            }
        })
        .collect();
    pycaches.sort_by_key(|i| std::cmp::Reverse(i.size));
    (out, pycaches)
}

/// Delete the `.pyc`-only `__pycache__` folders of a project found by the scan. Re-checked: inside `home`, not a
/// link, and only folders that still hold nothing but `.pyc` files go (permanent, Python rebuilds them).
pub fn clear_pycaches(home: &Path, project: &str) -> io::Result<()> {
    let p = Path::new(project);
    let clean =
        p.is_absolute() && p != home && p.starts_with(home) && !p.components().any(|c| c == Component::ParentDir);
    if !(clean && fs::symlink_metadata(p).is_ok_and(|m| m.is_dir())) {
        return Err(io::Error::other("not a project folder any more, scan again"));
    }
    let (mut removed, mut visits) = (0, BUILD_CAP);
    let mut it = WalkDir::new(p).same_file_system(true).into_iter();
    while let Some(Ok(e)) = it.next() {
        if visits == 0 {
            break;
        }
        visits -= 1;
        if !e.file_type().is_dir() {
            continue;
        }
        if e.depth() > 0 && (is_skipped_dir(e.file_name()) || is_build(e.path())) {
            it.skip_current_dir();
        } else if is_pycache(e.path()) {
            // Only the caches the scan counted for this project: a nested project's are its own row.
            if pycache_project(home, e.path()).as_deref() == Some(p) {
                fs::remove_dir_all(e.path())?;
                removed += 1;
            }
            it.skip_current_dir();
        }
    }
    if removed == 0 {
        return Err(io::Error::other("nothing to clear any more, scan again"));
    }
    Ok(())
}

fn is_installer(name: &str) -> bool {
    let lower = name.to_lowercase();
    INSTALLER_EXT.iter().any(|e| lower.ends_with(e))
}

/// Installers in `dir` (not below it) that are big enough and have not changed for `days` days.
fn installers(dir: &Path, now: u64, days: u32) -> Vec<Item> {
    let cutoff = now.saturating_sub(u64::from(days) * 86_400);
    let mut out: Vec<Item> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let meta = fs::symlink_metadata(e.path()).ok()?;
            let secs = meta.modified().ok()?.duration_since(UNIX_EPOCH).ok()?.as_secs();
            (meta.is_file() && meta.len() >= INSTALLER_MIN && is_installer(&name) && secs <= cutoff).then_some(Item {
                id: name,
                size: meta.len(),
                newest: Some(secs),
                ..Default::default()
            })
        })
        .collect();
    out.sort_by_key(|i| std::cmp::Reverse(i.size));
    out
}

fn caches(dir: &Path) -> Vec<Item> {
    let mut out: Vec<Item> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        // The browsers have their own row (it refuses while the browser is open), so they are not counted twice.
        .filter(|e| !browsers::CACHE_FOLDERS.contains(&e.file_name().to_string_lossy().as_ref()))
        .map(|e| {
            let (size, newest) = walk(&e.path(), &mut WALK_CAP.clone());
            Item {
                id: e.file_name().to_string_lossy().into_owned(),
                size,
                newest,
                ..Default::default()
            }
        })
        .filter(|i| i.size >= CACHE_MIN)
        .collect();
    out.sort_by_key(|i| std::cmp::Reverse(i.size));
    out.truncate(CACHE_TOP);
    out
}

/// Size of the `.deb` files in an APT archive folder (readable by every user).
fn apt_cache_size(dir: &Path) -> u64 {
    fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".deb"))
        .filter_map(|e| e.metadata().ok())
        .filter(|m| m.is_file())
        .map(|m| m.len())
        .sum()
}

/// Smallest file looked at for duplicates: icons and caches below this are noise.
const DUP_MIN: u64 = 1_000_000;
/// Groups listed, biggest waste first.
const DUP_TOP: usize = 50;
const DUP_HEAD: usize = 64 * 1024;

/// Hash of the first `limit` bytes (all of the file when `None`). `None` when the file cannot be read or `cancel` is
/// set, polled between chunks so one huge file cannot hold the Stop button.
/// shortcut: std SipHash only groups candidates; `trash_duplicate` compares the bytes before anything is trashed.
fn hash_file(path: &Path, limit: Option<usize>, cancel: &AtomicBool) -> Option<u64> {
    use std::{
        hash::{DefaultHasher, Hasher},
        io::Read,
    };
    let mut f = fs::File::open(path).ok()?;
    let (mut h, mut buf, mut left) = (DefaultHasher::new(), vec![0u8; DUP_HEAD], limit.unwrap_or(usize::MAX));
    while left > 0 {
        if cancel.load(Relaxed) {
            return None;
        }
        let n = f.read(&mut buf[..left.min(DUP_HEAD)]).ok()?;
        if n == 0 {
            break;
        }
        h.write(&buf[..n]);
        left -= n;
    }
    Some(h.finish())
}

/// Fills `buf` unless the file ends first (`read` alone may return less than asked).
fn read_full(f: &mut fs::File, buf: &mut [u8]) -> io::Result<usize> {
    use std::io::Read;
    let mut total = 0;
    while total < buf.len() {
        match f.read(&mut buf[total..])? {
            0 => break,
            n => total += n,
        }
    }
    Ok(total)
}

fn same_bytes(a: &Path, b: &Path) -> io::Result<bool> {
    let (mut fa, mut fb) = (fs::File::open(a)?, fs::File::open(b)?);
    let (mut ba, mut bb) = (vec![0u8; DUP_HEAD], vec![0u8; DUP_HEAD]);
    loop {
        let (n, m) = (read_full(&mut fa, &mut ba)?, read_full(&mut fb, &mut bb)?);
        if n != m || ba[..n] != bb[..m] {
            return Ok(false);
        }
        if n == 0 {
            return Ok(true);
        }
    }
}

/// Files of the same size and content under `home`, one group per set, oldest file first (the one to keep). Hidden
/// folders and excluded paths are skipped, hard links to one inode count once, and a path with a newline is skipped
/// because the UI hands two paths to the action in one string.
pub fn duplicates(home: &Path, excluded: &[String], cancel: &AtomicBool) -> Vec<Vec<Item>> {
    use std::os::unix::fs::MetadataExt;
    let excluded: Vec<PathBuf> = excluded.iter().map(PathBuf::from).collect();
    let mut by_size: HashMap<u64, Vec<(PathBuf, u64, u64, u64)>> = HashMap::new();
    let (mut visits, mut it) = (BUILD_CAP, WalkDir::new(home).same_file_system(true).into_iter());
    while let Some(entry) = it.next() {
        let Ok(e) = entry else { continue };
        if visits == 0 || cancel.load(Relaxed) {
            break;
        }
        visits -= 1;
        let t = e.file_type();
        if e.depth() > 0 && t.is_dir() {
            let hidden = e.file_name().to_string_lossy().starts_with('.');
            if hidden || excluded.iter().any(|x| e.path().starts_with(x)) {
                it.skip_current_dir();
            }
        } else if t.is_file()
            && !e.path().to_string_lossy().contains('\n')
            && let Some(m) = e.metadata().ok().filter(|m| m.len() >= DUP_MIN)
        {
            by_size
                .entry(m.len())
                .or_default()
                .push((e.into_path(), m.mtime() as u64, m.dev(), m.ino()));
        }
    }
    let mut groups: Vec<Vec<Item>> = Vec::new();
    for (size, mut files) in by_size {
        files.sort_by_key(|f| (f.2, f.3));
        files.dedup_by_key(|f| (f.2, f.3));
        if files.len() < 2 {
            continue;
        }
        let mut heads: HashMap<u64, Vec<_>> = HashMap::new();
        for f in files {
            if let Some(h) = hash_file(&f.0, Some(DUP_HEAD), cancel) {
                heads.entry(h).or_default().push(f);
            }
        }
        for same_head in heads.into_values().filter(|v| v.len() > 1) {
            let mut full: HashMap<u64, Vec<_>> = HashMap::new();
            for f in same_head {
                if let Some(h) = hash_file(&f.0, None, cancel) {
                    full.entry(h).or_default().push(f);
                }
            }
            for mut g in full.into_values().filter(|v| v.len() > 1) {
                g.sort_by_key(|f| (f.1, f.0.clone()));
                groups.push(
                    g.into_iter()
                        .map(|f| Item {
                            id: f.0.to_string_lossy().into_owned(),
                            size,
                            newest: Some(f.1),
                            ..Default::default()
                        })
                        .collect(),
                );
            }
        }
        if cancel.load(Relaxed) {
            break;
        }
    }
    groups.sort_by_key(|g| std::cmp::Reverse(g[0].size * (g.len() as u64 - 1)));
    groups.truncate(DUP_TOP);
    groups
}

/// Trashes `copy` only when `original` is still a different file with the very same bytes, both under `home`.
pub fn trash_duplicate(home: &Path, copy: &str, original: &str) -> io::Result<()> {
    let ok = |p: &str| {
        let p = Path::new(p);
        p.is_absolute()
            && p.starts_with(home)
            && !p.components().any(|c| c == Component::ParentDir)
            && fs::symlink_metadata(p).is_ok_and(|m| m.is_file())
    };
    if !(ok(copy) && ok(original) && copy != original) {
        return Err(io::Error::other("not a duplicate any more, scan again"));
    }
    if !same_bytes(Path::new(copy), Path::new(original))? {
        return Err(io::Error::other("the files differ now, scan again"));
    }
    command_ok(Command::new("gio").args(["trash", "--", copy])).map(drop)
}

/// Timeshift snapshot names, oldest first, from the readable snapshot folders. Btrfs mode keeps them in a top-level
/// subvolume that is mounted only while Timeshift runs, so this is empty there.
pub fn timeshift_snapshots() -> Vec<String> {
    let dirs = [
        "/timeshift/snapshots",
        "/timeshift-btrfs/snapshots",
        "/run/timeshift/backup/timeshift/snapshots",
        "/run/timeshift/backup/timeshift-btrfs/snapshots",
    ];
    let mut names: Vec<String> = dirs.iter().flat_map(|d| snapshot_names(Path::new(d))).collect();
    names.sort();
    names
}

/// Newest run whose log says it saved a snapshot (world-readable, named like the snapshot). Only the newest is
/// trustworthy: Timeshift deletes old snapshots but keeps their logs, so counting logs overstates.
pub fn last_logged_snapshot() -> Option<String> {
    last_logged_in(Path::new("/var/log/timeshift"))
}

fn last_logged_in(dir: &Path) -> Option<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .ok()?
        .flatten()
        .filter_map(|e| {
            e.file_name()
                .to_string_lossy()
                .strip_suffix("_backup.log")
                .map(String::from)
        })
        .collect();
    names.sort();
    names.into_iter().rev().find(|n| {
        fs::read_to_string(dir.join(format!("{n}_backup.log"))).is_ok_and(|t| t.contains("saved successfully"))
    })
}

/// Snapshots are only offered for deletion when older than this and not among the newest `SNAP_KEEP_NEWEST`.
pub const SNAP_KEEP_DAYS: u32 = 180;
pub const SNAP_KEEP_NEWEST: usize = 3;

/// Epoch seconds of a snapshot name (`2026-11-09_11-17-04`); `None` for anything else, so odd folders are never old.
fn snapshot_time(name: &str) -> Option<u64> {
    let (d, t) = name.split_once('_')?;
    let digits = |s: &str, sep: char| {
        s.split(sep)
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    };
    (name.len() == 19 && digits(d, '-') && digits(t, '-')).then_some(())?;
    stamp(d, t, '-', '-')
}

/// For each name (oldest first): true when it must be kept (one of the newest 3, younger than 6 months, or not a date).
pub fn snapshot_keep(names: &[String], now: u64) -> Vec<bool> {
    let cutoff = old_cutoff(now, SNAP_KEEP_DAYS);
    let first_newest = names.len().saturating_sub(SNAP_KEEP_NEWEST);
    names
        .iter()
        .enumerate()
        .map(|(i, n)| i >= first_newest || !snapshot_time(n).is_some_and(|s| s <= cutoff))
        .collect()
}

pub const TIMESHIFT: &str = "/usr/bin/timeshift";

/// Deletes one old snapshot with Timeshift itself (it knows rsync hard links, btrfs and the backup device). The name
/// goes to a root command, so it must be a plain date; age and rank are checked again against the current list.
pub fn delete_snapshot(name: &str) -> io::Result<()> {
    let old = snapshot_time(name).is_some_and(|s| s <= cutoff(SNAP_KEEP_DAYS));
    let names = timeshift_snapshots();
    // shortcut: the folder is usually root-only, so without a readable list only the age is re-checked (the newest-3
    // rule was applied when the list was shown); upgrade if Timeshift ever becomes readable for users.
    let newest = names
        .iter()
        .position(|n| n == name)
        .is_some_and(|i| snapshot_keep(&names, now())[i]);
    if !old || newest {
        return Err(io::Error::other("not an old snapshot any more, scan again"));
    }
    pkexec_run(TIMESHIFT, &["--delete", "--snapshot", name, "--scripted"])
}

/// Snapshot folder names, oldest first. Names only: rsync snapshots are hard-linked, so a size per snapshot would be
/// wrong and walking them is very slow.
pub(crate) fn snapshot_names(dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    out.sort();
    out
}

/// `Archived and active journals take up 1.2G in the file system.` (binary units).
fn parse_journal(text: &str) -> u64 {
    let Some(token) = text.split("take up ").nth(1).and_then(|t| t.split_whitespace().next()) else {
        return 0;
    };
    let (n, unit) = token.split_at(token.len().saturating_sub(1));
    let scale = match unit {
        "K" => 1u64 << 10,
        "M" => 1 << 20,
        "G" => 1 << 30,
        "T" => 1 << 40,
        _ => return token.parse().unwrap_or(0),
    };
    (n.parse::<f64>().unwrap_or(0.0) * scale as f64) as u64
}

const COREDUMP_DIR: &str = "/var/lib/systemd/coredump";

/// The crash dumps `systemd-coredump` keeps: their total size, how many, and the program that crashed most.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Coredumps {
    pub size: u64,
    pub count: usize,
    pub top: String,
}

/// `core.<program>.<uid>.<boot id>.<pid>.<time>[.zst|.xz|.lz4]` -> `<program>`. The program may hold dots, the five
/// fields after it never do, so they are counted from the end.
fn dump_program(name: &str) -> Option<&str> {
    let rest = name.strip_prefix("core.")?;
    let rest = [".zst", ".xz", ".lz4"]
        .iter()
        .find_map(|e| rest.strip_suffix(e))
        .unwrap_or(rest);
    let mut parts = rest.rsplitn(5, '.');
    (parts.by_ref().take(4).count() == 4).then_some(())?;
    parts.next().filter(|p| !p.is_empty())
}

/// The dump folder is listable without root (its files are not readable, but their sizes are).
fn coredumps(dir: &Path) -> Coredumps {
    let mut per = HashMap::<String, usize>::new();
    let mut out = Coredumps::default();
    for e in fs::read_dir(dir).into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(program) = dump_program(&name) else { continue };
        let Ok(meta) = e.metadata() else { continue };
        if meta.is_file() {
            out.size += meta.len();
            out.count += 1;
            *per.entry(program.to_string()).or_default() += 1;
        }
    }
    // Ties go to the name that sorts first, so the label does not change between scans.
    out.top = per
        .into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0)))
        .map(|p| p.0)
        .unwrap_or_default();
    out
}

const LOG_DIR: &str = "/var/log";
/// `/var/log/apt/history.log.1.gz` is two levels down; deeper folders are not logrotate's.
const LOG_DEPTH: usize = 3;

/// What logrotate leaves behind: `syslog.1`, `syslog.2.gz`, `auth.log.10`, `*.xz`. The live `syslog` never matches.
fn is_rotated(name: &str) -> bool {
    let Some((stem, ext)) = name.rsplit_once('.') else {
        return false;
    };
    matches!(ext, "gz" | "xz")
        || (!stem.is_empty() && (1..=2).contains(&ext.len()) && ext.bytes().all(|b| b.is_ascii_digit()))
}

/// Size and count of the rotated logs, readable without root (folders list, sizes are metadata).
fn rotated_logs(dir: &Path) -> (u64, usize) {
    walkdir::WalkDir::new(dir)
        .max_depth(LOG_DEPTH)
        .into_iter()
        .flatten()
        .filter(|e| e.file_type().is_file() && is_rotated(&e.file_name().to_string_lossy()))
        .filter_map(|e| e.metadata().ok())
        .fold((0, 0), |(s, n), m| (s + m.len(), n + 1))
}

pub fn rotated_log_bytes() -> u64 {
    rotated_logs(Path::new(LOG_DIR)).0
}

/// Deletes the rotated logs, in the same root script the bulk dialog shows (step 24).
pub fn clear_rotated_logs() -> io::Result<()> {
    run_root(&[24]).pop().map_or(Ok(()), |r| r.1)
}

pub fn coredump_bytes() -> u64 {
    coredumps(Path::new(COREDUMP_DIR)).size
}

/// Deletes every dump, in the same root script the bulk dialog shows (step 22).
pub fn clear_coredumps() -> io::Result<()> {
    run_root(&[22]).pop().map_or(Ok(()), |r| r.1)
}

pub fn journal_usage() -> u64 {
    command_read(Command::new("journalctl").arg("--disk-usage")).map_or(0, |t| parse_journal(&t))
}

/// Lines of `docker system df --format '{{json .}}'`.
fn parse_docker(text: &str) -> Vec<DockerRow> {
    text.lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|v| {
            let field = |k: &str| v.get(k)?.as_str().map(String::from);
            let reclaimable = field("Reclaimable")?;
            // "1.2GB (50%)": the number is the first word.
            let bytes = parse_size(reclaimable.split_whitespace().next()?);
            Some(DockerRow {
                kind: field("Type")?,
                size: field("Size")?,
                reclaimable,
                reclaimable_bytes: bytes,
            })
        })
        .collect()
}

pub fn docker_usage() -> Vec<DockerRow> {
    command_read(Command::new("docker").args(["system", "df", "--format", "{{json .}}"]))
        .map_or(vec![], |t| parse_docker(&t))
}

/// `df -P -B1` rows: device, total, used, available, capacity, mount point (which may hold spaces).
fn parse_df(text: &str) -> Vec<Mount> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let (total, used) = (f.get(1)?.parse().ok()?, f.get(2)?.parse().ok()?);
            let path = f.get(5..)?.join(" ");
            // Running AppImages mount a read-only image (always 100%) and /sys holds firmware variables: not disks.
            (total > 0 && !path.starts_with("/tmp/.mount_") && !path.starts_with("/sys/")).then_some(Mount {
                path,
                total,
                used,
            })
        })
        .collect()
}

fn mounts() -> Vec<Mount> {
    let args = [
        "-P", "-B1", "-x", "tmpfs", "-x", "devtmpfs", "-x", "squashfs", "-x", "overlay",
    ];
    // A dead network share (NAS asleep, NFS gone) makes `df` hang until it is killed. Then ask again for local disks
    // only, so the real disks still show.
    command_read(Command::new("df").args(args))
        .or_else(|_| command_read(Command::new("df").arg("-l").args(args)))
        .map_or(vec![], |t| parse_df(&t))
}

/// Biggest first, at most `n`.
fn keep_top(v: &mut Vec<Item>, n: usize) {
    v.sort_by_key(|i| std::cmp::Reverse(i.size));
    v.truncate(n);
}

/// One walk of $HOME: size per first-level folder and the files of at least `big_min` bytes. Unlike `builds`, hidden
/// folders count (`.steam`, `.cache` are where the space goes). Links are not followed.
fn home_usage(home: &Path, excluded: &[PathBuf], big_min: u64, cancel: &AtomicBool) -> (Vec<Item>, Vec<Item>) {
    let (mut per, mut big, mut visits) = (HashMap::<OsString, u64>::new(), Vec::new(), BUILD_CAP);
    let mut it = WalkDir::new(home).same_file_system(true).into_iter();
    while let Some(entry) = it.next() {
        let Ok(e) = entry else { continue };
        if visits == 0 || cancel.load(Relaxed) {
            break;
        }
        visits -= 1;
        if e.file_type().is_dir() && excluded.iter().any(|x| e.path().starts_with(x)) {
            it.skip_current_dir();
        }
        if !e.file_type().is_file() {
            continue;
        }
        let Ok(meta) = e.metadata() else { continue };
        if let Some(Component::Normal(top)) = e.path().strip_prefix(home).ok().and_then(|p| p.components().next()) {
            *per.entry(top.to_owned()).or_default() += meta.len();
        }
        if meta.len() >= big_min {
            let path = e.path().to_string_lossy().into_owned();
            big.push(Item {
                id: path.clone(),
                path,
                size: meta.len(),
                newest: meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs()),
            });
            if big.len() > 4 * BIG_TOP {
                keep_top(&mut big, BIG_TOP);
            }
        }
    }
    let mut folders: Vec<Item> = per
        .into_iter()
        .map(|(k, size)| Item {
            id: k.to_string_lossy().into_owned(),
            size,
            ..Default::default()
        })
        .collect();
    keep_top(&mut folders, FOLDER_TOP);
    keep_top(&mut big, BIG_TOP);
    (folders, big)
}

/// Sub-folders of `dir` (a Heroic games folder, Bottles' bottles) as `label/name`, sized by walking them.
fn child_folders(dir: &Path, label: &str) -> Vec<Item> {
    fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| Item {
            id: format!("{label}/{}", e.file_name().to_string_lossy()),
            size: walk(&e.path(), &mut WALK_CAP.clone()).0,
            path: e.path().to_string_lossy().into_owned(),
            ..Default::default()
        })
        .collect()
}

fn games(home: &Path, libs: &[PathBuf]) -> Vec<Item> {
    let mut out = steam_games(libs);
    out.extend(child_folders(&home.join("Games/Heroic"), "Heroic"));
    for bottles in [
        ".var/app/com.usebottles.bottles/data/bottles/bottles",
        ".local/share/bottles/bottles",
    ] {
        out.extend(child_folders(&home.join(bottles), "Bottles"));
    }
    keep_top(&mut out, usize::MAX);
    out
}

/// What the Open button shows for a path from a row: a file opens its folder. Absolute, no `..`, must exist.
pub fn open_target(path: &str) -> Option<PathBuf> {
    let p = Path::new(path);
    if !p.is_absolute() || p.components().any(|c| c == Component::ParentDir) {
        return None;
    }
    let meta = fs::symlink_metadata(p).ok()?;
    if meta.is_dir() {
        Some(p.to_path_buf())
    } else {
        p.parent().map(Path::to_path_buf)
    }
}

fn tree_size(dir: &Path) -> (u64, usize) {
    let count = fs::read_dir(dir).map_or(0, |r| r.count());
    (walk(dir, &mut WALK_CAP.clone()).0, count)
}

/// The "Look only" tab, run on request because it walks all of $HOME: first-level folders by size, files of
/// `BIG_MIN` and up, and the game libraries. Returns `(folders, big_files, games)`.
pub fn look(home: &Path, excluded: &[String], cancel: &AtomicBool) -> (Vec<Item>, Vec<Item>, Vec<Item>) {
    let excluded: Vec<PathBuf> = excluded.iter().map(PathBuf::from).collect();
    let (folders, big_files) = home_usage(home, &excluded, BIG_MIN, cancel);
    let games = games(home, &steam_libraries(&steam_roots(home)));
    (folders, big_files, games)
}

/// `cancel` is polled between entries; what was found so far is returned.
pub fn scan(home: &Path, usage_days: u32, excluded: &[String], cancel: &AtomicBool) -> Scan {
    let excluded: Vec<PathBuf> = excluded.iter().map(PathBuf::from).collect();
    let (trash_size, trash_count) = tree_size(&trash_files(home));
    let roots = steam_roots(home);
    let libs = steam_libraries(&roots);
    let (builds, pycaches) = builds(home, &excluded, cancel);
    Scan {
        old_versions: all_old_versions(home, &libs, &roots),
        steam_leftovers: steam_leftovers(&roots, &libs),
        mounts: mounts(),
        builds,
        pycaches,
        browsers: browsers::scan(home),
        cargo: cargo::scan(home),
        flatpak_caches: flatpak::scan(home),
        installers: installers(&downloads(home), now(), usage_days),
        caches: caches(&cache_dir(home)),
        old_trash: old_trash(home, now(), usage_days),
        trash_size,
        trash_count,
        journal: journal_usage(),
        coredumps: coredumps(Path::new(COREDUMP_DIR)),
        rotated_logs: rotated_logs(Path::new(LOG_DIR)),
        apt_cache: apt_cache_size(Path::new("/var/cache/apt/archives")),
        snapshots: timeshift_snapshots(),
        timeshift: Path::new("/etc/timeshift/timeshift.json").exists(),
        docker: docker_usage(),
    }
}

/// Folder to show for a row: Flatpak data (`kind` 0), a cache (1) or a first-level folder of $HOME (2). `None` when the name is not plain or it is gone.
pub fn folder(home: &Path, kind: i32, name: &str) -> Option<PathBuf> {
    let path = match kind {
        0 => home.join(".var/app"),
        2 => home.to_path_buf(),
        _ => cache_dir(home),
    }
    .join(name);
    (plain(name) && fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir())).then_some(path)
}

/// A build folder found by the scan. Re-checked: it must still be one, inside `home`, and not a link.
pub fn trash_build(home: &Path, path: &str) -> io::Result<()> {
    let p = Path::new(path);
    let clean = p.is_absolute() && p.starts_with(home) && !p.components().any(|c| c == Component::ParentDir);
    let real = fs::symlink_metadata(p).is_ok_and(|m| m.is_dir());
    if !(clean && real && is_build(p)) {
        return Err(io::Error::other("not a build folder any more, scan again"));
    }
    command_ok(Command::new("gio").args(["trash", "--"]).arg(p)).map(drop)
}

/// An old tool version found by the scan. Re-checked by listing again (a few capped walks, only on a click), so
/// only a folder the scan would show can go, never a path made up by the caller.
pub fn trash_old_version(home: &Path, path: &str) -> io::Result<()> {
    let roots = steam_roots(home);
    let libs = steam_libraries(&roots);
    let listed = all_old_versions(home, &libs, &roots)
        .iter()
        .any(|v| v.item.path == path && v.keep == Keep::No);
    if !listed || !Path::new(path).is_absolute() {
        return Err(io::Error::other("not an old version any more, scan again"));
    }
    command_ok(Command::new("gio").args(["trash", "--"]).arg(path)).map(drop)
}

/// The folders `gio trash` takes for a leftover row: its prefix and shader cache (`path` = `<steamapps>/<dir>/<appid>`).
pub fn steam_leftover_paths(path: &str) -> Vec<PathBuf> {
    let p = Path::new(path);
    match (
        p.parent().and_then(Path::parent),
        p.file_name().and_then(|n| n.to_str()),
    ) {
        (Some(steamapps), Some(id)) if p.is_absolute() => leftover_dirs(steamapps, id),
        _ => Vec::new(),
    }
}

/// A Steam leftover found by the scan: listed again so only a row the scan would show can go, never a made-up path.
/// Both folders of the app id go to the Trash together, so the saves in the prefix stay recoverable.
pub fn trash_steam_leftover(home: &Path, path: &str) -> io::Result<()> {
    let roots = steam_roots(home);
    let libs = steam_libraries(&roots);
    let paths = steam_leftover_paths(path);
    if paths.is_empty() || !steam_leftovers(&roots, &libs).iter().any(|i| i.path == path) {
        return Err(io::Error::other("not a Steam leftover any more, scan again"));
    }
    command_ok(Command::new("gio").args(["trash", "--"]).args(paths)).map(drop)
}

pub fn trash_installer(home: &Path, file: &str) -> io::Result<()> {
    if !is_installer(file) {
        return Err(io::Error::other("not an installer"));
    }
    trash_in(&downloads(home), file)
}

pub fn empty_trash() -> io::Result<()> {
    command_ok(Command::new("gio").args(["trash", "--empty"])).map(drop)
}

/// Deletes `~/.cache/name` for good: caches are rebuilt by their app, so the Trash would only hold junk.
pub fn clear_cache(home: &Path, name: &str) -> io::Result<()> {
    let path = cache_dir(home).join(name);
    if !plain(name) || !fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir()) {
        return Err(io::Error::other("not a cache folder any more, scan again"));
    }
    fs::remove_dir_all(path)
}

pub fn vacuum_journal() -> io::Result<()> {
    pkexec_run(JOURNALCTL, &["--vacuum-size=100M"])
}

/// `apt-get clean` only deletes downloaded package files; installed software is untouched.
pub fn apt_clean() -> io::Result<()> {
    pkexec_run(APT_GET, &["clean"])
}

pub fn apt_cache_bytes() -> u64 {
    apt_cache_size(Path::new("/var/cache/apt/archives"))
}

/// Never `-a` and never volumes: only what Docker itself calls dangling or stopped.
pub fn docker_prune(system: bool) -> io::Result<()> {
    let args: [&str; 3] = if system {
        ["system", "prune", "-f"]
    } else {
        ["builder", "prune", "-f"]
    };
    command_ok(Command::new("docker").args(args)).map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("fastcheckup-storage-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn touch(path: &Path, bytes: usize) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, vec![0u8; bytes]).unwrap();
    }

    #[test]
    fn finds_same_content_skips_hardlinks_small_hidden_and_near_misses() {
        let home = tmp("dups");
        let big = DUP_MIN as usize + 10;
        touch(&home.join("a/one.bin"), big);
        touch(&home.join("b/two.bin"), big);
        fs::hard_link(home.join("a/one.bin"), home.join("a/link.bin")).unwrap();
        touch(&home.join("c/near.bin"), big);
        let mut other = vec![0u8; big];
        other[big - 1] = 1; // same size and same first 64 KB, different tail
        fs::write(home.join("c/near.bin"), other).unwrap();
        touch(&home.join("d/small.bin"), 10);
        touch(&home.join("e/small.bin"), 10);
        touch(&home.join(".hidden/three.bin"), big);
        let found = duplicates(&home, &[], &AtomicBool::new(false));
        assert_eq!(found.len(), 1);
        let names: Vec<_> = found[0]
            .iter()
            .map(|i| i.id.rsplit('/').nth(1).unwrap().to_string())
            .collect();
        assert_eq!(names.len(), 2);
        assert!(names.iter().all(|n| n == "a" || n == "b"));
    }

    #[test]
    fn trash_duplicate_refuses_changed_or_foreign_files() {
        let home = tmp("dupact");
        touch(&home.join("x.bin"), 100);
        fs::write(home.join("y.bin"), vec![1u8; 100]).unwrap();
        let (x, y) = (home.join("x.bin"), home.join("y.bin"));
        let (xs, ys) = (x.to_str().unwrap(), y.to_str().unwrap());
        assert!(trash_duplicate(&home, ys, xs).is_err()); // differ
        assert!(trash_duplicate(&home, xs, xs).is_err()); // same path
        assert!(trash_duplicate(&home, "/etc/passwd", xs).is_err()); // outside home
        assert!(same_bytes(&x, &x).unwrap() && !same_bytes(&x, &y).unwrap());
    }

    #[test]
    fn last_logged_snapshot_skips_runs_that_saved_nothing() {
        let d = tmp("tslogs");
        fs::write(d.join("2026-11-03_11-00-01_backup.log"), "Snapshot saved successfully").unwrap();
        fs::write(d.join("2026-11-05_00-00-01_backup.log"), "nothing").unwrap();
        assert_eq!(last_logged_in(&d).as_deref(), Some("2026-11-03_11-00-01"));
    }

    #[test]
    fn snapshots_are_listed_oldest_first_and_files_ignored() {
        let d = tmp("snaps");
        touch(&d.join("2026-03-14_10-00-01/info.json"), 1);
        touch(&d.join("2025-12-01_08-00-00/info.json"), 1);
        touch(&d.join("stray.txt"), 1);
        assert_eq!(snapshot_names(&d), ["2025-12-01_08-00-00", "2026-03-14_10-00-01"]);
        assert!(snapshot_names(&d.join("missing")).is_empty());
    }

    #[test]
    fn snapshot_keep_rule() {
        let now = stamp("2026-11-13", "00:00:00", '-', ':').unwrap();
        let v = |l: &[&str]| l.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        // 1 year, 8 months, 2 months, 3 weeks, 1 week ago: only the two oldest go.
        let names = v(&[
            "2025-11-10_10-00-00",
            "2026-03-01_10-00-00",
            "2026-09-10_10-00-00",
            "2026-10-20_10-00-00",
            "2026-11-06_10-00-00",
        ]);
        assert_eq!(snapshot_keep(&names, now), [false, false, true, true, true]);
        // The newest 3 stay even when ancient.
        let old = v(&[
            "2020-01-01_00-00-00",
            "2020-02-01_00-00-00",
            "2020-03-01_00-00-00",
            "2020-04-01_00-00-00",
        ]);
        assert_eq!(snapshot_keep(&old, now), [false, true, true, true]);
        // Not a date: kept.
        assert_eq!(snapshot_keep(&v(&["a", "b", "c", "weird"]), now), [true; 4]);
    }

    #[test]
    fn snapshot_time_rejects_odd_names() {
        assert!(snapshot_time("2026-03-14_10-00-01").is_some());
        for bad in [
            "",
            "../x",
            "2026-03-14_10-00-01; rm",
            "2026-03-14 10-00-01",
            "2026-3-14_10-00-01",
            "x",
        ] {
            assert!(snapshot_time(bad).is_none(), "{bad}");
        }
        assert!(delete_snapshot("../etc").is_err());
    }

    #[test]
    fn apt_cache_counts_only_deb_files() {
        let d = tmp("apt");
        touch(&d.join("a_1_amd64.deb"), 400);
        touch(&d.join("b_2_all.deb"), 100);
        touch(&d.join("lock"), 50);
        touch(&d.join("partial/c.deb"), 999); // a folder, not counted
        assert_eq!(apt_cache_size(&d), 500);
        assert_eq!(apt_cache_size(&d.join("missing")), 0);
    }

    #[test]
    fn build_folders_need_their_manifest_and_skip_hidden_and_excluded() {
        let home = tmp("builds");
        touch(&home.join("a/Cargo.toml"), 1);
        touch(&home.join("a/target/x.o"), 500);
        touch(&home.join("b/target/y.o"), 500); // no Cargo.toml: not a Rust build
        touch(&home.join("c/package.json"), 1);
        touch(&home.join("c/node_modules/p/package.json"), 300);
        touch(&home.join("c/node_modules/p/node_modules/q"), 5); // inside a hit: counted once
        touch(&home.join(".hidden/Cargo.toml"), 1);
        touch(&home.join(".hidden/target/z"), 9);
        touch(&home.join("p/requirements.txt"), 1);
        touch(&home.join("p/.venv/pyvenv.cfg"), 20); // a venv next to a project file
        touch(&home.join("q/.venv/pyvenv.cfg"), 20); // nothing could recreate it
        touch(&home.join("r/pyproject.toml"), 1);
        touch(&home.join("r/venv/x"), 20); // no pyvenv.cfg: not a venv
        touch(&home.join("skip/Cargo.toml"), 1);
        touch(&home.join("skip/target/w"), 9);
        let (found, _) = builds(&home, &[home.join("skip")], &AtomicBool::new(false));
        let ids: Vec<_> = found
            .iter()
            .map(|i| i.id.strip_prefix(home.to_str().unwrap()).unwrap())
            .collect();
        assert_eq!(ids, ["/a/target", "/c/node_modules", "/p/.venv"]);
        assert_eq!(found[0].size, 500);
    }

    #[test]
    fn pycaches_group_per_project_and_only_pyc_only_folders_go() {
        let home = tmp("pyc");
        touch(&home.join("app/pyproject.toml"), 1);
        touch(&home.join("app/__pycache__/a.cpython-312.pyc"), 100);
        touch(&home.join("app/sub/__pycache__/b.pyc"), 50);
        touch(&home.join("loose/__pycache__/c.pyc"), 7); // no marker: its parent is the project
        touch(&home.join("mixed/__pycache__/d.pyc"), 9);
        touch(&home.join("mixed/__pycache__/notes.txt"), 9); // not only .pyc: left alone
        touch(&home.join(".hidden/__pycache__/e.pyc"), 9);
        touch(&home.join("__pycache__/f.pyc"), 9); // right in $HOME: not a project
        touch(
            &home.join("venvs/x/lib/python3.12/site-packages/pip/__pycache__/g.pyc"),
            9,
        ); // a venv's packages
        touch(&home.join("outer/__pycache__/h.pyc"), 5); // no marker: two nested folders are two projects
        touch(&home.join("outer/inner/__pycache__/i.pyc"), 3);
        let (_, found) = builds(&home, &[], &AtomicBool::new(false));
        let ids: Vec<_> = found
            .iter()
            .map(|i| (i.id.strip_prefix(home.to_str().unwrap()).unwrap(), i.size))
            .collect();
        assert_eq!(ids, [("/app", 150), ("/loose", 7), ("/outer", 5), ("/outer/inner", 3)]);
        // Clearing the outer one leaves the inner one for its own row instead of failing it later.
        clear_pycaches(&home, &found[2].id).unwrap();
        assert!(!home.join("outer/__pycache__").exists() && home.join("outer/inner/__pycache__").exists());
        clear_pycaches(&home, &found[3].id).unwrap();
        assert!(clear_pycaches(&home, home.to_str().unwrap()).is_err());
        clear_pycaches(&home, &found[0].id).unwrap();
        assert!(!home.join("app/__pycache__").exists() && !home.join("app/sub/__pycache__").exists());
        assert!(home.join("app/pyproject.toml").exists());
        assert!(clear_pycaches(&home, &found[0].id).is_err()); // nothing left
        assert!(home.join("mixed/__pycache__/notes.txt").exists());
    }

    #[test]
    fn installers_need_age_size_and_extension() {
        let dir = tmp("dl");
        let big = INSTALLER_MIN as usize;
        touch(&dir.join("app.AppImage"), big);
        touch(&dir.join("notes.txt"), big);
        touch(&dir.join("tiny.deb"), 10);
        let in_100_days = now() + 100 * 86_400;
        assert_eq!(
            installers(&dir, in_100_days, 90)
                .iter()
                .map(|i| i.id.as_str())
                .collect::<Vec<_>>(),
            ["app.AppImage"]
        );
        assert!(installers(&dir, now(), 90).is_empty(), "too new");
    }

    #[test]
    fn actions_reject_bad_targets() {
        let home = tmp("act");
        touch(&home.join("p/Cargo.toml"), 1);
        touch(&home.join("p/target/x"), 1);
        let outside = tmp("outside");
        touch(&outside.join("Cargo.toml"), 1);
        touch(&outside.join("target/x"), 1);
        for bad in [
            outside.join("target").to_string_lossy().into_owned(),
            format!("{}/p/../p/target", home.display()),
            "target".into(),
            home.join("p").to_string_lossy().into_owned(),
        ] {
            assert!(trash_build(&home, &bad).is_err(), "{bad}");
        }
        for bad in ["", "..", "a/b", "../x", "missing"] {
            assert!(clear_cache(&home, bad).is_err(), "{bad}");
        }
        for bad in ["", "..", "relative", "/etc", &outside.join("target").to_string_lossy()] {
            assert!(trash_old_version(&home, bad).is_err(), "{bad}");
        }
        assert!(trash_installer(&home, "x.txt").is_err());
        assert!(trash_installer(&home, "../x.deb").is_err());
    }

    #[test]
    fn folder_rows_resolve_only_plain_existing_names() {
        let home = tmp("folder");
        touch(&home.join(".cache/a/f"), 1);
        touch(&home.join(".var/app/x.y/f"), 1);
        assert_eq!(folder(&home, 1, "a"), Some(home.join(".cache/a")));
        assert_eq!(folder(&home, 0, "x.y"), Some(home.join(".var/app/x.y")));
        assert!(
            [(1, "missing"), (1, ".."), (0, "../../.cache/a"), (1, "")]
                .iter()
                .all(|(k, n)| folder(&home, *k, n).is_none())
        );
    }

    #[test]
    fn clear_cache_removes_only_that_folder() {
        let home = tmp("cache");
        touch(&home.join(".cache/a/f"), 1);
        touch(&home.join(".cache/b/f"), 1);
        clear_cache(&home, "a").unwrap();
        assert!(!home.join(".cache/a").exists() && home.join(".cache/b/f").exists());
    }

    #[test]
    fn downloads_follow_user_dirs() {
        let home = Path::new("/home/u");
        let dirs = |v: &str| parse_user_dir(&format!("XDG_MUSIC_DIR=\"$HOME/M\"\nXDG_DOWNLOAD_DIR={v}\n"), home);
        assert_eq!(dirs("\"$HOME/Transferências\""), Some(home.join("Transferências")));
        assert_eq!(dirs("\"/data/dl\""), Some(PathBuf::from("/data/dl")));
        assert_eq!(dirs("\"$HOME/../x\""), None);
        assert_eq!(dirs("\"$HOME/\""), None);
        assert_eq!(parse_user_dir("nothing", home), None);
    }

    #[test]
    fn df_is_parsed() {
        let text = "Filesystem 1-blocks Used Available Capacity Mounted on\n\
                    /dev/sda2 1000 400 600 40% /\n/dev/sdb1 2000 1900 100 95% /mnt/my data\nnone 0 0 0 - /x\n\
                    x 5 5 0 100% /tmp/.mount_spotifGAdfMc\nefivarfs 9 1 8 1% /sys/firmware/efi/efivars\n";
        let m = parse_df(text);
        assert_eq!(m.len(), 2);
        assert_eq!(
            (m[1].path.as_str(), m[1].total, m[1].used),
            ("/mnt/my data", 2000, 1900)
        );
    }

    #[test]
    fn home_usage_ranks_folders_and_big_files() {
        let home = tmp("usage");
        touch(&home.join(".steam/g/big.bin"), 900);
        touch(&home.join("docs/a"), 100);
        touch(&home.join("docs/b"), 100);
        touch(&home.join("skip/c"), 5000);
        let (folders, big) = home_usage(&home, &[home.join("skip")], 500, &AtomicBool::new(false));
        let ids: Vec<_> = folders.iter().map(|i| (i.id.as_str(), i.size)).collect();
        assert_eq!(ids, [(".steam", 900), ("docs", 200)]);
        assert_eq!(big.len(), 1);
        assert!(big[0].id.ends_with(".steam/g/big.bin"));
        let (f, b) = home_usage(&home, &[], 500, &AtomicBool::new(true));
        assert!(f.is_empty() && b.is_empty(), "cancelled before the first entry");
    }

    #[test]
    fn open_target_needs_an_existing_absolute_path() {
        let dir = tmp("open");
        touch(&dir.join("a/f"), 1);
        assert_eq!(open_target(dir.join("a").to_str().unwrap()), Some(dir.join("a")));
        assert_eq!(open_target(dir.join("a/f").to_str().unwrap()), Some(dir.join("a")));
        for bad in [
            "a/f",
            "",
            &format!("{}/a/../a", dir.display()),
            &format!("{}/nope", dir.display()),
        ] {
            assert!(open_target(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn journal_usage_is_parsed() {
        assert_eq!(
            parse_journal("Archived and active journals take up 1.5G in the file system.\n"),
            3 << 29
        );
        assert_eq!(
            parse_journal("Archived and active journals take up 8.0M in the file system."),
            8 << 20
        );
        assert_eq!(parse_journal("garbage"), 0);
    }

    #[test]
    fn docker_df_is_parsed() {
        let text = concat!(
            r#"{"Active":"2","Reclaimable":"1.2GB (50%)","Size":"2.4GB","TotalCount":"5","Type":"Images"}"#,
            "\n",
            r#"{"Active":"0","Reclaimable":"0B","Size":"0B","TotalCount":"0","Type":"Build Cache"}"#,
            "\nnot json\n"
        );
        let rows = parse_docker(text);
        assert_eq!(rows.len(), 2);
        assert_eq!(
            (rows[0].kind.as_str(), rows[0].reclaimable_bytes),
            ("Images", 1_200_000_000)
        );
        assert_eq!(rows[1].reclaimable_bytes, 0);
    }

    #[test]
    fn trash_date_is_epoch_seconds_or_none() {
        assert_eq!(
            trash_date("[Trash Info]\nDeletionDate=1970-01-02T00:00:10"),
            Some(86_410)
        );
        assert_eq!(trash_date("DeletionDate=2000-03-01T00:00:00"), Some(951_868_800));
        assert_eq!(trash_date("DeletionDate=2000-13-01T00:00:00"), None);
        assert_eq!(trash_date("Path=/x"), None);
        assert_eq!(trash_date("DeletionDate=soon"), None);
    }

    fn trashed(home: &Path, name: &str, date: &str) {
        touch(&trash_files(home).join(name).join("f"), 10);
        fs::create_dir_all(trash_info(home)).unwrap();
        fs::write(
            trash_info(home).join(format!("{name}.trashinfo")),
            format!("[Trash Info]\nPath=/x\nDeletionDate={date}\n"),
        )
        .unwrap();
    }

    #[test]
    fn old_trash_lists_only_old_dated_entries_and_deletes_them_with_their_info() {
        let home = tmp("trash");
        // 1970-01-02 is old; the second is in the future; the third has no date and is never old.
        trashed(&home, "old", "1970-01-02T00:00:00");
        trashed(&home, "fresh", "2999-01-01T00:00:00");
        touch(&trash_files(&home).join("nodate"), 5);
        fs::write(trash_info(&home).join("nodate.trashinfo"), "[Trash Info]\n").unwrap();
        let ids: Vec<_> = old_trash(&home, now(), 90).into_iter().map(|i| i.id).collect();
        assert_eq!(ids, ["old"]);
        assert!(delete_trash_entry(&home, "fresh", 90).is_err());
        assert!(delete_trash_entry(&home, "../old", 90).is_err());
        delete_trash_entry(&home, "old", 90).unwrap();
        assert!(!trash_files(&home).join("old").exists());
        assert!(!trash_info(&home).join("old.trashinfo").exists());
        assert!(trash_files(&home).join("fresh").exists());
    }

    #[test]
    fn trash_entry_command_quotes_names_with_spaces_and_quotes() {
        let cmd = trash_entry_command(Path::new("/home/u"), "My file's $x.txt");
        assert_eq!(
            cmd,
            "rm -r '/home/u/.local/share/Trash/files/My file'\\''s $x.txt' \
             '/home/u/.local/share/Trash/info/My file'\\''s $x.txt.trashinfo'"
        );
    }

    #[test]
    fn root_command_shows_exactly_the_script_that_runs() {
        let script = root_script(&[3, 16, 10, 9, 22]);
        assert_eq!(
            root_command(&[3, 16, 10, 9, 22]),
            format!("pkexec /bin/sh -c '{script}'")
        );
        // Unknown actions are left out; each known step has its marker.
        assert_eq!(script.matches("@@").count(), 4);
        assert!(script.contains("-name core.\\* -delete"));
        assert!(script.starts_with("/usr/bin/apt-get autoremove -y 2>&1; printf"));
        assert!(!script.contains('\''));
    }

    #[test]
    fn coredumps_are_counted_by_program() {
        let id = "1ef56881ef8e4c31acc41394755bd6eb.125754.1794630395000000";
        assert_eq!(dump_program(&format!("core.nemo.1000.{id}.zst")), Some("nemo"));
        assert_eq!(dump_program(&format!("core.opencam.1000.{id}")), Some("opencam"));
        assert_eq!(dump_program(&format!("core.my.app.1000.{id}.xz")), Some("my.app"));
        assert_eq!(dump_program("core.nemo"), None);
        assert_eq!(dump_program("notes.txt"), None);
        let dir = tmp("dumps");
        touch(&dir.join(format!("core.opencam.1000.{id}.zst")), 100);
        touch(
            &dir.join("core.opencam.1000.1ef56881ef8e4c31acc41394755bd6eb.9.1794630395000001.zst"),
            50,
        );
        touch(&dir.join(format!("core.nemo.1000.{id}.zst")), 10);
        touch(&dir.join("readme.txt"), 999);
        let c = coredumps(&dir);
        assert_eq!((c.size, c.count, c.top.as_str()), (160, 3, "opencam"));
        assert_eq!(coredumps(&dir.join("missing")), Coredumps::default());
    }

    #[test]
    fn rotated_logs_are_only_the_old_copies() {
        for n in ["syslog.1", "auth.log.10", "dpkg.log.2.gz", "Xorg.0.log.old.xz", "a.gz"] {
            assert!(is_rotated(n), "{n}");
        }
        for n in ["syslog", "kern.log", "boot.log", "x.123", "wtmp", ".1", "Xorg.0.log"] {
            assert!(!is_rotated(n), "{n}");
        }
        let dir = tmp("rotated");
        touch(&dir.join("syslog"), 1000);
        touch(&dir.join("syslog.1"), 100);
        touch(&dir.join("syslog.2.gz"), 20);
        touch(&dir.join("apt/history.log.1.gz"), 3);
        assert_eq!(rotated_logs(&dir), (123, 3));
        assert_eq!(rotated_logs(&dir.join("missing")), (0, 0));
    }

    #[test]
    fn root_results_are_per_step_and_a_missing_marker_fails() {
        // Step 3 printed a warning but succeeded; step 16 failed with its own message; step 10 never ran.
        let out = "W: noisy\n\n@@ 3 0\nE: Could not lock\n\n@@ 16 100\n";
        let r = parse_root(&[3, 16, 10], out, "pkexec says no");
        assert!(r[0].1.is_ok());
        assert_eq!(r[1].1.as_ref().unwrap_err().to_string(), "E: Could not lock (exit 100)");
        assert_eq!(r[2].1.as_ref().unwrap_err().to_string(), "pkexec says no");
        // The journal step fails silently: it must not show apt's warning from the step before it.
        let out = "W: apt noise\n\n@@ 3 0\n\n@@ 10 1\n";
        let r = parse_root(&[3, 10], out, "");
        assert_eq!(r[1].1.as_ref().unwrap_err().to_string(), "failed (exit 1)");
        assert_eq!(
            parse_root(&[10], "", "")[0].1.as_ref().unwrap_err().to_string(),
            "did not run"
        );
    }
}
