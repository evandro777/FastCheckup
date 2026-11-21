//! Browser clean-up: only what the browser rebuilds (cache, crash reports, Chrome's on-device AI models). Logins,
//! cookies, tabs, history, settings and Firefox's backups are never in the list. The folders are a fixed table, so
//! a caller can only name a browser, never a path.
use std::{
    fs, io,
    path::{Path, PathBuf},
};

use super::Item;
use crate::apps::{WALK_CAP, walk};

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Chromium,
    Firefox,
    /// VS Code and forks: Chromium's lock, but the caches sit inside the profile folder and nothing else is touched.
    Electron,
}

/// (id, profile folder under `$HOME`, cache folder under `$HOME` (unused for `Electron`), kind).
const BROWSERS: [(&str, &str, &str, Kind); 7] = [
    (
        "google-chrome",
        ".config/google-chrome",
        ".cache/google-chrome",
        Kind::Chromium,
    ),
    ("chromium", ".config/chromium", ".cache/chromium", Kind::Chromium),
    (
        "brave",
        ".config/BraveSoftware/Brave-Browser",
        // Only this flavour: its lock is the one checked, Brave Beta/Nightly may be running.
        ".cache/BraveSoftware/Brave-Browser",
        Kind::Chromium,
    ),
    ("firefox", ".mozilla/firefox", ".cache/mozilla/firefox", Kind::Firefox),
    ("vscode", ".config/Code", "", Kind::Electron),
    ("vscodium", ".config/VSCodium", "", Kind::Electron),
    ("cursor", ".config/Cursor", "", Kind::Electron),
];

/// Rebuilt by VS Code on the next start. Never `Backups` (unsaved files), `User`, `Local Storage` or `logs`.
const ELECTRON_CACHES: [&str; 5] = ["Cache", "CachedData", "CachedExtensionVSIXs", "Code Cache", "GPUCache"];

/// First-level folders of `~/.cache` that belong to these browsers (the plain Caches list skips them).
pub const CACHE_FOLDERS: [&str; 4] = ["google-chrome", "chromium", "BraveSoftware", "mozilla"];

/// Folders of the Chromium base that are caches, crash reports or downloaded models.
const CHROMIUM_BASE: [&str; 8] = [
    "GrShaderCache",
    "ShaderCache",
    "GraphiteDawnCache",
    "component_crx_cache",
    "Crash Reports",
    "OptGuideOnDeviceModel",
    "optimization_guide_model_store",
    "OnDeviceHeadSuggestModel",
];
/// Per profile (`Default`, `Profile N`).
const CHROMIUM_PROFILE: [&str; 3] = ["Cache", "Code Cache", "GPUCache"];

fn entries(dir: &Path) -> Vec<PathBuf> {
    fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .collect()
}

fn is_profile(p: &Path) -> bool {
    p.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n == "Default" || n.starts_with("Profile "))
}

/// Every existing file or folder the clean-up of one browser would delete.
fn targets(home: &Path, base: &str, cache: &str, kind: Kind) -> Vec<PathBuf> {
    // `cache` is "" for Electron apps: joining it would name `$HOME` itself, so only the other arms may use it.
    let (base, cache) = (home.join(base), home.join(cache));
    let mut out = vec![];
    match kind {
        Kind::Electron => out.extend(ELECTRON_CACHES.iter().map(|n| base.join(n))),
        Kind::Chromium => {
            out.push(cache);
            out.extend(CHROMIUM_BASE.iter().map(|n| base.join(n)));
            for profile in entries(&base).into_iter().filter(|p| is_profile(p)) {
                out.extend(CHROMIUM_PROFILE.iter().map(|n| profile.join(n)));
            }
        }
        Kind::Firefox => {
            out.push(cache);
            // The settings file only holds the "send reports" choice.
            out.extend(
                entries(&base.join("Crash Reports"))
                    .into_iter()
                    .filter(|p| p.file_name().is_some_and(|n| n != "crashreporter_settings.json")),
            );
            for profile in entries(&base) {
                out.extend(entries(&profile.join("minidumps")));
            }
        }
    }
    out.retain(|p| fs::symlink_metadata(p).is_ok());
    out
}

/// The browser is running when its lock names a live process (`host-PID` for Chromium, `IP:+PID` for Firefox).
/// A stale lock left by a crash points at a dead PID, so it does not block the clean-up.
fn running(lock: &Path) -> bool {
    let Ok(target) = fs::read_link(lock) else { return false };
    let target = target.to_string_lossy();
    let digits: String = target
        .chars()
        .rev()
        .take_while(char::is_ascii_digit)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    digits
        .parse::<u32>()
        .is_ok_and(|pid| Path::new(&format!("/proc/{pid}")).exists())
}

fn is_running(home: &Path, base: &str, kind: Kind) -> bool {
    let base = home.join(base);
    match kind {
        Kind::Chromium | Kind::Electron => running(&base.join("SingletonLock")),
        Kind::Firefox => entries(&base).iter().any(|p| running(&p.join("lock"))),
    }
}

/// One row per installed browser with something to free (`id` = browser id, `path` = its profile folder).
pub fn scan(home: &Path) -> Vec<Item> {
    BROWSERS
        .iter()
        .filter_map(|&(id, base, cache, kind)| {
            let walked: Vec<_> = targets(home, base, cache, kind)
                .iter()
                .map(|p| walk(p, &mut WALK_CAP.clone()))
                .collect();
            let size: u64 = walked.iter().map(|w| w.0).sum();
            (size > 0).then(|| Item {
                id: id.to_string(),
                size,
                newest: walked.iter().filter_map(|w| w.1).max(),
                path: home.join(base).to_string_lossy().into_owned(),
            })
        })
        .collect()
}

/// The paths a clean-up of `id` would delete now (for the command line the dialog shows).
pub fn paths(home: &Path, id: &str) -> Vec<PathBuf> {
    BROWSERS
        .iter()
        .find(|b| b.0 == id)
        .map_or_else(Vec::new, |&(_, base, cache, kind)| targets(home, base, cache, kind))
}

/// Deletes the browser's caches for good. Refuses while the browser runs, and re-lists the targets now, so only
/// what the scan would show can go. Links are removed, never followed. Keeps going after a failure.
pub fn clear(home: &Path, id: &str) -> io::Result<()> {
    let Some(&(_, base, cache, kind)) = BROWSERS.iter().find(|b| b.0 == id) else {
        return Err(io::Error::other("unknown browser, scan again"));
    };
    if is_running(home, base, kind) {
        return Err(io::Error::other("the browser is open, close it first"));
    }
    let mut first = Ok(());
    for p in targets(home, base, cache, kind) {
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

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("fastcheckup-browsers-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn touch(path: &Path) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, vec![0u8; 10]).unwrap();
    }

    fn fake_home(name: &str) -> PathBuf {
        let h = tmp(name);
        for f in [
            ".cache/google-chrome/Default/Cache/data_0",
            ".config/google-chrome/GrShaderCache/a",
            ".config/google-chrome/Crash Reports/r",
            ".config/google-chrome/optimization_guide_model_store/m",
            ".config/google-chrome/Default/Code Cache/js/x",
            ".config/google-chrome/Default/Cookies",
            ".config/google-chrome/Default/Login Data",
            ".config/google-chrome/Local State",
            ".cache/mozilla/firefox/p.default/cache2/e",
            ".mozilla/firefox/Crash Reports/LastCrash",
            ".mozilla/firefox/Crash Reports/crashreporter_settings.json",
            ".mozilla/firefox/p.default/minidumps/d.dmp",
            ".mozilla/firefox/p.default/logins.json",
            ".mozilla/firefox/p.default/logins-backup.json",
            ".mozilla/firefox/p.default/bookmarkbackups/b.jsonlz4",
            ".mozilla/firefox/p.default/cookies.sqlite",
        ] {
            touch(&h.join(f));
        }
        h
    }

    #[test]
    fn only_the_listed_folders_go() {
        let h = fake_home("list");
        assert_eq!(scan(&h).len(), 2);
        clear(&h, "google-chrome").unwrap();
        clear(&h, "firefox").unwrap();
        for gone in [
            ".cache/google-chrome",
            ".config/google-chrome/GrShaderCache",
            ".config/google-chrome/Crash Reports",
            ".config/google-chrome/optimization_guide_model_store",
            ".config/google-chrome/Default/Code Cache",
            ".cache/mozilla/firefox",
            ".mozilla/firefox/Crash Reports/LastCrash",
            ".mozilla/firefox/p.default/minidumps/d.dmp",
        ] {
            assert!(!h.join(gone).exists(), "{gone} should be gone");
        }
        for kept in [
            ".config/google-chrome/Default/Cookies",
            ".config/google-chrome/Default/Login Data",
            ".config/google-chrome/Local State",
            ".mozilla/firefox/Crash Reports/crashreporter_settings.json",
            ".mozilla/firefox/p.default/logins.json",
            ".mozilla/firefox/p.default/logins-backup.json",
            ".mozilla/firefox/p.default/bookmarkbackups/b.jsonlz4",
            ".mozilla/firefox/p.default/cookies.sqlite",
        ] {
            assert!(h.join(kept).exists(), "{kept} must stay");
        }
        assert!(scan(&h).is_empty());
    }

    #[test]
    fn vscode_loses_only_its_caches_and_never_the_unsaved_backups() {
        let h = tmp("code");
        for f in [
            ".config/Code/Cache/c",
            ".config/Code/CachedData/d",
            ".config/Code/Code Cache/j",
            ".config/Code/Backups/unsaved-file",
            ".config/Code/User/settings.json",
            ".config/Code/logs/l",
            "keep.txt",
        ] {
            touch(&h.join(f));
        }
        assert_eq!(scan(&h).len(), 1);
        clear(&h, "vscode").unwrap();
        for gone in [
            ".config/Code/Cache",
            ".config/Code/CachedData",
            ".config/Code/Code Cache",
        ] {
            assert!(!h.join(gone).exists(), "{gone}");
        }
        for kept in [
            ".config/Code/Backups/unsaved-file",
            ".config/Code/User/settings.json",
            ".config/Code/logs/l",
            "keep.txt",
        ] {
            assert!(h.join(kept).exists(), "{kept}");
        }
        std::os::unix::fs::symlink(
            format!("host-{}", std::process::id()),
            h.join(".config/Code/SingletonLock"),
        )
        .unwrap();
        touch(&h.join(".config/Code/Cache/c"));
        assert!(clear(&h, "vscode").is_err());
    }

    #[test]
    fn an_open_browser_is_left_alone_and_a_stale_lock_is_not() {
        let h = fake_home("lock");
        let lock = h.join(".config/google-chrome/SingletonLock");
        std::os::unix::fs::symlink(format!("host-{}", std::process::id()), &lock).unwrap();
        assert!(clear(&h, "google-chrome").is_err());
        assert!(h.join(".cache/google-chrome").exists());
        fs::remove_file(&lock).unwrap();
        std::os::unix::fs::symlink("host-4194999", &lock).unwrap();
        clear(&h, "google-chrome").unwrap();
        assert!(!h.join(".cache/google-chrome").exists());

        let ff = h.join(".mozilla/firefox/p.default/lock");
        std::os::unix::fs::symlink(format!("127.0.0.2:+{}", std::process::id()), &ff).unwrap();
        assert!(clear(&h, "firefox").is_err());
        assert!(h.join(".cache/mozilla/firefox").exists());
    }

    #[test]
    fn unknown_ids_and_links_are_not_followed() {
        let h = fake_home("link");
        assert!(clear(&h, "../x").is_err());
        let outside = tmp("outside");
        touch(&outside.join("keep"));
        fs::remove_dir_all(h.join(".config/google-chrome/GrShaderCache")).unwrap();
        std::os::unix::fs::symlink(&outside, h.join(".config/google-chrome/GrShaderCache")).unwrap();
        clear(&h, "google-chrome").unwrap();
        assert!(outside.join("keep").exists());
    }
}
