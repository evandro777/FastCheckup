//! Flatpak app caches: `~/.var/app/<app-id>/cache` is the app's `XDG_CACHE_HOME`, so the app rebuilds it. Never
//! `data`, `config` or `.local` next to it (logins, saves). One row per app; an id must match a real folder, so a
//! caller can only name an installed app, never a path.
use std::{fs, io, path::Path, process::Command};

use super::Item;
use crate::apps::{WALK_CAP, command_read, walk};

/// Smaller caches are not worth a row (many apps leave an empty `fontconfig`).
const MIN_BYTES: u64 = 1_000_000;

fn apps_dir(home: &Path) -> std::path::PathBuf {
    home.join(".var/app")
}

/// Caches an app keeps outside `cache/` (fixed table, never user input). Stremio's streaming server stores the
/// torrent chunks of what was played there; they are fetched again on demand, and the watch history is in the account.
const EXTRA: &[(&str, &str)] = &[("com.stremio.Stremio", ".stremio-server/stremio-cache")];

fn real_dir(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok_and(|m| m.is_dir())
}

/// The cache folders of `id`, which is the name of a real, non-link folder in `~/.var/app` (re-read now, so nothing
/// else can be named). Empty when there is none.
fn cache_dirs(home: &Path, id: &str) -> Vec<std::path::PathBuf> {
    let app = apps_dir(home).join(id);
    if id.is_empty() || id.starts_with('.') || id.contains('/') || !real_dir(&app) {
        return vec![];
    }
    let extra = EXTRA.iter().filter(|(a, _)| *a == id).map(|(_, sub)| app.join(sub));
    std::iter::once(app.join("cache"))
        .chain(extra)
        // every folder above the target must be a plain folder too, so a link cannot redirect the delete
        .filter(|d| d.ancestors().skip(1).take_while(|a| *a != app).all(real_dir) && real_dir(d))
        .collect()
}

/// One row per app whose caches add up to at least `MIN_BYTES` (`id` = app id, `path` = its first cache folder).
pub fn scan(home: &Path) -> Vec<Item> {
    let mut rows: Vec<Item> = fs::read_dir(apps_dir(home))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let id = e.file_name().to_string_lossy().into_owned();
            let dirs = cache_dirs(home, &id);
            let (mut size, mut newest) = (0u64, None::<u64>);
            for d in &dirs {
                let (s, n) = walk(d, &mut WALK_CAP.clone());
                size += s;
                newest = newest.max(n);
            }
            (size >= MIN_BYTES).then(|| Item {
                id,
                size,
                newest,
                path: dirs[0].to_string_lossy().into_owned(),
            })
        })
        .collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r.size));
    rows
}

/// The folders a row clears (for the command line the dialog shows).
pub fn path(home: &Path, id: &str) -> Vec<std::path::PathBuf> {
    cache_dirs(home, id)
}

fn listed(ps: &str, id: &str) -> bool {
    ps.lines().any(|l| l.trim() == id)
}

/// Empties the app's cache folder for good and keeps the folder. Refuses while the app runs, and when that cannot
/// be told (`flatpak ps` failed). Links are removed, never followed. Keeps going after a failure.
pub fn clear(home: &Path, id: &str) -> io::Result<()> {
    let dirs = cache_dirs(home, id);
    if dirs.is_empty() {
        return Err(io::Error::other("unknown Flatpak app, scan again"));
    }
    let ps = command_read(Command::new("flatpak").args(["ps", "--columns=application"]))?;
    if listed(&ps, id) {
        return Err(io::Error::other("the app is open, close it first"));
    }
    let mut first = Ok(());
    for dir in dirs {
        for e in fs::read_dir(&dir)?.flatten() {
            let p = e.path();
            let done = if real_dir(&p) {
                fs::remove_dir_all(&p)
            } else {
                fs::remove_file(&p)
            };
            if first.is_ok() {
                first = done;
            }
        }
    }
    first
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_are_big_caches_of_real_apps_only() {
        let home = std::env::temp_dir().join(format!("fastcheckup-flatpak-{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        let big = home.join(".var/app/org.big.App");
        fs::create_dir_all(big.join("cache/mesa")).unwrap();
        fs::write(big.join("cache/mesa/db"), vec![0u8; 2_000_000]).unwrap();
        fs::create_dir_all(big.join("data")).unwrap();
        fs::write(big.join("data/save"), vec![0u8; 2_000_000]).unwrap();
        let small = home.join(".var/app/org.small.App/cache");
        fs::create_dir_all(&small).unwrap();
        fs::write(small.join("f"), [0u8; 10]).unwrap();

        let rows = scan(&home);
        assert_eq!(rows.len(), 1);
        assert_eq!((rows[0].id.as_str(), rows[0].size), ("org.big.App", 2_000_000));
        assert!(cache_dirs(&home, "../app").is_empty());
        assert!(cache_dirs(&home, "org.big.App/cache").is_empty());

        let s = home.join(".var/app/com.stremio.Stremio/.stremio-server/stremio-cache");
        fs::create_dir_all(&s).unwrap();
        fs::write(s.join("chunk"), vec![0u8; 3_000_000]).unwrap();
        let rows = scan(&home);
        assert_eq!((rows[0].id.as_str(), rows[0].size), ("com.stremio.Stremio", 3_000_000));
        assert_eq!(cache_dirs(&home, "com.stremio.Stremio"), vec![s]);
        assert!(listed("Application ID\norg.big.App\n", "org.big.App"));
        assert!(!listed("org.big.App.Plugin\n", "org.big.App"));
        let _ = fs::remove_dir_all(&home);
    }
}
