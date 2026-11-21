//! Steam libraries, installed games and the versions of tools kept next to them (Proton, GE-Proton, rustup toolchains,
//! `~/.local/share/<tool>/versions`). Report only: sizes are Steam's own where it records them.
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

use super::Item;
use crate::apps::{WALK_CAP, walk};

/// Newest versions of a tool that are not listed as old.
const KEEP_VERSIONS: usize = 2;

/// Values of every `"key"<tabs>"value"` line in a Steam VDF/ACF file.
fn parse_vdf_values(text: &str, key: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| {
            let parts: Vec<&str> = l.trim().split('"').collect();
            (parts.len() >= 4 && parts[1] == key).then(|| parts[3].to_string())
        })
        .collect()
}

/// Steam installs found, resolved so `~/.steam/steam` and the folder it links to count once.
pub(super) fn steam_roots(home: &Path) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = [
        ".steam/steam",
        ".local/share/Steam",
        ".var/app/com.valvesoftware.Steam/.local/share/Steam",
    ]
    .iter()
    .filter_map(|r| fs::canonicalize(home.join(r)).ok())
    .collect();
    roots.sort();
    roots.dedup();
    roots
}

/// Every library of the given Steam installs. One on a drive that is not mounted is skipped.
pub(super) fn steam_libraries(roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut libs = roots.to_vec();
    for root in roots {
        let text = fs::read_to_string(root.join("steamapps/libraryfolders.vdf")).unwrap_or_default();
        libs.extend(
            parse_vdf_values(&text, "path")
                .iter()
                .filter_map(|p| fs::canonicalize(p).ok()),
        );
    }
    libs.sort();
    libs.dedup();
    libs
}

/// Installed Steam games with the size Steam recorded, so no folder is walked.
pub(super) fn steam_games(libs: &[PathBuf]) -> Vec<Item> {
    libs.iter()
        .flat_map(|lib| {
            let apps = lib.join("steamapps");
            fs::read_dir(&apps)
                .into_iter()
                .flatten()
                .flatten()
                .filter_map(move |e| {
                    let file = e.file_name().to_string_lossy().into_owned();
                    if !(file.starts_with("appmanifest_") && file.ends_with(".acf")) {
                        return None;
                    }
                    let text = fs::read_to_string(e.path()).ok()?;
                    let first = |k| parse_vdf_values(&text, k).into_iter().next();
                    Some(Item {
                        id: first("name")?,
                        size: first("SizeOnDisk").and_then(|s| s.parse().ok()).unwrap_or(0),
                        path: apps
                            .join("common")
                            .join(first("installdir")?)
                            .to_string_lossy()
                            .into_owned(),
                        ..Default::default()
                    })
                })
        })
        .collect()
}

/// Why a version is, or is not, offered for the Trash. The numbers are what the UI row reads.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Keep {
    No = 0,
    /// One of the newest `KEEP_VERSIONS`.
    Newest = 1,
    /// A game in Steam's `CompatToolMapping` runs on it.
    InUse = 2,
    /// A Steam tool app: Steam keeps its `appmanifest`, so only Steam can uninstall it cleanly.
    Steam = 3,
    /// Steam's default tool, for every game without its own.
    Default = 4,
}

/// A version of a tool, why it stays and, for Steam tools, the games set to run on it.
#[derive(Clone, Debug)]
pub struct Version {
    pub item: Item,
    pub keep: Keep,
    pub games: Vec<String>,
}

/// `(app id, tool name lowercase)` of every entry of `CompatToolMapping` in `config.vdf`. App id "0" is the default
/// tool for games without their own. Stale entries (game or tool gone) are still returned, so they count as in use.
/// shortcut: line-based scan of Valve's text format, when a name spans lines or a value has `"` read it with a vdf parser.
fn parse_tool_map(text: &str) -> Vec<(String, String)> {
    let mut map = Vec::new();
    let Some(start) = text.find("\"CompatToolMapping\"") else {
        return map;
    };
    let (mut depth, mut appid) = (0, "");
    for line in text[start..].lines().map(str::trim) {
        match line {
            "{" => depth += 1,
            "}" => {
                depth -= 1;
                if depth <= 0 {
                    break;
                }
            }
            _ if depth == 1 => appid = line.trim_matches('"'),
            _ if depth == 2 && line.starts_with("\"name\"") => {
                if let Some(v) = line["\"name\"".len()..]
                    .trim()
                    .strip_prefix('"')
                    .and_then(|v| v.strip_suffix('"'))
                {
                    map.push((appid.to_string(), v.to_lowercase()));
                }
            }
            _ => {}
        }
    }
    map
}

/// App ids Steam lists as installed, in every library of `libraryfolders.vdf` (also those on drives not mounted now).
fn parse_installed_ids(text: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut in_apps = false;
    for line in text.lines().map(str::trim) {
        match line {
            "\"apps\"" => in_apps = true,
            "}" => in_apps = false,
            _ if in_apps && line != "{" => ids.extend(line.split('"').nth(1).map(String::from)),
            _ => {}
        }
    }
    ids
}

/// Installed Steam games by app id, for naming who uses a tool.
fn steam_app_names(libs: &[PathBuf]) -> HashMap<String, String> {
    let mut names = HashMap::new();
    for e in libs
        .iter()
        .flat_map(|l| fs::read_dir(l.join("steamapps")).into_iter().flatten().flatten())
    {
        if !e.file_name().to_string_lossy().starts_with("appmanifest_") {
            continue;
        }
        let text = fs::read_to_string(e.path()).unwrap_or_default();
        let first = |k| parse_vdf_values(&text, k).into_iter().next();
        if let (Some(id), Some(name)) = (first("appid"), first("name")) {
            names.insert(id, name);
        }
    }
    names
}

/// `installdir` of every appmanifest in the libraries: the folders of `steamapps/common` that Steam still manages.
fn tracked_dirs(libs: &[PathBuf]) -> HashSet<String> {
    libs.iter()
        .flat_map(|l| fs::read_dir(l.join("steamapps")).into_iter().flatten().flatten())
        .filter(|e| e.file_name().to_string_lossy().starts_with("appmanifest_"))
        .filter_map(|e| fs::read_to_string(e.path()).ok())
        .filter_map(|t| parse_vdf_values(&t, "installdir").into_iter().next())
        .collect()
}

fn u32_at(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(i..i.checked_add(4)?)?.try_into().ok()?))
}

/// `common/name` of one app from its binary key-values (type 0 = object, 1 = string, 8 = end, keys are string-table indices).
fn app_name(b: &[u8], keys: &[&[u8]]) -> Option<String> {
    let (mut i, mut stack) = (0, Vec::new());
    loop {
        let t = *b.get(i)?;
        i += 1;
        if t == 8 {
            stack.pop()?;
            continue;
        }
        let key = *keys.get(u32_at(b, i)? as usize)?;
        i += 4;
        match t {
            0 => stack.push(key),
            1 => {
                let len = b.get(i..)?.iter().position(|&c| c == 0)?;
                if stack.len() == 2 && stack[1] == b"common" && key == b"name" {
                    return Some(String::from_utf8_lossy(&b[i..i + len]).into_owned());
                }
                i += len + 1;
            }
            2 | 4 | 6 => i += 4,
            7 | 10 => i += 8,
            _ => return None,
        }
    }
}

/// Game names from Steam's own cache, `appcache/appinfo.vdf` (read offline; it also knows uninstalled games). Only format
/// v29 (magic `0x07564429`, keys in a string table at the end) is read: any other version or a damaged file gives
/// nothing and the caller keeps `#appid`. shortcut: older v27/v28 files are not read, add them if one turns up.
fn steam_titles(roots: &[PathBuf], wanted: &HashSet<u32>) -> HashMap<u32, String> {
    let mut out = HashMap::new();
    for root in roots {
        let Ok(d) = fs::read(root.join("appcache/appinfo.vdf")) else {
            continue;
        };
        if u32_at(&d, 0) != Some(0x0756_4429) {
            continue;
        }
        let Some(table) = d
            .get(8..16)
            .and_then(|b| usize::try_from(i64::from_le_bytes(b.try_into().ok()?)).ok())
        else {
            continue;
        };
        let (Some(n), Some(strings)) = (u32_at(&d, table), d.get(table + 4..)) else {
            continue;
        };
        let keys: Vec<&[u8]> = strings.split(|&c| c == 0).take(n as usize).collect();
        let mut pos = 16;
        // Entry: appid, size, then `size` bytes of which the first 60 are fixed fields and the rest the key-values.
        while let (Some(id), Some(size)) = (u32_at(&d, pos), u32_at(&d, pos + 4)) {
            let end = pos + 8 + size as usize;
            if id == 0 || end > d.len() {
                break;
            }
            if wanted.contains(&id)
                && !out.contains_key(&id)
                && let Some(name) = d.get(pos + 68..end).and_then(|b| app_name(b, &keys))
            {
                out.insert(id, name);
            }
            pos = end;
        }
    }
    out
}

/// The prefix and shader-cache folders of one app id in a library's `steamapps`, those that exist.
pub(super) fn leftover_dirs(steamapps: &Path, appid: &str) -> Vec<PathBuf> {
    ["compatdata", "shadercache"]
        .iter()
        .map(|d| steamapps.join(d).join(appid))
        .filter(|p| fs::symlink_metadata(p).is_ok_and(|m| m.is_dir()))
        .collect()
}

/// Wine prefixes and shader caches Steam leaves behind when a game is uninstalled, one `Item` per library and app id
/// (`id` is `#appid`, or `Name (#appid)` when `appinfo.vdf` knows it; `path` is the prefix, or the cache when there is none).
/// Nothing is listed unless Steam's own list of installed apps could be read, and non-Steam shortcuts (ids with the
/// high bit set) and the shared default prefix `0` are never listed, so a prefix that holds saves is not guessed at.
pub(super) fn steam_leftovers(roots: &[PathBuf], libs: &[PathBuf]) -> Vec<Item> {
    let texts: Vec<String> = roots
        .iter()
        .filter_map(|r| fs::read_to_string(r.join("steamapps/libraryfolders.vdf")).ok())
        .collect();
    if texts.is_empty() {
        return Vec::new();
    }
    let mut installed: HashSet<String> = texts.iter().flat_map(|t| parse_installed_ids(t)).collect();
    installed.extend(steam_app_names(libs).into_keys());
    let mut out = Vec::new();
    for lib in libs {
        let steamapps = lib.join("steamapps");
        let mut ids = HashSet::new();
        for d in ["compatdata", "shadercache"] {
            for e in fs::read_dir(steamapps.join(d)).into_iter().flatten().flatten() {
                let id = e.file_name().to_string_lossy().into_owned();
                if id.parse::<u32>().is_ok_and(|n| n != 0 && n < 1 << 31) && !installed.contains(&id) {
                    ids.insert(id);
                }
            }
        }
        for id in ids {
            let dirs = leftover_dirs(&steamapps, &id);
            let Some(first) = dirs.first() else { continue };
            let mut size = 0;
            let mut newest = None;
            for d in &dirs {
                let (s, n) = walk(d, &mut WALK_CAP.clone());
                size += s;
                newest = newest.max(n);
            }
            out.push(Item {
                id: format!("#{id}"),
                size,
                newest,
                path: first.to_string_lossy().into_owned(),
            });
        }
    }
    let wanted = out.iter().filter_map(|i| i.id[1..].parse().ok()).collect();
    let titles = steam_titles(roots, &wanted);
    for i in &mut out {
        if let Some(t) = i.id[1..].parse::<u32>().ok().and_then(|n| titles.get(&n)) {
            i.id = format!("{t} ({})", i.id);
        }
    }
    out.sort_by_key(|i| std::cmp::Reverse(i.size));
    out
}

/// Steam's name for an official Proton folder: `Proton 9.0 (Beta)` is `proton_9`, `Proton 6.3` is `proton_63`.
fn proton_name(dir: &str) -> String {
    let d = dir.to_lowercase();
    for word in ["experimental", "hotfix"] {
        if d.contains(word) {
            return format!("proton_{word}");
        }
    }
    let ver: String = d
        .trim_start_matches("proton")
        .trim()
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    format!("proton_{}", ver.trim_end_matches(".0").replace('.', ""))
}

/// Entries of `dir` whose name starts with `prefix`, newest first; links are skipped (`GE-Proton-latest`).
/// Those `users` names games for get a `Keep` reason. With `tracked` (the install folders of Steam's appmanifests), a
/// folder Steam lists gets `Keep::Steam` and one it no longer lists is `Keep::No`: Steam can neither use nor remove it.
/// Otherwise the newest `KEEP_VERSIONS` stay. `users` gives the games of a folder name; an empty name stands for
/// Steam's default tool.
/// shortcut: "newest" is the folder's mtime, not the version in use, when it misleads read the launcher's link.
fn old_versions(
    dir: &Path,
    prefix: &str,
    label: &str,
    users: &dyn Fn(&str) -> Vec<String>,
    tracked: Option<&HashSet<String>>,
) -> Vec<Version> {
    let mut found: Vec<(u64, PathBuf)> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with(prefix))
        .filter_map(|e| {
            let meta = fs::symlink_metadata(e.path()).ok().filter(|m| m.is_dir())?;
            let secs = meta.modified().ok()?.duration_since(UNIX_EPOCH).ok()?.as_secs();
            Some((secs, e.path()))
        })
        .collect();
    found.sort_by_key(|(secs, _)| std::cmp::Reverse(*secs));
    found
        .into_iter()
        .enumerate()
        .map(|(n, (secs, path))| {
            let name = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
            let (default, games): (Vec<String>, Vec<String>) = users(&name).into_iter().partition(String::is_empty);
            let keep = match () {
                _ if !default.is_empty() => Keep::Default,
                _ if !games.is_empty() => Keep::InUse,
                _ if tracked.is_some_and(|t| t.contains(&name)) => Keep::Steam,
                _ if tracked.is_some() => Keep::No,
                _ if n < KEEP_VERSIONS => Keep::Newest,
                _ => Keep::No,
            };
            let item = Item {
                id: format!("{label}/{name}"),
                size: walk(&path, &mut WALK_CAP.clone()).0,
                newest: Some(secs),
                path: path.to_string_lossy().into_owned(),
            };
            Version { item, keep, games }
        })
        .collect()
}

/// Folders that hold several versions of one tool: `~/.local/share/<tool>/versions`, Steam's compatibility tools and
/// Proton, rustup toolchains. Biggest first.
pub(super) fn all_old_versions(home: &Path, libs: &[PathBuf], roots: &[PathBuf]) -> Vec<Version> {
    let names = steam_app_names(libs);
    let installed: HashSet<String> = roots
        .iter()
        .filter_map(|r| fs::read_to_string(r.join("steamapps/libraryfolders.vdf")).ok())
        .flat_map(|t| parse_installed_ids(&t))
        .collect();
    let mut used = HashMap::<String, Vec<String>>::new();
    for (appid, tool) in roots
        .iter()
        .filter_map(|r| fs::read_to_string(r.join("config/config.vdf")).ok())
        .flat_map(|t| parse_tool_map(&t))
    {
        // Steam keeps a game's tool after it is uninstalled; that game no longer needs it. Without the list, trust all.
        if appid != "0" && !installed.is_empty() && !installed.contains(&appid) {
            continue;
        }
        // Installed on a drive that is not mounted: no manifest to read the name from, so the app id stands in.
        let who = match appid.as_str() {
            "0" => String::new(),
            _ => names.get(&appid).cloned().unwrap_or_else(|| format!("#{appid}")),
        };
        used.entry(tool).or_default().push(who);
    }
    let games = |tool: &str| used.get(tool).cloned().unwrap_or_default();
    let mut out = Vec::new();
    for e in fs::read_dir(home.join(".local/share")).into_iter().flatten().flatten() {
        let tool = e.file_name().to_string_lossy().into_owned();
        out.extend(old_versions(&e.path().join("versions"), "", &tool, &|_| vec![], None));
    }
    out.extend(old_versions(
        &home.join(".rustup/toolchains"),
        "",
        "rustup",
        &|_| vec![],
        None,
    ));
    for root in roots {
        let dir = root.join("compatibilitytools.d");
        // shortcut: the folder name stands for the tool's internal name (compatibilitytool.vdf), true for GE-Proton.
        out.extend(old_versions(
            &dir,
            "",
            "Steam tools",
            &|n| games(&n.to_lowercase()),
            None,
        ));
    }
    let tracked = tracked_dirs(libs);
    for lib in libs {
        out.extend(old_versions(
            &lib.join("steamapps/common"),
            "Proton",
            "Proton",
            &|n| games(&proton_name(n)),
            Some(&tracked),
        ));
    }
    out.sort_by_key(|v| std::cmp::Reverse(v.item.size));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("fastcheckup-steam-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn touch(path: &Path, bytes: usize) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, vec![0u8; bytes]).unwrap();
    }

    #[test]
    fn vdf_values_are_read_by_key() {
        let text = "\"libraryfolders\"\n{\n\t\"0\"\n\t{\n\t\t\"path\"\t\t\"/a b\"\n\t\t\"label\"\t\t\"\"\n\t}\n\t\"1\" { \"path\" \"/c\" }\n}";
        assert_eq!(parse_vdf_values(text, "path"), ["/a b"]);
        assert_eq!(parse_vdf_values(text, "label"), [""]);
        assert!(parse_vdf_values(text, "missing").is_empty());
    }

    #[test]
    fn steam_games_come_from_every_mounted_library() {
        let (root, other) = (tmp("steam-root"), tmp("steam-other"));
        let acf = |id: &str, name: &str, size: u64| {
            format!(
                "\"AppState\"\n{{\n\t\"appid\"\t\t\"{id}\"\n\t\"name\"\t\t\"{name}\"\n\t\"installdir\"\t\t\"{name} dir\"\n\t\"SizeOnDisk\"\t\t\"{size}\"\n}}"
            )
        };
        let vdf = format!(
            "\"libraryfolders\"\n{{\n\t\"1\"\n\t{{\n\t\t\"path\"\t\t\"{}\"\n\t}}\n\t\"2\"\n\t{{\n\t\t\"path\"\t\t\"/not/mounted\"\n\t}}\n}}",
            other.display()
        );
        touch(&root.join("steamapps/libraryfolders.vdf"), 0);
        fs::write(root.join("steamapps/libraryfolders.vdf"), vdf).unwrap();
        fs::write(root.join("steamapps/appmanifest_1.acf"), acf("1", "Small", 10)).unwrap();
        touch(&other.join("steamapps/appmanifest_2.acf"), 0);
        fs::write(other.join("steamapps/appmanifest_2.acf"), acf("2", "Big", 99)).unwrap();
        let libs = steam_libraries(&[root.canonicalize().unwrap()]);
        assert_eq!(libs.len(), 2);
        let mut found = steam_games(&libs);
        found.sort_by_key(|i| std::cmp::Reverse(i.size));
        assert_eq!(
            found.iter().map(|i| (i.id.as_str(), i.size)).collect::<Vec<_>>(),
            [("Big", 99), ("Small", 10)]
        );
        assert!(found[0].path.ends_with("steamapps/common/Big dir"));
    }

    #[test]
    fn old_versions_keep_the_newest_and_skip_links() {
        let dir = tmp("versions");
        for (name, age) in [("1.0", 400), ("1.1", 300), ("1.2", 200), ("1.3", 100)] {
            touch(&dir.join(name).join("f"), 7);
            let t = std::time::SystemTime::now() - std::time::Duration::from_secs(age);
            fs::File::open(dir.join(name)).unwrap().set_modified(t).unwrap();
        }
        std::os::unix::fs::symlink(dir.join("1.0"), dir.join("latest")).unwrap();
        let all = old_versions(&dir, "", "tool", &|_| vec![], None);
        let ids = |keep: Keep| {
            all.iter()
                .filter(|v| v.keep == keep)
                .map(|v| v.item.id.as_str())
                .collect::<Vec<_>>()
        };
        assert_eq!(ids(Keep::No), ["tool/1.1", "tool/1.0"]);
        assert_eq!(ids(Keep::Newest), ["tool/1.3", "tool/1.2"]);
        assert_eq!(all[2].item.size, 7);
        assert!(
            old_versions(&dir, "Proton", "tool", &|_| vec![], None).is_empty(),
            "prefix filter"
        );
        // In use beats everything, the default tool beats both. With a tracked list, a folder Steam lists is left to
        // Steam, one it does not list is offered (the "newest" rule does not apply to it).
        let users = |n: &str| match n {
            "1.0" => vec!["Game A".to_string(), "Game B".into()],
            "1.3" => vec![String::new(), "Game C".into()],
            _ => vec![],
        };
        let tracked = HashSet::from(["1.2".to_string()]);
        let used = old_versions(&dir, "", "tool", &users, Some(&tracked));
        let keeps: Vec<Keep> = used.iter().map(|v| v.keep).collect();
        assert_eq!(keeps, [Keep::Default, Keep::Steam, Keep::No, Keep::InUse]);
        assert_eq!(used[0].games, ["Game C"]);
        assert_eq!(used[3].games, ["Game A", "Game B"]);
    }

    #[test]
    fn untracked_proton_is_offered_and_listed_ones_are_left_to_steam() {
        let root = tmp("proton-root");
        touch(&root.join("steamapps/common/Proton 8.0/dist/f"), 5);
        touch(&root.join("steamapps/common/Proton 7.0/dist/f"), 5);
        fs::write(
            root.join("steamapps/appmanifest_1.acf"),
            "\"AppState\"\n{\n\t\"appid\"\t\t\"1\"\n\t\"installdir\"\t\t\"Proton 7.0\"\n}",
        )
        .unwrap();
        let tracked = tracked_dirs(std::slice::from_ref(&root));
        assert_eq!(tracked, HashSet::from(["Proton 7.0".to_string()]));
        let keep = |tool: &[(&str, &str)]| {
            let users = |n: &str| {
                tool.iter()
                    .filter(|t| t.0 == n)
                    .map(|t| t.1.to_string())
                    .collect::<Vec<_>>()
            };
            old_versions(
                &root.join("steamapps/common"),
                "Proton",
                "Proton",
                &users,
                Some(&tracked),
            )
            .into_iter()
            .map(|v| (v.item.id, v.keep))
            .collect::<HashMap<_, _>>()
        };
        let k = keep(&[]);
        assert_eq!(k["Proton/Proton 8.0"], Keep::No);
        assert_eq!(k["Proton/Proton 7.0"], Keep::Steam);
        // A game still set to run on an untracked one keeps it.
        assert_eq!(keep(&[("Proton 8.0", "Game")])["Proton/Proton 8.0"], Keep::InUse);
    }

    #[test]
    fn steam_leftovers_skip_installed_default_and_shortcuts() {
        let root = tmp("left-root");
        let sa = root.join("steamapps");
        let vdf = |apps: &str| {
            format!(
                "\"libraryfolders\"\n{{\n\t\"0\"\n\t{{\n\t\t\"path\"\t\t\"x\"\n\t\t\"apps\"\n\t\t{{\n{apps}\t\t}}\n\t}}\n}}"
            )
        };
        let libs = [root.clone()];
        // Without Steam's own list nothing is guessed.
        touch(&sa.join("compatdata/100/pfx/f"), 10);
        assert!(steam_leftovers(&libs, &libs).is_empty());
        fs::write(sa.join("libraryfolders.vdf"), vdf("\t\t\t\"200\"\t\t\"1\"\n")).unwrap();
        touch(&sa.join("shadercache/100/f"), 4);
        touch(&sa.join("compatdata/0/f"), 9); // shared default prefix
        touch(&sa.join("compatdata/200/f"), 9); // installed on a drive that is not mounted
        touch(&sa.join("compatdata/300/f"), 9); // installed here (manifest)
        fs::write(
            sa.join("appmanifest_300.acf"),
            "\"AppState\"\n{\n\t\"appid\"\t\t\"300\"\n\t\"name\"\t\t\"G\"\n}",
        )
        .unwrap();
        touch(&sa.join("compatdata/3000000000/f"), 9); // non-Steam shortcut
        touch(&sa.join("compatdata/notanid/f"), 9);
        let found = steam_leftovers(&libs, &libs);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, "#100");
        assert_eq!(found[0].size, 14, "prefix and shader cache count together");
        assert!(found[0].path.ends_with("compatdata/100"));
        assert_eq!(leftover_dirs(&sa, "100").len(), 2);
    }

    #[test]
    fn titles_come_from_a_v29_appinfo_and_other_versions_give_nothing() {
        let root = tmp("titles");
        fs::create_dir_all(root.join("appcache")).unwrap();
        let keys = ["appinfo", "common", "name", "appid"];
        let idx = |k: &str| (keys.iter().position(|x| *x == k).unwrap() as u32).to_le_bytes();
        let entry = |id: u32, name: &str| {
            let mut kv = vec![0];
            kv.extend(idx("appinfo"));
            kv.push(2); // an int to skip
            kv.extend(idx("appid"));
            kv.extend(id.to_le_bytes());
            kv.push(0);
            kv.extend(idx("common"));
            kv.push(1);
            kv.extend(idx("name"));
            kv.extend(name.bytes().chain([0]));
            kv.extend([8, 8, 8]);
            let mut e = [id.to_le_bytes(), ((60 + kv.len()) as u32).to_le_bytes()].concat();
            e.extend([0; 60]);
            e.extend(kv);
            e
        };
        let mut f = [0x0756_4429u32.to_le_bytes(), 1u32.to_le_bytes()].concat();
        f.extend([0; 8]);
        for e in [entry(63710, "BIT.TRIP RUNNER"), entry(5, "Other")] {
            f.extend(e);
        }
        f.extend([0; 8]);
        let table = f.len() as i64;
        f[8..16].copy_from_slice(&table.to_le_bytes());
        f.extend((keys.len() as u32).to_le_bytes());
        for k in keys {
            f.extend(k.bytes().chain([0]));
        }
        let path = root.join("appcache/appinfo.vdf");
        fs::write(&path, &f).unwrap();
        let roots = [root.clone()];
        let got = steam_titles(&roots, &HashSet::from([63710, 99]));
        assert_eq!(got.len(), 1);
        assert_eq!(got[&63710], "BIT.TRIP RUNNER");
        f[0] = 0x28; // v28: not read
        fs::write(&path, &f).unwrap();
        assert!(steam_titles(&roots, &HashSet::from([63710])).is_empty());
        fs::write(&path, &f[..40]).unwrap(); // cut short: no panic
        assert!(steam_titles(&roots, &HashSet::from([63710])).is_empty());
    }

    #[test]
    fn steam_tool_names_come_from_the_compat_mapping_only() {
        let vdf = "\"Steam\"\n{\n\t\"name\"\t\"not me\"\n\t\"CompatToolMapping\"\n\t{\n\t\t\"0\"\n\t\t{\n\t\t\t\"name\"\t\t\"Proton-Experimental\"\n\t\t}\n\t\t\"1\"\n\t\t{\n\t\t\t\"name\"\t\t\"GE-Proton9-7\"\n\t\t\t\"config\"\t\t\"\"\n\t\t}\n\t}\n\t\"name\"\t\"after\"\n}\n";
        assert_eq!(
            parse_tool_map(vdf),
            [
                ("0".to_string(), "proton-experimental".to_string()),
                ("1".to_string(), "ge-proton9-7".to_string())
            ]
        );
        assert!(parse_tool_map("no mapping").is_empty());
    }

    #[test]
    fn installed_ids_come_from_every_library_apps_block() {
        let vdf = "\"libraryfolders\"\n{\n\t\"0\"\n\t{\n\t\t\"path\"\t\t\"/a\"\n\t\t\"apps\"\n\t\t{\n\t\t\t\"228980\"\t\t\"1\"\n\t\t\t\"367520\"\t\t\"2\"\n\t\t}\n\t}\n\t\"1\"\n\t{\n\t\t\"path\"\t\t\"/b\"\n\t\t\"apps\"\n\t\t{\n\t\t\t\"588650\"\t\t\"3\"\n\t\t}\n\t}\n}\n";
        assert_eq!(parse_installed_ids(vdf), ["228980", "367520", "588650"]);
        assert!(parse_installed_ids("").is_empty());
    }

    #[test]
    fn official_proton_folders_map_to_steam_names() {
        for (dir, name) in [
            ("Proton 9.0 (Beta)", "proton_9"),
            ("Proton 10.0", "proton_10"),
            ("Proton 6.3", "proton_63"),
            ("Proton - Experimental", "proton_experimental"),
            ("Proton Hotfix", "proton_hotfix"),
        ] {
            assert_eq!(proton_name(dir), name, "{dir}");
        }
    }
}
