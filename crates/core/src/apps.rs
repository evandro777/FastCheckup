//! Apps module: installed Debian packages with a launcher, Flatpaks and AppImages, with size, a "last data activity"
//! hint, leftover Flatpak data and overlapping apps. Parsers take plain text so tests need no apt or flatpak.
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs, io,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    autostart::{list, matches, parse, rules},
    services::pkexec_run,
};

pub(crate) const APT_GET: &str = "/usr/bin/apt-get";
/// Upper bound on entries read per folder, so a game library in `~/.config` cannot stall a scan.
/// shortcut: bigger folders report a partial size, when users complain switch to `du`.
pub(crate) const WALK_CAP: u32 = 200_000;
/// freedesktop `Categories=` tokens whose apps do the same job. Index = `App::group`; the UI names them.
const GROUPS: [&str; 10] = [
    "WebBrowser",
    "TextEditor",
    "VideoPlayer",
    "AudioPlayer",
    "Monitor",
    "Archiving",
    "Email",
    "FileManager",
    "TerminalEmulator",
    "InstantMessaging",
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Source {
    Deb,
    Flatpak,
    AppImage,
}

#[derive(Clone, Debug)]
pub struct App {
    /// Package name, Flatpak id or AppImage file name: the stable id, validated before any action.
    pub id: String,
    pub name: String,
    pub source: Source,
    /// Bytes on disk.
    pub size: u64,
    /// Installed on purpose (apt-mark showmanual); Flatpaks and AppImages always are.
    pub manual: bool,
    /// Protected system software: shown as a recommendation to keep it; the user can still act on it.
    pub essential: bool,
    /// Newest change in the app's config/data folders, seconds since the epoch. A hint, not proof of use.
    pub last_activity: Option<u64>,
    /// `last_activity` is older than the cutoff. Never set for `None`: no data folder means Unknown, not Unused.
    pub stale: bool,
    /// Index into `GROUPS` when other apps do the same job, `-1` otherwise.
    pub group: i32,
    pub group_count: usize,
    /// Raw `Icon=` of its launcher (theme name or absolute path), `""` when it has none; the UI resolves it.
    pub icon: String,
}

/// Data of a Flatpak that is no longer installed.
#[derive(Clone, Debug)]
pub struct Leftover {
    pub id: String,
    pub size: u64,
    pub last_activity: Option<u64>,
}

/// Things that no installed app needs any more, and the bytes removing them frees.
#[derive(Default, Debug)]
pub struct Cleanup {
    pub items: Vec<String>,
    pub freed: u64,
}

/// An installed kernel. `keep` ones (the running one, the newest and, if those are the same, the one before) are
/// never removed, so GRUB always has a fallback.
#[derive(Clone, Debug, PartialEq)]
pub struct Kernel {
    pub running: bool,
    pub keep: bool,
    /// Version without the flavour, e.g. `7.0.0-28`. The stable id.
    pub version: String,
    /// Every installed package of it (image, modules, headers...).
    pub packages: Vec<String>,
    pub size: u64,
}

#[derive(Default)]
pub struct Scan {
    pub apps: Vec<App>,
    pub leftovers: Vec<Leftover>,
    /// Settings folders in `~/.config` and `~/.local/share` that no installed app owns (`id` is the path from home).
    pub home_data: Vec<Leftover>,
    /// Flatpak runtimes nothing needs (`flatpak uninstall --unused`).
    pub runtimes: Cleanup,
    /// Packages `apt autoremove` would remove.
    pub autoremove: Cleanup,
    /// Removed packages that still have their config files in /etc (dpkg state `rc`).
    pub residual: Cleanup,
    pub kernels: Vec<Kernel>,
}

pub struct Dirs {
    pub home: PathBuf,
    /// System launchers (`/usr/share/applications`).
    pub applications: PathBuf,
    /// Where Flatpak exports its launchers, system and user.
    pub flatpak_exports: Vec<PathBuf>,
    pub appimages: PathBuf,
}

impl Dirs {
    pub fn from_env() -> Self {
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
        Self {
            applications: "/usr/share/applications".into(),
            flatpak_exports: vec![
                "/var/lib/flatpak/exports/share/applications".into(),
                home.join(".local/share/flatpak/exports/share/applications"),
            ],
            appimages: home.join("AppImages"),
            home,
        }
    }

    fn flatpak_data(&self) -> PathBuf {
        self.home.join(".var/app")
    }
}

/// Runs with the C locale: Flatpak prints sizes as `40,6 MB` in some locales.
pub(crate) fn run(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// Letters, digits and `+.-` (Debian policy), starting with a letter or digit: it can never become a flag.
pub fn valid_pkg(p: &str) -> bool {
    p.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        && p.bytes().all(|b| b.is_ascii_alphanumeric() || b"+.-".contains(&b))
}

/// Flatpak ids and runtime names: letters, digits and `._-`, starting with a letter or digit.
pub fn valid_id(id: &str) -> bool {
    id.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

/// `40.6 MB`, `1.4 GB`, `623 bytes` (SI units, as Flatpak prints them) to bytes. The C locale turns Flatpak's
/// no-break space into `?`, so the number ends at the first character that is not a digit or a dot.
pub(crate) fn parse_size(text: &str) -> u64 {
    let (n, unit) = text.split_at(
        text.find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(text.len()),
    );
    let scale = match unit.trim_matches(|c: char| c.is_whitespace() || c == '?') {
        "kB" => 1e3,
        "MB" => 1e6,
        "GB" => 1e9,
        "TB" => 1e12,
        _ => 1.0,
    };
    (n.parse::<f64>().unwrap_or(0.0) * scale) as u64
}

/// `(id, name, bytes)` from `flatpak list --app --columns=application,name,size`.
fn parse_flatpaks(text: &str) -> Vec<(String, String, u64)> {
    text.lines()
        .filter_map(|l| {
            let mut c = l.split('\t');
            let (id, name) = (c.next()?.trim(), c.next()?.trim());
            (valid_id(id)).then(|| (id.to_string(), name.to_string(), parse_size(c.next().unwrap_or(""))))
        })
        .collect()
}

/// `(package, file)` from `dpkg-query -S`: lines like `firefox: /usr/share/applications/firefox.desktop`, possibly
/// `pkg:amd64` or `a, b: path`. Diversion lines are skipped.
fn parse_owners(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter(|l| !l.starts_with("diversion"))
        .filter_map(|l| {
            let (pkgs, file) = l.rsplit_once(": ")?;
            let pkg = pkgs.split(',').next()?.trim();
            Some((pkg.split(':').next()?.to_string(), file.trim().to_string()))
        })
        .collect()
}

/// `(package, bytes)` from `dpkg-query -W -f='${Package}\t${Installed-Size}\n'` (KiB).
fn parse_installed_sizes(text: &str) -> HashMap<String, u64> {
    text.lines()
        .filter_map(|l| {
            let (p, kib) = l.split_once('\t')?;
            Some((p.to_string(), kib.trim().parse::<u64>().ok()? * 1024))
        })
        .collect()
}

/// Packages `apt-get -s remove` would remove: lines like `Remv foo [1.0] (repo)`.
fn parse_removals(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.strip_prefix("Remv ")?.split_whitespace().next().map(String::from))
        .collect()
}

/// `(size, newest mtime)` of everything under `dir`, not following symlinks. `None` newest when empty or unreadable.
pub(crate) fn walk(dir: &Path, budget: &mut u32) -> (u64, Option<u64>) {
    let (mut size, mut newest) = (0, None::<u64>);
    let Ok(read) = fs::read_dir(dir) else { return (0, None) };
    for e in read.flatten() {
        if *budget == 0 {
            break;
        }
        *budget -= 1;
        let Ok(meta) = e.metadata() else { continue };
        let secs = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs());
        newest = newest.max(secs);
        if meta.is_dir() {
            let (s, n) = walk(&e.path(), budget);
            size += s;
            newest = newest.max(n);
        } else {
            size += meta.len();
        }
    }
    (size, newest)
}

/// Newest change in the folders an app usually keeps its data in. `names` are lowercase guesses (id, name, package).
fn last_activity(dirs: &Dirs, flatpak_id: Option<&str>, names: &[&str]) -> Option<u64> {
    let mut folders: Vec<PathBuf> = flatpak_id.map(|id| dirs.flatpak_data().join(id)).into_iter().collect();
    // Matched case-insensitively (VS Code keeps ~/.config/Code); `~/.mozilla/firefox` and `~/.<name>` are common too.
    for (base, prefix) in [(".config", ""), (".local/share", ""), (".mozilla", ""), ("", ".")] {
        let Ok(read) = fs::read_dir(dirs.home.join(base)) else {
            continue;
        };
        for e in read.flatten() {
            let file = e.file_name().to_string_lossy().to_lowercase();
            if names.iter().any(|n| valid_id(n) && file == format!("{prefix}{n}")) {
                folders.push(e.path());
            }
        }
    }
    folders.iter().filter_map(|f| walk(f, &mut WALK_CAP.clone()).1).max()
}

fn group_of(categories: &[&str]) -> Option<usize> {
    let has = |c: &str| categories.contains(&c);
    let name = if has("Player") {
        if has("Video") {
            "VideoPlayer"
        } else if has("Audio") {
            "AudioPlayer"
        } else {
            return None;
        }
    } else {
        *GROUPS.iter().find(|g| has(g) && !g.ends_with("Player"))?
    };
    GROUPS.iter().position(|g| *g == name)
}

pub(crate) fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Name, group and `Icon=` of a launcher file, if it is a visible application.
fn launcher(path: &Path) -> Option<(String, Option<usize>, String)> {
    let text = fs::read_to_string(path).ok()?;
    let map = parse(&text);
    if map.get("NoDisplay") == Some(&"true") || map.get("Hidden") == Some(&"true") {
        return None;
    }
    Some((
        map.get("Name")?.to_string(),
        group_of(&list(&map, "Categories")),
        map.get("Icon").unwrap_or(&"").to_string(),
    ))
}

fn debs(dirs: &Dirs) -> Vec<App> {
    let mut files: Vec<PathBuf> = fs::read_dir(&dirs.applications)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "desktop"))
        .collect();
    files.sort();
    if files.is_empty() {
        return vec![];
    }
    let paths: Vec<&str> = files.iter().filter_map(|f| f.to_str()).collect();
    let owners = parse_owners(&run("dpkg-query", &[&["-S"], &paths[..]].concat()));
    // One entry per package: its first launcher names it (libreoffice has a dozen).
    let mut pkgs: BTreeMap<String, (String, Option<usize>, String)> = BTreeMap::new();
    for (pkg, file) in owners.into_iter().filter(|(p, _)| valid_pkg(p)) {
        if let Some(l) = launcher(Path::new(&file)) {
            pkgs.entry(pkg).or_insert(l);
        }
    }
    let names: Vec<&str> = pkgs.keys().map(String::as_str).collect();
    let sizes = parse_installed_sizes(&run(
        "dpkg-query",
        &[&["-W", "-f=${Package}\t${Installed-Size}\n"], &names[..]].concat(),
    ));
    let manual: HashSet<String> = run("apt-mark", &["showmanual"]).lines().map(String::from).collect();
    let rules = rules();
    pkgs.into_iter()
        .map(|(id, (name, group, icon))| App {
            icon,
            size: sizes.get(&id).copied().unwrap_or(0),
            manual: manual.contains(&id),
            essential: matches(&rules.essential_apps, &id),
            last_activity: last_activity(dirs, None, &[&id, &name.to_lowercase()]),
            group: group.map_or(-1, |g| g as i32),
            group_count: 0,
            stale: false,
            source: Source::Deb,
            name,
            id,
        })
        .collect()
}

fn flatpaks(dirs: &Dirs) -> Vec<App> {
    let list = parse_flatpaks(&run("flatpak", &["list", "--app", "--columns=application,name,size"]));
    list.into_iter()
        .map(|(id, name, size)| {
            let found = dirs
                .flatpak_exports
                .iter()
                .find_map(|d| launcher(&d.join(format!("{id}.desktop"))));
            let group = found.as_ref().and_then(|l| l.1);
            let short = id.rsplit('.').next().unwrap_or("").to_lowercase();
            App {
                icon: found.map(|l| l.2).unwrap_or_default(),
                last_activity: last_activity(dirs, Some(&id), &[&short]),
                group: group.map_or(-1, |g| g as i32),
                group_count: 0,
                manual: true,
                essential: false,
                stale: false,
                source: Source::Flatpak,
                size,
                name,
                id,
            }
        })
        .collect()
}

/// Icon of an AppImage: the user launcher that runs it (what AppImage integrators write), else `.icons/<stem>`
/// next to it. shortcut: reads `~/.local/share/applications` directly, ignoring `XDG_DATA_HOME`.
fn appimage_icon(dirs: &Dirs, file: &str, stem: &str) -> String {
    let launchers = fs::read_dir(dirs.home.join(".local/share/applications"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| fs::read_to_string(e.path()).ok());
    for text in launchers {
        let map = parse(&text);
        let runs_it = map.get("Exec").is_some_and(|x| x.contains(&format!("/{file}")));
        if let Some(icon) = map.get("Icon").filter(|i| runs_it && !i.is_empty()) {
            return icon.to_string();
        }
    }
    let icons = dirs.appimages.join(".icons");
    [format!("{stem}.svg"), format!("{stem}.png"), stem.to_string()]
        .into_iter()
        .map(|n| icons.join(n))
        .find(|p| p.is_file())
        .map_or_else(String::new, |p| p.to_string_lossy().into_owned())
}

fn appimages(dirs: &Dirs) -> Vec<App> {
    fs::read_dir(&dirs.appimages)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let path = e.path();
            let meta = e.metadata().ok()?;
            let ext = path.extension()?.to_str()?.to_lowercase();
            let stem = path.file_stem()?.to_str()?.to_string();
            (ext == "appimage" && meta.is_file()).then(|| App {
                icon: appimage_icon(dirs, &e.file_name().to_string_lossy(), &stem),
                id: e.file_name().to_string_lossy().into_owned(),
                last_activity: last_activity(dirs, None, &[&stem.to_lowercase()]),
                size: meta.len(),
                name: stem,
                source: Source::AppImage,
                manual: true,
                essential: false,
                stale: false,
                group: -1,
                group_count: 0,
            })
        })
        .collect()
}

/// `stale_months` is the cutoff for `App::stale`; `now` is seconds since the epoch.
fn finish(mut s: Scan, stale_months: u32, now: u64) -> Scan {
    let cutoff = now.saturating_sub(u64::from(stale_months) * 30 * 86400);
    let mut counts = [0usize; GROUPS.len()];
    for a in &s.apps {
        if a.group >= 0 {
            counts[a.group as usize] += 1;
        }
    }
    for a in &mut s.apps {
        a.stale = a.last_activity.is_some_and(|t| t < cutoff);
        a.group_count = if a.group >= 0 { counts[a.group as usize] } else { 0 };
        // A group of one is not an overlap.
        if a.group_count < 2 {
            a.group = -1;
        }
    }
    // Things you can act on first (largest first), protected software last.
    s.apps.sort_by(|a, b| {
        (a.essential, b.size)
            .cmp(&(b.essential, a.size))
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    s.leftovers.sort_by_key(|l| std::cmp::Reverse(l.size));
    s
}

fn leftovers(dirs: &Dirs, apps: &[App]) -> Vec<Leftover> {
    let installed: HashSet<&str> = apps
        .iter()
        .filter(|a| a.source == Source::Flatpak)
        .map(|a| a.id.as_str())
        .collect();
    fs::read_dir(dirs.flatpak_data())
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let id = e.file_name().into_string().ok()?;
            if installed.contains(id.as_str()) || !valid_id(&id) || !e.metadata().ok()?.is_dir() {
                return None;
            }
            let (size, last_activity) = walk(&e.path(), &mut WALK_CAP.clone());
            Some(Leftover {
                id,
                size,
                last_activity,
            })
        })
        .collect()
}

/// Folders in `~/.config` and `~/.local/share` that the desktop itself uses, whoever owns them.
const SHARED_DATA: &[&str] = &[
    "applications",
    "autostart",
    "cinnamon",
    "dconf",
    "fastcheckup",
    "flatpak",
    "fontconfig",
    "fonts",
    "gnome",
    "gtk-3.0",
    "gtk-4.0",
    "gvfs-metadata",
    "icons",
    "ibus",
    "keyrings",
    "menus",
    "mime",
    "pulse",
    "systemd",
    "themes",
    "trash",
    "xdg-desktop-portal",
];

/// Lowercase names of everything installed: every dpkg package, plus the name and id of each app found.
fn known_names(dirs: &Dirs, apps: &[App]) -> HashSet<String> {
    let mut known: HashSet<String> = run("dpkg-query", &["-W", "-f=${Package}\n"])
        .lines()
        .map(str::to_lowercase)
        .collect();
    for a in apps {
        known.insert(a.id.to_lowercase());
        known.insert(a.name.to_lowercase());
    }
    // VS Code extensions (`publisher.name-version`) keep data under the publisher's name.
    for e in fs::read_dir(dirs.home.join(".vscode/extensions"))
        .into_iter()
        .flatten()
        .flatten()
    {
        if let Some((publisher, _)) = e.file_name().to_string_lossy().to_lowercase().split_once('.') {
            known.insert(publisher.to_string());
        }
    }
    known
}

/// Settings folders of apps that are not installed any more. A folder counts as owned when its lowercase name is an
/// installed name or the start of one (`google-chrome` for `google-chrome-stable`). Only a guess: the list says so.
fn home_leftovers(dirs: &Dirs, known: &HashSet<String>) -> Vec<Leftover> {
    let mut out = vec![];
    for base in [".config", ".local/share"] {
        for e in fs::read_dir(dirs.home.join(base)).into_iter().flatten().flatten() {
            let Ok(name) = e.file_name().into_string() else {
                continue;
            };
            let lower = name.to_lowercase();
            // Also owned when it starts with an installed name's first word (`DBeaverData` for `dbeaver-ce`).
            let owned = known.contains(&lower)
                || known.iter().any(|k| {
                    let word = k.split('-').next().unwrap_or(k);
                    k.strip_prefix(&lower).is_some_and(|r| r.starts_with('-'))
                        || (word.len() >= 4 && lower.starts_with(word))
                });
            if owned
                || SHARED_DATA.contains(&lower.as_str())
                || !valid_id(&name)
                || !e.metadata().is_ok_and(|m| m.is_dir())
            {
                continue;
            }
            let (size, last_activity) = walk(&e.path(), &mut WALK_CAP.clone());
            out.push(Leftover {
                id: format!("{base}/{name}"),
                size,
                last_activity,
            });
        }
    }
    out.sort_by_key(|l| std::cmp::Reverse(l.size));
    out
}

/// `id` is `.config/<name>` or `.local/share/<name>`: the only two shapes `home_leftovers` makes.
pub fn home_data_path(dirs: &Dirs, id: &str) -> Option<PathBuf> {
    let name = id
        .strip_prefix(".config/")
        .or_else(|| id.strip_prefix(".local/share/"))?;
    (plain(name) && valid_id(name)).then(|| dirs.home.join(id))
}

/// Settings folder of a removed app, to the Trash. Re-checked: the app may have been installed since the scan.
pub fn trash_home_data(dirs: &Dirs, id: &str) -> io::Result<()> {
    let path = home_data_path(dirs, id).ok_or_else(|| io::Error::other("invalid folder"))?;
    let mut apps = debs(dirs);
    apps.extend(flatpaks(dirs));
    apps.extend(appimages(dirs));
    if !home_leftovers(dirs, &known_names(dirs, &apps))
        .iter()
        .any(|l| l.id == id)
    {
        return Err(io::Error::other("an installed app uses it now, scan again"));
    }
    command_ok(Command::new("gio").args(["trash", "--"]).arg(path)).map(drop)
}

pub fn scan(dirs: &Dirs, stale_months: u32) -> Scan {
    let mut apps = debs(dirs);
    apps.extend(flatpaks(dirs));
    apps.extend(appimages(dirs));
    let leftovers = leftovers(dirs, &apps);
    let home_data = home_leftovers(dirs, &known_names(dirs, &apps));
    let (items, freed) = unused_flatpak().unwrap_or_default();
    let scan = Scan {
        apps,
        leftovers,
        home_data,
        runtimes: Cleanup { items, freed },
        autoremove: autoremove_plan(),
        residual: residual_plan(),
        kernels: installed_kernels(),
    };
    finish(scan, stale_months, now())
}

/// What `apt-get remove` would do: everything that goes with the app, and the bytes freed.
#[derive(Debug)]
pub struct DebPlan {
    pub removes: Vec<String>,
    pub freed: u64,
}

pub fn precheck_deb(pkg: &str) -> io::Result<DebPlan> {
    if !valid_pkg(pkg) {
        return Err(io::Error::other("invalid package name"));
    }
    let removes = parse_removals(&run("apt-get", &["-s", "remove", pkg]));
    // The package may have been removed since the scan.
    if !removes.iter().any(|r| r == pkg) {
        return Err(io::Error::other("package is not installed, scan again"));
    }
    let freed = installed_size(&removes);
    Ok(DebPlan { removes, freed })
}

/// Bytes the installed packages `names` take.
fn installed_size(names: &[String]) -> u64 {
    if names.is_empty() {
        return 0;
    }
    let args = [
        &["-W", "-f=${Package}\t${Installed-Size}\n"],
        &names.iter().map(String::as_str).collect::<Vec<_>>()[..],
    ];
    let sizes = parse_installed_sizes(&run("dpkg-query", &args.concat()));
    names.iter().filter_map(|r| sizes.get(r)).sum()
}

/// Packages nothing needs, from the simulated `apt-get autoremove`.
pub fn autoremove_plan() -> Cleanup {
    let items = parse_removals(&run("apt-get", &["-s", "autoremove"]));
    Cleanup {
        freed: installed_size(&items),
        items,
    }
}

/// Packages in state `rc` from `dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n'`.
fn parse_residual(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.strip_prefix("rc ").map(|p| p.trim().to_string()))
        .filter(|p| valid_pkg(p))
        .collect()
}

pub fn residual_configs() -> Vec<String> {
    parse_residual(&run("dpkg-query", &["-W", "-f=${db:Status-Abbrev} ${Package}\n"]))
}

/// Paths from `${Conffiles}` output: lines like ` /etc/mame/mame.ini 0a1b... [obsolete]`.
fn parse_conffiles(text: &str) -> HashSet<&str> {
    text.lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|p| p.starts_with('/'))
        .collect()
}

/// The config files are all a removed package leaves, so their size is what purging frees. A file shared by two
/// packages counts once.
pub fn residual_plan() -> Cleanup {
    let items = residual_configs();
    if items.is_empty() {
        return Cleanup::default();
    }
    let out = run(
        "dpkg-query",
        &[
            &["-W", "-f=${Conffiles}\n"],
            &items.iter().map(String::as_str).collect::<Vec<_>>()[..],
        ]
        .concat(),
    );
    let freed = parse_conffiles(&out)
        .into_iter()
        .filter_map(|f| fs::metadata(f).ok())
        .map(|m| m.len())
        .sum();
    Cleanup { items, freed }
}

/// The kernel version at the end of a kernel package name (`linux-hwe-6.8-headers-6.8.0-57` gives `6.8.0-57`).
/// Meta packages (`linux-image-generic-7.0`) have no `N.N.N`, so they never match.
fn kernel_release(pkg: &str) -> Option<&str> {
    let kind = ["image", "modules", "headers", "tools", "buildinfo"];
    let is_version = |v: &str| {
        let mut n = v.splitn(3, '.');
        n.next().is_some_and(|x| x.parse::<u32>().is_ok())
            && n.next().is_some_and(|x| x.parse::<u32>().is_ok())
            && n.next().is_some_and(|x| x.starts_with(|c: char| c.is_ascii_digit()))
    };
    pkg.strip_prefix("linux-")?;
    pkg.match_indices('-')
        .map(|(i, _)| i + 1)
        .find(|&i| is_version(&pkg[i..]) && kind.iter().any(|k| pkg[..i].contains(k)))
        .map(|i| &pkg[i..])
}

/// `7.0.0-38-generic` and `7.0.0-38` both give `7.0.0-38`: the flavour is not part of the version.
fn kernel_version(release: &str) -> &str {
    release
        .match_indices('-')
        .nth(1)
        .map_or(release, |(i, _)| &release[..i])
}

fn version_key(v: &str) -> Vec<u64> {
    v.split(['.', '-']).map(|n| n.parse().unwrap_or(0)).collect()
}

/// Installed kernels, newest first, with `keep` set on the ones that must stay. From `dpkg-query -W -f='${db:Status-Abbrev} ${Package} ${Installed-Size}\n'`.
fn parse_kernels(text: &str, running: &str) -> Vec<Kernel> {
    let mut all: BTreeMap<String, Kernel> = BTreeMap::new();
    for l in text.lines() {
        let mut c = l.split_whitespace();
        let (Some("ii"), Some(pkg), Some(kib)) = (c.next(), c.next(), c.next()) else {
            continue;
        };
        let Some(rest) = kernel_release(pkg).filter(|_| valid_pkg(pkg)) else {
            continue;
        };
        let version = kernel_version(rest).to_string();
        let k = all.entry(version.clone()).or_insert_with(|| Kernel {
            running: false,
            keep: false,
            version,
            packages: vec![],
            size: 0,
        });
        k.packages.push(pkg.to_string());
        k.size += kib.parse::<u64>().unwrap_or(0) * 1024;
    }
    let mut versions: Vec<String> = all.keys().cloned().collect();
    versions.sort_by_key(|v| std::cmp::Reverse(version_key(v)));
    let running = kernel_version(running);
    let mut keep: Vec<&str> = vec![running];
    for v in &versions {
        if keep.len() >= 2 {
            break;
        }
        if !keep.contains(&v.as_str()) {
            keep.push(v);
        }
    }
    // The newest is kept even when the running one is older than the first two.
    if let Some(newest) = versions.first().filter(|v| !keep.contains(&v.as_str())) {
        keep.push(newest);
    }
    let keep: Vec<String> = keep.into_iter().map(String::from).collect();
    versions
        .into_iter()
        .filter_map(|v| all.remove(&v))
        .map(|k| Kernel {
            running: k.version == running,
            keep: keep.contains(&k.version),
            ..k
        })
        .collect()
}

/// Empty when `uname -r` cannot be read: without it nothing is known to be safe to remove.
pub fn installed_kernels() -> Vec<Kernel> {
    let running = run("uname", &["-r"]);
    if running.trim().is_empty() {
        return vec![];
    }
    parse_kernels(
        &run(
            "dpkg-query",
            &["-W", "-f=${db:Status-Abbrev} ${Package} ${Installed-Size}\n", "linux-*"],
        ),
        running.trim(),
    )
}

/// What removing `version` would do. The kernel is looked up again, so only an offered one can be removed.
pub fn kernel_plan(version: &str) -> io::Result<(Kernel, DebPlan)> {
    let kernel = installed_kernels()
        .into_iter()
        .find(|k| k.version == version && !k.keep)
        .ok_or_else(|| io::Error::other("kernel is not an old kernel any more, scan again"))?;
    let mut args = vec!["-s", "remove"];
    args.extend(kernel.packages.iter().map(String::as_str));
    let removes = parse_removals(&run("apt-get", &args));
    let freed = installed_size(&removes);
    Ok((kernel, DebPlan { removes, freed }))
}

pub fn remove_kernel(version: &str) -> io::Result<()> {
    let (kernel, _) = kernel_plan(version)?;
    pkexec_run(
        APT_GET,
        &[
            &["remove", "-y"],
            &kernel.packages.iter().map(String::as_str).collect::<Vec<_>>()[..],
        ]
        .concat(),
    )
}

/// Runs as root. The list is re-read first: it may have changed since the scan.
pub fn autoremove() -> io::Result<()> {
    if autoremove_plan().items.is_empty() {
        return Err(io::Error::other("nothing to remove, scan again"));
    }
    pkexec_run(APT_GET, &["autoremove", "-y"])
}

/// Deletes the config files of packages that are already removed.
pub fn purge_residual() -> io::Result<()> {
    let pkgs = residual_configs();
    if pkgs.is_empty() {
        return Err(io::Error::other("nothing to remove, scan again"));
    }
    pkexec_run(
        APT_GET,
        &[
            &["purge", "-y"],
            &pkgs.iter().map(String::as_str).collect::<Vec<_>>()[..],
        ]
        .concat(),
    )
}

/// `remove`, not `purge`: the user's settings in /etc stay.
pub fn uninstall_deb(pkg: &str) -> io::Result<()> {
    precheck_deb(pkg)?;
    pkexec_run(APT_GET, &["remove", "-y", pkg])
}

pub(crate) fn command_ok(cmd: &mut Command) -> io::Result<String> {
    let out = cmd.env("LC_ALL", "C").output()?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(io::Error::other(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ))
    }
}

pub fn uninstall_flatpak(id: &str) -> io::Result<()> {
    if !valid_id(id) {
        return Err(io::Error::other("invalid application id"));
    }
    if !parse_flatpaks(&run("flatpak", &["list", "--app", "--columns=application,name,size"]))
        .iter()
        .any(|(i, ..)| i == id)
    {
        return Err(io::Error::other("application is not installed, scan again"));
    }
    // Flatpak asks polkit itself for system installs.
    command_ok(Command::new("flatpak").args(["uninstall", "-y", id])).map(drop)
}

/// `(id, branch)` of the runtimes `flatpak uninstall --unused` would remove, from its table:
/// ` 1. [-] org.freedesktop.Platform.Locale   23.08   r`.
fn parse_unused(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| {
            let mut c = l.split_whitespace();
            c.next()?.strip_suffix('.')?.parse::<u32>().ok()?;
            c.next().filter(|m| m.starts_with('['))?;
            Some((c.next()?.to_string(), c.next()?.to_string()))
        })
        .filter(|(id, _)| valid_id(id))
        .collect()
}

/// `(id, branch)` to bytes for installed runtimes.
fn parse_runtime_sizes(text: &str) -> HashMap<(String, String), u64> {
    text.lines()
        .filter_map(|l| {
            let mut c = l.split('\t');
            Some(((c.next()?.to_string(), c.next()?.to_string()), parse_size(c.next()?)))
        })
        .collect()
}

/// The runtimes no installed app needs, with the bytes freed. Old Flatpak has no dry run, so this answers `n` to
/// the prompt of the real command, which prints the list first.
pub fn unused_flatpak() -> io::Result<(Vec<String>, u64)> {
    let mut child = Command::new("flatpak")
        .args(["uninstall", "--unused"])
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    // Dropping stdin after one "n" also ends any further prompt.
    if let Some(mut stdin) = child.stdin.take() {
        let _ = io::Write::write_all(&mut stdin, b"n\n");
    }
    let out = child.wait_with_output()?;
    let unused = parse_unused(&String::from_utf8_lossy(&out.stdout));
    let sizes = parse_runtime_sizes(&run(
        "flatpak",
        &["list", "--runtime", "--columns=application,branch,size"],
    ));
    let freed = unused.iter().filter_map(|k| sizes.get(k)).sum();
    Ok((unused.into_iter().map(|(id, b)| format!("{id}//{b}")).collect(), freed))
}

pub fn remove_unused_flatpak() -> io::Result<()> {
    command_ok(Command::new("flatpak").args(["uninstall", "--unused", "-y"])).map(drop)
}

/// One path component: no `/`, `..` or absolute path.
pub(crate) fn plain(name: &str) -> bool {
    let mut parts = Path::new(name).components();
    matches!(parts.next(), Some(std::path::Component::Normal(_))) && parts.next().is_none()
}

/// Moves `root/name` to the Trash. `name` must be one plain path component, so nothing outside `root` can be named.
pub(crate) fn trash_in(root: &Path, name: &str) -> io::Result<()> {
    if !plain(name) {
        return Err(io::Error::other("invalid file name"));
    }
    let path = root.join(name);
    if fs::symlink_metadata(&path).is_err() {
        return Err(io::Error::other("file is gone, scan again"));
    }
    command_ok(Command::new("gio").args(["trash", "--"]).arg(path)).map(drop)
}

/// Data of a Flatpak that is no longer installed. Re-checked: it may have been reinstalled since the scan.
pub fn trash_leftover(dirs: &Dirs, id: &str) -> io::Result<()> {
    if !valid_id(id) {
        return Err(io::Error::other("invalid application id"));
    }
    if parse_flatpaks(&run("flatpak", &["list", "--app", "--columns=application,name,size"]))
        .iter()
        .any(|(i, ..)| i == id)
    {
        return Err(io::Error::other("application is installed again, scan again"));
    }
    trash_in(&dirs.flatpak_data(), id)
}

/// A startup entry in `~/.config/autostart` whose program is gone. Re-checked: the app may have been installed since.
pub fn trash_stale_startup(file: &str) -> io::Result<()> {
    let dirs = crate::autostart::Dirs::from_env();
    if !file.ends_with(".desktop") || !crate::autostart::stale(&dirs).iter().any(|e| e.file == file) {
        return Err(io::Error::other("entry is not stale any more, scan again"));
    }
    trash_in(&dirs.user, file)
}

pub fn trash_appimage(dirs: &Dirs, file: &str) -> io::Result<()> {
    if !file.to_lowercase().ends_with(".appimage") {
        return Err(io::Error::other("not an AppImage"));
    }
    trash_in(&dirs.appimages, file)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("fastcheckup-apps-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn dirs(home: &Path) -> Dirs {
        Dirs {
            home: home.into(),
            applications: home.join("apps"),
            flatpak_exports: vec![home.join("exports")],
            appimages: home.join("AppImages"),
        }
    }

    fn app(id: &str, group: i32, last: Option<u64>) -> App {
        App {
            id: id.into(),
            name: id.into(),
            source: Source::Deb,
            size: 1,
            manual: true,
            essential: false,
            last_activity: last,
            stale: false,
            group,
            group_count: 0,
            icon: String::new(),
        }
    }

    #[test]
    fn names() {
        assert!(valid_pkg("libstdc++6") && valid_pkg("g++-12") && valid_pkg("python3.12"));
        assert!(!valid_pkg("-x") && !valid_pkg("a b") && !valid_pkg("../x") && !valid_pkg(""));
        assert!(valid_id("com.github.tchx84.Flatseal") && !valid_id("-x") && !valid_id("a/b") && !valid_id(".."));
    }

    #[test]
    fn sizes() {
        assert_eq!(parse_size("40.6 MB"), 40_600_000);
        assert_eq!(parse_size("1.4 GB"), 1_400_000_000);
        assert_eq!(parse_size("623 bytes"), 623);
        assert_eq!(parse_size("40.6?MB"), 40_600_000);
        assert_eq!(parse_size("1.4\u{a0}GB"), 1_400_000_000);
        assert_eq!(parse_size(""), 0);
        let got = parse_flatpaks("com.stremio.Stremio\tStremio\t133.5 MB\n-bad\tX\t1 MB\n");
        assert_eq!(got, vec![("com.stremio.Stremio".into(), "Stremio".into(), 133_500_000)]);
    }

    #[test]
    fn owners_and_sizes() {
        let text = "firefox: /usr/share/applications/firefox.desktop\nlibfoo:amd64, libbar: /x/a.desktop\n\
                    diversion by dash from: /bin/sh\n";
        assert_eq!(
            parse_owners(text),
            vec![
                ("firefox".into(), "/usr/share/applications/firefox.desktop".into()),
                ("libfoo".into(), "/x/a.desktop".into())
            ]
        );
        assert_eq!(parse_installed_sizes("bash\t1900\nbad\tx\n")["bash"], 1900 * 1024);
    }

    #[test]
    fn removals() {
        let text = "NOTE: This is only a simulation!\nRemv vlc [3.0] (repo)\nRemv vlc-plugin [3.0]\nInst x [1]\n";
        assert_eq!(parse_removals(text), vec!["vlc", "vlc-plugin"]);
        assert!(parse_removals("Package 'x' is not installed, so not removed\n").is_empty());
    }

    #[test]
    fn residual_configs_are_state_rc() {
        let text = "ii  bash\nrc  old-pkg\nrc  -bad\nun  gone\n";
        assert_eq!(parse_residual(text), vec!["old-pkg"]);
    }

    #[test]
    fn conffiles_are_paths_once() {
        let text = " /etc/a.ini 0a1b\n /etc/b obsolete\n\n /etc/a.ini 0a1b\n";
        assert_eq!(parse_conffiles(text).len(), 2);
    }

    #[test]
    fn old_kernels_keep_running_newest_and_a_fallback() {
        let text = "ii  linux-image-7.0.0-28-generic 100\nii  linux-modules-7.0.0-28-generic 50\n\
                    ii  linux-headers-7.0.0-28 5\nii  linux-image-7.0.0-38-generic 100\n\
                    ii  linux-image-unsigned-7.0.14-070014-generic 90\nrc  linux-image-6.8.0-52-generic 1\n\
                    ii  linux-firmware 9\nii  linux-libc-dev 9\nii  linux-image-generic-7.0 9\n";
        let old = |t, r| parse_kernels(t, r).into_iter().filter(|k| !k.keep).collect::<Vec<_>>();
        let got = old(text, "7.0.0-38-generic");
        assert_eq!(got.len(), 1);
        assert_eq!(
            (got[0].version.as_str(), got[0].packages.len(), got[0].size),
            ("7.0.0-28", 3, 155 * 1024)
        );
        // Running = newest: the next newest stays as the fallback, the oldest is offered.
        let got = old(text, "7.0.14-070014-generic");
        assert_eq!(got.iter().map(|k| k.version.as_str()).collect::<Vec<_>>(), ["7.0.0-28"]);
        assert_eq!(kernel_release("linux-hwe-6.8-headers-6.8.0-57"), Some("6.8.0-57"));
        assert_eq!(
            kernel_release("linux-main-modules-zfs-7.0.0-38-generic"),
            Some("7.0.0-38-generic")
        );
        assert_eq!(kernel_release("linux-headers-generic-7.0"), None);
        assert_eq!(kernel_release("linux-source-6.8.0"), None);
        // Two kernels or fewer: nothing to offer. Unknown running kernel keeps the newest two.
        let two = "ii  linux-image-5.1.0-1-generic 1\nii  linux-image-5.2.0-1-generic 1\n";
        assert!(old(two, "5.2.0-1-generic").is_empty());
        let all = parse_kernels(text, "7.0.0-38-generic");
        let flags = |v: &str| all.iter().find(|k| k.version == v).map(|k| (k.running, k.keep));
        assert_eq!(
            (flags("7.0.0-38"), flags("7.0.14-070014"), flags("7.0.0-28")),
            (Some((true, true)), Some((false, true)), Some((false, false)))
        );
    }

    #[test]
    fn unused_table() {
        let text = "        ID                          Branch   Op\n 1. [-] org.freedesktop.Platform.Locale   23.08    r\n\
                    10. [✗] org.gnome.Platform   44    r\nProceed with these changes? [Y/n]:\n";
        assert_eq!(
            parse_unused(text)[0],
            ("org.freedesktop.Platform.Locale".into(), "23.08".into())
        );
        assert_eq!(parse_unused(text).len(), 2);
        let sizes = parse_runtime_sizes("org.gnome.Platform\t44\t1.5 GB\n");
        assert_eq!(
            sizes[&("org.gnome.Platform".to_string(), "44".to_string())],
            1_500_000_000
        );
    }

    #[test]
    fn groups() {
        assert_eq!(group_of(&["AudioVideo", "Player", "Video"]), Some(2));
        assert_eq!(group_of(&["AudioVideo", "Player", "Audio"]), Some(3));
        assert_eq!(group_of(&["Network", "WebBrowser"]), Some(0));
        assert_eq!(group_of(&["Game"]), None);
    }

    #[test]
    fn overlap_needs_two_and_stale_needs_data() {
        let day = 86400;
        let s = Scan {
            apps: vec![
                app("a", 0, Some(100 * day)),
                app("b", 0, None),
                app("c", 1, Some(1000 * day)),
            ],
            ..Default::default()
        };
        let s = finish(s, 6, 1000 * day);
        let get = |id| s.apps.iter().find(|a| a.id == id).unwrap();
        assert_eq!((get("a").group, get("a").group_count, get("a").stale), (0, 2, true));
        assert!(!get("b").stale);
        assert_eq!((get("c").group, get("c").stale), (-1, false));
    }

    #[test]
    fn activity_leftovers_and_appimages() {
        let home = tmp("scan");
        let d = dirs(&home);
        fs::create_dir_all(home.join(".var/app/org.gone.App/data")).unwrap();
        fs::write(home.join(".var/app/org.gone.App/data/f"), vec![0u8; 100]).unwrap();
        fs::create_dir_all(home.join(".config/esde")).unwrap();
        fs::write(home.join(".config/esde/c"), "x").unwrap();
        fs::create_dir_all(&d.appimages).unwrap();
        fs::write(d.appimages.join("esde.appimage"), vec![0u8; 10]).unwrap();
        fs::write(d.appimages.join("notes.txt"), "").unwrap();
        let apps = appimages(&d);
        assert_eq!(apps.len(), 1);
        assert_eq!((apps[0].size, apps[0].name.as_str()), (10, "esde"));
        assert!(apps[0].last_activity.is_some());
        assert_eq!(apps[0].icon, "");
        // A user launcher that runs the file wins over `.icons/`.
        fs::create_dir_all(home.join(".local/share/applications")).unwrap();
        fs::write(
            home.join(".local/share/applications/esde.desktop"),
            "[Desktop Entry]\nExec=env X=1 /h/AppImages/esde.appimage %F\nIcon=/x/esde.svg\n",
        )
        .unwrap();
        assert_eq!(appimage_icon(&d, "esde.appimage", "esde"), "/x/esde.svg");
        fs::create_dir_all(d.appimages.join(".icons")).unwrap();
        fs::write(d.appimages.join(".icons/other.svg"), "").unwrap();
        assert!(appimage_icon(&d, "other.appimage", "other").ends_with(".icons/other.svg"));
        let left = leftovers(&d, &apps);
        assert_eq!(
            (left.len(), left[0].id.as_str(), left[0].size),
            (1, "org.gone.App", 100)
        );
        assert_eq!(last_activity(&d, None, &["nothing"]), None);
        fs::create_dir_all(home.join(".config/Code")).unwrap();
        fs::write(home.join(".config/Code/c"), "x").unwrap();
        fs::create_dir_all(home.join(".mozilla/firefox")).unwrap();
        fs::write(home.join(".mozilla/firefox/c"), "x").unwrap();
        assert!(last_activity(&d, None, &["code"]).is_some());
        assert!(last_activity(&d, None, &["firefox"]).is_some());
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn home_data_of_removed_apps() {
        let home = tmp("homedata");
        let d = dirs(&home);
        for p in [
            ".config/Insync",
            ".local/share/Insync",
            ".config/Code",
            ".config/google-chrome",
            ".config/dconf",
        ] {
            fs::create_dir_all(home.join(p)).unwrap();
            fs::write(home.join(p).join("f"), "x").unwrap();
        }
        fs::write(home.join(".config/loose-file"), "x").unwrap();
        for p in [".local/share/DBeaverData", ".local/share/DEVSENSE"] {
            fs::create_dir_all(home.join(p)).unwrap();
        }
        fs::create_dir_all(home.join(".vscode/extensions/devsense.phptools-1.0")).unwrap();
        let mut known: HashSet<String> = ["code", "google-chrome-stable", "dbeaver-ce"].map(String::from).into();
        known.extend(known_names(&d, &[]).into_iter().filter(|k| k == "devsense"));
        let ids: Vec<String> = home_leftovers(&d, &known).into_iter().map(|l| l.id).collect();
        assert_eq!(ids.len(), 2, "{ids:?}");
        assert!(ids.contains(&".config/Insync".into()) && ids.contains(&".local/share/Insync".into()));
        assert!(home_data_path(&d, ".config/Insync").is_some());
        for bad in [".config/../x", ".config/a/b", ".cache/x", "Insync", ".config/"] {
            assert!(home_data_path(&d, bad).is_none(), "{bad}");
        }
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn trash_names_are_plain() {
        let root = tmp("trash");
        for bad in ["", "..", "a/b", "/etc", "../x"] {
            assert!(trash_in(&root, bad).is_err(), "{bad}");
        }
        assert!(trash_in(&root, "missing").is_err());
        assert!(trash_appimage(&dirs(&root), "x.txt").is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rules_load() {
        assert!(matches(&rules().essential_apps, "nemo-desktop"));
        assert!(!matches(&rules().essential_apps, "vlc"));
    }
}
