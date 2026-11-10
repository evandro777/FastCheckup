//! Startup module: lists the apps that start at login and enables/disables them with a user-level override.
//! Files under /etc/xdg are never edited; the override lives in `~/.config/autostart`.
use std::{
    collections::BTreeMap,
    fs, io,
    path::{Path, PathBuf},
    sync::OnceLock,
};

use serde::Deserialize;

/// Written instead of `Hidden=true`: Mint/GNOME "Startup Applications" keep such an entry listed (switched off), while
/// `Hidden=true` makes them show it as deleted.
const OFF_KEY: &str = "X-GNOME-Autostart-enabled";
const DELAY_KEY: &str = "X-GNOME-Autostart-Delay";

#[derive(Deserialize)]
pub(crate) struct Rules {
    essential: Vec<String>,
    pub essential_services: Vec<String>,
    pub essential_apps: Vec<String>,
    pub timer_services: Vec<String>,
}

pub(crate) fn rules() -> &'static Rules {
    static RULES: OnceLock<Rules> = OnceLock::new();
    RULES.get_or_init(|| toml::from_str(include_str!("rules.toml")).expect("rules.toml is embedded and tested"))
}

/// `name` equals a pattern, or starts with it when the pattern ends in `*`.
pub(crate) fn matches(patterns: &[String], name: &str) -> bool {
    patterns.iter().any(|p| match p.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => name == p,
    })
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    Enabled,
    /// `Hidden=true` or `X-GNOME-Autostart-enabled=false`, set by anyone: FastCheckup does not track who.
    Disabled,
}

#[derive(Clone, Debug)]
pub struct Entry {
    /// File name, e.g. `syncthing-start.desktop`. The stable id.
    pub file: String,
    pub name: String,
    pub comment: String,
    pub exec: String,
    /// Raw `Icon=` value: a theme icon name or an absolute path; resolving it is the UI's job.
    pub icon: String,
    /// `X-GNOME-Autostart-Delay` in seconds; 0 when absent or not a number.
    pub delay: u32,
    /// The file that decides what happens at login (a user file wins over a system one).
    pub source: PathBuf,
    pub state: State,
    /// Protected system software: shown as a recommendation to keep it; the user can still act on it.
    pub essential: bool,
    /// Name of another enabled entry that runs the same program; empty when none. A hint, not proof.
    pub duplicate_of: String,
    /// The program (or `TryExec`) is not installed, so the entry can never start.
    pub missing: bool,
}

pub struct Dirs {
    pub system: Vec<PathBuf>,
    pub user: PathBuf,
    /// `XDG_CURRENT_DESKTOP` split on `:`, for `OnlyShowIn`/`NotShowIn`.
    pub desktops: Vec<String>,
    /// User-manager unit folders, read only to spot a program that is also started by an enabled user service.
    pub systemd_user: Vec<PathBuf>,
}

impl Dirs {
    pub fn from_env() -> Self {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let home = var("HOME").map(PathBuf::from).unwrap_or_default();
        let config = var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| home.join(".config"));
        let system = var("XDG_CONFIG_DIRS").unwrap_or_else(|| "/etc/xdg".into());
        Self {
            system: system.split(':').map(|d| Path::new(d).join("autostart")).collect(),
            user: config.join("autostart"),
            desktops: var("XDG_CURRENT_DESKTOP")
                .map(|d| d.split(':').map(str::to_string).collect())
                .unwrap_or_default(),
            systemd_user: vec![config.join("systemd/user"), "/etc/systemd/user".into()],
        }
    }
}

/// Key/value pairs of the `[Desktop Entry]` group only.
pub(crate) fn parse(text: &str) -> BTreeMap<&str, &str> {
    let mut in_group = false;
    let mut map = BTreeMap::new();
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            in_group = line == "[Desktop Entry]";
        } else if in_group && let Some((k, v)) = line.split_once('=') {
            map.entry(k.trim()).or_insert(v.trim());
        }
    }
    map
}

pub(crate) fn list<'a>(map: &BTreeMap<&str, &'a str>, key: &str) -> Vec<&'a str> {
    map.get(key)
        .map(|v| v.split(';').filter(|s| !s.is_empty()).collect())
        .unwrap_or_default()
}

fn essential(file: &str) -> bool {
    matches(&rules().essential, &file.trim_end_matches(".desktop").to_lowercase())
}

pub fn scan(dirs: &Dirs) -> Vec<Entry> {
    // Later directories win: system first, then the user's, like the autostart spec.
    let mut files: BTreeMap<String, PathBuf> = BTreeMap::new();
    for dir in dirs.system.iter().rev().chain([&dirs.user]) {
        let Ok(read) = fs::read_dir(dir) else { continue };
        for e in read.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.ends_with(".desktop") {
                files.insert(name, e.path());
            }
        }
    }
    let mut out: Vec<Entry> = files
        .into_iter()
        .filter_map(|(file, source)| {
            let text = fs::read_to_string(&source).ok()?;
            let map = parse(&text);
            let here = |l: Vec<&str>| l.iter().any(|d| dirs.desktops.iter().any(|x| x == d));
            let only = list(&map, "OnlyShowIn");
            // Never starts on this desktop, so it is not a finding.
            if (!only.is_empty() && !here(only)) || here(list(&map, "NotShowIn")) {
                return None;
            }
            // No [Desktop Entry] / Exec (e.g. a stub holding only `X-GNOME-Autostart-enabled=false`): nothing would start.
            if !map.contains_key("Exec") && !map.contains_key("DBusActivatable") {
                return None;
            }
            let off = map.get("Hidden") == Some(&"true") || map.get("X-GNOME-Autostart-enabled") == Some(&"false");
            let state = if off { State::Disabled } else { State::Enabled };
            Some(Entry {
                name: map
                    .get("Name")
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| file.trim_end_matches(".desktop").into()),
                comment: map.get("Comment").unwrap_or(&"").to_string(),
                exec: map.get("Exec").unwrap_or(&"").to_string(),
                icon: map.get("Icon").unwrap_or(&"").to_string(),
                delay: map.get(DELAY_KEY).and_then(|v| v.parse().ok()).unwrap_or(0),
                essential: essential(&file),
                duplicate_of: String::new(),
                missing: is_missing(&map),
                file,
                source,
                state,
            })
        })
        .collect();
    mark_duplicates(&mut out, &user_services(&dirs.systemd_user));
    // Things you can act on first, then disabled ones, protected software last.
    out.sort_by_key(|e| (e.essential, e.state != State::Enabled, e.name.to_lowercase()));
    out
}

/// The program an `Exec=` line starts: first word after any `env`/`VAR=x` prefix, without its directory.
/// None for shells and interpreters, where the real program is hidden in the arguments.
fn program(exec: &str) -> Option<String> {
    let cmd = command(exec)?;
    let name = cmd.rsplit('/').next()?;
    // shortcut: flatpak/snap launchers and `sh -c` are not unwrapped; unwrap them if duplicates there matter.
    (!matches!(
        name,
        "" | "sh" | "bash" | "dash" | "zsh" | "python" | "python3" | "flatpak" | "snap"
    ))
    .then(|| name.to_string())
}

/// First word of an `Exec=` line after any `env`/`VAR=x` prefix, with its directory. Quotes (`"…"`, `'…'`) and
/// backslash escapes keep spaces inside the word (`Exec="/home/me/My Apps/run.sh"`, `My\ Apps`).
fn command(exec: &str) -> Option<String> {
    let mut chars = exec.chars().peekable();
    loop {
        while chars.next_if(|c| c.is_whitespace()).is_some() {}
        let (mut word, mut quote, mut quoted) = (String::new(), None, false);
        while let Some(c) = chars.next_if(|c| quote.is_some() || !c.is_whitespace()) {
            match (c, quote) {
                ('\\', q) if q != Some('\'') => word.extend(chars.next()),
                ('"' | '\'', None) => (quote, quoted) = (Some(c), true),
                (c, Some(q)) if c == q => quote = None,
                _ => word.push(c),
            }
        }
        if word.is_empty() && !quoted {
            return None;
        }
        if quoted || (word != "env" && !word.contains('=')) {
            return (!word.is_empty()).then_some(word);
        }
    }
}

/// True when the program is not on disk: a path that does not exist, or a name found in no `$PATH` folder.
fn gone(cmd: &str) -> bool {
    if cmd.contains('/') {
        return !Path::new(cmd).exists();
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    !std::env::split_paths(&path).any(|d| d.join(cmd).exists())
}

/// An entry whose `TryExec` or program is gone, so it can never start. Shells and launchers hide the real program, so
/// their `Exec` is not judged.
fn is_missing(map: &BTreeMap<&str, &str>) -> bool {
    let exec = map.get("Exec").copied().unwrap_or_default();
    map.get("TryExec").is_some_and(|t| gone(t)) || (program(exec).is_some() && command(exec).is_some_and(|c| gone(&c)))
}

/// User-level entries (the ones FastCheckup may move to the Trash) whose program is not installed any more.
pub fn stale(dirs: &Dirs) -> Vec<Entry> {
    let mut out: Vec<Entry> = scan(dirs)
        .into_iter()
        .filter(|e| e.missing && e.source.parent() == Some(&dirs.user))
        .collect();
    out.sort_by_key(|e| e.name.to_lowercase());
    out
}

/// Flags enabled, non-essential entries that start the same program as another enabled entry.
/// Essential ones are skipped: the desktop starts several helpers on purpose.
/// `services` (unit name, program) are enabled user services: they can be the other side of a duplicate but are never
/// rows, because autostart cannot toggle them.
fn mark_duplicates(entries: &mut [Entry], services: &[(String, String)]) {
    let progs: Vec<Option<String>> = entries
        .iter()
        .map(|e| {
            (e.state == State::Enabled && !e.essential)
                .then(|| program(&e.exec).map(|p| p.to_lowercase()))
                .flatten()
        })
        .collect();
    for i in 0..entries.len() {
        let Some(p) = &progs[i] else { continue };
        if let Some(j) = (0..entries.len()).find(|&j| j != i && progs[j].as_ref() == Some(p)) {
            entries[i].duplicate_of = entries[j].name.clone();
        } else if let Some((unit, _)) = services.iter().find(|(_, sp)| sp == p) {
            entries[i].duplicate_of = unit.clone();
        }
    }
}

/// Enabled user services as (unit name, lowercase program): the `*.wants/*.service` links, followed to the unit file
/// and read for `ExecStart=`. Units that start through a shell or a launcher are skipped like in `program`.
fn user_services(dirs: &[PathBuf]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for dir in dirs {
        let Ok(read) = fs::read_dir(dir) else { continue };
        for wants in read
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".wants"))
        {
            for unit in fs::read_dir(wants.path()).into_iter().flatten().flatten() {
                let name = unit.file_name().to_string_lossy().into_owned();
                let Ok(text) = fs::read_to_string(unit.path()) else {
                    continue;
                };
                let exec = text.lines().find_map(|l| l.trim().strip_prefix("ExecStart="));
                // `-`, `@`, `:`, `+` and `!` before the program only change how systemd runs it.
                let prog = exec.and_then(|e| program(e.trim_start_matches(['-', '@', ':', '+', '!'])));
                if let (true, Some(p)) = (name.ends_with(".service"), prog) {
                    out.push((name, p.to_lowercase()));
                }
            }
        }
    }
    out
}

/// Where the override for `file` is written. Rejects anything that is not a plain `.desktop` file name.
fn user_path(dirs: &Dirs, file: &str) -> io::Result<PathBuf> {
    let plain = !file.is_empty() && !file.starts_with('.') && !file.contains('/') && file.ends_with(".desktop");
    if plain {
        Ok(dirs.user.join(file))
    } else {
        Err(io::Error::other("invalid autostart file name"))
    }
}

fn find(dirs: &Dirs, file: &str) -> io::Result<Entry> {
    scan(dirs)
        .into_iter()
        .find(|e| e.file == file)
        .ok_or_else(|| io::Error::other("entry not found, scan again"))
}

/// Rewrites the `[Desktop Entry]` group: drops lines starting with any of `drop`, then appends `add` at the end of the
/// group, where the desktop tools put new keys too.
fn rewrite(text: &str, drop: &[&str], add: &str) -> String {
    let mut out = String::new();
    let mut in_group = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            if in_group {
                out += add;
            }
            in_group = t == "[Desktop Entry]";
        } else if in_group && drop.iter().any(|k| t.starts_with(k)) {
            continue;
        }
        out += line;
        out.push('\n');
    }
    if in_group {
        out += add;
    }
    out
}

/// Writes the user-level override, unless it would just repeat the system file: then it is removed instead, so the
/// system entry applies on its own and no redundant copy is left behind.
fn put(dirs: &Dirs, file: &str, text: &str) -> io::Result<()> {
    let user = user_path(dirs, file)?;
    let system = dirs.system.iter().map(|d| d.join(file)).find(|p| p.is_file());
    // shortcut: compares the sorted lines, so a key that sat mid-file in the system file still matches; it ignores which group a line is in.
    let sorted = |s: &str| {
        let mut l: Vec<_> = s
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect();
        l.sort();
        l
    };
    let same = system
        .and_then(|p| fs::read_to_string(p).ok())
        .is_some_and(|s| sorted(&s) == sorted(text));
    match (same, user.exists()) {
        (true, true) => fs::remove_file(&user),
        (true, false) => Ok(()),
        // Atomic, so a crash never leaves a half-written file (and a failed write leaves no temp file).
        (false, _) => crate::files::write_atomic(&user, text),
    }
}

pub fn disable(dirs: &Dirs, file: &str) -> io::Result<()> {
    user_path(dirs, file)?;
    // Re-check against the disk: the scan the user saw may be stale.
    let entry = find(dirs, file)?;
    if entry.state != State::Enabled {
        return Err(io::Error::other("this entry cannot be disabled"));
    }
    let text = rewrite(
        &fs::read_to_string(&entry.source)?,
        &["Hidden=", OFF_KEY],
        &format!("{OFF_KEY}=false\n"),
    );
    put(dirs, file, &text)
}

/// Undoes any disable, whoever did it. The copy is removed when it ends up equal to the system file.
pub fn enable(dirs: &Dirs, file: &str) -> io::Result<()> {
    user_path(dirs, file)?;
    let entry = find(dirs, file)?;
    if entry.state != State::Disabled {
        return Err(io::Error::other("this entry cannot be enabled"));
    }
    put(
        dirs,
        file,
        &rewrite(&fs::read_to_string(&entry.source)?, &["Hidden=", OFF_KEY], ""),
    )
}

/// Sets the start delay (0 removes it) in a user-level copy; the system file is never edited.
pub fn set_delay(dirs: &Dirs, file: &str, secs: u32) -> io::Result<()> {
    user_path(dirs, file)?;
    let entry = find(dirs, file)?;
    let add = if secs > 0 {
        format!("{DELAY_KEY}={secs}\n")
    } else {
        String::new()
    };
    put(
        dirs,
        file,
        &rewrite(&fs::read_to_string(&entry.source)?, &[DELAY_KEY], &add),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: &str = "[Desktop Entry]\nName=Gear Lever\nExec=gearlever\nType=Application\n";

    struct Fixture {
        root: PathBuf,
        dirs: Dirs,
    }

    fn fixture(name: &str, desktops: &[&str]) -> Fixture {
        let root = std::env::temp_dir().join(format!("fastcheckup-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("sys")).unwrap();
        let dirs = Dirs {
            system: vec![root.join("sys")],
            user: root.join("user"),
            desktops: desktops.iter().map(|d| d.to_string()).collect(),
            systemd_user: vec![root.join("units")],
        };
        Fixture { root, dirs }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn rules_file_parses() {
        assert!(essential("nm-applet.desktop") && essential("cinnamon-settings-daemon-xsettings.desktop"));
        assert!(!essential("gearlever.desktop"));
    }

    #[test]
    fn honors_show_in_and_hidden() {
        let f = fixture("showin", &["X-Cinnamon"]);
        fs::write(f.dirs.system[0].join("a.desktop"), format!("{APP}OnlyShowIn=GNOME;\n")).unwrap();
        fs::write(
            f.dirs.system[0].join("b.desktop"),
            format!("{APP}NotShowIn=X-Cinnamon;\n"),
        )
        .unwrap();
        fs::write(
            f.dirs.system[0].join("c.desktop"),
            format!("{APP}OnlyShowIn=X-Cinnamon;\nHidden=true\n"),
        )
        .unwrap();
        let found = scan(&f.dirs);
        assert_eq!(found.len(), 1);
        assert_eq!((found[0].file.as_str(), found[0].state), ("c.desktop", State::Disabled));
    }

    #[test]
    fn set_delay_writes_an_override_and_zero_removes_it() {
        let f = fixture("delay", &[]);
        let sys = f.dirs.system[0].join("a.desktop");
        fs::write(&sys, format!("{APP}X-GNOME-Autostart-Delay=3\n")).unwrap();
        assert_eq!(scan(&f.dirs)[0].delay, 3);
        set_delay(&f.dirs, "a.desktop", 20).unwrap();
        assert_eq!(scan(&f.dirs)[0].delay, 20);
        set_delay(&f.dirs, "a.desktop", 0).unwrap();
        assert_eq!(scan(&f.dirs)[0].delay, 0);
        assert!(
            fs::read_to_string(&sys).unwrap().contains("Delay=3"),
            "system file untouched"
        );
        // Back to what the system file says: the override is redundant, so it goes away.
        set_delay(&f.dirs, "a.desktop", 3).unwrap();
        assert!(!f.dirs.user.join("a.desktop").exists());
        assert_eq!(scan(&f.dirs)[0].delay, 3);
    }

    #[test]
    fn flags_two_enabled_entries_that_start_the_same_program() {
        let f = fixture("dup", &[]);
        fs::write(
            f.root.join("sys/a.desktop"),
            "[Desktop Entry]\nName=A\nExec=/usr/bin/syncthing serve\n",
        )
        .unwrap();
        fs::write(
            f.root.join("sys/b.desktop"),
            "[Desktop Entry]\nName=B\nExec=env X=1 syncthing -no-browser\n",
        )
        .unwrap();
        fs::write(
            f.root.join("sys/c.desktop"),
            "[Desktop Entry]\nName=C\nExec=sh -c syncthing\n",
        )
        .unwrap();
        let e = scan(&f.dirs);
        let dup = |n: &str| e.iter().find(|x| x.name == n).unwrap().duplicate_of.clone();
        assert_eq!((dup("A"), dup("B"), dup("C")), ("B".into(), "A".into(), "".into()));
    }

    #[test]
    fn flags_an_entry_that_an_enabled_user_service_also_starts() {
        let f = fixture("dupunit", &[]);
        let wants = f.root.join("units/default.target.wants");
        fs::create_dir_all(&wants).unwrap();
        fs::write(
            wants.join("syncthing.service"),
            "[Service]\nExecStart=-/usr/bin/syncthing serve\n",
        )
        .unwrap();
        fs::write(
            f.root.join("sys/a.desktop"),
            "[Desktop Entry]\nName=A\nExec=syncthing-gtk\n",
        )
        .unwrap();
        fs::write(
            f.root.join("sys/b.desktop"),
            "[Desktop Entry]\nName=B\nExec=syncthing\n",
        )
        .unwrap();
        let e = scan(&f.dirs);
        let dup = |n: &str| e.iter().find(|x| x.name == n).unwrap().duplicate_of.clone();
        assert_eq!((dup("A"), dup("B")), ("".into(), "syncthing.service".into()));
    }

    #[test]
    fn command_keeps_spaces_from_quotes_and_escapes() {
        let c = |s| command(s).unwrap();
        assert_eq!(c("\"/a b/run\" --x"), "/a b/run");
        assert_eq!(c("'/a b/run' --x"), "/a b/run");
        assert_eq!(c("/a\\ b/run --x"), "/a b/run");
        assert_eq!(c("env X=1 /a\\ b/run"), "/a b/run");
        assert_eq!(c("run %U"), "run");
        assert_eq!(command("   "), None);
    }

    #[test]
    fn stale_lists_only_user_entries_whose_program_is_gone() {
        let f = fixture("stale", &[]);
        fs::create_dir_all(&f.dirs.user).unwrap();
        let gone = "[Desktop Entry]\nName=Gone\nExec=insync start\nTryExec=/nonexistent/insync\n";
        fs::write(f.dirs.user.join("gone.desktop"), gone).unwrap();
        fs::write(
            f.dirs.user.join("sh.desktop"),
            "[Desktop Entry]\nName=Sh\nExec=sh -c /nonexistent/x\n",
        )
        .unwrap();
        fs::write(
            f.dirs.user.join("ok.desktop"),
            "[Desktop Entry]\nName=Ok\nExec=/bin/sh\n",
        )
        .unwrap();
        let spaced = f.root.join("My Apps, x");
        fs::create_dir_all(&spaced).unwrap();
        fs::write(spaced.join("run.sh"), "").unwrap();
        let entry = format!(
            "[Desktop Entry]\nName=Spaced\nExec=\"{}/run.sh\" --x\n",
            spaced.display()
        );
        fs::write(f.dirs.user.join("spaced.desktop"), entry).unwrap();
        fs::write(f.root.join("sys/sys.desktop"), gone).unwrap();
        let names: Vec<_> = stale(&f.dirs).into_iter().map(|e| e.name).collect();
        assert_eq!(names, ["Gone"]);
    }

    #[test]
    fn ignores_a_stub_without_a_desktop_entry() {
        let f = fixture("stub", &[]);
        fs::create_dir_all(&f.dirs.user).unwrap();
        fs::write(f.dirs.user.join("stub.desktop"), "X-GNOME-Autostart-enabled=false\n").unwrap();
        assert!(scan(&f.dirs).is_empty());
    }

    #[test]
    fn essential_entries_can_be_disabled_and_enabled() {
        let f = fixture("essential", &[]);
        fs::write(f.dirs.system[0].join("nm-applet.desktop"), APP).unwrap();
        disable(&f.dirs, "nm-applet.desktop").unwrap();
        enable(&f.dirs, "nm-applet.desktop").unwrap();
        assert_eq!(scan(&f.dirs)[0].state, State::Enabled);
    }

    #[test]
    fn enable_an_entry_hidden_by_another_tool() {
        let f = fixture("enable", &[]);
        let sys = f.dirs.system[0].join("blueman.desktop");
        let hidden = format!("{APP}Hidden=true\n");
        fs::write(&sys, &hidden).unwrap();
        enable(&f.dirs, "blueman.desktop").unwrap();
        assert_eq!(fs::read_to_string(&sys).unwrap(), hidden, "system file untouched");
        assert_eq!(scan(&f.dirs)[0].state, State::Enabled);
        assert!(enable(&f.dirs, "blueman.desktop").is_err(), "already enabled");
        // A user copy that only differs by the off key: enabling it must leave no copy of its own.
        fs::create_dir_all(&f.dirs.user).unwrap();
        fs::write(f.dirs.user.join("b.desktop"), &hidden).unwrap();
        fs::write(f.dirs.system[0].join("b.desktop"), APP).unwrap();
        enable(&f.dirs, "b.desktop").unwrap();
        assert!(!f.dirs.user.join("b.desktop").exists());
    }

    #[test]
    fn disable_a_system_entry_then_enable_deletes_the_override() {
        let f = fixture("sys", &[]);
        let sys = f.dirs.system[0].join("gearlever.desktop");
        fs::write(&sys, APP).unwrap();
        disable(&f.dirs, "gearlever.desktop").unwrap();
        assert_eq!(fs::read_to_string(&sys).unwrap(), APP, "system file untouched");
        assert_eq!(scan(&f.dirs)[0].state, State::Disabled);
        let written = fs::read_to_string(f.dirs.user.join("gearlever.desktop")).unwrap();
        assert!(written.ends_with("X-GNOME-Autostart-enabled=false\n") && !written.contains("Hidden"));
        enable(&f.dirs, "gearlever.desktop").unwrap();
        assert!(!f.dirs.user.join("gearlever.desktop").exists());
        assert_eq!(scan(&f.dirs)[0].state, State::Enabled);
    }

    #[test]
    fn disable_a_user_entry_then_enable_gives_back_the_same_text() {
        let f = fixture("user", &[]);
        fs::create_dir_all(&f.dirs.user).unwrap();
        let mine = f.dirs.user.join("dropbox.desktop");
        fs::write(&mine, APP).unwrap();
        disable(&f.dirs, "dropbox.desktop").unwrap();
        assert_eq!(scan(&f.dirs)[0].state, State::Disabled);
        enable(&f.dirs, "dropbox.desktop").unwrap();
        assert_eq!(fs::read_to_string(&mine).unwrap(), APP);
    }

    #[test]
    fn refuses_wrong_state_and_bad_names() {
        let f = fixture("refuse", &[]);
        fs::write(f.dirs.system[0].join("off.desktop"), format!("{APP}Hidden=true\n")).unwrap();
        assert!(disable(&f.dirs, "off.desktop").is_err());
        assert!(enable(&f.dirs, "gone.desktop").is_err());
        for bad in ["../x.desktop", "a/b.desktop", ".hidden.desktop", "x.txt", ""] {
            assert!(disable(&f.dirs, bad).is_err(), "{bad}");
        }
    }
}
