//! Boot module: where the boot time goes, which units the desktop waited for, and the GRUB menu timeout.
//! Parsers take text and file reads take a `root`, so tests run on temp dirs and never touch the real `/etc`.
use std::{
    fs, io,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    autostart::{matches, rules},
    services::{parse_secs, pkexec_sh, run},
};

const GRUB_FILE: &str = "/etc/default/grub";
const CP: &str = "/usr/bin/cp";
const SED: &str = "/usr/bin/sed";
const CMP: &str = "/usr/bin/cmp";
const UPDATE_GRUB: &str = "/usr/sbin/update-grub";
const MAX_TIMEOUT: u32 = 60;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Phase {
    Firmware,
    Loader,
    Kernel,
    Initrd,
    Userspace,
}

#[derive(Debug, Default, PartialEq)]
pub struct Breakdown {
    pub parts: Vec<(Phase, f32)>,
    pub total: f32,
}

#[derive(Debug, PartialEq)]
pub struct Link {
    pub unit: String,
    /// When it became active, seconds after userspace started.
    pub at: f32,
    /// How long it took to start; 0 for targets.
    pub took: f32,
    /// A service the user can act on (not protected).
    pub optional: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Loader {
    Grub,
    SystemdBoot,
    Unknown,
}

#[derive(Debug)]
pub struct GrubInfo {
    pub loader: Loader,
    pub efi: bool,
    /// `GRUB_TIMEOUT` as written; None when unset (GRUB then waits 5 s).
    pub timeout: Option<u32>,
    pub style: String,
    /// Files in `grub.d` that also set `GRUB_TIMEOUT` and may win over `/etc/default/grub`.
    pub overridden_by: Vec<String>,
    /// Windows has its own UEFI entry, so GRUB's menu is not needed to reach it.
    pub windows_entry: bool,
    /// Newest backup made by this app, if any.
    pub backup: Option<PathBuf>,
}

#[derive(Debug, Default, PartialEq)]
pub struct Bios {
    pub vendor: String,
    pub name: String,
    pub version: String,
}

/// What a confirm dialog shows before anything is written.
#[derive(Debug)]
pub struct Plan {
    pub diff: String,
    pub commands: String,
}

/// First line of `systemd-analyze`: `Startup finished in 12s (firmware) + 5s (loader) + 9s (kernel) + 13s (userspace) = 40s`.
fn parse_breakdown(text: &str) -> Breakdown {
    let Some(line) = text.lines().find_map(|l| l.split_once("finished in ").map(|(_, r)| r)) else {
        return Breakdown::default();
    };
    let (parts, total) = match line.split_once(" = ") {
        Some((p, t)) => (p, t),
        None => (line, ""),
    };
    let parts: Vec<_> = parts
        .split(" + ")
        .filter_map(|p| {
            let (dur, name) = p.split_once('(')?;
            let phase = match name.trim_end_matches([')', ' ']) {
                "firmware" => Phase::Firmware,
                "loader" => Phase::Loader,
                "kernel" => Phase::Kernel,
                "initrd" => Phase::Initrd,
                "userspace" => Phase::Userspace,
                _ => return None,
            };
            Some((phase, parse_secs(&dur.split_whitespace().collect::<Vec<_>>())?))
        })
        .collect();
    let total =
        parse_secs(&total.split_whitespace().collect::<Vec<_>>()).unwrap_or_else(|| parts.iter().map(|p| p.1).sum());
    Breakdown { parts, total }
}

pub fn breakdown() -> Breakdown {
    parse_breakdown(&run("systemd-analyze", &["--no-pager"]))
}

/// Lines like `└─smartmontools.service @2.042s +11.736s`; header text has no leading `@time` after a unit name.
fn parse_chain(text: &str) -> Vec<Link> {
    let essential = &rules().essential_services;
    text.lines()
        .filter_map(|l| {
            let l = l.trim_start_matches(|c: char| !c.is_alphanumeric());
            let (unit, rest) = l.split_once(" @")?;
            if unit.contains(' ') || !unit.contains('.') {
                return None;
            }
            let (at, took) = rest.split_once(" +").map_or((rest, ""), |(a, t)| (a, t));
            let secs = |s: &str| parse_secs(&s.split_whitespace().collect::<Vec<_>>());
            let stem = unit.trim_end_matches(".service").to_lowercase();
            Some(Link {
                unit: unit.into(),
                at: secs(at)?,
                took: secs(took).unwrap_or(0.0),
                optional: unit.ends_with(".service") && !matches(essential, &stem),
            })
        })
        .collect()
}

pub fn critical_chain() -> Vec<Link> {
    parse_chain(&run("systemd-analyze", &["critical-chain", "--no-pager"]))
}

/// Last active `KEY=value` in a shell-style file, quotes removed (the shell takes the last assignment too).
fn setting(text: &str, key: &str) -> Option<String> {
    text.lines()
        .filter_map(|l| l.trim().strip_prefix(key)?.strip_prefix('='))
        .next_back()
        .map(|v| v.trim().trim_matches(['"', '\'']).to_string())
}

fn backups(root: &Path) -> Vec<(u64, PathBuf)> {
    let mut found: Vec<_> = fs::read_dir(root.join("etc/default"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let secs = name
                .strip_prefix("grub.fastcheckup-")?
                .strip_suffix(".bak")?
                .parse()
                .ok()?;
            Some((secs, e.path()))
        })
        .collect();
    found.sort();
    found
}

/// `efibootmgr` is the output of that command (empty when it is missing or the machine is not EFI).
pub fn grub_info(root: &Path, efibootmgr: &str) -> GrubInfo {
    let efi = root.join("sys/firmware/efi").exists();
    let loader = if root.join("boot/grub/grub.cfg").exists() {
        Loader::Grub
    } else if root.join("boot/loader/loader.conf").exists() {
        Loader::SystemdBoot
    } else {
        Loader::Unknown
    };
    let text = fs::read_to_string(root.join("etc/default/grub")).unwrap_or_default();
    let mut overridden_by: Vec<_> = fs::read_dir(root.join("etc/default/grub.d"))
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| setting(&fs::read_to_string(e.path()).unwrap_or_default(), "GRUB_TIMEOUT").is_some())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    overridden_by.sort();
    GrubInfo {
        loader,
        efi,
        timeout: setting(&text, "GRUB_TIMEOUT").and_then(|v| v.parse().ok()),
        style: setting(&text, "GRUB_TIMEOUT_STYLE").unwrap_or_default(),
        overridden_by,
        windows_entry: efibootmgr.contains("Windows Boot Manager"),
        backup: backups(root).pop().map(|b| b.1),
    }
}

pub fn grub_info_here() -> GrubInfo {
    grub_info(Path::new("/"), &run("efibootmgr", &[]))
}

pub fn bios_info(root: &Path) -> Bios {
    let read = |f: &str| {
        fs::read_to_string(root.join("sys/class/dmi/id").join(f))
            .unwrap_or_default()
            .trim()
            .to_string()
    };
    Bios {
        vendor: read("board_vendor"),
        name: read("board_name"),
        version: read("bios_version"),
    }
}

/// Sets every `GRUB_TIMEOUT=` line, or appends the key. Same result as the `sed` command that is run for real.
fn with_timeout(text: &str, secs: u32) -> String {
    let mut found = false;
    let mut out: String = text
        .split_inclusive('\n')
        .map(|l| {
            if l.starts_with("GRUB_TIMEOUT=") {
                found = true;
                format!("GRUB_TIMEOUT={secs}{}", if l.ends_with('\n') { "\n" } else { "" })
            } else {
                l.to_string()
            }
        })
        .collect();
    if !found {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out += &format!("GRUB_TIMEOUT={secs}\n");
    }
    out
}

/// The changed block with 2 lines of context. shortcut: one block from the first to the last change, which is exact for
/// a single edit and just noisier when `GRUB_TIMEOUT=` is repeated; upgrade if more keys become editable.
fn diff(old: &str, new: &str) -> String {
    let (o, n): (Vec<_>, Vec<_>) = (old.lines().collect(), new.lines().collect());
    let pre = o.iter().zip(&n).take_while(|(a, b)| a == b).count();
    let suf = o
        .iter()
        .rev()
        .zip(n.iter().rev())
        .take_while(|(a, b)| a == b)
        .count()
        .min(o.len() - pre)
        .min(n.len() - pre);
    let mut out = String::new();
    for l in &o[pre.saturating_sub(2)..pre] {
        out += &format!("  {l}\n");
    }
    for l in &o[pre..o.len() - suf] {
        out += &format!("- {l}\n");
    }
    for l in &n[pre..n.len() - suf] {
        out += &format!("+ {l}\n");
    }
    for l in &o[o.len() - suf..(o.len() - suf + 2).min(o.len())] {
        out += &format!("  {l}\n");
    }
    out
}

fn check(secs: u32) -> io::Result<()> {
    if secs > MAX_TIMEOUT {
        return Err(io::Error::other(format!("timeout must be 0 to {MAX_TIMEOUT} seconds")));
    }
    Ok(())
}

fn sed_script(text: &str, secs: u32) -> String {
    if text.lines().any(|l| l.starts_with("GRUB_TIMEOUT=")) {
        format!("s/^GRUB_TIMEOUT=.*/GRUB_TIMEOUT={secs}/")
    } else {
        format!("$a GRUB_TIMEOUT={secs}")
    }
}

/// The whole change as one root script, so one password covers it. The edited file is checked against the text on
/// stdin (the preview) before `update-grub`; on any failure the backup is put back and the menu rebuilt. Only digits
/// and fixed paths go in: `secs` is checked, `backup` is built from a clock reading.
fn set_script(old: &str, secs: u32, backup: &str) -> String {
    let sed = sed_script(old, secs);
    format!(
        "{CP} -a {GRUB_FILE} {backup} || exit 1
if {SED} -i -E '{sed}' {GRUB_FILE}; then
  if {CMP} -s - {GRUB_FILE}; then
    {UPDATE_GRUB} && exit 0
    r=$?
  else
    echo \"the file does not match the preview\" >&2
    r=1
  fi
else
  r=$?
fi
{CP} -a {backup} {GRUB_FILE} >/dev/null 2>&1 && {UPDATE_GRUB} >/dev/null 2>&1
exit $r"
    )
}

fn restore_script(backup: &Path) -> String {
    format!("{CP} -a {} {GRUB_FILE} && {UPDATE_GRUB}", backup.display())
}

/// What the confirm dialog shows: the script as it would be typed.
fn shown(script: &str) -> String {
    format!("pkexec /bin/sh -c '{script}'")
}

pub fn plan_set(secs: u32) -> io::Result<Plan> {
    check(secs)?;
    let old = fs::read_to_string(GRUB_FILE)?;
    Ok(Plan {
        diff: diff(&old, &with_timeout(&old, secs)),
        commands: shown(&set_script(&old, secs, &format!("{GRUB_FILE}.fastcheckup-<time>.bak"))),
    })
}

fn run_script(script: &str, stdin: &str) -> io::Result<()> {
    let out = pkexec_sh(script, stdin)?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    let err = err.trim();
    Err(io::Error::other(if err.is_empty() {
        format!("failed (exit {})", out.status.code().unwrap_or(-1))
    } else {
        err.to_string()
    }))
}

pub fn plan_restore() -> io::Result<Plan> {
    let backup = backups(Path::new("/"))
        .pop()
        .ok_or_else(|| io::Error::other("no backup found"))?
        .1;
    let (old, new) = (fs::read_to_string(GRUB_FILE)?, fs::read_to_string(&backup)?);
    Ok(Plan {
        diff: diff(&old, &new),
        commands: shown(&restore_script(&backup)),
    })
}

/// Backs up, edits, verifies and regenerates the menu in one root script (one password). On any failure after the
/// edit the script puts the backup back.
pub fn set_timeout(secs: u32) -> io::Result<()> {
    check(secs)?;
    // The file may have changed since the preview.
    let old = fs::read_to_string(GRUB_FILE)?;
    let want = with_timeout(&old, secs);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    run_script(
        &set_script(&old, secs, &format!("{GRUB_FILE}.fastcheckup-{now}.bak")),
        &want,
    )
}

pub fn restore_backup() -> io::Result<()> {
    let backup = backups(Path::new("/"))
        .pop()
        .ok_or_else(|| io::Error::other("no backup found"))?
        .1;
    run_script(&restore_script(&backup), "")
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINE: &str =
        "Startup finished in 12.034s (firmware) + 5.455s (loader) + 9.308s (kernel) + 13.808s (userspace) = 40.607s\n";

    #[test]
    fn breakdown_reads_every_phase() {
        let b = parse_breakdown(LINE);
        assert_eq!(b.parts.len(), 4);
        assert_eq!(b.parts[0].0, Phase::Firmware);
        assert!((b.total - 40.607).abs() < 1e-3 && (b.parts[3].1 - 13.808).abs() < 1e-3);
    }

    #[test]
    fn breakdown_without_firmware_and_with_initrd() {
        let b = parse_breakdown("Startup finished in 2.1s (kernel) + 1min 3.5s (userspace) = 1min 5.6s\n");
        assert_eq!(
            b.parts.iter().map(|p| p.0).collect::<Vec<_>>(),
            [Phase::Kernel, Phase::Userspace]
        );
        assert!((b.total - 65.6).abs() < 1e-3 && (b.parts[1].1 - 63.5).abs() < 1e-3);
        let b = parse_breakdown("Startup finished in 1s (kernel) + 2s (initrd) + 3s (userspace) = 6s\n");
        assert_eq!(b.parts[1].0, Phase::Initrd);
        assert_eq!(parse_breakdown("garbage"), Breakdown::default());
    }

    #[test]
    fn chain_skips_the_header_and_reads_times() {
        let text = "The time when unit became active or started is printed after the \"@\" character.\nThe time the unit took to start is printed after the \"+\" character.\n\ngraphical.target @13.779s\n└─multi-user.target @13.779s\n  └─smartmontools.service @2.042s +11.736s\n    └─basic.target @2.000s\n      └─systemd-resolved.service @1.906s +61ms\n";
        let chain = parse_chain(text);
        assert_eq!(chain.len(), 5);
        assert_eq!(chain[0].unit, "graphical.target");
        assert_eq!(
            (chain[2].unit.as_str(), chain[2].optional),
            ("smartmontools.service", true)
        );
        assert!((chain[2].took - 11.736).abs() < 1e-3 && (chain[2].at - 2.042).abs() < 1e-3);
        assert!(!chain[4].optional && (chain[4].took - 0.061).abs() < 1e-4);
        assert_eq!(chain[1].took, 0.0);
    }

    #[test]
    fn settings_take_the_last_active_value() {
        let t = "# GRUB_TIMEOUT=9\nGRUB_TIMEOUT=\"3\"\nGRUB_TIMEOUT_STYLE=hidden\nGRUB_TIMEOUT=2\n";
        assert_eq!(setting(t, "GRUB_TIMEOUT").as_deref(), Some("2"));
        assert_eq!(setting(t, "GRUB_TIMEOUT_STYLE").as_deref(), Some("hidden"));
        assert_eq!(setting("# GRUB_TIMEOUT=9\n", "GRUB_TIMEOUT"), None);
    }

    #[test]
    fn timeout_edit_matches_the_sed_cases() {
        assert_eq!(
            with_timeout("A=1\nGRUB_TIMEOUT=5\nB=2\n", 1),
            "A=1\nGRUB_TIMEOUT=1\nB=2\n"
        );
        assert_eq!(
            with_timeout("# GRUB_TIMEOUT=5\nA=1", 2),
            "# GRUB_TIMEOUT=5\nA=1\nGRUB_TIMEOUT=2\n"
        );
        assert_eq!(
            with_timeout("GRUB_TIMEOUT=5\nGRUB_TIMEOUT=7\n", 0),
            "GRUB_TIMEOUT=0\nGRUB_TIMEOUT=0\n"
        );
        assert_eq!(with_timeout("", 3), "GRUB_TIMEOUT=3\n");
        assert!(sed_script("GRUB_TIMEOUT=5\n", 1).starts_with("s/^GRUB_TIMEOUT=.*/"));
        assert!(sed_script("A=1\n", 1).starts_with("$a "));
    }

    #[test]
    fn the_root_scripts_are_valid_shell_and_keep_their_safety_steps() {
        let script = set_script("GRUB_TIMEOUT=5\n", 2, "/etc/default/grub.fastcheckup-1.bak");
        let check = |s: &str| {
            let ok = std::process::Command::new("sh").args(["-n", "-c", s]).status().unwrap();
            assert!(ok.success(), "not valid shell:\n{s}");
        };
        check(&script);
        check(&restore_script(Path::new("/etc/default/grub.fastcheckup-1.bak")));
        // Backup first, then the edit, then the preview check, then the menu; a failure restores the backup.
        let at = |needle: &str| script.find(needle).unwrap_or_else(|| panic!("missing {needle}"));
        assert!(at("/usr/bin/cp -a /etc/default/grub /etc/default/grub.fastcheckup-1.bak") < at("/usr/bin/sed -i"));
        assert!(at("/usr/bin/sed -i") < at("/usr/bin/cmp -s - /etc/default/grub"));
        assert!(at("/usr/bin/cmp -s -") < at("/usr/sbin/update-grub"));
        assert!(script.contains("/usr/bin/cp -a /etc/default/grub.fastcheckup-1.bak /etc/default/grub"));
        assert!(shown(&script).starts_with("pkexec /bin/sh -c '"));
    }

    #[test]
    fn diff_shows_the_change_with_context() {
        let old = "A=1\nB=2\nGRUB_TIMEOUT=5\nC=3\nD=4\nE=5\n";
        assert_eq!(
            diff(old, &with_timeout(old, 1)),
            "  A=1\n  B=2\n- GRUB_TIMEOUT=5\n+ GRUB_TIMEOUT=1\n  C=3\n  D=4\n"
        );
        assert_eq!(diff("A=1\n", "A=1\nGRUB_TIMEOUT=1\n"), "  A=1\n+ GRUB_TIMEOUT=1\n");
        assert_eq!(diff("A=1\n", "A=1\n"), "  A=1\n");
    }

    #[test]
    fn timeouts_over_the_limit_are_refused() {
        assert!(check(60).is_ok() && check(61).is_err());
        assert!(plan_set(1000).is_err());
    }

    #[test]
    fn grub_info_reads_a_fake_system() {
        let root = std::env::temp_dir().join(format!("fastcheckup-boot-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for d in [
            "etc/default/grub.d",
            "boot/grub",
            "sys/firmware/efi",
            "sys/class/dmi/id",
        ] {
            fs::create_dir_all(root.join(d)).unwrap();
        }
        fs::write(root.join("boot/grub/grub.cfg"), "").unwrap();
        fs::write(
            root.join("etc/default/grub"),
            "GRUB_TIMEOUT=5\nGRUB_TIMEOUT_STYLE=menu\n",
        )
        .unwrap();
        fs::write(root.join("etc/default/grub.d/50_x.cfg"), "GRUB_TIMEOUT=10\n").unwrap();
        fs::write(root.join("etc/default/grub.d/10_y.cfg"), "GRUB_DISTRIBUTOR=x\n").unwrap();
        fs::write(root.join("etc/default/grub.fastcheckup-100.bak"), "").unwrap();
        fs::write(root.join("etc/default/grub.fastcheckup-200.bak"), "").unwrap();
        fs::write(root.join("sys/class/dmi/id/board_name"), "B550M\n").unwrap();
        let g = grub_info(&root, "Boot0001* Windows Boot Manager");
        assert_eq!((g.loader, g.efi, g.timeout), (Loader::Grub, true, Some(5)));
        assert_eq!((g.style.as_str(), g.windows_entry), ("menu", true));
        assert_eq!(g.overridden_by, ["50_x.cfg"]);
        assert!(g.backup.unwrap().ends_with("grub.fastcheckup-200.bak"));
        assert_eq!(
            bios_info(&root),
            Bios {
                vendor: "".into(),
                name: "B550M".into(),
                version: "".into()
            }
        );
        fs::remove_dir_all(root.join("boot/grub")).unwrap();
        fs::create_dir_all(root.join("boot/loader")).unwrap();
        fs::write(root.join("boot/loader/loader.conf"), "").unwrap();
        assert_eq!(grub_info(&root, "").loader, Loader::SystemdBoot);
        let _ = fs::remove_dir_all(&root);
    }
}
