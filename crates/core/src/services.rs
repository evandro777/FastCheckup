//! Services module: lists systemd services with their boot time, checks what depends on one, and enables/disables it
//! through `pkexec systemctl`. Parsers take plain text so tests need no systemd.
use std::{
    fs,
    io::{self, Write},
    path::Path,
    process::{Command, Output, Stdio},
};

use crate::autostart::{matches, rules};

/// The only binary run as root; also what the polkit policy in `packaging/` matches.
const SYSTEMCTL: &str = "/usr/bin/systemctl";

#[derive(Clone, Debug, PartialEq)]
pub struct Service {
    /// Full unit name, e.g. `cups-browsed.service`. The stable id.
    pub unit: String,
    pub description: String,
    pub enabled: bool,
    pub active: bool,
    /// Time the unit took to start (`systemd-analyze blame`); 0 when unknown. Not the same as boot delay.
    pub secs: f32,
    /// Protected system software: shown as a recommendation to keep it; the user can still act on it.
    pub essential: bool,
    /// Started by a timer after boot, so it is not a boot cost.
    pub background: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HintKind {
    Zfs,
    Touchegg,
    ModemManager,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Hint {
    pub kind: HintKind,
    /// The hardware or data the service exists for was found, so disabling it probably breaks something.
    pub in_use: bool,
}

#[derive(Debug, Default)]
pub struct Precheck {
    /// Other services that pull this one in. When any exist the app disables without stopping it.
    pub dependents: Vec<String>,
    pub hint: Option<Hint>,
}

/// Letters, digits and `:_.@-\` only (systemd escapes), ending in `.service`, no leading `-`: it can never become a flag.
pub fn valid(unit: &str) -> bool {
    unit.strip_suffix(".service").is_some_and(|stem| {
        !stem.is_empty()
            && !unit.starts_with('-')
            && unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b":_.@-\\".contains(&b))
    })
}

pub(crate) fn run(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// `(unit, enabled)` from `list-unit-files --no-legend --plain`. Templates (`getty@.service`) are skipped: they are
/// never started on their own.
fn parse_unit_files(text: &str) -> Vec<(String, bool)> {
    text.lines()
        .filter_map(|l| {
            let mut c = l.split_whitespace();
            let (unit, state) = (c.next()?, c.next()?);
            (unit.ends_with(".service") && !unit.contains("@.")).then(|| (unit.to_string(), state == "enabled"))
        })
        .collect()
}

/// `(unit, description, active)` from `list-units --all --no-legend --plain`.
fn parse_units(text: &str) -> Vec<(String, String, bool)> {
    text.lines()
        .filter_map(|l| {
            let c: Vec<_> = l.split_whitespace().collect();
            (c.len() >= 4).then(|| (c[0].to_string(), c[4..].join(" "), c[2] == "active"))
        })
        .collect()
}

/// Sums systemd durations such as `["1min", "2.5s"]` or `["345ms"]`; None if a token is not one.
pub(crate) fn parse_secs(tokens: &[&str]) -> Option<f32> {
    let mut secs = 0.0;
    for t in tokens {
        // "ms" and "us" end in "s", so they are tried first.
        let (n, scale) = [("ms", 1e-3), ("us", 1e-6), ("min", 60.0), ("h", 3600.0), ("s", 1.0)]
            .iter()
            .find_map(|(suffix, scale)| t.strip_suffix(suffix).map(|n| (n, *scale)))?;
        secs += n.parse::<f32>().ok()? * scale;
    }
    (!tokens.is_empty()).then_some(secs)
}

/// `(unit, seconds)` from `systemd-analyze blame`: lines like `1min 2.345s foo.service` or `345ms bar.service`.
fn parse_blame(text: &str) -> Vec<(String, f32)> {
    text.lines()
        .filter_map(|l| {
            let mut tokens: Vec<_> = l.split_whitespace().collect();
            let unit = tokens.pop()?.to_string();
            Some((unit, parse_secs(&tokens)?))
        })
        .collect()
}

pub fn scan() -> Vec<Service> {
    let files = parse_unit_files(&run(
        "systemctl",
        &[
            "list-unit-files",
            "--type=service",
            "--state=enabled,disabled",
            "--no-legend",
            "--plain",
        ],
    ));
    let loaded = parse_units(&run(
        "systemctl",
        &["list-units", "--type=service", "--all", "--no-legend", "--plain"],
    ));
    let blame = parse_blame(&run("systemd-analyze", &["blame", "--no-pager"]));
    let rules = rules();
    let mut out: Vec<Service> = files
        .into_iter()
        .map(|(unit, enabled)| {
            let stem = unit.trim_end_matches(".service").to_lowercase();
            let unit_info = loaded.iter().find(|(u, ..)| *u == unit);
            Service {
                description: unit_info.map(|(_, d, _)| d.clone()).unwrap_or_default(),
                active: unit_info.is_some_and(|(.., a)| *a),
                secs: blame.iter().find(|(u, _)| *u == unit).map_or(0.0, |(_, s)| *s),
                essential: matches(&rules.essential_services, &stem),
                background: matches(&rules.timer_services, &stem),
                enabled,
                unit,
            }
        })
        .collect();
    // Things you can act on first (slowest first), then disabled ones, protected software last.
    out.sort_by(|a, b| {
        (a.essential, !a.enabled)
            .cmp(&(b.essential, !b.enabled))
            .then(b.secs.total_cmp(&a.secs))
            .then_with(|| a.unit.to_lowercase().cmp(&b.unit.to_lowercase()))
    });

    out
}

/// Units that depend on `unit`, from `list-dependencies --reverse --plain`: the unit itself comes first, and targets
/// (`multi-user.target`) only mean "wanted at boot".
fn parse_dependents(text: &str, unit: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && *l != unit && !l.ends_with(".target"))
        .map(String::from)
        .collect()
}

/// Per-service advice. `root` is `/` outside tests; `pools` is the output of `zpool list -H`, read only for ZFS.
fn hint(unit: &str, root: &Path, pools: impl FnOnce() -> String) -> Option<Hint> {
    let (kind, in_use) = if unit.starts_with("zfs") {
        (HintKind::Zfs, !pools().trim().is_empty())
    } else if unit == "touchegg.service" {
        let input = fs::read_dir(root.join("sys/class/input"))
            .into_iter()
            .flatten()
            .flatten();
        let touch = input
            .filter_map(|e| fs::read_to_string(e.path().join("name")).ok())
            .any(|n| {
                let n = n.to_lowercase();
                n.contains("touchpad") || n.contains("touchscreen")
            });
        (HintKind::Touchegg, touch)
    } else if unit == "ModemManager.service" {
        let dev = fs::read_dir(root.join("dev")).into_iter().flatten().flatten();
        let modem = dev
            .filter_map(|e| e.file_name().into_string().ok())
            .any(|n| n.starts_with("cdc-wdm") || n.starts_with("ttyUSB"));
        (HintKind::ModemManager, modem)
    } else {
        return None;
    };
    Some(Hint { kind, in_use })
}

pub fn precheck(unit: &str) -> io::Result<Precheck> {
    if !valid(unit) {
        return Err(io::Error::other("invalid service name"));
    }
    let deps = run(
        "systemctl",
        &["list-dependencies", "--reverse", "--plain", "--no-legend", unit],
    );
    Ok(Precheck {
        dependents: parse_dependents(&deps, unit),
        hint: hint(unit, Path::new("/"), || run("zpool", &["list", "-H"])),
    })
}

fn is_enabled(unit: &str) -> bool {
    run("systemctl", &["is-enabled", unit]).trim() == "enabled"
}

/// Runs `program` as root through polkit and returns what it printed, whatever its exit code (smartctl's is a bit mask).
/// Callers pass a fixed absolute path, never user input.
pub(crate) fn pkexec_output(program: &str, args: &[&str]) -> io::Result<Output> {
    dialog_answered(Command::new("pkexec").arg(program).args(args).output()?)
}

/// pkexec exits 126 when the dialog was dismissed. 127 also means "no authentication agent", "not authorized" or a
/// program that could not be started, so it is not an error here: pkexec's own message in stderr says which.
fn dialog_answered(out: Output) -> io::Result<Output> {
    if out.status.code() == Some(126) {
        return Err(io::Error::other("administrator password was not given"));
    }
    Ok(out)
}

/// Runs `script` as `pkexec /bin/sh -c`, so one password covers every step in it. `stdin` is for data the script reads
/// (never put it in the script: argv is world-readable). Same exit-code rule as `pkexec_output`. The script is fixed
/// text built by the caller, never user input.
pub(crate) fn pkexec_sh(script: &str, stdin: &str) -> io::Result<Output> {
    let mut child = Command::new("pkexec")
        .args(["/bin/sh", "-c", script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut pipe) = child.stdin.take() {
        // Fails when pkexec already refused; its exit code says why.
        let _ = pipe.write_all(stdin.as_bytes());
    }
    dialog_answered(child.wait_with_output()?)
}

pub(crate) fn pkexec_run(program: &str, args: &[&str]) -> io::Result<()> {
    let out = pkexec_output(program, args)?;
    if out.status.success() {
        return Ok(());
    }
    Err(io::Error::other(
        String::from_utf8_lossy(&out.stderr).trim().to_string(),
    ))
}

fn pkexec(args: &[&str]) -> io::Result<()> {
    pkexec_run(SYSTEMCTL, args)
}

/// `now` also stops the running service; the UI passes false when something depends on it.
pub fn disable(unit: &str, now: bool) -> io::Result<()> {
    if !valid(unit) {
        return Err(io::Error::other("invalid service name"));
    }
    // The state may have changed since the scan.
    if !is_enabled(unit) {
        return Err(io::Error::other("service is not enabled, scan again"));
    }
    pkexec(
        &["disable", unit]
            .into_iter()
            .chain(now.then_some("--now"))
            .collect::<Vec<_>>(),
    )
}

pub fn enable(unit: &str) -> io::Result<()> {
    if !valid(unit) {
        return Err(io::Error::other("invalid service name"));
    }
    if is_enabled(unit) {
        return Err(io::Error::other("service is already enabled, scan again"));
    }
    pkexec(&["enable", "--now", unit])
}

/// Starts or stops the unit now; boot-time enablement is untouched.
pub fn set_running(unit: &str, start: bool) -> io::Result<()> {
    if !valid(unit) {
        return Err(io::Error::other("invalid service name"));
    }
    pkexec(&[if start { "start" } else { "stop" }, unit])
}

#[cfg(test)]
mod tests {
    use std::os::unix::process::ExitStatusExt;

    use super::*;

    fn exited(code: i32, stderr: &str) -> Output {
        Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: vec![],
            stderr: stderr.into(),
        }
    }

    #[test]
    fn only_a_dismissed_dialog_is_the_password_message() {
        let err = dialog_answered(exited(126, "")).unwrap_err();
        assert_eq!(err.to_string(), "administrator password was not given");
        // 127 keeps pkexec's own words (no agent, not authorized), which the caller shows.
        let out = dialog_answered(exited(127, "No authentication agent found.")).unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stderr), "No authentication agent found.");
        assert!(dialog_answered(exited(1, "")).is_ok());
    }

    #[test]
    fn unit_names() {
        assert!(valid("cups-browsed.service") && valid("user@1000.service") && valid("systemd-fsck@dev-sda1.service"));
        assert!(!valid("--now.service") && !valid("a b.service") && !valid("a/b.service") && !valid("cups.timer"));
        assert!(!valid(".service") && !valid("x.service;rm"));
    }

    #[test]
    fn unit_files_skip_templates_and_other_states() {
        let text = "cups.service enabled enabled\ngetty@.service enabled enabled\nfoo.service disabled enabled\nbar.timer enabled -\n";
        assert_eq!(
            parse_unit_files(text),
            vec![("cups.service".into(), true), ("foo.service".into(), false)]
        );
    }

    #[test]
    fn units_keep_the_description() {
        let text = "cups.service loaded active running CUPS Scheduler\nfoo.service loaded inactive dead Foo\n";
        assert_eq!(
            parse_units(text),
            vec![
                ("cups.service".into(), "CUPS Scheduler".into(), true),
                ("foo.service".into(), "Foo".into(), false)
            ]
        );
    }

    #[test]
    fn blame_durations() {
        let text = "1min 2.5s a.service\n345ms b.service\n1.5s c.service\n";
        let got = parse_blame(text);
        assert_eq!(got[0], ("a.service".into(), 62.5));
        assert!((got[1].1 - 0.345).abs() < 1e-4);
        assert_eq!(got[2], ("c.service".into(), 1.5));
    }

    #[test]
    fn dependents_ignore_self_and_targets() {
        let text = "cups.service\ncups.path\nmulti-user.target\ngraphical.target\n";
        assert_eq!(parse_dependents(text, "cups.service"), vec!["cups.path"]);
    }

    #[test]
    fn hints_read_the_system() {
        let tmp = std::env::temp_dir().join(format!("fastcheckup-hint-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(tmp.join("sys/class/input/input0")).unwrap();
        fs::create_dir_all(tmp.join("dev")).unwrap();
        fs::write(tmp.join("sys/class/input/input0/name"), "AT Keyboard\n").unwrap();
        let none = |u| hint(u, &tmp, String::new);
        assert_eq!(none("cups.service"), None);
        assert_eq!(none("touchegg.service").map(|h| h.in_use), Some(false));
        assert_eq!(none("ModemManager.service").map(|h| h.in_use), Some(false));
        fs::write(tmp.join("sys/class/input/input0/name"), "SynPS/2 Synaptics TouchPad\n").unwrap();
        fs::write(tmp.join("dev/ttyUSB0"), "").unwrap();
        assert_eq!(none("touchegg.service").map(|h| h.in_use), Some(true));
        assert_eq!(none("ModemManager.service").map(|h| h.in_use), Some(true));
        assert_eq!(
            hint("zfs-zed.service", &tmp, || "tank 1G\n".into()).map(|h| h.in_use),
            Some(true)
        );
        assert_eq!(
            hint("zfs-zed.service", &tmp, String::new).map(|h| h.in_use),
            Some(false)
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn rules_load_and_match() {
        let r = rules();
        assert!(matches(&r.essential_services, "systemd-logind") && matches(&r.essential_services, "networkmanager"));
        assert!(!matches(&r.essential_services, "cups-browsed"));
        assert!(matches(&r.timer_services, "apt-daily"));
    }
}
