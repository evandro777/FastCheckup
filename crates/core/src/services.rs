//! Services module: lists systemd services with their boot time, checks what depends on one, and enables/disables it
//! through `pkexec systemctl`. Parsers take plain text so tests need no systemd.
use std::{
    collections::HashMap,
    fs,
    io::{self, Read, Write},
    path::Path,
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};

use crate::{
    apps::run,
    autostart::{matches, rules},
};

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
    /// Debian package that ships the unit file; empty when none does (see `packaged`).
    pub package: String,
    /// False when there is no dpkg database, so an empty `package` means nothing.
    pub packaged: bool,
    /// Seconds this unit sat on the boot's critical chain (it held the desktop back); 0 when it was not on it.
    pub delay: f32,
    /// Sockets/paths/timers that start it on demand, space separated.
    pub triggers: String,
    pub memory_mb: f32,
    pub cpu_secs: f32,
    /// The last run did not end in success.
    pub failed: bool,
    pub restarts: u32,
    /// First `Documentation=` entry (`https://…` or `man:…`); empty for SysV scripts, whose entry is generic.
    pub doc: String,
    /// Generated from an old `/etc/init.d` script.
    pub sysv: bool,
}

/// What `systemctl show` and dpkg tell about one unit.
#[derive(Default)]
struct Facts {
    package: String,
    triggers: String,
    memory_mb: f32,
    cpu_secs: f32,
    failed: bool,
    restarts: u32,
    doc: String,
    sysv: bool,
}

/// `systemctl show a b -p …` prints one `Key=Value` block per unit, blank-line separated; keyed here by `Id`.
fn parse_show(text: &str) -> HashMap<String, HashMap<String, String>> {
    text.split("\n\n")
        .filter_map(|block| {
            let props: HashMap<String, String> = block
                .lines()
                .filter_map(|l| l.split_once('='))
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            Some((props.get("Id")?.clone(), props))
        })
        .collect()
}

/// systemd prints `[not set]` or u64::MAX when it does not account for a value.
fn counter(v: Option<&String>) -> Option<f64> {
    v?.parse::<u64>().ok().filter(|n| *n != u64::MAX).map(|n| n as f64)
}

/// `/usr/lib/x` and `/lib/x` are the same file on merged-/usr systems, and dpkg only knows the package's spelling.
fn unmerged(path: &str) -> &str {
    path.strip_prefix("/usr")
        .filter(|p| p.starts_with("/lib/"))
        .unwrap_or(path)
}

fn facts(units: &[String]) -> HashMap<String, Facts> {
    let units: Vec<&str> = units.iter().map(String::as_str).filter(|u| valid(u)).collect();
    let props = "Id,FragmentPath,SourcePath,TriggeredBy,MemoryCurrent,CPUUsageNSec,Result,NRestarts,Documentation";
    let args = [&["show", "-p", props][..], &units[..]].concat();
    let shown = parse_show(&run("systemctl", &args));
    let file_of = |p: &HashMap<String, String>| {
        ["SourcePath", "FragmentPath"]
            .iter()
            .filter_map(|k| p.get(*k).filter(|v| !v.is_empty()))
            .next()
            .cloned()
    };
    let files: Vec<String> = shown.values().filter_map(file_of).collect();
    let mut owners = HashMap::new();
    if Path::new("/var/lib/dpkg/status").exists() && !files.is_empty() {
        let both: Vec<&str> = files.iter().flat_map(|f| [f.as_str(), unmerged(f)]).collect();
        let out = run("dpkg-query", &[&["-S"][..], &both[..]].concat());
        owners.extend(
            crate::apps::parse_owners(&out)
                .into_iter()
                .map(|(pkg, f)| (unmerged(&f).to_string(), pkg)),
        );
    }
    shown
        .into_iter()
        .map(|(unit, p)| {
            let get = |k: &str| p.get(k).map(String::as_str).unwrap_or("");
            let sysv = get("SourcePath").starts_with("/etc/init.d/");
            let doc = get("Documentation")
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_matches('"');
            let f = Facts {
                package: file_of(&p)
                    .and_then(|f| owners.get(unmerged(&f)).cloned())
                    .unwrap_or_default(),
                triggers: get("TriggeredBy").to_string(),
                memory_mb: counter(p.get("MemoryCurrent")).map_or(0.0, |b| (b / 1048576.0) as f32),
                cpu_secs: counter(p.get("CPUUsageNSec")).map_or(0.0, |n| (n / 1e9) as f32),
                failed: !matches!(get("Result"), "" | "success"),
                restarts: get("NRestarts").parse().unwrap_or(0),
                doc: if sysv { String::new() } else { doc.to_string() },
                sysv,
            };
            (unit, f)
        })
        .collect()
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

/// Like `Command::output`, but a program still running after `limit` is killed and what it printed so far is kept:
/// a stuck daemon (Docker, a dead NFS mount for `df`, a broken GPU driver) must not leave a scan busy forever.
/// For reads only. The kill would cut a deletion short. Stdin is closed so nothing waits for an answer.
pub(crate) fn output_within(cmd: &mut Command, limit: Duration) -> io::Result<Output> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    // Drained on their own threads so a full pipe cannot block the child.
    fn drain(pipe: Option<impl Read + Send + 'static>) -> std::sync::mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut p) = pipe {
                let _ = p.read_to_end(&mut buf);
            }
            let _ = tx.send(buf);
        });
        rx
    }
    let (out, err) = (drain(child.stdout.take()), drain(child.stderr.take()));
    let deadline = Instant::now() + limit;
    let mut killed = false;
    let status = loop {
        match child.try_wait()? {
            Some(status) => break status,
            None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            None => {
                let _ = child.kill();
                killed = true;
                break child.wait()?;
            }
        }
    };
    // A killed program's own children can keep the pipe open, so after a kill the readers get a moment, not forever.
    let take = |rx: std::sync::mpsc::Receiver<Vec<u8>>| {
        if killed {
            rx.recv_timeout(Duration::from_millis(300)).unwrap_or_default()
        } else {
            rx.recv().unwrap_or_default()
        }
    };
    Ok(Output {
        status,
        stdout: take(out),
        stderr: take(err),
    })
}

/// `(unit, enabled)` from `list-unit-files --no-legend --plain`. Templates (`getty@.service`) are skipped: they are
/// never started on their own. `generated` (SysV scripts in /etc/init.d) runs at boot, so it counts as enabled.
fn parse_unit_files(text: &str) -> Vec<(String, bool)> {
    text.lines()
        .filter_map(|l| {
            let mut c = l.split_whitespace();
            let (unit, state) = (c.next()?, c.next()?);
            (unit.ends_with(".service") && !unit.contains("@.")).then(|| (unit.to_string(), state != "disabled"))
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
            "--state=enabled,disabled,generated",
            "--no-legend",
            "--plain",
        ],
    ));
    let names: Vec<String> = files.iter().map(|(u, _)| u.clone()).collect();
    // The slow reads (systemctl show + dpkg, blame, critical chain) overlap, so the page waits for the slowest only.
    let (facts, chain, loaded, blame) = std::thread::scope(|s| {
        let facts = s.spawn(|| facts(&names));
        let chain = s.spawn(crate::boot::critical_chain);
        let blame = s.spawn(|| parse_blame(&run("systemd-analyze", &["blame", "--no-pager"])));
        let loaded = parse_units(&run(
            "systemctl",
            &["list-units", "--type=service", "--all", "--no-legend", "--plain"],
        ));
        (
            facts.join().unwrap_or_default(),
            chain.join().unwrap_or_default(),
            loaded,
            blame.join().unwrap_or_default(),
        )
    });
    let packaged = Path::new("/var/lib/dpkg/status").exists();
    let rules = rules();
    let mut out: Vec<Service> = files
        .into_iter()
        .map(|(unit, enabled)| {
            let stem = unit.trim_end_matches(".service").to_lowercase();
            let unit_info = loaded.iter().find(|(u, ..)| *u == unit);
            let f = facts.get(&unit);
            Service {
                package: f.map(|f| f.package.clone()).unwrap_or_default(),
                packaged,
                delay: chain.iter().find(|l| l.unit == unit).map_or(0.0, |l| l.took),
                triggers: f.map(|f| f.triggers.clone()).unwrap_or_default(),
                memory_mb: f.map_or(0.0, |f| f.memory_mb),
                cpu_secs: f.map_or(0.0, |f| f.cpu_secs),
                failed: f.is_some_and(|f| f.failed),
                restarts: f.map_or(0, |f| f.restarts),
                doc: f.map(|f| f.doc.clone()).unwrap_or_default(),
                sysv: f.is_some_and(|f| f.sysv),
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

    #[test]
    fn a_stuck_command_is_killed_and_a_quick_one_keeps_its_output() {
        let slow = output_within(
            Command::new("sh").args(["-c", "echo partial; exec sleep 30"]),
            Duration::from_millis(300),
        )
        .unwrap();
        assert!(!slow.status.success());
        assert_eq!(String::from_utf8_lossy(&slow.stdout).trim(), "partial");
        // A grandchild that keeps the pipe open must not hold the caller either.
        let start = Instant::now();
        output_within(
            Command::new("sh").args(["-c", "sleep 3 & wait"]),
            Duration::from_millis(200),
        )
        .unwrap();
        assert!(start.elapsed() < Duration::from_secs(5));
        let quick = output_within(
            Command::new("sh").args(["-c", "echo hi; echo oops >&2"]),
            Duration::from_secs(5),
        )
        .unwrap();
        assert!(quick.status.success());
        assert_eq!(String::from_utf8_lossy(&quick.stderr).trim(), "oops");
    }

    #[test]
    fn show_reads_blocks_and_unknown_counters() {
        let text = "Id=cups.service\nTriggeredBy=cups.path cups.socket\nMemoryCurrent=2097152\nNRestarts=0\nDocumentation=\"man:cupsd(8)\"\nResult=success\n\nId=AMPctl.service\nMemoryCurrent=[not set]\nCPUUsageNSec=18446744073709551615\nResult=exit-code\n";
        let m = parse_show(text);
        assert_eq!(m.len(), 2);
        assert_eq!(m["cups.service"]["TriggeredBy"], "cups.path cups.socket");
        assert_eq!(counter(m["cups.service"].get("MemoryCurrent")), Some(2097152.0));
        assert_eq!(counter(m["AMPctl.service"].get("MemoryCurrent")), None);
        assert_eq!(counter(m["AMPctl.service"].get("CPUUsageNSec")), None);
    }

    #[test]
    fn merged_usr_paths_match_dpkg_spelling() {
        assert_eq!(
            unmerged("/usr/lib/systemd/system/cups.service"),
            "/lib/systemd/system/cups.service"
        );
        assert_eq!(unmerged("/etc/init.d/AMPctl"), "/etc/init.d/AMPctl");
        assert_eq!(unmerged("/usr/share/x"), "/usr/share/x");
    }

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
