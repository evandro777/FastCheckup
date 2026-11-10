//! Root-only data in one `pkexec` call (one password prompt). The app itself never runs as root: a GUI started through
//! pkexec loses DISPLAY and would read root's home. Parsers take text so tests need no root.
use std::{fs, io, os::unix::fs::MetadataExt};

use crate::{apps::plain, health::valid_disk, services::pkexec_sh};

/// Fixed text; `n` is a per-run nonce read from stdin that only prefixes the section markers, so output the scanned
/// system controls (process names, exe paths, login names) cannot forge a section.
const SCRIPT: &str = r#"read -r n
echo "@@$n listen"; /usr/bin/ss -tulnH -p
echo "@@$n conn"; /usr/bin/ss -tnpH state established
echo "@@$n procs"; for p in /proc/[0-9]*; do e=$(readlink "$p/exe") && echo "${p#/proc/} $e"; done
echo "@@$n logins"; /usr/bin/journalctl --since "24 hours ago" -o cat --no-pager -g "Failed password|authentication failure"
echo "@@$n ufw"; /usr/sbin/ufw status verbose
/usr/bin/lsblk -dno NAME,TYPE | while read d t; do
  [ "$t" = disk ] && { echo "@@$n smart $d"; /usr/sbin/smartctl -H -A "/dev/$d"; }
done
echo "@@$n snapshots"
for d in /timeshift/snapshots /timeshift-btrfs/snapshots /run/timeshift/backup/timeshift/snapshots /run/timeshift/backup/timeshift-btrfs/snapshots; do /usr/bin/ls -1 "$d"; done
"#;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Admin {
    pub listen: String,
    pub conn: String,
    pub logins: String,
    pub ufw: String,
    /// `(pid, exe)` of every process, other users' included.
    pub procs: Vec<(i32, String)>,
    /// `(disk, smartctl output)`; disks without a health verdict are left out.
    pub smart: Vec<(String, String)>,
    pub snapshots: Vec<String>,
}

pub fn is_root() -> bool {
    fs::metadata("/proc/self").is_ok_and(|m| m.uid() == 0)
}

/// `Err` when a section appears twice: every real marker is printed once, so a repeat means output forged one.
pub fn parse(text: &str, nonce: &str) -> io::Result<Admin> {
    let mark = format!("@@{nonce} ");
    let mut a = Admin::default();
    let mut seen = std::collections::HashSet::new();
    let mut section = "";
    let mut body = String::new();
    // Flushes the section that just ended.
    let flush = |a: &mut Admin, section: &str, body: &mut String| {
        let text = std::mem::take(body);
        match section.split_once(' ').unwrap_or((section, "")) {
            ("listen", _) => a.listen = text,
            ("conn", _) => a.conn = text,
            ("logins", _) => a.logins = text,
            ("ufw", _) => a.ufw = text.trim().to_string(),
            ("procs", _) => {
                a.procs = text
                    .lines()
                    .filter_map(|l| {
                        let (pid, exe) = l.split_once(' ')?;
                        Some((pid.parse().ok()?, exe.to_string()))
                    })
                    .collect()
            }
            // No verdict line = smartctl missing or the device unsupported (many USB sticks): not a failing disk.
            ("smart", d) if valid_disk(d) && (text.contains("overall-health") || text.contains("Health Status")) => {
                a.smart.push((d.to_string(), text))
            }
            ("snapshots", _) => {
                a.snapshots = text.lines().filter(|n| plain(n)).map(String::from).collect();
                a.snapshots.sort();
            }
            _ => {}
        }
    };
    for l in text.lines() {
        if let Some(name) = l.strip_prefix(&mark) {
            flush(&mut a, section, &mut body);
            section = name.trim();
            if !seen.insert(section) {
                return Err(io::Error::other("the output looked tampered with, so it was not used"));
            }
        } else {
            body.push_str(l);
            body.push('\n');
        }
    }
    flush(&mut a, section, &mut body);
    Ok(a)
}

/// Asks for the administrator password. 126 = dialog dismissed, 127 = not authorized.
pub fn run() -> io::Result<Admin> {
    let nonce = fs::read_to_string("/proc/sys/kernel/random/uuid")?
        .trim()
        .replace('-', "");
    // The nonce goes on stdin, not argv: other users can read a process's command line.
    let out = pkexec_sh(SCRIPT, &format!("{nonce}\n"))?;
    // 126 (dialog dismissed) is already an error. 127 is no auth agent, not authorized or a failed launch: show pkexec's words.
    if out.status.code() == Some(127) {
        let why = String::from_utf8_lossy(&out.stderr);
        let why = why.trim();
        return Err(io::Error::other(if why.is_empty() {
            "pkexec failed (exit 127)"
        } else {
            why
        }));
    }
    parse(&String::from_utf8_lossy(&out.stdout), &nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sections_are_split_and_forged_markers_ignored() {
        let t = "@@abc ufw\nStatus: inactive\n@@abc procs\n1 /usr/lib/systemd/systemd\n7 /tmp/x\n@@evil ufw\nStatus: active\n\
                 @@abc smart sda\nSMART overall-health: PASSED\n@@abc smart ../x\nbad\n@@abc smart sdb\n\n\
                 @@abc snapshots\n2024-01-01_10-00-00\n";
        let a = parse(t, "abc").unwrap();
        // The forged marker is plain text inside the procs section, so it opens no section and drops out as a non-pid line.
        assert_eq!(a.ufw, "Status: inactive");
        assert_eq!(a.procs.len(), 2);
        assert_eq!(a.smart.len(), 1);
        assert_eq!(a.smart[0].0, "sda");
        assert_eq!(a.snapshots, ["2024-01-01_10-00-00"]);
    }

    #[test]
    fn a_repeated_section_is_rejected() {
        assert!(parse("@@abc listen\n@@abc ufw\nx\n@@abc listen\n", "abc").is_err());
    }
}
