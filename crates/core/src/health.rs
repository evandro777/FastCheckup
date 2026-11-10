//! Disk health: kernel I/O errors, failed mounts, unclean shutdowns and SMART. Report only, nothing is repaired.
//! Parsers take text so tests need no hardware.
use std::{collections::HashMap, fs, io};

use crate::services::{pkexec_output, run};

const SMARTCTL: &str = "/usr/sbin/smartctl";

#[derive(Debug, PartialEq)]
pub struct KernelError {
    /// Disk or ATA port named in the line, empty when there is none.
    pub device: String,
    pub line: String,
    pub count: u32,
}

/// What stands between a full memory and a frozen desktop. Without swap and without a watcher the kernel thrashes for
/// minutes before its own OOM killer acts, which looks like a hang.
#[derive(Debug, Default, PartialEq)]
pub struct Memory {
    /// `/swapfile`, `/dev/zram0`...; empty when there is no swap.
    pub swap: Vec<String>,
    /// `systemd-oomd` or `earlyoom` when one is running.
    pub watcher: String,
    /// "Out of memory" kills in the kernel log of this and the previous boot.
    pub oom_kills: u32,
}

impl Memory {
    /// The bare gap: nothing to swap to and nothing watching.
    pub fn unprotected(&self) -> bool {
        self.swap.is_empty() && self.watcher.is_empty()
    }
}

/// `systemctl is-active a b` prints one state per unit, in the order asked.
pub fn parse_active(units: &[&str], out: &str) -> String {
    units
        .iter()
        .zip(out.lines())
        .find(|(_, state)| state.trim() == "active")
        .map_or(String::new(), |(u, _)| (*u).to_string())
}

pub fn count_oom(log: &str) -> u32 {
    log.lines().filter(|l| l.contains("Out of memory:")).count() as u32
}

#[derive(Debug, Default)]
pub struct Health {
    pub memory: Memory,
    pub errors: Vec<KernelError>,
    pub failed_mounts: Vec<String>,
    pub crashes: Vec<String>,
    pub disks: Vec<DiskInfo>,
    /// See `backup()`.
    pub backup: (i32, String),
    /// True when anything failed, including what was filed under a disk (the Boot page warns on it).
    pub problems: bool,
}

#[derive(Debug, Default, PartialEq)]
pub struct Smart {
    pub passed: bool,
    pub reallocated: u64,
    pub pending: u64,
    pub uncorrectable: u64,
    pub crc: u64,
    /// NVMe only: wear and spare capacity in percent.
    pub used: Option<u64>,
    pub spare: Option<u64>,
}

fn is_disk_error(l: &str) -> bool {
    let l = l.to_lowercase();
    // An empty SATA port: the kernel found no drive, which is not an error.
    if l.contains("failed to resume link") {
        return false;
    }
    ["i/o error", "medium error", "failed command", "buffer i/o"]
        .iter()
        .any(|k| l.contains(k))
        || (l.starts_with("ata") && (l.contains("error") || l.contains("failed")))
}

/// The disk a kernel message is about: `[sda]`, `dev sda`, or the SATA port of `ata1.00:` (`ata1`).
fn error_device(l: &str) -> String {
    let is_disk = |w: &str| ["sd", "hd", "vd", "nvme", "mmcblk"].iter().any(|p| w.starts_with(p));
    if let Some(w) = l
        .split('[')
        .skip(1)
        .filter_map(|r| r.split_once(']'))
        .map(|(w, _)| w)
        .find(|w| is_disk(w) && w.bytes().all(|b| b.is_ascii_alphanumeric()))
    {
        return w.into();
    }
    if let Some((_, rest)) = l.split_once("dev ") {
        return rest.split([',', ' ']).next().unwrap_or("").into();
    }
    match l.split_whitespace().next() {
        Some(w) if w.starts_with("ata") => w.trim_end_matches(':').split('.').next().unwrap_or("").into(),
        _ => String::new(),
    }
}

/// Same device repeated thousands of times is one finding with a count.
pub fn parse_kernel_errors(text: &str) -> Vec<KernelError> {
    let mut found: Vec<KernelError> = Vec::new();
    for l in text.lines().filter(|l| is_disk_error(l)) {
        let device = error_device(l);
        let device = device.as_str();
        match found.iter_mut().find(|e| e.device == device) {
            Some(e) => e.count += 1,
            None => found.push(KernelError {
                device: device.into(),
                line: l.trim().into(),
                count: 1,
            }),
        }
    }
    found
}

/// `systemctl --failed --type=mount --plain --no-legend`: the description (last column) is the mount point; the unit
/// name stands in when there is none.
pub fn parse_failed_mounts(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| {
            let c: Vec<&str> = l.split_whitespace().collect();
            c.last()
                .filter(|w| w.starts_with('/'))
                .or(c.first())
                .map(|w| w.to_string())
        })
        .collect()
}

/// `last -x` marks a session that ended without a shutdown record with `- crash`.
pub fn parse_crashes(text: &str) -> Vec<String> {
    text.lines()
        .filter(|l| l.contains(" - crash"))
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect()
}

#[derive(Debug, PartialEq)]
pub struct Part {
    pub name: String,
    pub label: String,
    pub size: String,
    pub mount: String,
    /// 0 mounted, 1 failed to mount, 2 set up in fstab but not mounted.
    pub state: i32,
}

#[derive(Debug, PartialEq)]
pub struct DiskInfo {
    pub name: String,
    pub model: String,
    pub size: String,
    /// 0 SSD, 1 hard drive, 2 NVMe, 3 USB.
    pub kind: i32,
    /// SATA port such as `ata1`, empty for NVMe/USB: kernel messages name the port, not the disk.
    pub port: String,
    pub parts: Vec<Part>,
    pub errors: Vec<KernelError>,
}

/// `KEY="value" KEY2="value"` as printed by `lsblk -P` (spaces in values come as `\x20`, quotes never appear).
pub(crate) fn pairs(l: &str) -> HashMap<&str, String> {
    let mut m = HashMap::new();
    let mut rest = l;
    while let Some((key, after)) = rest.split_once("=\"") {
        let Some((val, next)) = after.split_once('"') else {
            break;
        };
        m.insert(key.trim(), val.replace("\\x20", " "));
        rest = next;
    }
    m
}

/// `(source, mount point)` of the fstab lines; `\040` is a space in the mount point.
fn parse_fstab(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .filter_map(|l| {
            let mut c = l.split_whitespace();
            Some((c.next()?.to_string(), c.next()?.replace("\\040", " ")))
        })
        .collect()
}

/// Whole disks (`lsblk -P`) with the partitions that are mounted or that fstab wants mounted. `failed` are the mount
/// points of failed mount units: a partition fstab wants, not mounted, in that list is a failed mount.
fn parse_disks(lsblk: &str, fstab: &str, failed: &[String]) -> Vec<DiskInfo> {
    let rows: Vec<_> = lsblk.lines().map(pairs).collect();
    let fstab = parse_fstab(fstab);
    let get = |r: &HashMap<&str, String>, k: &str| r.get(k).cloned().unwrap_or_default();
    rows.iter()
        .filter(|r| get(r, "TYPE") == "disk" && valid_disk(&get(r, "NAME")))
        .map(|d| {
            let name = get(d, "NAME");
            let (tran, rota) = (get(d, "TRAN"), get(d, "ROTA"));
            let kind = match () {
                _ if tran == "usb" => 3,
                _ if name.starts_with("nvme") => 2,
                _ if rota == "1" => 1,
                _ => 0,
            };
            let parts = rows
                .iter()
                .filter(|p| get(p, "TYPE") == "part" && get(p, "PKNAME") == name)
                .filter_map(|p| {
                    let (pname, uuid, label, puuid) =
                        (get(p, "NAME"), get(p, "UUID"), get(p, "LABEL"), get(p, "PARTUUID"));
                    let is_src = |src: &str| {
                        src == format!("/dev/{pname}")
                            || (!uuid.is_empty() && src == format!("UUID={uuid}"))
                            || (!label.is_empty() && src == format!("LABEL={label}"))
                            || (!puuid.is_empty() && src == format!("PARTUUID={puuid}"))
                    };
                    let wanted = fstab.iter().find(|(src, _)| is_src(src)).map(|(_, mp)| mp.clone());
                    let mounted = get(p, "MOUNTPOINT");
                    let (mount, state) = if !mounted.is_empty() && mounted != "[SWAP]" {
                        (mounted, 0)
                    } else {
                        let mp = wanted.filter(|_| mounted.is_empty())?;
                        let state = if failed.contains(&mp) { 1 } else { 2 };
                        (mp, state)
                    };
                    Some(Part {
                        name: pname,
                        label,
                        size: get(p, "SIZE"),
                        mount,
                        state,
                    })
                })
                .collect();
            DiskInfo {
                name,
                model: get(d, "MODEL").trim().to_string(),
                size: get(d, "SIZE"),
                kind,
                port: String::new(),
                parts,
                errors: Vec::new(),
            }
        })
        .collect()
}

pub(crate) fn valid_disk(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Timeshift state without root: 0 not installed, 1 no snapshot readable, 2 newest snapshot in `latest`.
/// Snapshots on a backup disk that is not mounted are invisible, so state 1 is "none found", not "none exist".
pub fn backup() -> (i32, String) {
    if !std::path::Path::new("/etc/timeshift/timeshift.json").exists() {
        return (0, String::new());
    }
    crate::storage::timeshift_snapshots()
        .pop()
        .or_else(crate::storage::last_logged_snapshot)
        .map_or((1, String::new()), |l| (2, l))
}

pub fn scan() -> Health {
    let mut errors = parse_kernel_errors(&run("journalctl", &["-k", "-b", "-o", "cat", "--no-pager"]));
    let mut failed_mounts = parse_failed_mounts(&run(
        "systemctl",
        &["--failed", "--type=mount", "--plain", "--no-legend"],
    ));
    let lsblk = run(
        "lsblk",
        &[
            "-P",
            "-o",
            "NAME,TYPE,PKNAME,SIZE,ROTA,TRAN,MODEL,UUID,PARTUUID,LABEL,MOUNTPOINT",
        ],
    );
    let fstab = fs::read_to_string("/etc/fstab").unwrap_or_default();
    let mut disks = parse_disks(&lsblk, &fstab, &failed_mounts);
    for d in &mut disks {
        d.port = fs::canonicalize(format!("/sys/block/{}", d.name))
            .map_or(String::new(), |p| ata_port(&p.to_string_lossy()));
    }
    let problems = !errors.is_empty() || !failed_mounts.is_empty();
    assign(&mut disks, &mut errors, &mut failed_mounts);
    let units = ["systemd-oomd", "earlyoom"];
    // `-b -1` is the boot that was reset; it needs the adm group or root, otherwise it is empty and counts as 0.
    let oom_kills = count_oom(&run("journalctl", &["-k", "-b", "-o", "cat", "--no-pager"]))
        + count_oom(&run("journalctl", &["-k", "-b", "-1", "-o", "cat", "--no-pager"]));
    Health {
        memory: Memory {
            swap: crate::sysinfo::parse_swaps(&fs::read_to_string("/proc/swaps").unwrap_or_default()),
            watcher: parse_active(&units, &run("systemctl", &["is-active", units[0], units[1]])),
            oom_kills,
        },
        errors,
        failed_mounts,
        crashes: parse_crashes(&run("last", &["-x", "-n", "200"])),
        disks,
        backup: backup(),
        problems,
    }
}

/// `/sys/devices/pci0000:00/0000:00:17.0/ata1/host0/target0:0:0/0:0:0:0/block/sda` -> `ata1`.
fn ata_port(path: &str) -> String {
    path.split('/')
        .find(|c| {
            c.strip_prefix("ata")
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        })
        .unwrap_or("")
        .into()
}

/// Moves what belongs to a disk under it; what is left (ATA ports, network shares) stays in the lists.
fn assign(disks: &mut [DiskInfo], errors: &mut Vec<KernelError>, failed_mounts: &mut Vec<String>) {
    for d in disks.iter_mut() {
        // `sdb`, `sdb1`, `nvme0n1p2`: the disk name plus an optional `p` and digits.
        let is_mine = |dev: &str| {
            (!d.port.is_empty() && dev == d.port)
                || dev
                    .strip_prefix(&d.name)
                    .is_some_and(|r| r.trim_start_matches('p').bytes().all(|b| b.is_ascii_digit()))
        };
        let (mine, rest): (Vec<_>, Vec<_>) = std::mem::take(errors).into_iter().partition(|e| is_mine(&e.device));
        (d.errors, *errors) = (mine, rest);
        failed_mounts.retain(|m| !d.parts.iter().any(|p| p.state == 1 && &p.mount == m));
    }
}

/// `smartctl -H -A` output. ATA tables end in the raw value; NVMe has no such table, so only `passed` is filled.
pub fn parse_smart(text: &str) -> Smart {
    let mut s = Smart {
        passed: text.contains("PASSED") || text.contains("Health Status: OK"),
        ..Smart::default()
    };
    for l in text.lines() {
        if let Some((key, val)) = l.split_once(':') {
            let num = || {
                val.split_whitespace()
                    .next()?
                    .trim_end_matches('%')
                    .replace(',', "")
                    .parse::<u64>()
                    .ok()
            };
            match key.trim() {
                "Percentage Used" => s.used = num(),
                "Available Spare" => s.spare = num(),
                "Media and Data Integrity Errors" => s.uncorrectable = num().unwrap_or(0),
                "Critical Warning" if val.trim() != "0x00" => s.passed = false,
                _ => {}
            }
        }
        let c: Vec<&str> = l.split_whitespace().collect();
        let (Some(id), Some(raw)) = (c.first(), c.last().and_then(|r| r.parse::<u64>().ok())) else {
            continue;
        };
        match *id {
            "5" => s.reallocated = raw,
            "197" => s.pending = raw,
            "198" => s.uncorrectable = raw,
            "199" => s.crc = raw,
            _ => {}
        }
    }
    s
}

/// Asks for the administrator password. smartctl's exit code is a bit mask that is non-zero for a failing disk too, so
/// only a missing output counts as an error.
pub fn smart(disk: &str) -> io::Result<Smart> {
    if !valid_disk(disk) {
        return Err(io::Error::other("invalid disk name"));
    }
    let out = pkexec_output(SMARTCTL, &["-H", "-A", &format!("/dev/{disk}")])?;
    let text = String::from_utf8_lossy(&out.stdout);
    if text.trim().is_empty() {
        return Err(io::Error::other(
            String::from_utf8_lossy(&out.stderr).trim().to_string() + " (is smartmontools installed?)",
        ));
    }
    Ok(parse_smart(&text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_log_has_no_errors() {
        assert!(parse_kernel_errors("usb 1-1: new device\nEXT4-fs (sda1): mounted\n").is_empty());
    }

    #[test]
    fn repeated_errors_are_grouped_by_device() {
        let log = "blk_update_request: I/O error, dev sdb, sector 100\n\
                   blk_update_request: I/O error, dev sdb, sector 200\n\
                   ata3.00: failed command: READ DMA\n\
                   ntfs: $Bitmap read error\n";
        let e = parse_kernel_errors(log);
        assert_eq!(e.len(), 2);
        assert_eq!((e[0].device.as_str(), e[0].count), ("sdb", 2));
        assert_eq!(e[1].device, "ata3");
    }

    #[test]
    fn real_errors_are_filed_by_disk_and_empty_ports_ignored() {
        let log = "ata5: failed to resume link (SControl 0)\n\
                   ata1.00: failed command: READ FPDMA QUEUED\n\
                   sd 0:0:0:0: [sda] tag#18 Sense Key : Medium Error [current]\n";
        let e = parse_kernel_errors(log);
        assert_eq!(e.iter().map(|e| e.device.as_str()).collect::<Vec<_>>(), ["ata1", "sda"]);
        assert_eq!(
            ata_port("/sys/devices/pci0000:00/0000:00:17.0/ata1/host0/target0:0:0/0:0:0:0/block/sda"),
            "ata1"
        );
        assert_eq!(ata_port("/sys/devices/pci0000:00/nvme/nvme0/nvme0n1"), "");
        let mut disks = parse_disks(
            "NAME=\"sda\" TYPE=\"disk\" PKNAME=\"\" SIZE=\"1T\" ROTA=\"1\"\n",
            "",
            &[],
        );
        disks[0].port = "ata1".into();
        let (mut e, mut f) = (e, vec![]);
        assign(&mut disks, &mut e, &mut f);
        assert_eq!((disks[0].errors.len(), e.len()), (2, 0));
    }

    #[test]
    fn memory_gap_and_oom_log() {
        let units = ["systemd-oomd", "earlyoom"];
        assert_eq!(parse_active(&units, "inactive\nactive\n"), "earlyoom");
        assert_eq!(parse_active(&units, "inactive\ninactive\n"), "");
        assert_eq!(parse_active(&units, ""), "");
        assert_eq!(
            count_oom("Out of memory: Killed process 1 (firefox)\nusb 1-1: new device\n"),
            1
        );
        assert!(Memory::default().unprotected());
        assert!(
            !Memory {
                swap: vec!["/swapfile".into()],
                ..Memory::default()
            }
            .unprotected()
        );
    }

    #[test]
    fn crashes_and_failed_mounts() {
        let last =
            "seven pts/0 :0 Mon Oct 26 08:00 - crash (1+02:00)\nseven pts/1 :0 Sun Oct 25 08:00 - 09:00 (01:00)\n";
        assert_eq!(parse_crashes(last).len(), 1);
        assert_eq!(
            parse_failed_mounts("mnt-data.mount loaded failed failed /mnt/data\n"),
            ["/mnt/data"]
        );
    }

    #[test]
    fn smart_attributes() {
        let out = "SMART overall-health self-assessment test result: PASSED\n\
                   ID# ATTRIBUTE_NAME FLAG VALUE WORST THRESH TYPE UPDATED WHEN_FAILED RAW_VALUE\n  \
                   5 Reallocated_Sector_Ct 0x0033 100 100 036 Pre-fail Always - 8\n\
                   197 Current_Pending_Sector 0x0012 100 100 000 Old_age Always - 2\n\
                   199 UDMA_CRC_Error_Count 0x003e 200 200 000 Old_age Always - 0\n";
        let s = parse_smart(out);
        assert_eq!(
            (s.passed, s.reallocated, s.pending, s.uncorrectable, s.crc),
            (true, 8, 2, 0, 0)
        );
    }

    #[test]
    fn nvme_attributes() {
        let out = "SMART overall-health self-assessment test result: PASSED\n\
                   Critical Warning:                   0x00\n\
                   Available Spare:                    98%\n\
                   Percentage Used:                    7%\n\
                   Media and Data Integrity Errors:    1,204\n";
        let s = parse_smart(out);
        assert_eq!(
            (s.passed, s.used, s.spare, s.uncorrectable),
            (true, Some(7), Some(98), 1204)
        );
        assert!(!parse_smart("PASSED\nCritical Warning: 0x04\n").passed);
    }

    #[test]
    fn disks_group_their_partitions_and_failures() {
        let lsblk = "NAME=\"sda\" TYPE=\"disk\" PKNAME=\"\" SIZE=\"465.8G\" ROTA=\"0\" TRAN=\"sata\" MODEL=\"Samsung\\x20SSD\" UUID=\"\" PARTUUID=\"\" LABEL=\"\" MOUNTPOINT=\"\"\n\
            NAME=\"sda1\" TYPE=\"part\" PKNAME=\"sda\" SIZE=\"465G\" ROTA=\"0\" TRAN=\"\" MODEL=\"\" UUID=\"aaa\" PARTUUID=\"p1\" LABEL=\"\" MOUNTPOINT=\"/\"\n\
            NAME=\"sdb\" TYPE=\"disk\" PKNAME=\"\" SIZE=\"2T\" ROTA=\"1\" TRAN=\"usb\" MODEL=\"Elements\" UUID=\"\" PARTUUID=\"\" LABEL=\"\" MOUNTPOINT=\"\"\n\
            NAME=\"sdb1\" TYPE=\"part\" PKNAME=\"sdb\" SIZE=\"2T\" ROTA=\"1\" TRAN=\"\" MODEL=\"\" UUID=\"bbb\" PARTUUID=\"p2\" LABEL=\"Data\\x20Drive\" MOUNTPOINT=\"\"\n\
            NAME=\"sdb2\" TYPE=\"part\" PKNAME=\"sdb\" SIZE=\"1G\" ROTA=\"1\" TRAN=\"\" MODEL=\"\" UUID=\"ccc\" PARTUUID=\"p3\" LABEL=\"\" MOUNTPOINT=\"\"\n\
            NAME=\"loop0\" TYPE=\"loop\" PKNAME=\"\" SIZE=\"4K\" ROTA=\"0\" TRAN=\"\" MODEL=\"\" UUID=\"\" PARTUUID=\"\" LABEL=\"\" MOUNTPOINT=\"/snap/x\"\n";
        let fstab = "# comment\nUUID=aaa / ext4 defaults 0 1\nUUID=bbb /mnt/my\\040data ntfs defaults 0 0\n";
        let failed = vec!["/mnt/my data".to_string()];
        let d = parse_disks(lsblk, fstab, &failed);
        assert_eq!(d.len(), 2);
        assert_eq!(
            (d[0].name.as_str(), d[0].model.as_str(), d[0].kind),
            ("sda", "Samsung SSD", 0)
        );
        assert_eq!((d[0].parts[0].mount.as_str(), d[0].parts[0].state), ("/", 0));
        assert_eq!(d[1].kind, 3);
        // sdb2 has no fstab line and is not mounted: left out.
        assert_eq!(d[1].parts.len(), 1);
        assert_eq!((d[1].parts[0].mount.as_str(), d[1].parts[0].state), ("/mnt/my data", 1));
        assert_eq!(d[1].parts[0].label, "Data Drive");
    }

    #[test]
    fn errors_and_failed_mounts_go_under_their_disk() {
        let mut disks = parse_disks(
            "NAME=\"sdb\" TYPE=\"disk\" PKNAME=\"\" SIZE=\"2T\" ROTA=\"1\" TRAN=\"\" MODEL=\"\" UUID=\"\" PARTUUID=\"\" LABEL=\"\" MOUNTPOINT=\"\"\n\
             NAME=\"sdb1\" TYPE=\"part\" PKNAME=\"sdb\" SIZE=\"2T\" ROTA=\"1\" TRAN=\"\" MODEL=\"\" UUID=\"u\" PARTUUID=\"\" LABEL=\"\" MOUNTPOINT=\"\"\n",
            "UUID=u /mnt/d ntfs defaults 0 0\n",
            &["/mnt/d".to_string()],
        );
        let mut errors = parse_kernel_errors("I/O error, dev sdb, sector 1\nata3.00: failed command: READ\n");
        let mut failed = vec!["/mnt/d".to_string(), "/srv/nfs".to_string()];
        assign(&mut disks, &mut errors, &mut failed);
        assert_eq!(disks[0].errors.len(), 1);
        assert_eq!(errors.len(), 1);
        assert_eq!(failed, ["/srv/nfs"]);
    }
}
