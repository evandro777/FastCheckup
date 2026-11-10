//! Append-only log of what the app changed: `history.jsonl` in the data dir, one JSON object per line.
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{
    files::{create_private_dir, write_atomic},
    settings::data_dir,
};

/// Newest records kept; the History page shows these.
const MAX_RECORDS: usize = 1000;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum Kind {
    Disabled,
    Restored,
    /// A value changed in a system file (e.g. the GRUB timeout).
    Changed,
    /// An app was uninstalled or its leftover data moved to the Trash.
    Removed,
    /// The start delay of a startup entry was set or cleared.
    Delayed,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Record {
    /// Seconds since the Unix epoch.
    pub time: u64,
    pub kind: Kind,
    pub name: String,
    pub file: String,
}

impl Record {
    pub fn now(kind: Kind, name: &str, file: &str) -> Self {
        let time = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        Self {
            time,
            kind,
            name: name.into(),
            file: file.into(),
        }
    }
}

/// shortcut: UTC, not local time (no date crate), when users ask for local time.
pub fn utc(secs: u64) -> String {
    // Civil-from-days (H. Hinnant), valid for all dates the app will see.
    let (days, rem) = ((secs / 86400) as i64, secs % 86400);
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02} {:02}:{:02}", rem / 3600, rem % 3600 / 60)
}

/// A failed write is reported, never fatal: the action it describes already happened.
pub fn append(record: &Record) {
    if let Err(e) = append_to(&history_path(), record) {
        eprintln!("cannot write history: {e}");
    }
}

fn history_path() -> PathBuf {
    data_dir().join("history.jsonl")
}

/// The log is private like the other files (0700 folder, 0600 file), also for a file made by an older version.
fn append_to(path: &Path, record: &Record) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        create_private_dir(dir)?;
    }
    let mut f = OpenOptions::new().create(true).append(true).mode(0o600).open(path)?;
    f.set_permissions(fs::Permissions::from_mode(0o600))?;
    writeln!(f, "{}", serde_json::to_string(record).map_err(io::Error::other)?)
}

/// Newest first. Lines that do not parse (hand-edited, older versions) are skipped.
pub fn read() -> Vec<Record> {
    read_from(&history_path())
}

/// A log that has grown past twice `MAX_RECORDS` lines is cut to the newest `MAX_RECORDS` (the slack means the file is
/// rewritten once per `MAX_RECORDS` actions, not on every read).
fn read_from(path: &Path) -> Vec<Record> {
    let text = fs::read_to_string(path).unwrap_or_default();
    let mut lines: Vec<&str> = text.lines().collect();
    if lines.len() > MAX_RECORDS * 2 {
        lines.drain(..lines.len() - MAX_RECORDS);
        let _ = write_atomic(path, lines.join("\n") + "\n");
    }
    lines
        .iter()
        .rev()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_formats_known_dates() {
        assert_eq!(utc(0), "1970-01-01 00:00");
        assert_eq!(utc(1_709_164_800 + 3600 * 13 + 60 * 5), "2024-02-29 13:05");
    }

    #[test]
    fn old_and_new_kinds_load() {
        let old: Record = serde_json::from_str(r#"{"time":1,"kind":"Disabled","name":"A","file":"a"}"#).unwrap();
        let new: Record = serde_json::from_str(r#"{"time":1,"kind":"Changed","name":"A","file":"a"}"#).unwrap();
        assert_eq!((old.kind, new.kind), (Kind::Disabled, Kind::Changed));
    }

    fn temp_log(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fastcheckup-history-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir.join("history.jsonl")
    }

    #[test]
    fn append_then_read_is_newest_first_private_and_skips_bad_lines() {
        let log = temp_log("roundtrip");
        append_to(&log, &Record::now(Kind::Disabled, "A", "a.desktop")).unwrap();
        writeln!(OpenOptions::new().append(true).open(&log).unwrap(), "not json").unwrap();
        append_to(&log, &Record::now(Kind::Restored, "B", "b.desktop")).unwrap();
        let files: Vec<_> = read_from(&log).into_iter().map(|r| r.file).collect();
        assert_eq!(files, ["b.desktop", "a.desktop"]);
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!((mode(&log), mode(log.parent().unwrap())), (0o600, 0o700));
        let _ = fs::remove_dir_all(log.parent().unwrap());
    }

    #[test]
    fn a_long_log_is_cut_to_the_newest_records() {
        let log = temp_log("trim");
        for i in 0..=MAX_RECORDS * 2 {
            append_to(&log, &Record::now(Kind::Disabled, "A", &format!("{i}.desktop"))).unwrap();
        }
        let records = read_from(&log);
        assert_eq!(records.len(), MAX_RECORDS);
        assert_eq!(records[0].file, format!("{}.desktop", MAX_RECORDS * 2));
        assert_eq!(
            fs::read_to_string(&log).unwrap().lines().count(),
            MAX_RECORDS,
            "file rewritten too"
        );
        let _ = fs::remove_dir_all(log.parent().unwrap());
    }

    #[test]
    fn record_round_trips() {
        let json = serde_json::to_string(&Record::now(Kind::Restored, "A", "a.desktop")).unwrap();
        let back: Record = serde_json::from_str(&json).unwrap();
        assert_eq!((back.kind, back.file.as_str()), (Kind::Restored, "a.desktop"));
    }
}
