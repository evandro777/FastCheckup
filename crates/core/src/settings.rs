//! User settings in one TOML file under the XDG data dir (`~/.local/share/FastCheckup`).
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::files::{read_or_backup, write_atomic};

/// Folder name under the XDG data dir; `rename.sh` rewrites it.
pub const APP_DIR: &str = "FastCheckup";
pub const MIN_SIZE: (u32, u32) = (400, 300);
/// Upper bound for a hand-edited size; a huge value would fail at window creation.
pub const MAX_SIZE: u32 = 8192;
/// Range of `usage_days` ("older than" in Preferences).
pub const MIN_OLD_DAYS: u32 = 1;
pub const MAX_OLD_DAYS: u32 = 3650;

#[derive(Serialize, Deserialize, Clone)]
#[serde(default)] // older files keep loading when a field is added
pub struct Settings {
    /// "" follows the system locale; otherwise a gettext code such as "pt_BR".
    pub language: String,
    pub width: u32,
    pub height: u32,
    /// Apps whose data has not changed for this many months are marked as possibly unused.
    pub stale_months: u32,
    /// "Almost safe" means older than this many days: installers in Downloads, build folders, Trash entries.
    pub usage_days: u32,
    /// Folders the build-output scan never enters.
    pub excluded_paths: Vec<String>,
    /// "" follows the system's light or dark mode; otherwise "light" or "dark".
    pub theme: String,
    /// Off by default: everything else the app cleans goes to the Trash, so emptying it is the one step with no way back.
    pub allow_empty_trash: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            language: String::new(),
            width: 1200,
            height: 720,
            stale_months: 6,
            usage_days: 90,
            excluded_paths: Vec::new(),
            theme: String::new(),
            allow_empty_trash: false,
        }
    }
}

fn parse(text: &str) -> Result<Settings, toml::de::Error> {
    toml::from_str(text)
}

pub(crate) fn data_dir() -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join(APP_DIR)
}

fn path() -> PathBuf {
    data_dir().join("settings.toml")
}

impl Settings {
    pub fn load() -> Self {
        // The file is hand-edited; a bad one is moved aside so the next save() must not overwrite what the user wrote.
        let mut s = read_or_backup(&path(), |t| parse(t).map_err(|e| e.to_string())).0;
        s.normalize();
        s
    }

    fn normalize(&mut self) {
        self.width = self.width.clamp(MIN_SIZE.0, MAX_SIZE);
        self.height = self.height.clamp(MIN_SIZE.1, MAX_SIZE);
        // 0 would make everything "old" and so open to the bulk clean-up.
        self.usage_days = self.usage_days.clamp(MIN_OLD_DAYS, MAX_OLD_DAYS);
    }

    /// Atomic write so a crash can never leave a half-written file. Failures are reported on stderr;
    /// the app keeps working with the in-memory settings.
    pub fn save(&self) {
        if let Err(e) = self.try_save() {
            eprintln!("cannot save settings to {}: {e}", path().display());
        }
    }

    fn try_save(&self) -> std::io::Result<()> {
        let text = toml::to_string_pretty(self).map_err(std::io::Error::other)?;
        write_atomic(&path(), text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_files_still_load() {
        let parsed: Settings = toml::from_str("width = 700").unwrap();
        assert_eq!(
            (parsed.width, parsed.language.as_str(), parsed.stale_months),
            (700, "", 6)
        );
        assert_eq!((parsed.usage_days, parsed.excluded_paths.len()), (90, 0));
    }

    #[test]
    fn theme_defaults_to_the_system_and_loads_when_set() {
        let old: Settings = toml::from_str("width = 700").unwrap();
        assert_eq!(old.theme, "");
        let dark: Settings = toml::from_str("theme = \"dark\"").unwrap();
        assert_eq!(dark.theme, "dark");
    }

    #[test]
    fn emptying_the_trash_is_off_unless_set() {
        let old: Settings = toml::from_str("width = 700").unwrap();
        assert!(!old.allow_empty_trash);
        let on: Settings = toml::from_str("allow_empty_trash = true").unwrap();
        assert!(on.allow_empty_trash);
    }

    #[test]
    fn invalid_file_is_an_error_not_defaults() {
        assert!(parse("width = \"wide\"").is_err());
    }

    #[test]
    fn window_size_is_clamped_both_ways() {
        let mut s: Settings = toml::from_str("width = 4000000000\nheight = 1").unwrap();
        s.normalize();
        assert_eq!((s.width, s.height), (MAX_SIZE, MIN_SIZE.1));
    }

    #[test]
    fn old_days_never_reaches_zero() {
        let mut s: Settings = toml::from_str("usage_days = 0").unwrap();
        s.normalize();
        assert_eq!(s.usage_days, MIN_OLD_DAYS);
    }
}
