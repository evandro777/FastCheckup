//! UI-independent logic: settings, the Startup, Services, Apps and Storage scanners and the history log. Keep Slint out of this crate so a CLI can reuse it.
pub mod admin;
pub mod apps;
pub mod autostart;
pub mod boot;
pub mod files;
pub mod health;
pub mod history;
pub mod perf;
pub mod security;
pub mod services;
pub mod settings;
pub mod storage;
pub mod sysinfo;
