//! Flatpak only: runs the app on the host, so the scanners see the real system (`/proc`, `dpkg`, `systemctl`, `pkexec`,
//! the home folder) instead of the sandbox's own.
//!
//! It needs the manifest's `--talk-name=org.freedesktop.Flatpak` (so `flatpak-spawn --host` works), which means the
//! sandbox is no longer a security boundary. The app is started with the runtime's own dynamic loader and libraries
//! (`--library-path`), so it does not depend on what the host has installed.
use std::{
    fs,
    process::Command,
    time::{Duration, Instant},
};

/// Set on the host copy, so it does not relaunch itself.
const MARKER: &str = "FASTCHECKUP_ON_HOST";
/// A host copy that fails sooner than this never got going (bad loader, no display, or `flatpak-spawn` waiting out
/// the ~25 s D-Bus activation timeout of a missing session helper): fall back to the sandbox instead of quitting
/// with no window.
const STARTUP: Duration = Duration::from_secs(30);
/// The only id that may relaunch: another Flatpak's `FLATPAK_ID` can leak into an AppImage started from its terminal.
const APP_ID: &str = "io.github.evandro777.FastCheckup";

pub enum Outcome {
    /// Not in a Flatpak, or already the host copy: carry on as usual.
    NotNeeded,
    /// The host copy ran and exited: exit with its code.
    Exited(i32),
    /// The host copy could not start: carry on in the sandbox and say so.
    Failed,
}

/// `(app-path, runtime-path)` from `/.flatpak-info`. Both are paths on the host.
fn parse_paths(info: &str) -> Option<(&str, &str)> {
    let get = |key: &str| info.lines().find_map(|l| l.strip_prefix(key));
    Some((get("app-path=")?, get("runtime-path=")?))
}

/// `(library dir, dynamic loader)` of the runtime for this CPU.
fn arch_names() -> Option<(&'static str, &'static str)> {
    match std::env::consts::ARCH {
        "x86_64" => Some(("x86_64-linux-gnu", "ld-linux-x86-64.so.2")),
        "aarch64" => Some(("aarch64-linux-gnu", "ld-linux-aarch64.so.1")),
        _ => None,
    }
}

/// The `flatpak-spawn` arguments. `--watch-bus` ends the host copy when this sandbox goes away.
/// `data_home` is forwarded so both copies share one settings file (`$XDG_DATA_HOME/FastCheckup`), and `flatpak_id`
/// so the host copy listens on the socket the sandbox's `instance::send` looks for (`$XDG_RUNTIME_DIR/app/<id>/`).
fn spawn_args(app: &str, runtime: &str, data_home: Option<&str>, flatpak_id: &str) -> Option<Vec<String>> {
    let (triple, loader) = arch_names()?;
    let mut args = vec![
        "--host".to_string(),
        "--watch-bus".to_string(),
        format!("--env={MARKER}=1"),
        format!("--env=FLATPAK_ID={flatpak_id}"),
    ];
    if let Some(dir) = data_home {
        args.push(format!("--env=XDG_DATA_HOME={dir}"));
    }
    // DISPLAY, WAYLAND_DISPLAY and XAUTHORITY are deliberately not forwarded: inside the sandbox they point at
    // sandbox paths. The host's own session environment has the right ones.
    args.extend([
        format!("{runtime}/lib/{triple}/{loader}"),
        "--library-path".into(),
        format!("{runtime}/lib/{triple}:{app}/lib"),
        format!("{app}/bin/fastcheckup"),
    ]);
    Some(args)
}

pub fn run() -> Outcome {
    // `starts_with` also takes the `.Devel` build.
    let id = std::env::var("FLATPAK_ID").unwrap_or_default();
    let ours = id.starts_with(APP_ID);
    if !ours || std::env::var_os(MARKER).is_some() {
        return Outcome::NotNeeded;
    }
    let Ok(info) = fs::read_to_string("/.flatpak-info") else {
        return Outcome::NotNeeded;
    };
    let data_home = std::env::var("XDG_DATA_HOME").ok();
    let Some(args) = parse_paths(&info).and_then(|(app, runtime)| spawn_args(app, runtime, data_home.as_deref(), &id))
    else {
        return Outcome::Failed;
    };
    let started = Instant::now();
    match Command::new("flatpak-spawn").args(&args).status() {
        Ok(status) if status.success() || started.elapsed() > STARTUP => Outcome::Exited(status.code().unwrap_or(0)),
        Ok(status) => {
            eprintln!("the host copy exited with {status} right after starting: running in the sandbox instead");
            Outcome::Failed
        }
        Err(e) => {
            eprintln!("cannot run flatpak-spawn ({e}): running in the sandbox instead");
            Outcome::Failed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_host_paths() {
        let info = "[Application]\nname=x\n\n[Instance]\napp-path=/home/u/app/files\nruntime-path=/usr/lib/rt/files\n";
        assert_eq!(parse_paths(info), Some(("/home/u/app/files", "/usr/lib/rt/files")));
        assert_eq!(parse_paths("[Application]\nname=x\n"), None);
    }

    #[test]
    fn spawn_args_use_the_runtime_loader_and_no_display_variables() {
        let Some(args) = spawn_args("/app/files", "/rt/files", Some("/home/u/.var/app/x/data"), APP_ID) else {
            return; // an architecture the runtime has no loader name for
        };
        assert_eq!(&args[..2], ["--host", "--watch-bus"]);
        assert!(args.contains(&format!("--env={MARKER}=1")));
        assert!(args.contains(&format!("--env=FLATPAK_ID={APP_ID}")));
        assert!(args.contains(&"--env=XDG_DATA_HOME=/home/u/.var/app/x/data".to_string()));
        assert!(
            args.iter()
                .any(|a| a.starts_with("/rt/files/lib/") && a.contains("ld-linux"))
        );
        assert!(args.last().is_some_and(|a| a == "/app/files/bin/fastcheckup"));
        assert!(!args.iter().any(|a| a.contains("DISPLAY") || a.contains("XAUTHORITY")));
    }
}
