# FastCheckup

A light and fast Linux app that **shows what is slow, large, unused or exposed** on your computer, and lets you act on
each item one at a time. It never cleans everything in one click. Built with Rust + Slint. GPL-3.0-or-later.

## What it shows

- **Overview**: One card per area with its status, plus a **Right now** check of memory, swap, load and the busiest apps.
- **Speed**: **Startup**: turn login apps on or off. **Services**: enable or disable background services, with their start time. **Boot**: where boot time goes and the GRUB menu timeout. Also a check that something protects you when memory runs out.
- **Space**: the disks and one clean-up page, sorted by how safe it is to remove. **Safe**: caches, package files, old logs, Docker's build cache, unused Flatpak runtimes, packages nothing needs. **Almost safe**: build folders, installers and Trash entries older than a set number of days, and old tool versions. **Must analyze**: recent build folders, the whole Trash, duplicate files, Docker containers, old kernels, settings and data of removed apps, one item at a time. **Look only**: the biggest folders and files, game libraries.
  Safe and Almost safe also have **Review and clean up**: one dialog lists every item (untick what you want to keep) and can show the exact command lines before anything runs.
- **Safety**: **Disk health**: failing disks, failed mounts and SMART on request. **Security**: open ports, odd programs, things that start by themselves and risky browser add-ons. Report only.
- **Apps**: Installed Debian, Flatpak and AppImage apps with size and "last data activity"; uninstall one.
- **System**: What this computer is: hardware, drivers and whether graphics acceleration works. Copy it all as text.
- **History**: Every change you made.

## How it behaves

- **Scans never change anything.** Each change is a button on one item, or a reviewed bulk clean-up of the Safe and
  Almost safe groups, behind a confirm dialog that shows exactly what will run, and it is logged in History. The
  root steps of a bulk clean-up (apt autoremove, apt clean, journal) run in one administrator prompt.
- **Reversible where possible:** files go to the Trash, services are disabled (not removed), startup entries get an
  override instead of an edit, and the GRUB change keeps a backup.
- **Honest wording:** it says "last data activity", never "unused", and "nothing visible looks wrong", never "your
  system is clean".
- **Essential system software** is marked as such and protected.
- **Private and light:** no network calls, no telemetry, about 27 MB of memory.

## Install

- **`.deb`** (recommended): the password prompt says what FastCheckup is doing.
- **AppImage**: works the same, but the password prompt is generic and it does not update through `apt`.
- **Flatpak** (updates itself): **not sandboxed.** An inspector inside a sandbox only sees its own files and programs, so the app has the permission `--talk-name=org.freedesktop.Flatpak` and uses it to start itself on the host (`flatpak-spawn --host`). It can do anything you can do. Check it with `flatpak info --show-permissions io.github.evandro777.FastCheckup`. The password prompt is generic, as in the AppImage. Add the remote once; `flatpak update` and your software centre then keep it current:

  ```bash
  flatpak remote-add --system --if-not-exists fastcheckup https://evandro777.github.io/FastCheckup/fastcheckup.flatpakrepo
  flatpak install --system fastcheckup io.github.evandro777.FastCheckup
  ```

  Use `--system`: Linux Mint's Update Manager only looks at system-wide Flatpaks. If the host copy cannot start, the app runs inside the sandbox and shows only the sandbox.

The app never runs as root. Actions that need it ask for your password through `pkexec`. The Overview offers **Run admin checks**: one password prompt runs a fixed read-only script as root (`ss`, `/proc`, failed logins, `ufw status`, `smartctl`, Timeshift folders) so Security, Disk health and Timeshift show what they cannot see as your user. Nothing is changed, and the app stays under your account (relaunching a window as root would read root's settings and break on Wayland).

## Supported systems

- **Debian, Ubuntu and Linux Mint** with systemd. Tested on Mint (Cinnamon, X11); Wayland is not tested yet.
- By design it has no auto-cleaning, no background service, and never deletes your Documents, Dropbox or Pictures.
- Not yet: a command-line version, Arch and Fedora, and languages other than English and Português.

## Settings

`$XDG_DATA_HOME/FastCheckup/settings.toml` (usually `~/.local/share/FastCheckup/`), next to `history.jsonl`. The appearance
(system, light or dark) and the language are set in Preferences, from the menu button; the rest you edit by hand.

| Key              | Default | Meaning                                                                 |
|------------------|---------|-------------------------------------------------------------------------|
| `stale_months`   | `6`     | Months without data changes before an app is marked as possibly unused. |
| `usage_days`     | `90`    | "Almost safe" age in days (installers, build folders, Trash). Also in Preferences. |
| `excluded_paths` | `[]`    | Folders the build-output search never enters.                           |

## Build from source

```bash
cargo run --profile fast
```

System deps (Debian family): `libfontconfig-dev libxkbcommon-dev libxkbcommon-x11-dev libx11-dev libxcb1-dev`.
Contributor notes are in `AGENTS.md` and `CONTRIBUTING.md`.

## Credits

The interface icons in `crates/app/ui/icons/` are from [Lucide](https://lucide.dev), under the ISC licence
(see `crates/app/ui/icons/LICENSE`).
