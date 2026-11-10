# AGENTS.md: FastCheckup

Notes for AI agents and contributors. Read this before changing anything.

## What this is

A **light and fast** Linux system inspector in Rust + Slint. It reports what is slow, large, unused or exposed and the
user acts on each item individually (no "fix all"). Priorities: fast start, low memory, simplicity.
Design: `SYSTEM_CLEANER_PLAN.md`. Deferred features: `BACKLOG.md`. The modules so far are Startup, Services, Boot and Apps.

## Layout

```txt
Cargo.toml                workspace, release/fast profiles
crates/core/              UI-independent logic. No Slint here, so a CLI can reuse it
  autostart.rs            Startup scanner + enable/disable/delay (user-level override, removed when it equals the system file; atomic writes)
  rules.toml              protected (Essential) startup entries and services, timer-run services, embedded with include_str!
  services.rs             Services scanner (systemctl, systemd-analyze blame), reverse-dependency/hardware prechecks, enable/disable via pkexec
  boot.rs                 Boot breakdown, critical chain, GRUB timeout change (backup, verify, restore on failure), DMI board info
  apps.rs                 Apps scanner (dpkg-query, flatpak, ~/AppImages, last data activity, overlap) and the Leftovers lists (apt autoremove, rc configs, old kernels, unused runtimes, Flatpak data), uninstall via pkexec apt-get / flatpak, Trash via gio
  storage.rs              Storage scanner (build folders via walkdir, Downloads installers, Trash, ~/.cache, journal, Docker) and its actions
  health.rs               Disk health: disks with their partitions (lsblk -P + fstab), failed mounts and kernel I/O errors filed under the disk they name, unclean shutdowns (no root); SMART via pkexec smartctl on demand
  perf.rs                 Overview "Right now": /proc parsers (meminfo, PSI, stat), a 1 s two-sample CPU measure per app, `verdict()` (level + cause)
  security.rs             Security review (no root, report only): ss ports/connections, /proc exe paths, persistence files, browser add-on manifests, failed logins, ufw state, scanner list. One flat `Finding {code, level, subject, extra, n}`; the sentence per `code` lives in `Tr.finding-line`
  sysinfo.rs              System page (no root, report only): DMI, /proc, lspci, lsblk, lsusb, xrandr, glxinfo/vulkaninfo/vainfo/vdpauinfo. `scan(root)` + text parsers; Rust sets rows and the "Copy all" text from `Tr.sys-group/sys-label/sys-text`
  admin.rs                One `pkexec /bin/sh -c SCRIPT` for all root-only reads (ss, /proc exe, logins, ufw, smartctl, Timeshift dirs); sections are marked `@@NONCE name` so scanned text cannot forge one. The nonce goes in on stdin (argv is world-readable in /proc) and a repeated section makes `parse` fail. Fast data (sockets, procs) feeds one `security::scan(Some(..))` only; slow data (ufw, SMART, snapshots) is kept in `ADMIN` in main.rs and reapplied by `apply_admin` after rescans
  history.rs              history.jsonl log
  settings.rs             settings.toml
crates/app/               Slint UI + main.rs; build.rs compiles ui/ and bundles translations/
crates/app/src/instance.rs  one window: a second start sends `show` over `$XDG_RUNTIME_DIR/<crate>.sock` and exits; the running one is raised. A verbatim copy of FastHello's (change it there, not here)
packaging/                .desktop, icon, metainfo, polkit policy (AppImage, .deb via `[package.metadata.deb]` in crates/app/Cargo.toml, CI validation)
appimage/build.sh         AppImage + .zsync (host libs, not bundled); CI: appimage.yml
dev/gen_po.py             writes the .po files from one table
scripts/ui-snapshot.sh    renders pages on a private Xvfb with canned data (crates/app/src/fixtures.rs, env FASTCHECKUP_FIXTURES=empty|single|many, FASTCHECKUP_PAGE=<n>) to target/ui-snapshots/
crates/app/src/host.rs    Flatpak only: relaunches the app on the host (`flatpak-spawn --host`), copied from FastProcMan's. Needs `--talk-name=org.freedesktop.Flatpak` in the manifest, so the Flatpak is NOT sandboxed (on purpose: for auto-update). `instance::send` comes before `host::run()`. If the host copy fails the app runs in the sandbox and `Main.sandboxed` shows a warning on Overview (`STATE=sandboxed` in the snapshot script)
flatpak/                  manifest, build.sh (vendors crates, builds outside the repo), new-signing-key.sh; CI: flatpak.yml (signed remote on GitHub Pages)
docs/                     FLATPAK-SIGNING.md, landing page `site/index.html` (no screenshots yet)
```

## Commands

```bash
cargo build --profile fast    # iteration build, no LTO
cargo build --release         # thin LTO
cargo test                    # unit tests
```

System deps: `libfontconfig-dev libxkbcommon-dev libxkbcommon-x11-dev libx11-dev libxcb1-dev`. No GL/Skia/femtovg.

## Code conventions: Editing code

- Use the Edit tool for code changes. Don't splice files with sed, awk, python or heredocs through Bash.
- After editing Rust, run `cargo fmt && cargo clippy -- -D warnings && cargo test`. Re-read the surrounding block to confirm no braces, lines or whole components (e.g. pages) were deleted.
- After any change, also run `cargo build --profile fast` so the binary is built and cached for the owner's manual testing.

## Architecture decisions (inherited from FastMoji, measured there)

- **Software renderer only** (`winit` + `software`, forced in `main.rs` and in `Cargo.toml` features with `default-features = false`): ~27 MB RSS versus ~108 MB with the GL renderer.
- No async runtime. Scans/work in threads, results handed to the UI thread with `slint::invoke_from_event_loop`.
- Never hold a `RefCell` borrow while calling something that makes Slint re-read a model.
- Keep dependencies few and light.
- The sidebar is Overview, Speed, Space, Safety, Apps, System, History. System is page 13: report only, no level dot, scanned on first visit (not wired with fixtures, which show canned data). The "Copy all" `TextInput` sits outside every layout in `Main` because a 0-wide child inside a layout caps its maximum width and shrinks the whole window. Overview, Speed and Safety are dashboards (pages 9, 12, 11) that summarise and open the detail pages (Speed: Startup, Services, Boot; Safety: Disk health, Security), which show a `Back` link. Space (page 10) is not a dashboard: it holds the disks, the totals and every clean-up (what used to be the Leftovers and Storage pages, 4 and 6, now free), so it has no sub-pages. `Main.go(page)` opens a page and starts its lazy scan; use it, never set `page` directly. `fullest-pct` comes from `set_totals` in `main.rs`, also called by the fixtures. The "safe to clean" and "almost safe to clean" sizes (Space tiles, Overview card) are the sums of the same candidates the bulk dialog lists (`safe-scan-mb`, `almost-free-mb` from `refresh_storage`; the page adds `rt-mb` and `auto-mb` live), so a tile and its dialog agree.
- Space, Disk health and Security share `Tile` (number + label), `Bar` and `Section` (bordered card; `collapsible` starts closed). `@children` cannot sit inside an `if`, so a closed `Section` clips its body to height 0. Security findings are one text per line (worst first, sorted in `set_findings`), so select-all no longer spans the page. Each topic is its own `Section`; findings with the same `Finding.app` (a program, or a browser for its add-ons) are adjacent and sit under one header with its icon and path.
- Long pages are split, not stacked. `Section.empty` (a sentence) puts the green check on the header line and collapses the body and `sub`, so an empty group costs one line; use it instead of an `Empty` inside a card. A `collapsible` `Section` cannot also have a header `action` (the toggle is off then), so Disk health folds each disk's partitions with a local `show-parts` bool and a link row instead. Space has four tabs behind a `FilterBar` (`store-group`: 0 Safe, 1 Almost safe, 2 Must analyze, 3 Look only), below the disks and tiles; each is its own `if` block so a switch starts at the top (the Trash tile opens 2). Both scanners feed the tabs: Storage's lists and the Leftovers lists (autoremove, runtimes in Safe; kernels, residual settings, Flatpak data, home data, stale startup in Must analyze). "Scan again" runs both (`storage-rescan` and `app-rescan`). Tabs 0 and 1 start with a `Section` whose header action opens the bulk dialog (`bulk-plan(tier)`, `bulk-confirming`): `fn tier(action)` in main.rs decides which action codes belong to which tier, `CANDIDATES` keeps what the last scan offers, and `bulk_rows` adds the two live checks (unused Flatpak runtimes, apt autoremove) with their lists in `BulkRow.detail`, which the dialog shows through `Tr.runtimes` / `Tr.also-removed`. "Almost safe" means older than `settings.usage_days` (`OLD_DAYS` static, set from Preferences, clamped 1..3650; Preferences rescans on close when it changed): build folders (split by newest mtime into `old-builds` / `builds`), Downloads installers, home Trash entries by `DeletionDate` (action 18, deleted for good with `storage::delete_trash_entry`, which re-reads the date) and old tool versions with `Keep::No`. `run_action` is the one match over action codes, used by a single click and by `run_bulk`. The root steps (3 autoremove, 16 apt clean, 10 journal) of a bulk run share one `pkexec /bin/sh -c` script built by `storage::root_script`; the line shown in the dialog (`root_command`) is built from the same function, each step prints a `@@ <action> <exit>` marker, no step stops the next, and a missing marker is a failure. Never put user input into that script. Disk usage lives only on Space. The Memory safety net and swap/zram cards are on Speed (the health scan runs for page 12 too), so `mem-warning` feeds `speed-level`, not `health-level`.
- The sidebar shows the pages of the open group as `NavItem { sub: true }` (no icon or dot, starts at x=26 so long translations fit); the `Back` links stay. `FilterBar` is a segmented control (one track, the picked segment raised, no accent colour; Left/Right keys when focused). Segments are `max(64px, label + 20px)` wide, so they grow with the translation. Three labelled groups plus Search do not fit one line at the 960px default width (Services uses two rows); give a page's Search box `min-width: 60px`. Never put `max-width` on a `Text` that sits directly in a page layout: it caps the whole window width (a 760px cap shrank the window to 952px).
- Status colours, the type scale (11/13/16/20 px, weights 600/700) and spacing come from `Family` in `ui/family.slint`, a verbatim copy of FastHello's (rules in its `docs/UI-STYLE.md`: change it there, not here). `Theme` in `ui/main.slint` only holds what is specific to this app (`muted`, `purple`, `level-color`); never write a hex colour or a font size in a component. The one exception is the 18 px headline values of the Overview cards, which are content. Area status is a derived `*-level` binding in `Main` (0 not scanned, 1 fine, 2 worth a look, 3 problem; `Theme.level-color`), shared by the Overview cards (`Section.status`/`dot`, grey at 0) and the sidebar dots (`NavItem.level`, no dot at 0). Startup rows drop the Optional/Enabled chips while the matching filter is active; `AppIcon` draws a plain tile when an icon is missing. `FASTCHECKUP_FIXTURES=empty` renders the "nothing scanned yet" Overview.
- The safety level of a clean-up is a shield: `shield-check` (safe, `Family.success`), `shield-half` (almost safe, `Family.info`), `shield-question` (must analyze, `Family.warning`), so it reads without colour. `Theme.tier-icon(tier)` / `Theme.tier-tone(tier)` are the one source; `Section.tier` (0..2) draws it in a card header, `FilterBar` takes optional `icons` and `tones`, and the bulk dialog title uses `bulk-tier`. Not on every row: a tab holds one level. The three SVGs were composed from `shield.svg` plus Lucide's inner strokes without network access; compare them with lucide.dev when convenient.
- Icons are Lucide SVGs in `crates/app/ui/icons/` (ISC, licence file next to them), drawn by the kit's `Icon` component (`controls.slint`, like `FilterBar`, `SearchBox` and `NeutralBadge`: change them in FastHello and copy, not here; the nav bar uses the desktop accent, `Family.info` is for links), which repaints the black SVG with `colorize`; never hard-code a colour in the file. `NavItem`, `Section` and `Tile` take an optional `icon` (nothing is drawn when empty), `Back` and `Empty` (green check + sentence) draw their own. Copy new icons from Lucide at 24px, stroke 2, and keep them to these sizes: 16 nav and buttons, 18 headers and tiles, 14 chevrons. The SVGs are embedded raw by `@image-url`; there is no icon crate.
- `LearnMore { label, text, open }` is the quiet "what is this?" link (info icon + accent label) that opens a tinted, selectable panel; use it for paragraph-long explanations instead of always-visible text. Click, not hover (long, selectable, keyboard reachable). Never place it inside a `link: true` `Section` (its whole-card `TouchArea` takes the click); join paragraphs with `+ "\n\n" +` so each `@tr` stays one string. Used on Speed (swap/zram, `mem-info-open`), Boot, Disk health, Security and Leftovers.
- The sidebar menu button opens the Preferences (`menu-open`) and `about-open` overlays (same pattern as the confirm dialogs). `set-theme` saves `settings.theme` (`theme-index` already sets `Palette.color-scheme`). `set-language` saves `settings.language` and calls `select_bundled_translation`, which re-evaluates `@tr` live; strings built in Rust through `Tr` keep the old language until the next scan.
- Slint notes: use `content-y` (not `viewport-y`); a callback named `close` shadows a builtin (use `dismiss`); `FocusScope.capture-key-pressed` intercepts keys before `LineEdit`.

## Translations

- UI strings use `@tr()`; strings built in Rust go through the `Tr` global in `ui/main.slint`. Never `format!` user-visible text in Rust.
- `.po` files are generated by `dev/gen_po.py` (edit its table, run it, commit both). Slint's gettext context is the component name (`Main`, `Tr`). A new `@tr` string needs an entry in every language.
- Language = `settings.language` (`""` = system locale).
- Appearance = `settings.theme` (`""` = follow the system, `"light"`, `"dark"`). The Appearance box sets `Palette.color-scheme` in the `.slint` (`unknown` hands it back to the desktop). `THEMES` and `theme_index` in `crates/app/src/main.rs` keep the order of that list, and a test checks they agree. `Family.dark` reads the drawn background, so it stays right in every state.

## Conventions

- Rust 2024, `rustfmt` max_width 120, clippy `-D warnings`. Comments explain *why*, not what.
- Settings are serde TOML with `#[serde(default)]`; add a unit test for each new option so old files keep loading.
- Settings path: `$XDG_DATA_HOME/FastCheckup/settings.toml`; history in `history.jsonl` next to it.
- Scanners take a `Dirs` struct so tests run on temp dirs; tests never touch the real `~/.config`.
- Actions are re-checked against the disk before they write (the entry may have changed since the scan) and file names are validated (plain `*.desktop`, no `/`).
- Slint: `row` is a builtin on layouts, so a component property cannot be named `row` (use `item`). All `@tr` strings use the explicit context `"Main"`, and `gen_po.py` entries use the same.
- Update `README.md` when behaviour changes, and this file when you learn something non-obvious.

## Testing

- `cargo test`. Manual harnesses (if any) go in `dev/`, must never capture the whole screen, and must never click or type at hard-coded coordinates.
- Never `pkill -f` with a pattern that appears in your own command line; kill by PID.

### Verifying UI changes

- After any Slint UI change, build and launch the app (`cargo run`), navigate to the affected page, take a screenshot and inspect it before saying the change is done.
- Specifically check: rows don't stretch when a list has 1 item, badges and buttons are right-aligned, icons are sharp, text is selectable as a block, and empty or error states (e.g. "nothing found") don't throw errors.
- Controls in a row are the same height (32 px); tabs, search boxes and dialog cards use the kit's components (`TabBar`, `SearchBox`, the card in FastHello's `docs/UI-STYLE.md`).
- If you can't launch it (e.g. the flow needs pkexec or a live X11 session), say so explicitly and list what I should test manually.

## GitHub flow and releases

Work on branches, PRs to `master`. CI: `ci.yml` (fmt, clippy, tests, MSRV, metainfo/desktop validation), `appimage.yml` (AppImage and `.deb` on every push/PR; on a `v*` tag both attach to the release), `flatpak.yml` (bundle on every push/PR; on a `v*` tag also the signed remote and landing page on GitHub Pages; needs `flatpak/signing-key.b64` and the secret `FLATPAK_GPG_PRIVATE_KEY`, see `docs/FLATPAK-SIGNING.md`), `virustotal.yml` (scans release assets; needs the `VIRUSTOTAL_API_KEY` secret). CI also runs `cargo audit` (RustSec advisories against `Cargo.lock`), so a new advisory can fail an unrelated PR; Dependabot opens weekly cargo and github-actions updates. `RELEASING.md` has the steps. Never commit or push on the owner's behalf.

## Open items

- Storage: the scan is lazy (first visit to the page) and capped by entry count; the Stop button halts the walks between entries. Journal vacuum, Docker prune, `gio trash --empty` and cache clearing are only checked by hand; Downloads comes from `~/.config/user-dirs.dirs`. The bulk clean-up (one `pkexec /bin/sh -c`, deleting old Trash entries, the whole run) is only checked by hand, and the dialog's tick/command logic only by snapshot (`STATE=bulk0|bulk1`). Old Trash covers the home Trash only (not `/.Trash-UID` on other disks), and `DeletionDate` is read as UTC. A build folder is not re-aged when it runs: one rebuilt while the dialog was open still goes to the Trash.
- Storage lists Steam games from `libraryfolders.vdf` + `appmanifest_*.acf` (sizes are Steam's own) and old tool versions by folder mtime, not by the version in use; both are report only.
- Apps: uninstall, Trash and `flatpak uninstall --unused` are only checked by hand. The `--unused` list is read by answering `n` to flatpak's prompt; its table format was not seen with a real unused runtime, so a parse miss shows "no unused runtimes". Flatpak prints sizes with `?` for the no-break space under `LC_ALL=C`, which `parse_size` handles.
- Boot edits only `/etc/default/grub`, with `cp`/`sed`/`cmp`/`update-grub` (absolute paths) in one `pkexec /bin/sh -c` script (`boot::set_script`, one password; the preview text goes in on stdin and `cmp` checks the edited file against it before `update-grub`; on failure the script restores the backup). The script is only syntax-checked in a test; the policy has no GRUB actions, so the generic `/bin/sh` prompt applies. The pure parts are unit-tested; the real `pkexec` write is only checked by hand (set 2, restore the backup).
- Startup scan runs on the UI thread (a few small files). Storage has its own worker, so this stays until a scanner gets slow.
- Root actions run `pkexec /usr/bin/systemctl ...` directly (no helper binary); the policy in `packaging/` only improves the prompt and is installed by the `.deb` alone. `cargo deb` has not been run locally; CI is its first test.
- Security: parsers are tested on canned text only; the firewall button (`pkexec /usr/sbin/ufw status verbose`) is only checked by hand. Not covered: Flatpak/snap browsers, Chrome profiles outside `~/.config/{google-chrome,chromium,BraveSoftware}`, reverse DNS (off for privacy), `last -x` logins beyond failed ones. The Google built-in extension ID list was written from memory; check it against a real profile.
- Disk health: SMART through `pkexec smartctl` is only checked by hand; the NVMe parser is only tested on a fixture.
- Overview "Right now": CPU% is machine-wide (not per core like `top`), memory is summed RSS (not PSS), and the `verdict()` thresholds are rules of thumb never tuned on a machine under real pressure. Flatpak apps may group under `bwrap`. Sampled on every visit to page 9 via `go()`; the callback is not wired with fixtures.
- System: video decoding is the exit status of `vainfo`/`vdpauinfo` (VA-API on NVIDIA needs `nvidia-vaapi-driver`); only the default GPU is tested for OpenGL and Vulkan; memory type and speed need root (`dmidecode`) and are not shown; USB network adapters are not listed under Network; monitors come from `xrandr`, so they are empty on Wayland. "Copy all" is only checked by hand: the X11 clipboard is lost when the app quits unless a clipboard manager runs.
- Admin checks (Overview notice, `admin-state`): the real `pkexec` run is only checked by hand; the polkit prompt is the generic "run /bin/sh" (annotating `/bin/sh` would cover every `pkexec sh`). A disk whose smartctl output has no health line is skipped, not shown as failed. Not wired with fixtures (`is-root` stays false there, so the notice always shows).
- The window has only been run on X11; confirm on Wayland.
