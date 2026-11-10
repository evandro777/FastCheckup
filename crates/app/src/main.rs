use std::{
    process::Command,
    rc::Rc,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU32, Ordering::Relaxed},
    },
};

use fastcheckup_core::{
    admin::{self, Admin},
    apps,
    autostart::{self, Dirs, State},
    boot::{self, Loader, Phase as BootPhase},
    health,
    history::{self, Kind, Record},
    perf, security,
    services::{self, HintKind},
    settings::{MAX_OLD_DAYS, MIN_OLD_DAYS, Settings},
    storage,
    sysinfo::{self, Tool},
};
use slint::{Model, ModelRc, VecModel};

slint::include_modules!();

mod fixtures;
mod host;
mod instance;

/// Set by the Stop button; the Storage scan polls it.
static STORE_STOP: AtomicBool = AtomicBool::new(false);

/// The slow-changing part of the last admin run (firewall text, SMART, snapshots), reapplied after a rescan of those
/// pages. The fast part (sockets, processes) is shown once and never kept, so a later scan cannot show it as current.
static ADMIN: Mutex<Option<Admin>> = Mutex::new(None);

/// "Almost safe" means older than this many days (`settings.usage_days`, changed in Preferences). Actions re-check
/// against this value, so it is read at call time and not copied into closures.
static OLD_DAYS: AtomicU32 = AtomicU32::new(90);
/// The value the last Storage scan used, so closing Preferences rescans only when it changed.
static SCANNED_DAYS: AtomicU32 = AtomicU32::new(0);
/// `settings.allow_empty_trash`. While off, nothing here deletes from the Trash for good (action 8, old entries 18).
static ALLOW_EMPTY_TRASH: AtomicBool = AtomicBool::new(false);
/// The value the last Storage scan used (old Trash entries are only offered when on).
static SCANNED_EMPTY: AtomicBool = AtomicBool::new(false);

/// True when the lists were built for other preferences than the current ones.
fn scan_is_stale() -> bool {
    SCANNED_DAYS.load(Relaxed) != OLD_DAYS.load(Relaxed)
        || SCANNED_EMPTY.load(Relaxed) != ALLOW_EMPTY_TRASH.load(Relaxed)
}

/// What the last Storage scan offers to the bulk clean-up: `(action, id, bytes)`. Rechecked by each action when it runs.
static CANDIDATES: Mutex<Vec<(i32, String, u64)>> = Mutex::new(Vec::new());

/// The tier of a bulk action: 0 safe, 1 almost safe (old), 2 needs a look.
fn tier(action: i32) -> i32 {
    match action {
        2 | 3 | 9 | 10 | 11 | 16 => 0,
        6 | 7 | 13 | 18 => 1,
        _ => 2,
    }
}

/// Root steps run together in one `pkexec` (see `storage::run_root`).
fn is_root_step(action: i32) -> bool {
    matches!(action, 3 | 10 | 16)
}

fn main() {
    if std::env::args().skip(1).any(|a| a == "-V" || a == "--version") {
        return println!("fastcheckup {}", env!("CARGO_PKG_VERSION"));
    }
    // Fixtures (scripts/ui-snapshot.sh) never touch a real running instance.
    let fixture_run = fixtures::mode().is_some();
    // One window: a copy is already open, so it comes to the front and this one leaves before setting anything up.
    // Before `host::run`, so a second Flatpak start does not spawn another host copy.
    if !fixture_run && instance::send("show") {
        return;
    }
    // In a Flatpak this relaunches the app on the host, where the scanners see the real system. It has to come before
    // any Slint object exists. When the host cannot be reached it says why on stderr and the sandbox copy runs, with
    // a notice on Overview.
    let sandboxed = match host::run() {
        host::Outcome::Exited(code) => std::process::exit(code),
        host::Outcome::Failed => true,
        host::Outcome::NotNeeded => false,
    };
    // Forced so the 100 MB GL renderer is never pulled in by accident.
    slint::BackendSelector::new()
        .backend_name("winit".into())
        .renderer_name("software".into())
        .select()
        .expect("cannot start the Slint software renderer");

    let settings = Settings::load();
    let ui = Main::new().unwrap();
    // Take the socket now that the window exists; a later start sends "show" and this window is raised.
    if !fixture_run {
        let weak = ui.as_weak();
        let raise = move |_command: String| {
            let _ = weak.upgrade_in_event_loop(|ui| instance::raise(ui.window()));
        };
        if instance::claim("show", raise) {
            return;
        }
    }
    // Only fails when no translation matches; the source strings are English anyway.
    let _ = slint::select_bundled_translation(&language(&settings));
    ui.set_version(env!("CARGO_PKG_VERSION").into());
    ui.set_sandboxed(sandboxed);
    ui.set_lang_index(match settings.language.as_str() {
        "en" => 1,
        "pt_BR" => 2,
        _ => 0,
    });
    ui.set_theme_index(theme_index(&settings.theme));
    OLD_DAYS.store(settings.usage_days, Relaxed);
    ui.set_old_days(settings.usage_days as i32);
    ALLOW_EMPTY_TRASH.store(settings.allow_empty_trash, Relaxed);
    SCANNED_EMPTY.store(settings.allow_empty_trash, Relaxed);
    ui.set_allow_empty_trash(settings.allow_empty_trash);
    ui.on_set_allow_empty_trash(|on| {
        ALLOW_EMPTY_TRASH.store(on, Relaxed);
        let mut s = Settings::load();
        s.allow_empty_trash = on;
        s.save();
    });
    // Saved as soon as it changes, like the language; the window already shows the new mode (`theme-index`).
    ui.on_set_theme(|i| {
        let mut s = Settings::load();
        s.theme = THEMES.get(i as usize).copied().unwrap_or("").into();
        s.save();
    });
    ui.on_set_language(|i| {
        let mut s = Settings::load();
        s.language = ["", "en", "pt_BR"].get(i as usize).copied().unwrap_or("").into();
        s.save();
        // An unbundled system locale returns Err and would keep the old language; fall back to the source strings.
        let _ = slint::select_bundled_translation(&language(&s)).or_else(|_| slint::select_bundled_translation(""));
    });
    ui.on_open_url(|u| {
        // Reaped on a thread, or every click would leave a zombie in this long-lived process.
        if let Ok(mut child) = Command::new("xdg-open").arg(u.as_str()).spawn() {
            std::thread::spawn(move || _ = child.wait());
        }
    });
    ui.window()
        .set_size(slint::LogicalSize::new(settings.width as f32, settings.height as f32));

    let dirs = Rc::new(Dirs::from_env());
    // With fixtures (scripts/ui-snapshot.sh) nothing is scanned, so the real system is never read or changed.
    let fixture = fixtures::mode();
    if fixture.is_none() {
        refresh(&ui, &dirs);
    }

    // shortcut: the Startup scan reads a few small files, so it runs on the UI thread; move it to a worker when Storage lands.
    let (weak, d) = (ui.as_weak(), dirs.clone());
    ui.on_rescan(move || refresh(&weak.unwrap(), &d));

    let (weak, d) = (ui.as_weak(), dirs.clone());
    ui.on_apply(move |file, name, state| {
        let ui = weak.unwrap();
        let (result, kind) = match state {
            0 => (autostart::disable(&d, &file), Kind::Disabled),
            _ => (autostart::enable(&d, &file), Kind::Restored),
        };
        match result {
            Ok(()) => {
                history::append(&Record::now(kind, &name, &file));
                ui.set_error("".into());
            }
            Err(e) => ui.set_error(e.to_string().into()),
        }
        refresh(&ui, &d);
    });

    let (weak, d) = (ui.as_weak(), dirs.clone());
    ui.on_set_delay(move |file, secs| {
        let ui = weak.unwrap();
        // Capped so a typo cannot park an app for days.
        match autostart::set_delay(&d, &file, secs.clamp(0, 3600) as u32) {
            Ok(()) => {
                history::append(&Record::now(Kind::Delayed, &file, &file));
                ui.set_error("".into());
            }
            Err(e) => ui.set_error(e.to_string().into()),
        }
        refresh(&ui, &d);
    });

    ui.on_contains(|hay, needle| hay.to_lowercase().contains(&needle.trim().to_lowercase()));
    ui.on_edit(|path| open_in_editor(path.to_string()));
    ui.on_open_path(|path| {
        if let Some(dir) = storage::open_target(&path) {
            open_in_editor(dir.to_string_lossy().into_owned());
        }
    });
    ui.on_open_autostart(|file| {
        let path = autostart::Dirs::from_env().user.join(file.as_str());
        if !file.contains('/')
            && let Some(dir) = storage::open_target(&path.to_string_lossy())
        {
            open_in_editor(dir.to_string_lossy().into_owned());
        }
    });
    ui.on_open_folder(|kind, name| {
        if let Some(dir) = storage::folder(&apps::Dirs::from_env().home, kind, &name) {
            open_in_editor(dir.to_string_lossy().into_owned());
        }
    });

    if fixture.is_none() {
        refresh_services(&ui);
    }
    let weak = ui.as_weak();
    ui.on_svc_rescan(move || refresh_services(&weak.unwrap()));

    if fixture.is_none() {
        refresh_boot(&ui);
    }
    let weak = ui.as_weak();
    ui.on_boot_rescan(move || refresh_boot(&weak.unwrap()));
    let weak = ui.as_weak();
    ui.on_health_rescan(move || refresh_health(&weak.unwrap()));
    // Not wired with fixtures: the System page there shows canned data and must not read the real system.
    if fixture.is_none() {
        let weak = ui.as_weak();
        ui.on_sys_rescan(move || refresh_sysinfo(&weak.unwrap()));
    }
    // Not wired with fixtures: opening Overview there must not read the real system.
    if fixture.is_none() {
        let weak = ui.as_weak();
        ui.on_perf_rescan(move || refresh_perf(&weak.unwrap()));
        refresh_perf(&ui);
        let weak = ui.as_weak();
        ui.on_admin_run(move || run_admin(&weak.unwrap()));
        ui.set_is_root(admin::is_root());
    }
    let weak = ui.as_weak();
    ui.on_security_rescan(move || {
        let ui = weak.unwrap();
        // Back to user-level data, so the Overview offers the admin checks again.
        ui.set_admin_state(0);
        refresh_security(&ui, None);
    });
    let weak = ui.as_weak();
    ui.on_firewall_check(move || check_firewall(&weak.unwrap()));
    let weak = ui.as_weak();
    ui.on_smart_check(move |i, name| check_smart(&weak.unwrap(), i as usize, name.into()));

    let weak = ui.as_weak();
    ui.on_boot_preview(move |secs| {
        let ui = weak.unwrap();
        // Negative input is clamped; the core refuses anything above its limit.
        let secs = secs.max(0);
        show_plan(&ui, 0, secs, boot::plan_set(secs as u32));
    });
    let weak = ui.as_weak();
    ui.on_boot_restore_preview(move || show_plan(&weak.unwrap(), 1, 0, boot::plan_restore()));

    // pkexec blocks until the password dialog is answered, so it runs on a worker.
    let weak = ui.as_weak();
    ui.on_boot_apply(move |action, secs| {
        weak.unwrap().set_boot_busy(true);
        let weak = weak.clone();
        std::thread::spawn(move || {
            let before = boot::grub_info_here().timeout;
            let result = if action == 0 {
                boot::set_timeout(secs as u32)
            } else {
                boot::restore_backup()
            };
            if result.is_ok() {
                let (kind, name) = if action == 0 {
                    (
                        Kind::Changed,
                        format!(
                            "GRUB_TIMEOUT {} → {secs}",
                            before.map_or("(unset)".into(), |t| t.to_string())
                        ),
                    )
                } else {
                    (Kind::Restored, "GRUB_TIMEOUT backup".into())
                };
                history::append(&Record::now(kind, &name, "/etc/default/grub"));
            }
            let _ = weak.upgrade_in_event_loop(move |ui| {
                ui.set_error(result.err().map(|e| e.to_string()).unwrap_or_default().into());
                show_history(&ui);
                refresh_boot(&ui);
            });
        });
    });

    // The precheck runs commands, so it stays off the UI thread; the dialog opens when it is done.
    let weak = ui.as_weak();
    ui.on_svc_precheck(move |svc| {
        weak.unwrap().set_svc_busy(true);
        let weak = weak.clone();
        std::thread::spawn(move || {
            let check = services::precheck(&svc.unit);
            let _ = weak.upgrade_in_event_loop(move |ui| {
                ui.set_svc_busy(false);
                let check = match check {
                    Ok(c) => c,
                    Err(e) => return ui.set_error(e.to_string().into()),
                };
                let tr = ui.global::<Tr>();
                ui.set_svc_hint(match check.hint {
                    Some(h) => tr.invoke_hint(
                        match h.kind {
                            HintKind::Zfs => 0,
                            HintKind::Touchegg => 1,
                            HintKind::ModemManager => 2,
                        },
                        h.in_use,
                    ),
                    None => "".into(),
                });
                ui.set_svc_note(if check.dependents.is_empty() {
                    "".into()
                } else {
                    tr.invoke_dependents(check.dependents.join(", ").into())
                });
                ui.set_svc_now(check.dependents.is_empty());
                ui.set_svc_pending(svc);
                ui.set_svc_confirming(true);
            });
        });
    });

    // pkexec blocks until the password dialog is answered, so it runs on a worker.
    let weak = ui.as_weak();
    ui.on_svc_apply(move |unit, enable, now| {
        weak.unwrap().set_svc_busy(true);
        let weak = weak.clone();
        std::thread::spawn(move || {
            let result = if enable {
                services::enable(&unit)
            } else {
                services::disable(&unit, now)
            };
            if result.is_ok() {
                let kind = if enable { Kind::Restored } else { Kind::Disabled };
                history::append(&Record::now(kind, &unit, &unit));
            }
            let _ = weak.upgrade_in_event_loop(move |ui| {
                ui.set_error(result.err().map(|e| e.to_string()).unwrap_or_default().into());
                show_history(&ui);
                refresh_services(&ui);
            });
        });
    });

    let weak = ui.as_weak();
    ui.on_svc_run(move |unit, start| {
        weak.unwrap().set_svc_busy(true);
        let weak = weak.clone();
        std::thread::spawn(move || {
            let result = services::set_running(&unit, start);
            let _ = weak.upgrade_in_event_loop(move |ui| {
                ui.set_error(result.err().map(|e| e.to_string()).unwrap_or_default().into());
                refresh_services(&ui);
            });
        });
    });

    let months = settings.stale_months;
    if fixture.is_none() {
        refresh_apps(&ui, months);
    }
    let excluded = settings.excluded_paths.clone();
    let (weak, scan_excluded) = (ui.as_weak(), excluded.clone());
    ui.on_storage_rescan(move || refresh_storage(&weak.unwrap(), scan_excluded.clone()));
    // Saved on every step of the spin box; the lists are rebuilt once, when Preferences closes.
    ui.on_set_old_days(|n| {
        let n = (n.max(0) as u32).clamp(MIN_OLD_DAYS, MAX_OLD_DAYS);
        OLD_DAYS.store(n, Relaxed);
        let mut s = Settings::load();
        s.usage_days = n;
        s.save();
    });
    let (weak, close_excluded) = (ui.as_weak(), excluded.clone());
    ui.on_prefs_closed(move || {
        let ui = weak.unwrap();
        if ui.get_store_scanned() && !ui.get_store_busy() && scan_is_stale() {
            refresh_storage(&ui, close_excluded.clone());
        }
    });
    let (weak, plan_excluded) = (ui.as_weak(), excluded.clone());
    ui.on_bulk_plan(move |tier| {
        let ui = weak.unwrap();
        // The lists were built for another number of days (changed while a scan ran): scan again, review the fresh ones.
        if scan_is_stale() {
            return refresh_storage(&ui, plan_excluded.clone());
        }
        ui.set_app_busy(true);
        let weak = weak.clone();
        std::thread::spawn(move || {
            let rows = bulk_rows(tier);
            let _ = weak.upgrade_in_event_loop(move |ui| {
                ui.set_app_busy(false);
                ui.set_bulk_tier(tier);
                ui.set_bulk(ModelRc::new(VecModel::from(rows)));
                show_bulk(&ui);
                ui.set_bulk_confirming(true);
            });
        });
    });
    let weak = ui.as_weak();
    ui.on_bulk_toggle(move |i| {
        let ui = weak.unwrap();
        if let Some(m) = ui.get_bulk().as_any().downcast_ref::<VecModel<BulkRow>>()
            && let Some(mut r) = m.row_data(i as usize)
        {
            r.on = !r.on;
            m.set_row_data(i as usize, r);
        }
        show_bulk(&ui);
    });
    let (weak, bulk_excluded) = (ui.as_weak(), excluded.clone());
    ui.on_bulk_apply(move || {
        let ui = weak.unwrap();
        let rows: Vec<BulkRow> = ui.get_bulk().iter().filter(|r| r.on).collect();
        ui.set_bulk_confirming(false);
        ui.set_app_busy(true);
        let (weak, excluded) = (weak.clone(), bulk_excluded.clone());
        std::thread::spawn(move || {
            let errors = run_bulk(&rows);
            let _ = weak.upgrade_in_event_loop(move |ui| {
                ui.set_error(errors.into());
                show_history(&ui);
                refresh_apps(&ui, months);
                refresh_storage(&ui, excluded);
            });
        });
    });
    ui.on_storage_stop(|| STORE_STOP.store(true, Relaxed));
    let (weak, dup_excluded) = (ui.as_weak(), excluded.clone());
    ui.on_dup_find(move || {
        let ui = weak.unwrap();
        ui.set_dup_busy(true);
        STORE_STOP.store(false, Relaxed);
        let (weak, excluded) = (weak.clone(), dup_excluded.clone());
        std::thread::spawn(move || {
            let groups = storage::duplicates(&apps::Dirs::from_env().home, &excluded, &STORE_STOP);
            let rows: Vec<Left> = groups
                .into_iter()
                .flat_map(|g| {
                    let original = g[0].id.clone();
                    g.into_iter().enumerate().map(move |(i, f)| Left {
                        size_mb: mb(f.size),
                        last: date(f.newest).into(),
                        id: f.id.into(),
                        // A copy carries its original here; the original row has none.
                        path: if i == 0 { "".into() } else { original.clone().into() },
                        keep: if i == 0 { 5 } else { 0 },
                        used: "".into(),
                    })
                })
                .collect();
            let _ = weak.upgrade_in_event_loop(move |ui| {
                ui.set_dups(ModelRc::new(VecModel::from(rows)));
                ui.set_dup_scanned(true);
                ui.set_dup_busy(false);
            });
        });
    });
    let weak = ui.as_weak();
    ui.on_app_rescan(move || refresh_apps(&weak.unwrap(), months));
    let weak = ui.as_weak();
    ui.on_app_resort(move || {
        let ui = weak.unwrap();
        let mut rows: Vec<AppRow> = ui.get_apps().iter().collect();
        sort_apps(&mut rows, ui.get_app_sort(), ui.get_app_sort_flip());
        ui.set_apps(ModelRc::new(VecModel::from(rows)));
    });

    // The plan runs commands (apt-get -s, flatpak), so it stays off the UI thread; the dialog opens when it is done.
    let weak = ui.as_weak();
    ui.on_app_precheck(move |action, source, id, size_mb| {
        weak.unwrap().set_app_busy(true);
        let weak = weak.clone();
        std::thread::spawn(move || {
            let plan = app_plan(action, source, &id, size_mb);
            let _ = weak.upgrade_in_event_loop(move |ui| {
                ui.set_app_busy(false);
                let (cmd, freed, note) = match plan {
                    Ok(p) => p,
                    Err(e) => return ui.set_error(e.to_string().into()),
                };
                let tr = ui.global::<Tr>();
                ui.set_app_note(match (action, note.is_empty()) {
                    (_, true) => "".into(),
                    (2, _) => tr.invoke_runtimes(note.join(", ").into()),
                    _ => tr.invoke_also_removed(note.join(", ").into()),
                });
                ui.set_app_cmd(cmd.into());
                // Megabytes to three decimals: a few config files are only some KB.
                ui.set_app_freed(((freed / 1e3).round() / 1e3) as f32);
                ui.set_app_action(action);
                ui.set_app_source(source);
                ui.set_app_id(id);
                ui.set_app_confirming(true);
            });
        });
    });

    // pkexec blocks until the password dialog is answered, so it runs on a worker.
    let weak = ui.as_weak();
    ui.on_app_apply(move |action, source, id| {
        weak.unwrap().set_app_busy(true);
        let weak = weak.clone();
        let excluded = excluded.clone();
        std::thread::spawn(move || {
            let result = run_action(action, source, &id);
            // A duplicate's id also carries its original after a newline; only the trashed file is logged.
            let name = id.split('\n').next().unwrap_or_default().to_string();
            if result.is_ok() {
                history::append(&Record::now(Kind::Removed, &name, &name));
            }
            let ok = result.is_ok();
            let _ = weak.upgrade_in_event_loop(move |ui| {
                ui.set_error(result.err().map(|e| e.to_string()).unwrap_or_default().into());
                show_history(&ui);
                refresh_apps(&ui, months);
                if action == 17 {
                    // Not a full Storage rescan (a slow walk of $HOME): the row just leaves the list.
                    if ok {
                        drop_duplicate(&ui, &name);
                    }
                } else if action >= 6 {
                    refresh_storage(&ui, excluded);
                }
            });
        });
    });

    if let Some(mode) = fixture {
        fixtures::apply(&ui, mode);
    }
    // Opens a page directly (numbers as in `main.slint`: 0 Startup ... 8 Security, then the dashboards 9 Overview, 10 Space, 11 Safety, 12 Speed).
    if let Some(page) = std::env::var("FASTCHECKUP_PAGE").ok().and_then(|p| p.parse().ok()) {
        ui.set_page(page);
        if let Ok(state) = std::env::var("FASTCHECKUP_STATE") {
            fixtures::state(&ui, page, &state);
        }
    }
    ui.run().unwrap();
}

fn refresh(ui: &Main, dirs: &Dirs) {
    let rows: Vec<Row> = autostart::scan(dirs)
        .into_iter()
        .map(|e| Row {
            target: dirs.user.join(&e.file).to_string_lossy().into_owned().into(),
            file: e.file.into(),
            name: e.name.into(),
            comment: e.comment.into(),
            icon: icon(&e.icon),
            delay: e.delay as i32,
            exec: e.exec.into(),
            source: e.source.to_string_lossy().into_owned().into(),
            essential: e.essential,
            duplicate_of: e.duplicate_of.into(),
            state: match e.state {
                State::Enabled => 0,
                State::Disabled => 1,
            },
        })
        .collect();
    ui.set_rows(ModelRc::new(VecModel::from(rows)));
    show_history(ui);
}

fn show_history(ui: &Main) {
    let log: Vec<HistoryRow> = history::read()
        .into_iter()
        .map(|r| HistoryRow {
            time: history::utc(r.time).into(),
            kind: match r.kind {
                Kind::Disabled => 0,
                Kind::Restored => 1,
                Kind::Changed => 2,
                Kind::Removed => 3,
                Kind::Delayed => 4,
            },
            name: r.name.into(),
        })
        .collect();
    let tr = ui.global::<Tr>();
    let text: Vec<String> = log
        .iter()
        .map(|h| {
            tr.invoke_history_line(h.time.clone(), h.kind, h.name.clone())
                .to_string()
        })
        .collect();
    ui.set_history_text(text.join("\n").into());
    ui.set_history(ModelRc::new(VecModel::from(log)));
}

/// Scans off the UI thread: `systemd-analyze blame` alone takes a few hundred milliseconds.
fn refresh_services(ui: &Main) {
    ui.set_svc_busy(true);
    let weak = ui.as_weak();
    std::thread::spawn(move || {
        let rows: Vec<Svc> = services::scan()
            .into_iter()
            .map(|s| Svc {
                unit: s.unit.into(),
                description: s.description.into(),
                enabled: s.enabled,
                active: s.active,
                secs: (s.secs * 10.0).round() / 10.0,
                essential: s.essential,
                background: s.background,
            })
            .collect();
        let _ = weak.upgrade_in_event_loop(move |ui| {
            ui.set_services(ModelRc::new(VecModel::from(rows)));
            ui.set_svc_busy(false);
        });
    });
}

fn mb(b: u64) -> f32 {
    (b as f64 / 1e5).round() as f32 / 10.0
}

fn date(t: Option<u64>) -> String {
    t.map(|t| history::utc(t)[..10].to_string()).unwrap_or_default()
}

/// Scans off the UI thread: it walks $HOME for build folders and runs journalctl and docker.
/// Removes a trashed copy from the duplicates list. A group left with only its original is not a duplicate any more,
/// so that row goes too. Rows are `Left`: the original has `keep == 5`, a copy has `keep == 0`.
fn drop_duplicate(ui: &Main, copy: &str) {
    let model = ui.get_dups();
    let Some(rows) = model.as_any().downcast_ref::<VecModel<Left>>() else {
        return;
    };
    let Some(i) = rows.iter().position(|r| r.keep == 0 && r.id == copy) else {
        return;
    };
    rows.remove(i);
    let start = (0..i)
        .rev()
        .find(|&j| rows.row_data(j).is_some_and(|r| r.keep == 5))
        .unwrap_or(0);
    let copies_left = (start + 1..rows.row_count())
        .take_while(|&j| rows.row_data(j).is_some_and(|r| r.keep == 0))
        .count();
    if copies_left == 0 {
        rows.remove(start);
    }
}

/// One action of the Apps and Storage pages. `action`/`source` as in `main.slint`; shared by a single click and the bulk run.
fn run_action(action: i32, source: i32, id: &str) -> std::io::Result<()> {
    if matches!(action, 8 | 18) && !ALLOW_EMPTY_TRASH.load(Relaxed) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "emptying the Trash is off in Preferences",
        ));
    }
    let d = apps::Dirs::from_env();
    match (action, source) {
        (0, 0) => apps::uninstall_deb(id),
        (0, 1) => apps::uninstall_flatpak(id),
        (0, _) => apps::trash_appimage(&d, id),
        (1, _) => apps::trash_leftover(&d, id),
        (14, _) => apps::trash_stale_startup(id),
        (15, _) => apps::trash_home_data(&d, id),
        (2, _) => apps::remove_unused_flatpak(),
        (3, _) => apps::autoremove(),
        (5, _) => apps::remove_kernel(id),
        (6, _) => storage::trash_build(&d.home, id),
        (7, _) => storage::trash_installer(&d.home, id),
        (8, _) => storage::empty_trash(),
        (9, _) => storage::clear_cache(&d.home, id),
        (10, _) => storage::vacuum_journal(),
        (11 | 12, _) => storage::docker_prune(action == 12),
        (13, _) => storage::trash_old_version(&d.home, id),
        (16, _) => storage::apt_clean(),
        (17, _) => id
            .split_once('\n')
            .map_or(Err(std::io::Error::other("bad duplicate id")), |(copy, orig)| {
                storage::trash_duplicate(&d.home, copy, orig)
            }),
        (18, _) => storage::delete_trash_entry(&d.home, id, OLD_DAYS.load(Relaxed)),
        _ => apps::purge_residual(),
    }
}

/// The rows of the bulk dialog for a tier: what the last scan found plus the two checks that are cheap to repeat now.
fn bulk_rows(tier_: i32) -> Vec<BulkRow> {
    let mut found: Vec<(i32, String, u64)> = CANDIDATES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter(|c| tier(c.0) == tier_)
        .cloned()
        .collect();
    // What the two removals of packages and runtimes will take, so the dialog can name them.
    let (mut runtimes, mut packages, mut package_count) = (String::new(), String::new(), 0);
    if tier_ == 0 {
        if let Ok((list, freed)) = apps::unused_flatpak()
            && !list.is_empty()
        {
            runtimes = list.join(", ");
            found.push((2, "flatpak-unused".into(), freed));
        }
        let plan = apps::autoremove_plan();
        if !plan.items.is_empty() {
            (packages, package_count) = (plan.items.join(", "), plan.items.len());
            found.push((3, "apt-autoremove".into(), plan.freed));
        }
    }
    found
        .into_iter()
        .map(|(action, id, size)| {
            let cmd = match action {
                // The root steps share one line, added by `show_bulk`.
                a if is_root_step(a) => String::new(),
                2 => "flatpak uninstall --unused -y".into(),
                _ => app_plan(action, 0, &id, mb(size)).map(|p| p.0).unwrap_or_default(),
            };
            BulkRow {
                action,
                size_mb: mb(size),
                on: true,
                cmd: cmd.into(),
                detail: match action {
                    2 => runtimes.clone(),
                    3 => packages.clone(),
                    _ => String::new(),
                }
                .into(),
                name: if action == 3 {
                    package_count.to_string()
                } else {
                    short_name(action, &id)
                }
                .into(),
                id: id.into(),
            }
        })
        .collect()
}

/// A build folder (6) is shown as `project/target`, a tool version (13) by its folder name; the full path is in the
/// command line. Everything else is its own short id.
fn short_name(action: i32, id: &str) -> String {
    let keep = match action {
        6 => 2,
        13 => 1,
        _ => return id.to_string(),
    };
    let mut parts: Vec<&str> = id.rsplit('/').filter(|p| !p.is_empty()).take(keep).collect();
    parts.reverse();
    parts.join("/")
}

/// Totals and the command lines of the ticked rows. The root line is built by the function that runs it.
fn show_bulk(ui: &Main) {
    let on: Vec<BulkRow> = ui.get_bulk().iter().filter(|r| r.on).collect();
    let root: Vec<i32> = on.iter().map(|r| r.action).filter(|a| is_root_step(*a)).collect();
    let mut lines: Vec<String> = on.iter().map(|r| r.cmd.to_string()).filter(|c| !c.is_empty()).collect();
    if !root.is_empty() {
        lines.push(storage::root_command(&root));
    }
    ui.set_bulk_cmds(lines.join("\n").into());
    let tr = ui.global::<Tr>();
    let detail: Vec<String> = on
        .iter()
        .filter(|r| !r.detail.is_empty())
        .map(|r| match r.action {
            2 => tr.invoke_runtimes(r.detail.clone()),
            _ => tr.invoke_also_removed(r.detail.clone()),
        })
        .map(|s| s.to_string())
        .collect();
    ui.set_bulk_detail(detail.join("\n").into());
    ui.set_bulk_mb(on.iter().map(|r| r.size_mb).sum());
    ui.set_bulk_count(on.len() as i32);
    ui.set_bulk_root(!root.is_empty());
    ui.set_bulk_flatpak(on.iter().any(|r| r.action == 2));
}

/// Runs the ticked rows: the user-level ones one by one, then every root step in one `pkexec`. A failure does not stop
/// the rest. Returns the errors, one per line, empty when all worked.
fn run_bulk(rows: &[BulkRow]) -> String {
    let done = |id: &str| history::append(&Record::now(Kind::Removed, id, id));
    let mut errors = Vec::new();
    for r in rows.iter().filter(|r| !is_root_step(r.action)) {
        match run_action(r.action, 0, &r.id) {
            Ok(()) => done(&r.id),
            Err(e) => errors.push(format!("{}: {e}", r.id)),
        }
    }
    let mut root: Vec<i32> = rows.iter().map(|r| r.action).filter(|a| is_root_step(*a)).collect();
    // The dialog may have been open a while: autoremove never runs on a list that is empty now.
    if root.contains(&3) && apps::autoremove_plan().items.is_empty() {
        root.retain(|a| *a != 3);
    }
    if !root.is_empty() {
        for (action, result) in storage::run_root(&root) {
            let id = rows
                .iter()
                .find(|r| r.action == action)
                .map_or(String::new(), |r| r.id.to_string());
            match result {
                Ok(()) => done(&id),
                Err(e) => errors.push(format!("{id}: {e}")),
            }
        }
    }
    errors.join("\n")
}

fn refresh_storage(ui: &Main, excluded: Vec<String>) {
    ui.set_store_busy(true);
    STORE_STOP.store(false, Relaxed);
    let days = OLD_DAYS.load(Relaxed);
    SCANNED_DAYS.store(days, Relaxed);
    let allow_empty = ALLOW_EMPTY_TRASH.load(Relaxed);
    SCANNED_EMPTY.store(allow_empty, Relaxed);
    let weak = ui.as_weak();
    std::thread::spawn(move || {
        let scan = storage::scan(&apps::Dirs::from_env().home, days, &excluded, &STORE_STOP);
        // Build folders not touched for `days` are "almost safe"; the rest are looked at one by one.
        let cutoff = storage::cutoff(days);
        let (old_builds, builds): (Vec<_>, Vec<_>) = scan
            .builds
            .into_iter()
            .partition(|b| b.newest.is_some_and(|n| n <= cutoff));
        let mut found: Vec<(i32, String, u64)> = Vec::new();
        found.extend(scan.caches.iter().map(|i| (9, i.id.clone(), i.size)));
        found.extend(old_builds.iter().map(|i| (6, i.id.clone(), i.size)));
        found.extend(scan.installers.iter().map(|i| (7, i.id.clone(), i.size)));
        if allow_empty {
            found.extend(scan.old_trash.iter().map(|i| (18, i.id.clone(), i.size)));
        }
        found.extend(
            scan.old_versions
                .iter()
                .filter(|v| v.keep == storage::Keep::No)
                .map(|v| (13, v.item.path.clone(), v.item.size)),
        );
        // Same limits as the single buttons on the page.
        if scan.journal > 105_000_000 {
            found.push((10, "journal".into(), scan.journal.saturating_sub(storage::JOURNAL_KEEP)));
        }
        if scan.apt_cache > 1_000_000 {
            found.push((16, "apt-cache".into(), scan.apt_cache));
        }
        if let Some(r) = scan.docker.iter().find(|r| r.kind == "Build Cache")
            && r.reclaimable_bytes > 0
        {
            found.push((11, "docker-builder".into(), r.reclaimable_bytes));
        }
        // What each tab's bulk clean-up would free (Flatpak runtimes and autoremove are added live by the page).
        let tier_bytes = |t: i32| found.iter().filter(|c| tier(c.0) == t).map(|c| c.2).sum::<u64>();
        let (safe_mb, almost_mb) = (mb(tier_bytes(0)), mb(tier_bytes(1)));
        *CANDIDATES.lock().unwrap_or_else(|e| e.into_inner()) = found;
        let left = |(i, keep, used): (storage::Item, storage::Keep, String)| Left {
            size_mb: mb(i.size),
            last: date(i.newest).into(),
            id: i.id.into(),
            path: i.path.into(),
            keep: keep as i32,
            used: used.into(),
        };
        let rows = move |items: Vec<storage::Item>| {
            ModelRc::new(VecModel::from(
                items
                    .into_iter()
                    .map(|i| left((i, storage::Keep::No, String::new())))
                    .collect::<Vec<_>>(),
            ))
        };
        let versions: Vec<Left> = scan
            .old_versions
            .into_iter()
            .map(|v| left((v.item, v.keep, v.games.join(", "))))
            .collect();
        let gb = |b: u64| (b as f64 / 1e8).round() as f32 / 10.0;
        let mut mounts: Vec<Mnt> = scan
            .mounts
            .into_iter()
            .map(|m| Mnt {
                pct: (m.used * 100 / m.total) as i32,
                used_gb: gb(m.used),
                total_gb: gb(m.total),
                path: m.path.into(),
            })
            .collect();
        // Fullest first, so the disk that needs attention is on top and a short list can hide the rest.
        mounts.sort_by_key(|m| (std::cmp::Reverse(m.pct), m.path.to_lowercase()));
        let docker: Vec<Dock> = scan
            .docker
            .into_iter()
            .map(|d| Dock {
                kind: d.kind.into(),
                size: d.size.into(),
                reclaim: d.reclaimable.into(),
            })
            .collect();
        let _ = weak.upgrade_in_event_loop(move |ui| {
            ui.set_mounts(ModelRc::new(VecModel::from(mounts)));
            ui.set_top_folders(rows(scan.folders));
            ui.set_big_files(rows(scan.big_files));
            ui.set_games(rows(scan.games));
            ui.set_old_versions(ModelRc::new(VecModel::from(versions)));
            ui.set_builds(rows(builds));
            ui.set_old_builds(rows(old_builds));
            ui.set_old_trash(rows(scan.old_trash));
            ui.set_safe_scan_mb(safe_mb);
            ui.set_almost_free_mb(almost_mb);
            ui.set_installers(rows(scan.installers));
            ui.set_caches(rows(scan.caches));
            ui.set_docker(ModelRc::new(VecModel::from(docker)));
            ui.set_trash_count(scan.trash_count as i32);
            ui.set_trash_mb(mb(scan.trash_size));
            ui.set_journal_mb(mb(scan.journal));
            ui.set_apt_mb(mb(scan.apt_cache));
            ui.set_snap_count(scan.snapshots.len() as i32);
            ui.set_snap_oldest(
                scan.snapshots
                    .first()
                    .map(|s| s.split('_').next().unwrap_or(s).to_string())
                    .unwrap_or_default()
                    .into(),
            );
            ui.set_snap_set_up(scan.timeshift);
            apply_admin(&ui);
            set_totals(&ui);
            ui.set_store_busy(false);
            ui.set_store_ago(0);
        });
    });
}

/// `mode`: 0 size (protected software last, as the scanner orders it), 1 name, 2 last activity (newest first,
/// unknown dates at the end). `flip` reverses the order (oldest first, smallest first, Z to A); unknown dates and
/// protected software stay last. Stable, so ties keep the previous order.
fn sort_apps(rows: &mut [AppRow], mode: i32, flip: bool) {
    let name = |r: &AppRow| r.name.to_lowercase();
    match mode {
        1 => {
            rows.sort_by_key(name);
            if flip {
                rows.reverse();
            }
        }
        // "YYYY-MM-DD" sorts as text; "" (unknown) must come after every date.
        2 => rows.sort_by(|a, b| {
            let ord = a.last.cmp(&b.last);
            let ord = if flip { ord } else { ord.reverse() };
            a.last.is_empty().cmp(&b.last.is_empty()).then(ord)
        }),
        _ => rows.sort_by(|a, b| {
            let ord = b.size_mb.total_cmp(&a.size_mb);
            let ord = if flip { ord.reverse() } else { ord };
            a.essential
                .cmp(&b.essential)
                .then(ord)
                .then_with(|| name(a).cmp(&name(b)))
        }),
    }
}

/// Scans off the UI thread: it runs dpkg-query and flatpak and walks the apps' data folders.
fn refresh_apps(ui: &Main, months: u32) {
    ui.set_app_busy(true);
    let weak = ui.as_weak();
    std::thread::spawn(move || {
        let dirs = apps::Dirs::from_env();
        let scan = apps::scan(&dirs, months);
        // A `slint::Image` is not `Send`: find the files here, decode them on the UI thread.
        let found: Vec<_> = scan
            .apps
            .into_iter()
            .map(|a| {
                let path = icon_path(&a.icon);
                (a, path)
            })
            .collect();
        let left: Vec<Left> = scan
            .leftovers
            .into_iter()
            .map(|l| Left {
                size_mb: mb(l.size),
                last: date(l.last_activity).into(),
                id: l.id.into(),
                path: "".into(),
                keep: 0,
                used: "".into(),
            })
            .collect();
        let home_data: Vec<Left> = scan
            .home_data
            .into_iter()
            .map(|l| Left {
                size_mb: mb(l.size),
                last: date(l.last_activity).into(),
                path: apps::home_data_path(&dirs, &l.id)
                    .map_or_else(String::new, |p| p.to_string_lossy().into_owned())
                    .into(),
                id: l.id.into(),
                ..Left::default()
            })
            .collect();
        let stale: Vec<Left> = autostart::stale(&autostart::Dirs::from_env())
            .into_iter()
            .map(|e| Left {
                id: e.file.into(),
                used: e.name.into(),
                path: e.exec.into(),
                ..Left::default()
            })
            .collect();
        let (runtimes, autoremove, residual) = (scan.runtimes, scan.autoremove, scan.residual);
        let kernels: Vec<Kern> = scan
            .kernels
            .into_iter()
            .map(|k| Kern {
                size_mb: mb(k.size),
                running: k.running,
                keep: k.keep,
                version: k.version.into(),
            })
            .collect();
        let _ = weak.upgrade_in_event_loop(move |ui| {
            let mut rows: Vec<AppRow> = found
                .into_iter()
                .map(|(a, path)| AppRow {
                    icon: load_icon(path),
                    source: a.source as i32,
                    size_mb: mb(a.size),
                    last: date(a.last_activity).into(),
                    group_count: a.group_count as i32,
                    group: a.group,
                    manual: a.manual,
                    essential: a.essential,
                    stale: a.stale,
                    name: a.name.into(),
                    id: a.id.into(),
                })
                .collect();
            sort_apps(&mut rows, ui.get_app_sort(), ui.get_app_sort_flip());
            ui.set_rt_list(runtimes.items.join(", ").into());
            ui.set_rt_mb(mb(runtimes.freed));
            ui.set_auto_list(autoremove.items.join(", ").into());
            ui.set_auto_mb(mb(autoremove.freed));
            ui.set_res_list(residual.items.join(", ").into());
            // Config files are small, so keep three decimals for the KB label.
            ui.set_res_mb(residual.freed as f32 / 1e6);
            ui.set_kernels(ModelRc::new(VecModel::from(kernels)));
            ui.set_apps(ModelRc::new(VecModel::from(rows)));
            ui.set_leftovers(ModelRc::new(VecModel::from(left)));
            ui.set_stale_startup(ModelRc::new(VecModel::from(stale)));
            ui.set_home_data(ModelRc::new(VecModel::from(home_data)));
            set_totals(&ui);
            ui.set_app_busy(false);
        });
    });
}

/// `(command shown to the user, bytes freed, extra things removed)`. `action`/`source` as in `main.slint`.
fn app_plan(action: i32, source: i32, id: &str, size_mb: f32) -> std::io::Result<(String, f64, Vec<String>)> {
    let d = apps::Dirs::from_env();
    let size = f64::from(size_mb) * 1e6;
    Ok(match (action, source) {
        (0, 0) => {
            let plan = apps::precheck_deb(id)?;
            let also = plan.removes.into_iter().filter(|r| r != id).collect();
            (format!("pkexec apt-get remove -y {id}"), plan.freed as f64, also)
        }
        (0, 1) => (format!("flatpak uninstall -y {id}"), size, vec![]),
        (0, _) => (format!("gio trash -- {}", d.appimages.join(id).display()), size, vec![]),
        (1, _) => (
            format!("gio trash -- {}", d.home.join(".var/app").join(id).display()),
            size,
            vec![],
        ),
        (15, _) => (
            format!(
                "gio trash -- {}",
                apps::home_data_path(&d, id).unwrap_or_default().display()
            ),
            size,
            vec![],
        ),
        (14, _) => (
            format!("gio trash -- {}", autostart::Dirs::from_env().user.join(id).display()),
            0.0,
            vec![],
        ),
        (2, _) => {
            let (list, freed) = apps::unused_flatpak()?;
            if list.is_empty() {
                return Err(std::io::Error::other("no unused runtimes found, scan again"));
            }
            ("flatpak uninstall --unused -y".into(), freed as f64, list)
        }
        (3, _) => {
            let list = apps::autoremove_plan();
            ("pkexec apt-get autoremove -y".into(), list.freed as f64, list.items)
        }
        (6 | 13, _) => (format!("gio trash -- {id}"), size, vec![]),
        (7, _) => (
            format!("gio trash -- {}", storage::downloads(&d.home).join(id).display()),
            size,
            vec![],
        ),
        (18, _) => (storage::trash_entry_command(&d.home, id), size, vec![]),
        (8, _) => ("gio trash --empty".into(), size, vec![]),
        (9, _) => (
            format!("rm -r {}", d.home.join(".cache").join(id).display()),
            size,
            vec![],
        ),
        (10, _) => (
            "pkexec journalctl --vacuum-size=100M".into(),
            storage::journal_usage().saturating_sub(storage::JOURNAL_KEEP) as f64,
            vec![],
        ),
        (11, _) => {
            let cache = storage::docker_usage().into_iter().find(|r| r.kind == "Build Cache");
            (
                "docker builder prune -f".into(),
                cache.map_or(0, |r| r.reclaimable_bytes) as f64,
                vec![],
            )
        }
        (12, _) => ("docker system prune -f".into(), 0.0, vec![]),
        (16, _) => ("pkexec apt-get clean".into(), storage::apt_cache_bytes() as f64, vec![]),
        // The id is "copy\noriginal"; the dialog shows the copy only.
        (17, _) => (
            format!("gio trash -- {}", id.split('\n').next().unwrap_or_default()),
            size,
            vec![],
        ),
        (5, _) => {
            let (kernel, plan) = apps::kernel_plan(id)?;
            let also = plan
                .removes
                .into_iter()
                .filter(|r| !kernel.packages.contains(r))
                .collect();
            (
                format!("pkexec apt-get remove -y {}", kernel.packages.join(" ")),
                plan.freed as f64,
                also,
            )
        }
        _ => {
            let plan = apps::residual_plan();
            (
                "pkexec apt-get purge -y ".to_string() + &plan.items.join(" "),
                plan.freed as f64,
                plan.items,
            )
        }
    })
}

fn show_plan(ui: &Main, action: i32, secs: i32, plan: std::io::Result<boot::Plan>) {
    match plan {
        Ok(p) => {
            ui.set_error("".into());
            ui.set_boot_action(action);
            ui.set_boot_secs(secs);
            ui.set_boot_diff(p.diff.into());
            ui.set_boot_cmds(p.commands.into());
            ui.set_boot_confirming(true);
        }
        Err(e) => ui.set_error(e.to_string().into()),
    }
}

fn set_disk(ui: &Main, i: usize, f: impl FnOnce(&mut Disk)) {
    if let Some(m) = ui.get_disks().as_any().downcast_ref::<VecModel<Disk>>()
        && let Some(mut d) = m.row_data(i)
    {
        f(&mut d);
        m.set_row_data(i, d);
    }
}

/// SMART goes through `pkexec`, so it runs on a thread while the password dialog is open.
fn check_smart(ui: &Main, i: usize, name: String) {
    set_disk(ui, i, |d| d.state = 4);
    let weak = ui.as_weak();
    std::thread::spawn(move || {
        let r = health::smart(&name);
        let _ = weak.upgrade_in_event_loop(move |ui| {
            set_disk(&ui, i, |d| match r {
                Ok(s) => apply_smart(d, &s),
                Err(e) => (d.state, d.error) = (3, e.to_string().into()),
            });
        });
    });
}

fn apply_smart(d: &mut Disk, s: &health::Smart) {
    d.state = if s.passed { 1 } else { 2 };
    (d.reallocated, d.pending, d.uncorrectable, d.crc) = (
        s.reallocated as i32,
        s.pending as i32,
        s.uncorrectable as i32,
        s.crc as i32,
    );
    d.nvme = s.used.is_some();
    (d.used, d.spare) = (s.used.unwrap_or(0) as i32, s.spare.map_or(-1, |v| v as i32));
}

/// One password prompt for everything that needs root (see `core::admin`); runs on a worker while the dialog is open.
fn run_admin(ui: &Main) {
    ui.set_admin_state(1);
    let weak = ui.as_weak();
    std::thread::spawn(move || {
        let r = admin::run();
        let _ = weak.upgrade_in_event_loop(move |ui| match r {
            Ok(a) => {
                *ADMIN.lock().unwrap_or_else(|e| e.into_inner()) = Some(a.clone());
                ui.set_admin_state(2);
                // Else the first visit to Safety would rescan as the user and drop these findings.
                ui.set_security_scanned(true);
                apply_admin(&ui);
                refresh_security(&ui, Some(a));
            }
            Err(e) => {
                ui.set_admin_error(e.to_string().into());
                ui.set_admin_state(3);
            }
        });
    });
}

/// Puts the kept root data (firewall, SMART, Timeshift) on the pages. Called after an admin run and after the scans
/// that would overwrite it.
fn apply_admin(ui: &Main) {
    let guard = ADMIN.lock().unwrap_or_else(|e| e.into_inner());
    let Some(a) = guard.as_ref() else { return };
    if !a.ufw.is_empty() {
        ui.set_fw_state(2);
        ui.set_fw_text(a.ufw.as_str().into());
    }
    for (name, text) in &a.smart {
        if let Some(i) = ui.get_disks().iter().position(|d| d.name == name.as_str()) {
            set_disk(ui, i, |d| apply_smart(d, &health::parse_smart(text)));
        }
    }
    if let (Some(oldest), Some(newest)) = (a.snapshots.first(), a.snapshots.last()) {
        ui.set_snap_count(a.snapshots.len() as i32);
        ui.set_snap_oldest(oldest.split('_').next().unwrap_or(oldest).into());
        ui.set_snap_set_up(true);
        ui.set_backup_state(2);
        ui.set_backup_latest(newest.as_str().into());
    }
}

// The sample takes about a second, so it runs on a worker.
fn refresh_perf(ui: &Main) {
    ui.set_perf_busy(true);
    let weak = ui.as_weak();
    std::thread::spawn(move || {
        let s = perf::snapshot();
        let _ = weak.upgrade_in_event_loop(move |ui| {
            ui.set_perf_level(s.level);
            ui.set_perf_cause(s.cause);
            ui.set_perf_uptime_s(s.uptime_s as i32);
            ui.set_perf_cpus(s.cpus as i32);
            ui.set_perf_load(s.load1);
            ui.set_perf_mem_total_mb(s.mem_total_mb);
            ui.set_perf_mem_avail_mb(s.mem_avail_mb);
            ui.set_perf_swap_total_mb(s.swap_total_mb);
            ui.set_perf_swap_used_mb(s.swap_used_mb);
            let apps: Vec<PerfApp> = s
                .apps
                .iter()
                .map(|a| PerfApp {
                    name: a.name.as_str().into(),
                    procs: a.procs as i32,
                    cpu: a.cpu_pct,
                    mem_mb: a.mem_mb,
                })
                .collect();
            ui.set_perf_apps(ModelRc::new(VecModel::from(apps)));
            ui.set_perf_busy(false);
        });
    });
}

fn refresh_sysinfo(ui: &Main) {
    ui.set_sys_busy(true);
    let weak = ui.as_weak();
    std::thread::spawn(move || {
        // glxinfo, vulkaninfo and vainfo each take a few hundred milliseconds.
        let info = sysinfo::scan(std::path::Path::new("/"));
        let _ = weak.upgrade_in_event_loop(move |ui| {
            show_sysinfo(&ui, &info);
            ui.set_sys_busy(false);
        });
    });
}

/// Turns the scan into cards and the "Copy all" text. The words come from `Tr`; this only picks and joins.
fn show_sysinfo(ui: &Main, i: &sysinfo::Info) {
    let tr = ui.global::<Tr>();
    let text =
        |code: i32, a: &str, b: &str, c: &str| tr.invoke_sys_text(code, a.into(), b.into(), c.into()).to_string();
    let label = |code: i32| tr.invoke_sys_label(code).to_string();
    let tool = |t: &Tool, package: &str| match t {
        Tool::Missing => text(11, package, "", ""),
        Tool::On(d) if d.is_empty() => text(5, "", "", ""),
        Tool::On(d) => text(8, d, "", ""),
        Tool::Off(d) if d.is_empty() => text(9, "", "", ""),
        Tool::Off(d) => text(10, d, "", ""),
    };
    type Rows = Vec<(String, String)>;
    // Rows with no value are left out; a card with no rows says "None found".
    let rows = |list: &[(i32, String)]| -> Rows {
        list.iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(l, v)| (label(*l), v.clone()))
            .collect()
    };
    let lines = |list: Vec<String>| -> Rows { list.into_iter().map(|v| (String::new(), v)).collect() };
    let mut groups: Vec<(String, Rows)> = Vec::new();
    let mut group = |title: String, r: Rows| {
        let r = if r.is_empty() {
            vec![(String::new(), text(16, "", "", ""))]
        } else {
            r
        };
        groups.push((title, r));
    };
    let ghz = format!("{:.1}", f64::from(i.cpu_mhz) / 1000.0);
    let (cores, threads) = (i.cores.to_string(), i.threads.to_string());
    let cpu = match (i.cpu.is_empty(), i.cpu_mhz) {
        (true, _) => String::new(),
        (false, 0) => text(15, &i.cpu, &text(0, &cores, &threads, ""), ""),
        (false, _) => text(15, &i.cpu, &text(1, &cores, &threads, &ghz), ""),
    };
    let gb = if i.mem_mb == 0 {
        String::new()
    } else {
        text(2, &format!("{:.1}", i.mem_mb as f64 / 1024.0), "", "")
    };
    let swap = match (i.mem_mb, i.swap_mb) {
        (0, _) => String::new(),
        (_, 0) => text(20, "", "", ""),
        _ => {
            let size = text(2, &format!("{:.1}", i.swap_mb as f64 / 1024.0), "", "");
            match i.swap_devs.is_empty() {
                true => size,
                false => text(15, &size, &i.swap_devs.join(", "), ""),
            }
        }
    };
    let (d, h, m) = (
        i.uptime_secs / 86400,
        i.uptime_secs % 86400 / 3600,
        i.uptime_secs % 3600 / 60,
    );
    let uptime = match (i.uptime_secs, d, h) {
        (0, ..) => String::new(),
        (_, 0, 0) => text(17, &m.to_string(), "", ""),
        (_, 0, _) => text(18, &h.to_string(), &m.to_string(), ""),
        _ => text(19, &d.to_string(), &h.to_string(), &m.to_string()),
    };
    group(
        tr.invoke_sys_group(0).to_string(),
        rows(&[
            (0, i.computer.clone()),
            (22, i.hostname.clone()),
            (1, i.os.clone()),
            (2, i.kernel.clone()),
            (23, uptime),
            (3, cpu),
            (4, gb),
            (24, swap),
            (5, i.desktop.clone()),
            (6, i.session.clone()),
        ]),
    );
    // Legacy BIOS has no Secure Boot; the row is left out rather than saying "Unknown".
    let secure = match i.secure_boot {
        _ if !i.uefi => String::new(),
        Some(true) => text(5, "", "", ""),
        Some(false) => text(6, "", "", ""),
        None => text(7, "", "", ""),
    };
    group(
        tr.invoke_sys_group(1).to_string(),
        rows(&[
            (7, i.bios_vendor.clone()),
            (8, i.bios_version.clone()),
            (9, i.bios_release.clone()),
            (10, i.bios_date.clone()),
            (11, text(if i.uefi { 3 } else { 4 }, "", "", "")),
            (12, secure),
        ]),
    );
    group(
        tr.invoke_sys_group(2).to_string(),
        rows(&[
            (7, i.board_vendor.clone()),
            (13, i.board_name.clone()),
            (8, i.board_version.clone()),
        ]),
    );
    if i.gpus.is_empty() {
        group(tr.invoke_sys_group(3).to_string(), Vec::new());
    }
    for g in &i.gpus {
        // No driver bound means nothing to say about its version.
        let version = match (g.version.is_empty(), g.driver.is_empty()) {
            (false, _) => g.version.clone(),
            (true, false) => text(12, "", "", ""),
            (true, true) => String::new(),
        };
        group(
            g.name.clone(),
            rows(&[
                (14, g.pci.clone()),
                (15, g.driver.clone()),
                (16, version),
                (
                    25,
                    match g.vram_mb {
                        0 => String::new(),
                        mb => text(2, &format!("{:.1}", mb as f64 / 1024.0), "", ""),
                    },
                ),
            ]),
        );
    }
    group(
        tr.invoke_sys_group(4).to_string(),
        vec![
            (label(17), tool(&i.opengl, "mesa-utils")),
            (label(18), tool(&i.opengl_es, "mesa-utils")),
            (label(19), tool(&i.vulkan, "vulkan-tools")),
            (label(20), tool(&i.vaapi, "vainfo")),
            (label(21), tool(&i.vdpau, "vdpauinfo")),
        ],
    );
    group(
        tr.invoke_sys_group(5).to_string(),
        lines(
            i.disks
                .iter()
                .map(|d| match d.tran.is_empty() {
                    true => text(15, &d.model, &d.size, ""),
                    false => text(14, &d.model, &d.size, &d.tran),
                })
                .collect(),
        ),
    );
    group(tr.invoke_sys_group(6).to_string(), lines(i.usb.clone()));
    group(
        tr.invoke_sys_group(7).to_string(),
        // A connected output that is switched off has no current mode.
        lines(
            i.monitors
                .iter()
                .map(|m| {
                    if m.mode.is_empty() {
                        m.output.clone()
                    } else {
                        text(13, &m.output, &m.mode, &m.hz)
                    }
                })
                .collect(),
        ),
    );
    group(tr.invoke_sys_group(8).to_string(), lines(i.audio.clone()));
    group(
        tr.invoke_sys_group(9).to_string(),
        lines(
            i.network
                .iter()
                .map(|(n, iface)| {
                    if iface.is_empty() {
                        n.clone()
                    } else {
                        text(15, n, iface, "")
                    }
                })
                .collect(),
        ),
    );
    // Report only: the fix is a command to copy, never run by the app. A low value is flagged only when a program
    // that needs more is installed, so a plain desktop sees just the numbers.
    let fix = |key: &str, min: u64, file: &str| {
        format!("echo '{key}={min}' | sudo tee /etc/sysctl.d/{file} && sudo sysctl --system")
    };
    let watches = match i.max_watches {
        0 => String::new(),
        n if n < sysinfo::WATCHES_MIN && !i.big_watchers.is_empty() => text(
            21,
            &n.to_string(),
            &i.big_watchers.join(", "),
            &fix(
                "fs.inotify.max_user_watches",
                sysinfo::WATCHES_MIN,
                "60-fastcheckup-watches.conf",
            ),
        ),
        n => n.to_string(),
    };
    let maps = match i.max_maps {
        0 => String::new(),
        n if n < sysinfo::MAPS_MIN && i.steam => text(
            22,
            &n.to_string(),
            &fix("vm.max_map_count", sysinfo::MAPS_MIN, "60-fastcheckup-maps.conf"),
            "",
        ),
        n => n.to_string(),
    };
    group(tr.invoke_sys_group(10).to_string(), rows(&[(26, watches), (27, maps)]));
    let report = groups
        .iter()
        .map(|(title, rows)| {
            let body: Vec<String> = rows
                .iter()
                .map(|(l, v)| {
                    if l.is_empty() {
                        format!("  {v}")
                    } else {
                        format!("  {l}: {v}")
                    }
                })
                .collect();
            format!("{title}\n{}", body.join("\n"))
        })
        .collect::<Vec<_>>()
        .join("\n\n");
    let model: Vec<SysGroup> = groups
        .into_iter()
        .map(|(title, rows)| SysGroup {
            title: title.into(),
            rows: ModelRc::new(VecModel::from(
                rows.into_iter()
                    .map(|(l, v)| SysRow {
                        label: l.into(),
                        value: v.into(),
                    })
                    .collect::<Vec<_>>(),
            )),
        })
        .collect();
    ui.set_sys_groups(ModelRc::new(VecModel::from(model)));
    ui.set_sys_report(report.into());
}

fn refresh_health(ui: &Main) {
    ui.set_health_busy(true);
    let weak = ui.as_weak();
    std::thread::spawn(move || {
        let h = health::scan();
        let _ = weak.upgrade_in_event_loop(move |ui| {
            ui.set_disk_warning(h.problems);
            let tr = ui.global::<Tr>();
            let err_line = |e: &health::KernelError| {
                tr.invoke_error_line(e.device.as_str().into(), e.count as i32, e.line.as_str().into())
                    .to_string()
            };
            let part_line = |p: &health::Part| {
                let label = if p.label.is_empty() { &p.name } else { &p.label };
                tr.invoke_part_line(
                    p.state,
                    label.as_str().into(),
                    p.size.as_str().into(),
                    p.mount.as_str().into(),
                )
                .to_string()
            };
            let mut other: Vec<String> = h.errors.iter().map(err_line).collect();
            other.extend(
                h.failed_mounts
                    .iter()
                    .map(|m| tr.invoke_failed_mount_line(m.as_str().into()).to_string()),
            );
            ui.set_other_problems(other.join("\n").into());
            ui.set_backup_state(h.backup.0);
            ui.set_backup_latest(h.backup.1.as_str().into());
            ui.set_crashes(h.crashes.iter().take(5).cloned().collect::<Vec<_>>().join("\n").into());
            show_memory(&ui, &h.memory, !h.crashes.is_empty());
            let disks: Vec<Disk> = h
                .disks
                .iter()
                .map(|d| {
                    let (failed, fine): (Vec<_>, Vec<_>) = d.parts.iter().partition(|p| p.state == 1);
                    let mut problems: Vec<String> = failed.into_iter().map(part_line).collect();
                    problems.extend(d.errors.iter().map(err_line));
                    Disk {
                        name: d.name.as_str().into(),
                        model: d.model.as_str().into(),
                        size: d.size.as_str().into(),
                        kind: d.kind,
                        parts: fine.len() as i32,
                        info: fine.into_iter().map(part_line).collect::<Vec<_>>().join("\n").into(),
                        problems: problems.join("\n").into(),
                        ..Disk::default()
                    }
                })
                .collect();
            ui.set_disks(ModelRc::new(VecModel::from(disks)));
            apply_admin(&ui);
            ui.set_health_busy(false);
            ui.set_health_ago(0);
        });
    });
}

/// Report only: the fix is a command to copy. It becomes a warning (and lifts the Speed dot) only with a freeze or an
/// out-of-memory kill on record; `crashed` is any unclean shutdown in `last -x`, which may have another cause.
pub fn show_memory(ui: &Main, m: &health::Memory, crashed: bool) {
    let tr = ui.global::<Tr>();
    let line = |code: i32, a: &str| tr.invoke_memory_line(code, a.into()).to_string();
    let mut lines = vec![
        match m.swap.is_empty() {
            true => line(1, ""),
            false => line(0, &m.swap.join(", ")),
        },
        match m.watcher.is_empty() {
            true => line(3, ""),
            false => line(2, &m.watcher),
        },
    ];
    if m.oom_kills > 0 {
        lines.push(line(4, &m.oom_kills.to_string()));
    }
    let warning = m.unprotected() && (crashed || m.oom_kills > 0);
    if m.unprotected() {
        lines.push(line(5, "sudo apt install earlyoom"));
    }
    ui.set_mem_text(lines.join("\n").into());
    ui.set_mem_warning(warning);
}

// pkexec blocks until the password dialog is answered, so it runs on a worker.
fn check_firewall(ui: &Main) {
    ui.set_fw_state(1);
    let weak = ui.as_weak();
    std::thread::spawn(move || {
        let r = security::firewall_rules();
        let _ = weak.upgrade_in_event_loop(move |ui| {
            ui.set_fw_state(if r.is_ok() { 2 } else { 3 });
            ui.set_fw_text(r.unwrap_or_else(|e| e.to_string()).into());
        });
    });
}

/// The figures the dashboards show, read back from the lists the scans filled. The sizes of the Safe and Almost safe
/// tiers are not here: they come from the same list as the bulk dialog (`CANDIDATES`, see `refresh_storage`), so the
/// tile and the dialog agree.
pub fn set_totals(ui: &Main) {
    ui.set_fullest_pct(ui.get_mounts().iter().map(|m| m.pct).max().unwrap_or(0));
}

/// Sets the findings, worst first, and the per-level counts for the tiles.
/// Topic of a finding `code` (see `core::security::Finding`), as an index for `Tr.finding-group`:
/// 0 network, 1 programs running, 2 starts by itself, 3 accounts, 4 browser add-ons, 5 updates.
fn finding_group(code: i32) -> i32 {
    match code {
        0 | 1 | 10 => 0,
        2 | 3 => 1,
        4 | 5 | 7 => 2,
        6 | 9 => 3,
        11..=14 => 5,
        _ => 4,
    }
}

fn set_findings(ui: &Main, mut findings: Vec<Finding>) {
    for f in &mut findings {
        f.group = finding_group(f.code);
    }
    findings.sort_by_key(|f| std::cmp::Reverse(f.level));
    let count = |level| findings.iter().filter(|f| f.level == level).count() as i32;
    ui.set_sec_suspicious(count(2));
    ui.set_sec_look(count(1));
    ui.set_sec_info(count(0));
    // The dashboard shows the worst three whatever their topic.
    ui.set_top_findings(ModelRc::new(VecModel::from(
        findings.iter().take(3).cloned().collect::<Vec<_>>(),
    )));
    // The page groups by topic: the topic with the worst finding first, worst first inside it. The sort is stable.
    let worst = |g: i32| findings.iter().filter(|f| f.group == g).map(|f| f.level).max();
    let order: Vec<_> = (0..6).map(|g| (std::cmp::Reverse(worst(g)), g)).collect();
    // Inside a topic, rows without an application come first (the firewall), then one run per application, the one
    // with the worst finding first. The sort is stable, so each run stays worst first.
    let app_worst = |f: &Finding| {
        findings
            .iter()
            .filter(|o| o.group == f.group && o.app == f.app)
            .map(|o| o.level)
            .max()
    };
    let mut keyed: Vec<_> = findings
        .iter()
        .map(|f| {
            let app = f.app.to_string();
            let key = (
                order[f.group as usize],
                !app.is_empty(),
                std::cmp::Reverse(app_worst(f)),
                app,
            );
            (key, f.clone())
        })
        .collect();
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    findings = keyed.into_iter().map(|(_, f)| f).collect();
    let per_group: Vec<Vec<Finding>> = (0..6)
        .map(|g| findings.iter().filter(|f| f.group == g).cloned().collect())
        .collect();
    ui.set_fw_off(findings.iter().any(|f| f.code == 10));
    // Network always shows: it holds the firewall check.
    let mut ranked = order.clone();
    ranked.sort();
    let shown: Vec<i32> = ranked
        .iter()
        .map(|o| o.1)
        .filter(|&g| g == 0 || !per_group[g as usize].is_empty())
        .collect();
    ui.set_shown_groups(ModelRc::new(VecModel::from(shown)));
    ui.set_group_findings(ModelRc::new(VecModel::from(
        per_group
            .into_iter()
            .map(|v| ModelRc::new(VecModel::from(v)))
            .collect::<Vec<_>>(),
    )));
    ui.set_findings(ModelRc::new(VecModel::from(findings)));
}

fn refresh_security(ui: &Main, admin: Option<Admin>) {
    ui.set_security_busy(true);
    let weak = ui.as_weak();
    std::thread::spawn(move || {
        let s = security::scan(admin.as_ref());
        let _ = weak.upgrade_in_event_loop(move |ui| {
            let findings: Vec<Finding> = s
                .findings
                .into_iter()
                .map(|f| {
                    // The application a finding belongs to: the program of an open port (`extra`, `n` = pid) or of
                    // connections (`subject`), or the browser of an add-on (`n` indexes it). Rows sharing it are
                    // grouped under one header.
                    let (app, icon_name) = match f.code {
                        0 => (f.extra.as_str(), f.extra.as_str()),
                        1 => (f.subject.as_str(), f.subject.as_str()),
                        8 => security::BROWSERS.get(f.n as usize).map_or(("", ""), |b| (b.1, b.2)),
                        _ => ("", ""),
                    };
                    // A browser's connections (process `firefox`) and its add-ons share one group, named like the browser.
                    let (app, icon_name) = security::BROWSERS
                        .iter()
                        .find(|b| {
                            [b.1, b.2, b.2.trim_start_matches("google-")]
                                .iter()
                                // Firefox's process is `firefox-bin`.
                                .any(|k| k.eq_ignore_ascii_case(app.trim_end_matches("-bin")))
                        })
                        .map_or((app, icon_name), |b| (b.1, b.2));
                    Finding {
                        icon: icon(icon_name),
                        app: app.into(),
                        path: if f.code == 0 {
                            admin
                                .as_ref()
                                .and_then(|a| a.procs.iter().find(|p| p.0 == f.n).map(|p| p.1.clone()))
                                .unwrap_or_else(|| security::exe_of(f.n))
                                .into()
                        } else {
                            "".into()
                        },
                        code: f.code,
                        level: f.level,
                        subject: f.subject.clone().into(),
                        extra: f.extra.clone().into(),
                        n: f.n,
                        group: 0,
                    }
                })
                .collect();
            // Connections carry no pid: the header takes the path found for the same program's open ports.
            let paths: std::collections::HashMap<_, _> = findings
                .iter()
                .filter(|f| !f.path.is_empty())
                .map(|f| (f.app.clone(), f.path.clone()))
                .collect();
            let findings = findings
                .into_iter()
                .map(|mut f| {
                    if let Some(p) = paths.get(&f.app).filter(|_| f.code == 1) {
                        f.path = p.clone();
                    }
                    f
                })
                .collect();
            let tools: Vec<SecTool> = s
                .tools
                .iter()
                .map(|t| SecTool {
                    name: t.name.into(),
                    cmd: t.cmd.into(),
                    installed: t.installed,
                })
                .collect();
            set_findings(&ui, findings);
            ui.set_sec_tools(ModelRc::new(VecModel::from(tools)));
            ui.set_security_busy(false);
            ui.set_security_ago(0);
        });
    });
}

/// Reads the boot data off the UI thread: `systemd-analyze` and `efibootmgr` take a few hundred milliseconds.
fn refresh_boot(ui: &Main) {
    ui.set_boot_busy(true);
    let weak = ui.as_weak();
    std::thread::spawn(move || {
        let (b, chain, g, bios) = (
            boot::breakdown(),
            boot::critical_chain(),
            boot::grub_info_here(),
            boot::bios_info(std::path::Path::new("/")),
        );
        let unhealthy = health::scan();
        let warning = unhealthy.problems;
        let slowest = chain.iter().map(|l| l.took).fold(0.0, f32::max);
        let round = |s: f32| (s * 10.0).round() / 10.0;
        // Units on the chain often take tens of milliseconds, which one decimal would show as 0.1 or 0.0.
        let round2 = |s: f32| (s * 100.0).round() / 100.0;
        let phases: Vec<Phase> = b
            .parts
            .iter()
            .map(|&(p, secs)| Phase {
                kind: match p {
                    BootPhase::Firmware => 0,
                    BootPhase::Loader => 1,
                    BootPhase::Kernel => 2,
                    BootPhase::Initrd => 3,
                    BootPhase::Userspace => 4,
                },
                secs: round(secs),
            })
            .collect();
        let links: Vec<Link> = chain
            .into_iter()
            .map(|l| Link {
                frac: if slowest > 0.0 { l.took / slowest } else { 0.0 },
                slowest: slowest > 0.0 && l.took == slowest,
                at: round2(l.at),
                took: round2(l.took),
                optional: l.optional,
                mount: l.unit.ends_with(".mount"),
                unit: l.unit.into(),
            })
            .collect();
        let grub = Grub {
            loader: match g.loader {
                Loader::Grub => 0,
                Loader::SystemdBoot => 1,
                Loader::Unknown => 2,
            },
            efi: g.efi,
            timeout: g.timeout.map_or(-1, |t| t as i32),
            style: g.style.into(),
            overridden: g.overridden_by.join(", ").into(),
            windows: g.windows_entry,
            has_backup: g.backup.is_some(),
        };
        let board = format!("{} {} (BIOS {})", bios.vendor, bios.name, bios.version);
        let _ = weak.upgrade_in_event_loop(move |ui| {
            ui.set_boot_total(round(b.total));
            ui.set_phases(ModelRc::new(VecModel::from(phases)));
            ui.set_chain(ModelRc::new(VecModel::from(links)));
            ui.set_grub(grub);
            ui.set_bios_board(board.into());
            ui.set_disk_warning(warning);
            ui.set_boot_busy(false);
        });
    });
}

/// Opens `path` with the system default. `gtk-launch` opened an extra empty tab in xed; `xdg-open` does not.
/// shortcut: relies on the `.desktop` mime type opening an editor, which holds on Mint but is not checked elsewhere.
fn open_in_editor(path: String) {
    // On a thread so `status()` can reap the child without blocking the UI.
    std::thread::spawn(move || Command::new("xdg-open").arg(path).status());
}

/// Finds a PNG for a `.desktop` `Icon=` value. PNGs are preferred because they decode cheaper than SVGs.
fn icon(name: &str) -> slint::Image {
    load_icon(icon_path(name))
}

fn load_icon(path: Option<std::path::PathBuf>) -> slint::Image {
    path.and_then(|p| {
        // Slint decodes path images lazily and prints an error at render time, so a file it cannot decode is
        // never handed over by path: no extension (AppImage integrators, normcap) is sniffed from the bytes.
        if p.extension().is_some() {
            slint::Image::load_from_path(&p).ok()
        } else {
            slint::Image::load_from_data(&std::fs::read(&p).ok()?, None).ok()
        }
    })
    .unwrap_or_default()
}

fn icon_path(name: &str) -> Option<std::path::PathBuf> {
    let path = std::path::Path::new(name);
    // A missing file or an .xpm (Slint cannot decode it; xsensors points at one it does not ship) falls back to the
    // theme icon of the same name.
    let usable = path.is_file() && path.extension().is_none_or(|e| e != "xpm");
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or_default();
    let name = if path.is_absolute() && !usable { stem } else { name };
    if path.is_absolute() && usable {
        Some(path.to_path_buf())
    } else if name.is_empty() || name.contains('/') {
        None
    } else {
        // The active theme is not known without a settings daemon, so any installed theme will do.
        let home = std::env::var("HOME").unwrap_or_default();
        // Flatpak apps (like Sunshine) export their icons into their own hicolor tree, outside /usr/share/icons.
        let roots = [
            format!("{home}/.local/share/icons"),
            "/usr/share/icons".into(),
            format!("{home}/.local/share/flatpak/exports/share/icons"),
            "/var/lib/flatpak/exports/share/icons".into(),
        ];
        let mut themes: Vec<_> = roots
            .iter()
            .filter_map(|r| std::fs::read_dir(r).ok())
            .flat_map(|d| d.flatten().map(|e| e.path()))
            .collect();
        // read_dir order is arbitrary; sort so the same icon is picked every run, hicolor (the standard fallback) first.
        themes.sort_by_key(|t| (!t.ends_with("hicolor"), t.clone()));
        // Theme layouts differ (`48x48/apps`, `48/apps`, `apps/48`, `scalable/apps`); `status` and `devices` hold tray and hardware icons.
        let sizes = ["48", "32", "64", "24", "22", "16", "128", "256"];
        // PNG before SVG: it decodes cheaper. shortcut: first theme with a match wins, not the active one.
        ["png", "svg"]
            .iter()
            .flat_map(|ext| {
                themes.iter().flat_map(move |t| {
                    ["apps", "status", "devices"].into_iter().flat_map(move |ctx| {
                        let scalable = t.join(format!("scalable/{ctx}/{name}.{ext}"));
                        sizes
                            .into_iter()
                            .flat_map(move |s| {
                                [
                                    t.join(format!("{s}x{s}/{ctx}/{name}.{ext}")),
                                    t.join(format!("{s}/{ctx}/{name}.{ext}")),
                                    t.join(format!("{ctx}/{s}/{name}.{ext}")),
                                ]
                            })
                            .chain([scalable])
                    })
                })
            })
            .chain(["png", "svg"].map(|ext| format!("/usr/share/pixmaps/{name}.{ext}").into()))
            .find(|p| p.is_file())
    }
}

/// `settings.theme` for each entry of the Appearance list: system, light, dark.
const THEMES: [&str; 3] = ["", "light", "dark"];

/// The Appearance list index of a `settings.theme` value; anything unknown follows the system.
fn theme_index(theme: &str) -> i32 {
    THEMES.iter().position(|t| *t == theme).unwrap_or(0) as i32
}

/// `settings.language`, or the system locale (`LC_ALL`/`LC_MESSAGES`/`LANGUAGE`/`LANG`, minus `.UTF-8`).
fn language(settings: &Settings) -> String {
    if !settings.language.is_empty() {
        return settings.language.clone();
    }
    ["LC_ALL", "LC_MESSAGES", "LANGUAGE", "LANG"]
        .iter()
        .filter_map(|v| std::env::var(v).ok())
        .find(|v| !v.is_empty())
        .map(|v| v.split(['.', ':']).next().unwrap_or("").to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{THEMES, short_name, theme_index, tier};

    #[test]
    fn bulk_names_are_short_and_every_bulk_action_has_a_tier() {
        assert_eq!(short_name(6, "/home/u/dev/app/target"), "app/target");
        assert_eq!(short_name(13, "/home/u/.steam/tools/GE-Proton8-1/"), "GE-Proton8-1");
        assert_eq!(short_name(9, "mozilla"), "mozilla");
        // 8 (empty the whole Trash), 12 (Docker prune) and the per-item pages are never offered in bulk.
        assert!([2, 3, 9, 10, 11, 16].iter().all(|a| tier(*a) == 0));
        assert!([6, 7, 13, 18].iter().all(|a| tier(*a) == 1));
        assert!([0, 1, 5, 8, 12, 14, 15, 17].iter().all(|a| tier(*a) == 2));
    }

    #[test]
    fn themes_and_their_indexes_agree() {
        for (i, t) in THEMES.iter().enumerate() {
            assert_eq!(theme_index(t), i as i32);
        }
        assert_eq!(theme_index("bogus"), 0);
    }
}
