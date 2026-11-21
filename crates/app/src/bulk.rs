//! What a click deletes: the one `run_action` over the action codes (as in `main.slint`), the tiers of the bulk
//! clean-up and the bulk dialog's rows. Kept apart from the window wiring so a change here is easy to review.
use std::sync::{Mutex, atomic::Ordering::Relaxed};

use fastcheckup_core::{
    apps,
    history::{self, Kind, Record},
    storage,
};
use slint::{ComponentHandle, Model};

use crate::{ADMIN, ALLOW_EMPTY_TRASH, BulkRow, Main, OLD_DAYS, Tr, app_plan, mb};

/// What the last Storage scan offers to the bulk clean-up: `(action, id, bytes)`. Rechecked by each action when it runs.
pub(crate) static CANDIDATES: Mutex<Vec<(i32, String, u64)>> = Mutex::new(Vec::new());

/// The packages the open dialog says apt will remove (autoremove, a package, an old kernel). The run compares the
/// live list with it, so apt never removes something the user did not see. One dialog is open at a time, so one slot
/// is enough.
static REMOVAL_SHOWN: Mutex<Vec<String>> = Mutex::new(Vec::new());

pub(crate) fn removal_shown(items: &[String]) {
    *REMOVAL_SHOWN.lock().unwrap_or_else(|e| e.into_inner()) = items.to_vec();
}

fn removal_unchanged(live: &[String]) -> std::io::Result<()> {
    if live == *REMOVAL_SHOWN.lock().unwrap_or_else(|e| e.into_inner()) {
        Ok(())
    } else {
        Err(std::io::Error::other("the list of packages changed, scan again"))
    }
}

fn autoremove_unchanged() -> std::io::Result<()> {
    removal_unchanged(&apps::autoremove_plan().items)
}

/// The tier of a bulk action: 0 safe, 1 almost safe (old), 2 needs a look.
pub(crate) fn tier(action: i32) -> i32 {
    match action {
        2 | 3 | 9 | 10 | 11 | 16 | 21 | 22 | 23 | 24 | 26 => 0,
        6 | 7 | 13 | 18 | 25 => 1,
        _ => 2,
    }
}

/// Root steps run together in one `pkexec` (see `storage::run_root`).
fn is_root_step(action: i32) -> bool {
    matches!(action, 3 | 10 | 16 | 22 | 24)
}

/// One action of the Apps and Storage pages. `action`/`source` as in `main.slint`; shared by a single click and the bulk run.
pub(crate) fn run_action(action: i32, source: i32, id: &str) -> std::io::Result<()> {
    if matches!(action, 8 | 18) && !ALLOW_EMPTY_TRASH.load(Relaxed) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "emptying the Trash is off in Preferences",
        ));
    }
    let d = apps::Dirs::from_env();
    match (action, source) {
        (0, 0) => apps::precheck_deb(id)
            .and_then(|p| removal_unchanged(&p.removes))
            .and_then(|()| apps::uninstall_deb(id)),
        (0, 1) => apps::uninstall_flatpak(id),
        // Report only: no package to remove, and it must never fall through to the AppImage Trash.
        (0, 3) => Err(std::io::Error::other(
            "not installed from a package, use its own uninstaller",
        )),
        (0, _) => apps::trash_appimage(&d, id),
        (1, _) => apps::trash_leftover(&d, id),
        (14, _) => apps::trash_stale_startup(id),
        (15, _) => apps::trash_home_data(&d, id),
        (2, _) => apps::remove_unused_flatpak(),
        (3, _) => autoremove_unchanged().and_then(|()| apps::autoremove()),
        (4, _) => apps::purge_residual(),
        (5, _) => apps::kernel_plan(id)
            .and_then(|(_, p)| removal_unchanged(&p.removes))
            .and_then(|()| apps::remove_kernel(id)),
        (6, _) => storage::trash_build(&d.home, id),
        (7, _) => storage::trash_installer(&d.home, id),
        (8, _) => storage::empty_trash(),
        (9, _) => storage::clear_cache(&d.home, id),
        (21, _) => storage::clear_pycaches(&d.home, id),
        (23, _) => storage::browsers::clear(&d.home, id),
        (25, _) => storage::cargo::clear(&d.home, id),
        (26, _) => storage::flatpak::clear(&d.home, id),
        (10, _) => storage::vacuum_journal(),
        (22, _) => storage::clear_coredumps(),
        (24, _) => storage::clear_rotated_logs(),
        (11 | 12, _) => storage::docker_prune(action == 12),
        (13, _) => storage::trash_old_version(&d.home, id),
        (16, _) => storage::apt_clean(),
        (17, _) => id
            .split_once('\n')
            .map_or(Err(std::io::Error::other("bad duplicate id")), |(copy, orig)| {
                storage::trash_duplicate(&d.home, copy, orig)
            }),
        (18, _) => storage::delete_trash_entry(&d.home, id, OLD_DAYS.load(Relaxed)),
        (20, _) => storage::trash_steam_leftover(&d.home, id),
        (19, _) => storage::delete_snapshot(id).inspect(|()| {
            // Kept admin data would bring the row back on the next rescan.
            if let Some(a) = ADMIN.lock().unwrap_or_else(|e| e.into_inner()).as_mut() {
                a.snapshots.retain(|n| n != id);
            }
        }),
        _ => Err(std::io::Error::other("unknown action")),
    }
}

/// The rows of the bulk dialog for a tier: what the last scan found plus the two checks that are cheap to repeat now.
pub(crate) fn bulk_rows(tier_: i32) -> Vec<BulkRow> {
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
            removal_shown(&plan.items);
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
pub(crate) fn short_name(action: i32, id: &str) -> String {
    let keep = match action {
        6 | 21 => 2,
        13 => 1,
        _ => return id.to_string(),
    };
    let mut parts: Vec<&str> = id.rsplit('/').filter(|p| !p.is_empty()).take(keep).collect();
    parts.reverse();
    parts.join("/")
}

/// Totals and the command lines of the ticked rows. The root line is built by the function that runs it.
pub(crate) fn show_bulk(ui: &Main) {
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
pub(crate) fn run_bulk(rows: &[BulkRow]) -> String {
    let done = |id: &str| history::append(&Record::now(Kind::Removed, id, id));
    let mut errors = Vec::new();
    for r in rows.iter().filter(|r| !is_root_step(r.action)) {
        match run_action(r.action, 0, &r.id) {
            Ok(()) => done(&r.id),
            Err(e) => errors.push(format!("{}: {e}", r.id)),
        }
    }
    let mut root: Vec<i32> = rows.iter().map(|r| r.action).filter(|a| is_root_step(*a)).collect();
    // The dialog may have been open a while: autoremove never runs on a list other than the one it showed.
    if root.contains(&3)
        && let Err(e) = autoremove_unchanged()
    {
        root.retain(|a| *a != 3);
        errors.push(format!("apt-autoremove: {e}"));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bulk_names_are_short_and_every_bulk_action_has_a_tier() {
        assert_eq!(short_name(6, "/home/u/dev/app/target"), "app/target");
        assert_eq!(short_name(13, "/home/u/.steam/tools/GE-Proton8-1/"), "GE-Proton8-1");
        assert_eq!(short_name(9, "mozilla"), "mozilla");
        // 8 (empty the whole Trash), 12 (Docker prune) and the per-item pages are never offered in bulk.
        assert!([2, 3, 9, 10, 11, 16, 21, 22, 23, 24, 26].iter().all(|a| tier(*a) == 0));
        assert!([6, 7, 13, 18, 25].iter().all(|a| tier(*a) == 1));
        assert!([0, 1, 4, 5, 8, 12, 14, 15, 17, 19].iter().all(|a| tier(*a) == 2));
    }

    #[test]
    fn only_the_root_steps_share_the_script_and_unknown_actions_run_nothing() {
        let root: Vec<i32> = (0..30).filter(|a| is_root_step(*a)).collect();
        assert_eq!(root, [3, 10, 16, 22, 24]);
        // The old catch-all arm purged packages as root.
        assert!(run_action(99, 0, "").is_err_and(|e| e.to_string() == "unknown action"));
    }
}
