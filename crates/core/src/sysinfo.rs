//! System page data: machine, firmware, CPU, memory, GPUs, hardware acceleration and connected devices. Report only,
//! no root. Parsers take text so tests run on canned output; `scan` reads `root` (`/` for real) and runs the tools.
use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::{health, perf};

/// Result of one acceleration check.
#[derive(Debug, Default, Clone, PartialEq)]
pub enum Tool {
    /// The program that tests it is not installed.
    #[default]
    Missing,
    /// Works; the text is a version or device name (may be empty).
    On(String),
    /// Installed but reports no hardware support.
    Off(String),
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Gpu {
    /// `Vendor Device`, e.g. `NVIDIA Corporation AD104 [GeForce RTX 4070 SUPER]`.
    pub name: String,
    /// `10de:2783`.
    pub pci: String,
    pub driver: String,
    /// Empty when the driver ships with the kernel and says nothing more.
    pub version: String,
    /// Dedicated video memory in MB; 0 when unknown (integrated GPUs share system RAM).
    pub vram_mb: u64,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Monitor {
    pub output: String,
    pub mode: String,
    pub hz: String,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct DiskLine {
    pub model: String,
    pub size: String,
    pub tran: String,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Info {
    pub computer: String,
    pub os: String,
    pub kernel: String,
    pub cpu: String,
    pub cores: u32,
    pub threads: u32,
    pub cpu_mhz: u32,
    pub mem_mb: u64,
    /// 0 when no swap is configured.
    pub swap_mb: u64,
    /// `/swapfile`, `/dev/zram0`...
    pub swap_devs: Vec<String>,
    pub hostname: String,
    pub uptime_secs: u64,
    pub desktop: String,
    pub session: String,
    pub bios_vendor: String,
    pub bios_version: String,
    pub bios_release: String,
    pub bios_date: String,
    pub board_vendor: String,
    pub board_name: String,
    pub board_version: String,
    pub uefi: bool,
    /// `None`: not readable (legacy boot or no efivars).
    pub secure_boot: Option<bool>,
    pub gpus: Vec<Gpu>,
    pub opengl: Tool,
    pub opengl_es: Tool,
    pub vulkan: Tool,
    pub vaapi: Tool,
    pub vdpau: Tool,
    pub disks: Vec<DiskLine>,
    pub usb: Vec<String>,
    pub monitors: Vec<Monitor>,
    pub audio: Vec<String>,
    /// `(name, interface)`.
    pub network: Vec<(String, String)>,
    /// `fs.inotify.max_user_watches`; 0 when unreadable.
    pub max_watches: u64,
    /// `vm.max_map_count`; 0 when unreadable.
    pub max_maps: u64,
    /// Installed programs that watch many folders (Dropbox, Insync, editors).
    pub big_watchers: Vec<String>,
    pub steam: bool,
}

/// Below these a big watcher or a game fails without saying why. 524288 is the usual advice for Dropbox and IDEs;
/// 1048576 is the Debian/Mint default for maps and what Proton games ask for.
pub const WATCHES_MIN: u64 = 524_288;
pub const MAPS_MIN: u64 = 1_048_576;

/// Program in PATH → name shown. shortcut: PATH only, so Flatpak/snap installs are not seen; add them if asked.
const WATCHERS: [(&str, &str); 5] = [
    ("dropbox", "Dropbox"),
    ("insync", "Insync"),
    ("syncthing", "Syncthing"),
    ("code", "VS Code"),
    ("codium", "VSCodium"),
];

fn in_path(program: &str) -> bool {
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path).any(|d| d.join(program).is_file())
}

/// `None` when the program is not installed; otherwise `(exit ok, stdout)`. `LC_ALL=C` so the labels we parse are English.
/// Killed after 5 s: a broken GPU driver can make `vulkaninfo` or `vainfo` hang, and the page would stay busy forever.
fn cmd(program: &str, args: &[&str]) -> Option<(bool, String)> {
    let mut child = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    // Drained on its own thread so a full pipe cannot block the child.
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        buf
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    let ok = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.success(),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break false;
            }
        }
    };
    let bytes = reader.join().unwrap_or_default();
    Some((ok, String::from_utf8_lossy(&bytes).into_owned()))
}

fn read(root: &Path, rel: &str) -> String {
    fs::read_to_string(root.join(rel))
        .unwrap_or_default()
        .trim()
        .to_string()
}

pub fn parse_os_release(text: &str) -> String {
    text.lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
        .map(|v| v.trim_matches('"').to_string())
        .unwrap_or_default()
}

/// `(model name, cores, threads)`. `cpu cores` is per socket, so a dual-socket machine shows half its cores.
pub fn parse_cpuinfo(text: &str) -> (String, u32, u32) {
    let (mut name, mut cores, mut threads) = (String::new(), 0, 0);
    for l in text.lines() {
        let Some((k, v)) = l.split_once(':') else { continue };
        let v = v.trim();
        match k.trim() {
            "model name" if name.is_empty() => name = v.to_string(),
            "cpu cores" if cores == 0 => cores = v.parse().unwrap_or(0),
            "processor" => threads += 1,
            _ => {}
        }
    }
    (name, cores.max(u32::from(threads > 0)), threads)
}

pub struct Pci {
    pub slot: String,
    pub class: String,
    pub name: String,
    pub id: String,
}

/// `lspci -mmnn`: `slot "class [cccc]" "vendor [vvvv]" "device [dddd]" ...`. Brackets that end a field hold the hex id.
pub fn parse_lspci(text: &str) -> Vec<Pci> {
    fn split_id(s: &str) -> (String, String) {
        match s.trim().rsplit_once(" [") {
            Some((name, id)) if id.ends_with(']') => (name.to_string(), id.trim_end_matches(']').to_string()),
            _ => (s.trim().to_string(), String::new()),
        }
    }
    text.lines()
        .filter_map(|l| {
            let slot = l.split_whitespace().next()?;
            let q: Vec<&str> = l.split('"').collect();
            let (class, cid) = split_id(q.get(1)?);
            let (vendor, vid) = split_id(q.get(3)?);
            let (device, did) = split_id(q.get(5)?);
            Some(Pci {
                slot: slot.into(),
                class: format!("{class}|{cid}"),
                name: format!("{vendor} {device}"),
                id: format!("{vid}:{did}"),
            })
        })
        .collect()
}

fn class_code(p: &Pci) -> &str {
    p.class.rsplit('|').next().unwrap_or("")
}

/// Real devices only: the `1d6b` Linux Foundation root hubs are not peripherals.
pub fn parse_lsusb(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| {
            let rest = l.split_once(" ID ")?.1;
            let (id, name) = rest.split_once(' ')?;
            (!id.starts_with("1d6b:")).then(|| name.trim().to_string())
        })
        .collect()
}

/// Connected outputs with the current mode (`*`).
pub fn parse_xrandr(text: &str) -> Vec<Monitor> {
    let mut out: Vec<Monitor> = Vec::new();
    let mut open = false;
    for l in text.lines() {
        if !l.starts_with(' ') {
            open = l.contains(" connected");
            if open {
                out.push(Monitor {
                    output: l.split_whitespace().next().unwrap_or("").into(),
                    ..Monitor::default()
                });
            }
        } else if open && let Some(m) = out.last_mut() {
            let mut c = l.split_whitespace();
            let mode = c.next().unwrap_or("");
            if let Some(rate) = c.find(|r| r.contains('*')) {
                m.mode = mode.into();
                m.hz = rate.trim_matches(|ch| ch == '*' || ch == '+').into();
                open = false;
            }
        }
    }
    out
}

/// Long names of the sound cards (`/proc/asound/cards` lines `N [id]: driver - Long name`).
pub fn parse_asound(text: &str) -> Vec<String> {
    text.lines()
        .filter(|l| l.trim_start().starts_with(|c: char| c.is_ascii_digit()))
        .filter_map(|l| l.split_once(" - ").map(|(_, n)| n.trim().to_string()))
        .collect()
}

#[derive(Debug, Default, PartialEq)]
pub struct Gl {
    pub direct: bool,
    pub renderer: String,
    pub core: String,
    pub es: String,
    pub mesa: String,
    /// `GL_NVX_gpu_memory_info` (NVIDIA) or Mesa's `Video memory`; of the GPU that renders, in MB.
    pub vram_mb: u64,
}

/// First column of `/proc/swaps` after the header.
pub fn parse_swaps(text: &str) -> Vec<String> {
    text.lines()
        .skip(1)
        .filter_map(|l| l.split_whitespace().next().map(String::from))
        .collect()
}

pub fn parse_uptime(text: &str) -> u64 {
    text.split_whitespace()
        .next()
        .and_then(|s| s.split('.').next())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

pub fn parse_glxinfo(text: &str) -> Gl {
    let mut g = Gl::default();
    let mut full = String::new();
    for l in text.lines() {
        let Some((k, v)) = l.split_once(':') else { continue };
        let v = v.trim();
        match k.trim() {
            "direct rendering" => g.direct = v == "Yes",
            "OpenGL renderer string" => g.renderer = v.into(),
            "OpenGL core profile version string" => g.core = v.into(),
            "OpenGL ES profile version string" => g.es = v.into(),
            "Dedicated video memory" | "Video memory" => {
                let n = v.trim_end_matches("MB").trim_end_matches(' ');
                g.vram_mb = g.vram_mb.max(n.parse().unwrap_or(0));
            }
            "OpenGL version string" => {
                g.mesa = v.split_once("Mesa ").map(|m| m.1.into()).unwrap_or_default();
                full = v.into();
            }
            _ => {}
        }
    }
    // Old drivers and VMs print no core profile line.
    if g.core.is_empty() {
        g.core = full;
    }
    g
}

fn software(renderer: &str) -> bool {
    let r = renderer.to_lowercase();
    ["llvmpipe", "softpipe", "swrast"].iter().any(|s| r.contains(s))
}

/// First `deviceName` that is not a software rasteriser; `Err` carries the software one (or nothing).
pub fn parse_vulkan(text: &str) -> Result<String, String> {
    let names: Vec<&str> = text
        .lines()
        .filter_map(|l| l.trim().strip_prefix("deviceName"))
        .filter_map(|v| v.split_once('=').map(|x| x.1.trim()))
        .collect();
    names
        .iter()
        .find(|n| !software(n))
        .map(|n| n.to_string())
        .ok_or_else(|| names.first().unwrap_or(&"").to_string())
}

/// 5th byte of the `SecureBoot-*` EFI variable (the first four are attributes).
pub fn parse_secure_boot(bytes: &[u8]) -> Option<bool> {
    bytes.get(4).map(|b| *b == 1)
}

fn value_after<'a>(text: &'a str, key: &str) -> &'a str {
    text.lines()
        .find_map(|l| l.split_once(key).map(|x| x.1.trim()))
        .unwrap_or("")
}

fn tool_from(run: Option<(bool, String)>, detail: impl Fn(&str) -> String) -> Tool {
    match run {
        None => Tool::Missing,
        Some((true, out)) => Tool::On(detail(&out)),
        Some((false, out)) => Tool::Off(detail(&out)),
    }
}

fn max_cpu_mhz(root: &Path) -> u32 {
    let Ok(dir) = fs::read_dir(root.join("sys/devices/system/cpu")) else {
        return 0;
    };
    dir.flatten()
        .filter_map(|e| fs::read_to_string(e.path().join("cpufreq/cpuinfo_max_freq")).ok())
        .filter_map(|s| s.trim().parse::<u32>().ok())
        .max()
        .map_or(0, |khz| khz / 1000)
}

/// The interface (`enp5s0`) whose `device` link points at PCI slot `slot`.
fn net_iface(root: &Path, slot: &str) -> String {
    let Ok(dir) = fs::read_dir(root.join("sys/class/net")) else {
        return String::new();
    };
    dir.flatten()
        .find(|e| {
            fs::read_link(e.path().join("device"))
                .is_ok_and(|t| t.file_name().is_some_and(|n| n.to_string_lossy().ends_with(slot)))
        })
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn driver_of(root: &Path, slot: &str) -> String {
    // lspci prints the domain only when it is not 0000.
    let full = if slot.matches(':').count() == 1 {
        format!("0000:{slot}")
    } else {
        slot.to_string()
    };
    fs::read_link(root.join("sys/bus/pci/devices").join(full).join("driver"))
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_default()
}

pub fn scan(root: &Path) -> Info {
    let dmi = |f: &str| read(root, &format!("sys/class/dmi/id/{f}"));
    let (cpu, cores, threads) = parse_cpuinfo(&fs::read_to_string(root.join("proc/cpuinfo")).unwrap_or_default());
    // Mint reports `X-Cinnamon`; the prefix only marks a non-standard desktop name.
    let desktop = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
    let desktop = desktop.trim_start_matches("X-").to_string();
    let desktop = match desktop
        .to_lowercase()
        .contains("cinnamon")
        .then(|| cmd("cinnamon", &["--version"]))
    {
        Some(Some((true, v))) => format!("{desktop} {}", v.split_whitespace().last().unwrap_or("")),
        _ => desktop,
    };
    let computer = match (dmi("sys_vendor"), dmi("product_name")) {
        (v, p) if v.is_empty() || p.is_empty() => format!("{} {}", dmi("board_vendor"), dmi("board_name")),
        (v, p) => format!("{v} {p}"),
    };
    let gl = cmd("glxinfo", &["-B"]);
    let glx = gl.as_ref().map(|g| parse_glxinfo(&g.1));
    let lspci = cmd("lspci", &["-mmnn"]).map(|r| parse_lspci(&r.1)).unwrap_or_default();
    let mut gpus: Vec<Gpu> = lspci
        .iter()
        .filter(|p| class_code(p).starts_with("03"))
        .map(|p| {
            let driver = driver_of(root, &p.slot);
            let mut version = if driver.is_empty() {
                String::new()
            } else {
                read(root, &format!("sys/module/{driver}/version"))
            };
            // One Mesa install serves every Mesa driver; `mesa` is empty when GL runs on NVIDIA's own driver.
            if version.is_empty() && ["amdgpu", "radeon", "i915", "xe", "nouveau"].contains(&driver.as_str()) {
                version = glx.as_ref().map_or(String::new(), |g| g.mesa.clone());
            }
            Gpu {
                name: p.name.clone(),
                pci: p.id.clone(),
                driver,
                version,
                // amdgpu reports it per card in bytes.
                vram_mb: read(
                    root,
                    &format!("sys/bus/pci/devices/0000:{}/mem_info_vram_total", p.slot),
                )
                .parse::<u64>()
                .map_or(0, |b| b >> 20),
            }
        })
        .collect();
    // glxinfo describes only the GPU that renders, so it fills a gap only when exactly one GPU has no figure.
    let gl_vram = glx.as_ref().map_or(0, |g| g.vram_mb);
    if gl_vram > 0
        && gpus.iter().filter(|g| g.vram_mb == 0).count() == 1
        && let Some(g) = gpus.iter_mut().find(|g| g.vram_mb == 0)
    {
        g.vram_mb = gl_vram;
    }
    let (gl_on, gl_name) = glx
        .as_ref()
        .map_or((false, ""), |g| (g.direct && !software(&g.renderer), &g.renderer[..]));
    let gl_tool = |version: &dyn Fn(&Gl) -> String| match &glx {
        None => Tool::Missing,
        Some(g) if gl_on && !version(g).is_empty() => Tool::On(version(g)),
        Some(g) => Tool::Off(if gl_name.is_empty() { version(g) } else { gl_name.into() }),
    };
    let vulkan = match cmd("vulkaninfo", &["--summary"]) {
        None => Tool::Missing,
        Some((_, out)) => match parse_vulkan(&out) {
            Ok(n) => Tool::On(n),
            Err(n) => Tool::Off(n),
        },
    };
    let disks = cmd("lsblk", &["-d", "-n", "-P", "-o", "NAME,TYPE,SIZE,MODEL,TRAN"])
        .map(|r| {
            r.1.lines()
                .map(health::pairs)
                .filter(|d| d.get("TYPE").is_some_and(|t| t == "disk") && !d["NAME"].starts_with("zram"))
                .map(|d| DiskLine {
                    model: d
                        .get("MODEL")
                        .filter(|m| !m.trim().is_empty())
                        .unwrap_or(&d["NAME"])
                        .trim()
                        .into(),
                    size: d.get("SIZE").cloned().unwrap_or_default(),
                    tran: d.get("TRAN").cloned().unwrap_or_default(),
                })
                .collect()
        })
        .unwrap_or_default();
    let mem = perf::parse_meminfo(&fs::read_to_string(root.join("proc/meminfo")).unwrap_or_default());
    Info {
        computer: computer.trim().into(),
        hostname: read(root, "proc/sys/kernel/hostname"),
        uptime_secs: parse_uptime(&read(root, "proc/uptime")),
        swap_mb: mem.swap_total_kb / 1024,
        swap_devs: parse_swaps(&fs::read_to_string(root.join("proc/swaps")).unwrap_or_default()),
        os: parse_os_release(&fs::read_to_string(root.join("etc/os-release")).unwrap_or_default()),
        kernel: read(root, "proc/sys/kernel/osrelease"),
        cpu,
        cores,
        threads,
        cpu_mhz: max_cpu_mhz(root),
        mem_mb: mem.total_kb / 1024,
        desktop,
        session: std::env::var("XDG_SESSION_TYPE").unwrap_or_default(),
        bios_vendor: dmi("bios_vendor"),
        bios_version: dmi("bios_version"),
        bios_release: dmi("bios_release"),
        bios_date: dmi("bios_date"),
        board_vendor: dmi("board_vendor"),
        board_name: dmi("board_name"),
        board_version: dmi("board_version"),
        uefi: root.join("sys/firmware/efi").exists(),
        secure_boot: fs::read_dir(root.join("sys/firmware/efi/efivars"))
            .ok()
            .and_then(|d| {
                d.flatten()
                    .find(|e| e.file_name().to_string_lossy().starts_with("SecureBoot-"))
            })
            .and_then(|e| fs::read(e.path()).ok())
            .and_then(|b| parse_secure_boot(&b)),
        gpus,
        opengl: gl_tool(&|g| g.core.clone()),
        opengl_es: gl_tool(&|g| g.es.clone()),
        vulkan,
        vaapi: tool_from(cmd("vainfo", &[]), |o| value_after(o, "Driver version:").into()),
        vdpau: tool_from(cmd("vdpauinfo", &[]), |o| value_after(o, "Information string:").into()),
        disks,
        usb: cmd("lsusb", &[]).map(|r| parse_lsusb(&r.1)).unwrap_or_default(),
        monitors: cmd("xrandr", &["--query"])
            .map(|r| parse_xrandr(&r.1))
            .unwrap_or_default(),
        audio: parse_asound(&fs::read_to_string(root.join("proc/asound/cards")).unwrap_or_default()),
        network: lspci
            .iter()
            .filter(|p| class_code(p).starts_with("02"))
            .map(|p| (p.name.clone(), net_iface(root, &p.slot)))
            .collect(),
        max_watches: read(root, "proc/sys/fs/inotify/max_user_watches").parse().unwrap_or(0),
        max_maps: read(root, "proc/sys/vm/max_map_count").parse().unwrap_or(0),
        big_watchers: WATCHERS
            .iter()
            .filter(|(bin, _)| in_path(bin))
            .map(|(_, name)| (*name).to_string())
            .collect(),
        steam: in_path("steam"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_and_cpu() {
        assert_eq!(
            parse_os_release("NAME=\"Linux Mint\"\nPRETTY_NAME=\"Linux Mint 22.3\"\n"),
            "Linux Mint 22.3"
        );
        let t = "processor\t: 0\nmodel name\t: AMD Ryzen 7 5800X3D 8-Core Processor\ncpu cores\t: 8\nprocessor\t: 1\nmodel name\t: x\n";
        assert_eq!(parse_cpuinfo(t), ("AMD Ryzen 7 5800X3D 8-Core Processor".into(), 8, 2));
        assert_eq!(parse_cpuinfo(""), (String::new(), 0, 0));
    }

    #[test]
    fn lspci_line() {
        let t = "06:00.0 \"VGA compatible controller [0300]\" \"NVIDIA Corporation [10de]\" \"AD104 [GeForce RTX 4070 SUPER] [2783]\" -ra1 -p00 \"InnoVISION [1771]\" \"Device [18ca]\"\n";
        let p = &parse_lspci(t)[0];
        assert_eq!(p.slot, "06:00.0");
        assert_eq!(class_code(p), "0300");
        assert_eq!(p.name, "NVIDIA Corporation AD104 [GeForce RTX 4070 SUPER]");
        assert_eq!(p.id, "10de:2783");
    }

    #[test]
    fn usb_hides_root_hubs() {
        let t = "Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub\nBus 001 Device 002: ID 045e:07f8 Microsoft Corp. Wired Keyboard 600 (model 1576)\n";
        assert_eq!(parse_lsusb(t), ["Microsoft Corp. Wired Keyboard 600 (model 1576)"]);
    }

    #[test]
    fn xrandr_current_mode() {
        let t = "Screen 0: minimum 8 x 8\nHDMI-0 connected primary 1920x1080+0+0 (normal) 480mm x 270mm\n   1920x1080     60.00 +  74.97*   59.94\n   1280x720      60.00\nDP-0 disconnected (normal)\n";
        assert_eq!(
            parse_xrandr(t),
            [Monitor {
                output: "HDMI-0".into(),
                mode: "1920x1080".into(),
                hz: "74.97".into()
            }]
        );
    }

    #[test]
    fn sound_cards() {
        let t = " 0 [NVidia         ]: HDA-Intel - HDA NVidia\n                      HDA NVidia at 0xfc080000 irq 81\n 1 [Generic        ]: HDA-Intel - HD-Audio Generic\n";
        assert_eq!(parse_asound(t), ["HDA NVidia", "HD-Audio Generic"]);
    }

    #[test]
    fn gl_and_vulkan() {
        let t = "direct rendering: Yes\nOpenGL renderer string: NVIDIA GeForce RTX 4070 SUPER/PCIe/SSE2\nOpenGL core profile version string: 4.6.0 NVIDIA 595.91.07\nOpenGL ES profile version string: OpenGL ES 3.2 NVIDIA 595.91.07\nOpenGL version string: 4.6.0 NVIDIA 595.91.07\n";
        let g = parse_glxinfo(t);
        assert!(g.direct);
        assert_eq!((g.core.as_str(), g.mesa.as_str()), ("4.6.0 NVIDIA 595.91.07", ""));
        let mesa = "direct rendering: Yes\nOpenGL version string: 4.5 (Compatibility Profile) Mesa 25.0.7\n";
        let g = parse_glxinfo(mesa);
        assert_eq!(
            (g.core.as_str(), g.mesa.as_str()),
            ("4.5 (Compatibility Profile) Mesa 25.0.7", "25.0.7")
        );
        assert!(software("llvmpipe (LLVM 15)"));
        assert_eq!(
            parse_vulkan("deviceName = llvmpipe\ndeviceName = NVIDIA RTX"),
            Ok("NVIDIA RTX".into())
        );
        assert_eq!(parse_vulkan("deviceName = llvmpipe"), Err("llvmpipe".into()));
        assert_eq!(parse_vulkan(""), Err(String::new()));
    }

    #[test]
    fn swap_uptime_and_vram() {
        let swaps = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n/swapfile                               file\t\t2097148\t\t0\t\t-2\n/dev/zram0                              partition\t8388604\t\t0\t\t100\n";
        assert_eq!(parse_swaps(swaps), ["/swapfile", "/dev/zram0"]);
        assert!(parse_swaps("Filename Type Size Used Priority\n").is_empty());
        assert_eq!(parse_uptime("12345.67 98765.43\n"), 12345);
        assert_eq!(parse_uptime(""), 0);
        assert_eq!(parse_glxinfo("    Dedicated video memory: 12282 MB\n").vram_mb, 12282);
        assert_eq!(parse_glxinfo("    Video memory: 8192MB\n").vram_mb, 8192);
    }

    #[test]
    fn secure_boot_byte() {
        assert_eq!(parse_secure_boot(&[6, 0, 0, 0, 1]), Some(true));
        assert_eq!(parse_secure_boot(&[6, 0, 0, 0, 0]), Some(false));
        assert_eq!(parse_secure_boot(&[6]), None);
    }

    #[test]
    fn scan_reads_a_fake_root() {
        let root = std::env::temp_dir().join(format!("fastcheckup-sysinfo-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for d in [
            "sys/class/dmi/id",
            "sys/devices/system/cpu/cpu0/cpufreq",
            "sys/firmware/efi/efivars",
            "proc/sys/kernel",
        ] {
            fs::create_dir_all(root.join(d)).unwrap();
        }
        fs::write(root.join("sys/class/dmi/id/board_name"), "B550M\n").unwrap();
        fs::write(
            root.join("sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq"),
            "4500000\n",
        )
        .unwrap();
        fs::write(root.join("sys/firmware/efi/efivars/SecureBoot-x"), [6, 0, 0, 0, 0]).unwrap();
        fs::write(root.join("proc/sys/kernel/osrelease"), "7.0.0\n").unwrap();
        fs::create_dir_all(root.join("proc/sys/fs/inotify")).unwrap();
        fs::create_dir_all(root.join("proc/sys/vm")).unwrap();
        fs::write(root.join("proc/sys/fs/inotify/max_user_watches"), "8192\n").unwrap();
        fs::write(root.join("proc/sys/vm/max_map_count"), "65530\n").unwrap();
        let i = scan(&root);
        assert_eq!((i.max_watches, i.max_maps), (8192, 65530));
        assert_eq!(
            (i.board_name.as_str(), i.cpu_mhz, i.kernel.as_str()),
            ("B550M", 4500, "7.0.0")
        );
        assert!(i.uefi);
        assert_eq!(i.secure_boot, Some(false));
        assert_eq!(i.mem_mb, 0);
        let _ = fs::remove_dir_all(&root);
    }
}
