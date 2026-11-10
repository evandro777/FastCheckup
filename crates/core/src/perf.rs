//! Performance snapshot for the Overview: memory, swap, load, a verdict that names its cause and the busiest apps.
//! Read straight from `/proc` (no `top`/`ps`/`free`). Parsers take text so tests need no system. Report only.
use std::{collections::HashMap, fs, thread, time::Duration};

#[derive(Debug, Default, PartialEq)]
pub struct AppLoad {
    pub name: String,
    pub procs: u32,
    /// Share of the whole machine (100 = every core busy), not of one core like `top`.
    pub cpu_pct: f32,
    pub mem_mb: f32,
}

#[derive(Debug, Default)]
pub struct Snapshot {
    pub uptime_s: u64,
    pub cpus: u32,
    pub load1: f32,
    pub mem_total_mb: f32,
    pub mem_avail_mb: f32,
    pub swap_total_mb: f32,
    pub swap_used_mb: f32,
    /// 1 fine, 2 worth a look, 3 problem (same scale as the area status on the Overview).
    pub level: i32,
    /// 0 none, 1 memory, 2 processor, 3 disk.
    pub cause: i32,
    pub apps: Vec<AppLoad>,
}

#[derive(Debug, Default, PartialEq)]
pub struct Mem {
    pub total_kb: u64,
    pub avail_kb: u64,
    pub swap_total_kb: u64,
    pub swap_free_kb: u64,
}

pub fn parse_meminfo(text: &str) -> Mem {
    let mut m = Mem::default();
    for l in text.lines() {
        let Some((k, v)) = l.split_once(':') else { continue };
        let v = v.split_whitespace().next().and_then(|n| n.parse().ok()).unwrap_or(0);
        match k {
            "MemTotal" => m.total_kb = v,
            "MemAvailable" => m.avail_kb = v,
            "SwapTotal" => m.swap_total_kb = v,
            "SwapFree" => m.swap_free_kb = v,
            _ => {}
        }
    }
    m
}

/// `avg10` of the `some` line of a `/proc/pressure/*` file: the share of the last 10 s some task was stalled.
pub fn parse_psi(text: &str) -> Option<f32> {
    let line = text.lines().find(|l| l.starts_with("some"))?;
    line.split_whitespace()
        .find_map(|w| w.strip_prefix("avg10=")?.parse().ok())
}

/// Only the first 8 fields (user to steal): guest and guest_nice are already counted inside user and nice.
pub fn parse_cpu_total(stat: &str) -> Option<u64> {
    let line = stat.lines().find(|l| l.starts_with("cpu "))?;
    Some(
        line.split_whitespace()
            .skip(1)
            .take(8)
            .filter_map(|n| n.parse::<u64>().ok())
            .sum(),
    )
}

/// `(comm, utime + stime)` of `/proc/<pid>/stat`. The name sits in parentheses and may hold spaces or `)`, so the
/// fields after it are found from the last `)`.
pub fn parse_pid_stat(text: &str) -> Option<(String, u64)> {
    let (open, close) = (text.find('(')?, text.rfind(')')?);
    let comm = text.get(open + 1..close)?.to_string();
    let mut f = text.get(close + 1..)?.split_whitespace().skip(11);
    let (u, s) = (f.next()?.parse::<u64>().ok()?, f.next()?.parse::<u64>().ok()?);
    Some((comm, u + s))
}

fn parse_vmrss_kb(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// `(level, cause)`. Rules of thumb, not tuned on a machine under real pressure. Without `/proc/pressure` the
/// processor falls back to the load average. Idle pages sitting in swap are normal, so swap use is not a rule.
pub fn verdict(
    psi_cpu: Option<f32>,
    psi_mem: Option<f32>,
    psi_io: Option<f32>,
    avail_pct: f32,
    load1: f32,
    cpus: u32,
) -> (i32, i32) {
    let mem_p = psi_mem.unwrap_or(0.0);
    let mem = if mem_p >= 10.0 || avail_pct < 5.0 {
        3
    } else if mem_p >= 2.0 || avail_pct < 15.0 {
        2
    } else {
        1
    };
    let busy = psi_cpu.map_or(load1 > 2.0 * cpus as f32, |p| p >= 40.0);
    let io = psi_io.unwrap_or(0.0) >= 20.0;
    let mut best = (1, 0);
    for (level, cause) in [(mem, 1), (if busy { 2 } else { 1 }, 2), (if io { 2 } else { 1 }, 3)] {
        if level > best.0 {
            best = (level, cause);
        }
    }
    best
}

fn read(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

/// Total CPU jiffies and `pid -> (comm, jiffies)`.
fn sample() -> (u64, HashMap<u32, (String, u64)>) {
    let total = parse_cpu_total(&read("/proc/stat")).unwrap_or(0);
    let pids = fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let pid: u32 = e.file_name().to_str()?.parse().ok()?;
            Some((pid, parse_pid_stat(&fs::read_to_string(e.path().join("stat")).ok()?)?))
        })
        .collect();
    (total, pids)
}

/// Blocks about a second: CPU use needs two samples. Run it on a worker thread.
pub fn snapshot() -> Snapshot {
    let (t0, p0) = sample();
    thread::sleep(Duration::from_secs(1));
    let (t1, p1) = sample();
    let dt = t1.saturating_sub(t0).max(1) as f32;
    let me = std::process::id();

    // shortcut: RSS is summed (shared pages count once per process), comm is cut at 15 chars and scripts group under
    // their interpreter (python3, node, java); use smaps_rollup / cmdline if it misleads.
    let mut groups: HashMap<String, AppLoad> = HashMap::new();
    for (pid, (comm, j1)) in &p1 {
        // Only processes seen in both samples: a new one would add its whole lifetime of CPU time.
        let Some((_, j0)) = p0.get(pid).filter(|_| *pid != me) else {
            continue;
        };
        // Kernel threads have no VmRSS.
        let Some(rss_kb) = parse_vmrss_kb(&read(&format!("/proc/{pid}/status"))) else {
            continue;
        };
        // Right after an upgrade the exe reads "firefox (deleted)" until the app is restarted.
        let name = fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .and_then(|p| {
                p.file_name()
                    .map(|n| n.to_string_lossy().trim_end_matches(" (deleted)").to_string())
            })
            .unwrap_or_else(|| comm.clone());
        let g = groups.entry(name.clone()).or_insert_with(|| AppLoad {
            name,
            ..AppLoad::default()
        });
        g.procs += 1;
        g.cpu_pct += j1.saturating_sub(*j0) as f32 * 100.0 / dt;
        g.mem_mb += rss_kb as f32 / 1024.0;
    }
    let mut apps: Vec<AppLoad> = groups
        .into_values()
        .filter(|a| a.cpu_pct >= 1.0 || a.mem_mb >= 100.0)
        .collect();
    apps.sort_by(|a, b| {
        (b.cpu_pct, b.mem_mb)
            .partial_cmp(&(a.cpu_pct, a.mem_mb))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    apps.truncate(5);

    let m = parse_meminfo(&read("/proc/meminfo"));
    let mb = |kb: u64| kb as f32 / 1024.0;
    let cpus = thread::available_parallelism().map_or(1, |n| n.get() as u32);
    let load1 = read("/proc/loadavg")
        .split_whitespace()
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0.0);
    let avail_pct = if m.total_kb == 0 {
        100.0
    } else {
        m.avail_kb as f32 * 100.0 / m.total_kb as f32
    };
    let psi = |name: &str| parse_psi(&read(&format!("/proc/pressure/{name}")));
    let (level, cause) = verdict(psi("cpu"), psi("memory"), psi("io"), avail_pct, load1, cpus);
    Snapshot {
        uptime_s: read("/proc/uptime")
            .split_whitespace()
            .next()
            .and_then(|n| n.parse::<f64>().ok())
            .unwrap_or(0.0) as u64,
        cpus,
        load1,
        mem_total_mb: mb(m.total_kb),
        mem_avail_mb: mb(m.avail_kb),
        swap_total_mb: mb(m.swap_total_kb),
        swap_used_mb: mb(m.swap_total_kb.saturating_sub(m.swap_free_kb)),
        level,
        cause,
        apps,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meminfo() {
        let m = parse_meminfo(
            "MemTotal:       16000000 kB\nMemAvailable:    8000000 kB\nSwapTotal: 4000 kB\nSwapFree: 1000 kB\nX: 1\n",
        );
        assert_eq!(
            m,
            Mem {
                total_kb: 16000000,
                avail_kb: 8000000,
                swap_total_kb: 4000,
                swap_free_kb: 1000
            }
        );
    }

    #[test]
    fn psi() {
        let t = "some avg10=12.50 avg60=3.00 avg300=1.00 total=123\nfull avg10=1.00 avg60=0 avg300=0 total=1\n";
        assert_eq!(parse_psi(t), Some(12.5));
        assert_eq!(parse_psi(""), None);
    }

    #[test]
    fn cpu_total_ignores_guest() {
        // user nice system idle iowait irq softirq steal guest guest_nice
        assert_eq!(
            parse_cpu_total("cpu  1 2 3 4 5 6 7 8 900 1000\ncpu0 1 1 1 1 1 1 1 1 1 1\n"),
            Some(36)
        );
    }

    #[test]
    fn pid_stat_comm_with_parens_and_spaces() {
        let t = "42 (Web Content) x) S 1 2 3 4 5 6 7 8 9 10 100 50 0 0 20 0 1 0 5 6 7";
        assert_eq!(parse_pid_stat(t), Some(("Web Content) x".into(), 150)));
        assert_eq!(parse_pid_stat("garbage"), None);
    }

    #[test]
    fn vmrss() {
        assert_eq!(parse_vmrss_kb("Name:\tx\nVmRSS:\t  2048 kB\n"), Some(2048));
        assert_eq!(parse_vmrss_kb("Name:\tkthreadd\n"), None);
    }

    #[test]
    fn verdict_per_cause() {
        assert_eq!(verdict(Some(0.0), Some(0.0), Some(0.0), 50.0, 0.1, 4), (1, 0));
        assert_eq!(verdict(Some(0.0), Some(3.0), Some(0.0), 50.0, 0.1, 4), (2, 1));
        assert_eq!(verdict(Some(0.0), Some(0.0), Some(0.0), 3.0, 0.1, 4), (3, 1));
        assert_eq!(verdict(Some(50.0), Some(0.0), Some(0.0), 50.0, 0.1, 4), (2, 2));
        assert_eq!(verdict(Some(0.0), Some(0.0), Some(25.0), 50.0, 0.1, 4), (2, 3));
    }

    #[test]
    fn verdict_without_pressure_files_uses_load() {
        assert_eq!(verdict(None, None, None, 50.0, 9.0, 4), (2, 2));
        assert_eq!(verdict(None, None, None, 50.0, 2.0, 4), (1, 0));
    }
}
