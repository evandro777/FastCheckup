//! Local network scan, run only when the user presses the button (it sends packets to every address of the /24).
//! Plain TCP connects, no root: a connection or a refusal means the device is up, and the open ports are the ones
//! that connected. Devices that drop every probe still answer ARP, which `ip neigh` shows afterwards.
use std::{
    collections::BTreeMap,
    io,
    net::{Ipv4Addr, SocketAddr, TcpStream},
    path::Path,
    process::Command,
    thread,
    time::Duration,
};

use crate::apps::run;

/// Doors worth knowing about on a home or office network.
pub const PORTS: [u16; 14] = [21, 22, 23, 80, 139, 443, 445, 554, 1883, 3389, 5900, 8080, 8443, 9100];
const TIMEOUT: Duration = Duration::from_millis(300);

/// `(ip, answered, open ports)` of one address.
type Probe = (Ipv4Addr, bool, Vec<(u16, String)>);

/// `role`: 0 another device, 1 this computer, 2 the router (default gateway).
#[derive(Debug, PartialEq)]
pub struct Host {
    pub ip: Ipv4Addr,
    pub mac: String,
    /// Empty when the resolver knows none.
    pub name: String,
    /// Maker of the network card, empty when unknown (random MAC, or nmap is not installed).
    pub vendor: String,
    /// Model announced over mDNS (`Smart TV Pro`), empty when none.
    pub model: String,
    /// Guess of what it is, see `kind_of`.
    pub kind: i32,
    /// How many other addresses answer with this same MAC.
    pub shared: usize,
    /// `(port, service name)`; the name may be empty.
    pub ports: Vec<(u16, String)>,
    pub role: i32,
}

/// Open to anyone on the network with no or weak login: FTP, telnet, SMB, MQTT, RDP, VNC.
pub fn risky(port: u16) -> bool {
    [21, 23, 139, 445, 1883, 3389, 5900].contains(&port)
}

/// Protocol names are the same in every language, so they are built here.
pub fn port_name(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        80 | 8080 => "http",
        139 | 445 => "smb",
        443 | 8443 => "https",
        554 => "rtsp",
        1883 => "mqtt",
        3389 => "rdp",
        5900 => "vnc",
        9100 => "printer",
        _ => "",
    }
}

/// "23 telnet".
pub fn port_label((port, name): &(u16, String)) -> String {
    format!("{port} {name}").trim().to_string()
}

/// `(gateway, device)` from `ip -4 route show default`: `default via 192.168.1.1 dev wlp3s0 proto dhcp`.
fn parse_default(text: &str) -> Option<(Ipv4Addr, String)> {
    let w: Vec<&str> = text.lines().next()?.split_whitespace().collect();
    let after = |key: &str| w.iter().position(|x| *x == key).and_then(|i| w.get(i + 1)).copied();
    Some((after("via")?.parse().ok()?, after("dev")?.to_string()))
}

/// Our address from `ip -4 -o addr show dev X`: `2: wlp3s0    inet 192.168.1.23/24 brd ...`.
fn parse_addr(text: &str) -> Option<Ipv4Addr> {
    let w: Vec<&str> = text.split_whitespace().collect();
    let i = w.iter().position(|x| *x == "inet")?;
    w.get(i + 1)?.split('/').next()?.parse().ok()
}

/// `(this computer, router)`. shortcut: always the /24 around our address, a bigger network is not walked.
pub fn network() -> Option<(Ipv4Addr, Ipv4Addr)> {
    let (gateway, dev) = parse_default(&run("ip", &["-4", "route", "show", "default"]))?;
    // A full-tunnel VPN owns the default route: its /24 belongs to someone else, so it is never scanned.
    if is_tunnel(&dev) {
        return None;
    }
    Some((
        parse_addr(&run("ip", &["-4", "-o", "addr", "show", "dev", &dev]))?,
        gateway,
    ))
}

/// Real LAN devices (Ethernet, Wi-Fi, bridges) have ARP type 1. WireGuard, `tun` and `ppp` VPNs have another one,
/// whatever the client names them (`nordlynx`, `proton0`). `tap` is Ethernet-typed, so it is caught by name.
/// An unreadable type is not a reason to refuse.
fn is_tunnel(dev: &str) -> bool {
    let kind = std::fs::read_to_string(format!("/sys/class/net/{dev}/type")).unwrap_or_default();
    not_a_lan(dev, kind.trim())
}

fn not_a_lan(dev: &str, arp_type: &str) -> bool {
    dev.starts_with("tap") || !(arp_type.is_empty() || arp_type == "1")
}

/// `a.b.c.0/24`, for nmap.
pub fn cidr(own: Ipv4Addr) -> String {
    let o = own.octets();
    format!("{}.{}.{}.0/24", o[0], o[1], o[2])
}

/// Neighbours that answered ARP, from `ip -4 neigh`: `192.168.1.1 dev wlp3s0 lladdr aa:bb:cc:dd:ee:ff REACHABLE`.
pub(crate) fn parse_neigh(text: &str) -> Vec<(Ipv4Addr, String)> {
    text.lines()
        .filter_map(|l| {
            let w: Vec<&str> = l.split_whitespace().collect();
            let mac = w.iter().position(|x| *x == "lladdr").and_then(|i| w.get(i + 1))?;
            if matches!(w.last(), Some(&"FAILED" | &"INCOMPLETE")) {
                return None;
            }
            Some((w[0].parse().ok()?, mac.to_string()))
        })
        .collect()
}

/// Joins the probes (`(ip, up, open ports)`) with the ARP table into one sorted list.
fn merge(own: Ipv4Addr, gateway: Ipv4Addr, probed: Vec<Probe>, neigh: Vec<(Ipv4Addr, String)>) -> Vec<Host> {
    let host = |ip: Ipv4Addr| Host {
        ip,
        mac: String::new(),
        name: String::new(),
        vendor: String::new(),
        model: String::new(),
        kind: 0,
        shared: 0,
        ports: Vec::new(),
        role: if ip == own {
            1
        } else if ip == gateway {
            2
        } else {
            0
        },
    };
    let mut hosts: BTreeMap<Ipv4Addr, Host> = BTreeMap::new();
    for (ip, up, ports) in probed {
        if up || ip == own {
            hosts.insert(ip, Host { ports, ..host(ip) });
        }
    }
    for (ip, mac) in neigh {
        // Only addresses of the scanned network; the ARP table can hold others.
        if ip.octets()[..3] == own.octets()[..3] {
            hosts.entry(ip).or_insert_with(|| host(ip)).mac = mac;
        }
    }
    hosts.into_values().collect()
}

/// Probes the /24 of `own`: one thread per address, each walking `PORTS` one by one (a silent address costs
/// `PORTS.len() * 300 ms`, all in parallel). `None` when no network is up.
pub fn scan() -> Option<Vec<Host>> {
    let (own, gateway) = network()?;
    let o = own.octets();
    let probed = thread::scope(|s| {
        let handles: Vec<_> = (1..=254u8)
            .map(|last| {
                s.spawn(move || {
                    let ip = Ipv4Addr::new(o[0], o[1], o[2], last);
                    let (mut up, mut open) = (false, Vec::new());
                    for port in PORTS {
                        match TcpStream::connect_timeout(&SocketAddr::from((ip, port)), TIMEOUT) {
                            Ok(_) => {
                                up = true;
                                open.push((port, port_name(port).to_string()));
                            }
                            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => up = true,
                            Err(_) => {}
                        }
                    }
                    (ip, up, open)
                })
            })
            .collect();
        handles.into_iter().filter_map(|h| h.join().ok()).collect::<Vec<_>>()
    });
    Some(named(merge(
        own,
        gateway,
        probed,
        parse_neigh(&run("ip", &["-4", "neigh"])),
    )))
}

pub fn nmap_installed() -> bool {
    ["/usr/bin", "/usr/local/bin", "/bin"]
        .iter()
        .any(|d| Path::new(d).join("nmap").exists())
}

/// Hosts from `nmap -oG -` (grepable): `Host: 192.168.1.1 (name)\tPorts: 22/open/tcp//ssh///, 80/open/tcp//http///`.
/// Every `Host:` line is a host that is up; ports carry nmap's own service names.
fn parse_nmap(text: &str) -> Vec<Probe> {
    let mut found: BTreeMap<Ipv4Addr, Vec<(u16, String)>> = BTreeMap::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("Host: ") else {
            continue;
        };
        let Some(ip) = rest.split_whitespace().next().and_then(|w| w.parse().ok()) else {
            continue;
        };
        let ports = found.entry(ip).or_default();
        let list = rest
            .split("Ports: ")
            .nth(1)
            .and_then(|p| p.split('\t').next())
            .unwrap_or("");
        for entry in list.split(", ") {
            let f: Vec<&str> = entry.split('/').collect();
            if let (Some(Ok(port)), Some(&"open")) = (f.first().map(|p| p.trim().parse::<u16>()), f.get(1)) {
                ports.push((port, f.get(4).unwrap_or(&"").to_string()));
            }
        }
    }
    found.into_iter().map(|(ip, ports)| (ip, true, ports)).collect()
}

/// Same list as `scan`, but the ports come from `nmap -F --open -T4` (top 100 ports, TCP connect, no root), so it
/// shows more doors than `PORTS`. `Ok(None)`: no network. `Err`: nmap failed.
pub fn scan_nmap() -> io::Result<Option<Vec<Host>>> {
    let Some((own, gateway)) = network() else {
        return Ok(None);
    };
    let out = Command::new("nmap")
        .args(["-F", "--open", "-T4", "-oG", "-", &cidr(own)])
        .output()?;
    if !out.status.success() {
        return Err(io::Error::other(
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        ));
    }
    let probed = parse_nmap(&String::from_utf8_lossy(&out.stdout));
    Ok(Some(named(merge(
        own,
        gateway,
        probed,
        parse_neigh(&run("ip", &["-4", "neigh"])),
    ))))
}

/// The workstation name from `nmblookup -A`: the first `<00>` line that is not a group, e.g. `\tPC1   <00> -  B <ACTIVE>`.
fn parse_netbios(text: &str) -> String {
    text.lines()
        .find(|l| l.contains("<00>") && !l.contains("<GROUP>"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or("")
        .to_string()
}

/// `ip -> host name` from `avahi-browse -a -t -r -p` (`=;eth0;IPv4;service;type;local;host.local;192.168.1.5;port;..`):
/// every device that announces itself over mDNS, found in one pass. The name the owner gave the device ("Living Room
/// TV", announced by Android TV and AirPlay) wins over the host name; other service names (Spotify...) are not names.
fn parse_avahi(text: &str) -> BTreeMap<Ipv4Addr, Mdns> {
    let mut out: BTreeMap<Ipv4Addr, Mdns> = BTreeMap::new();
    let mut friendly: BTreeMap<Ipv4Addr, String> = BTreeMap::new();
    for f in text
        .lines()
        .filter(|l| l.starts_with("=;"))
        .map(|l| l.split(';').collect::<Vec<_>>())
    {
        let (Some(&"IPv4"), Some(host), Some(Ok(ip))) = (f.get(2), f.get(6), f.get(7).map(|a| a.parse::<Ipv4Addr>()))
        else {
            continue;
        };
        // TXT items are quoted strings ("md=Smart TV Pro" "ve=05") and may hold `;`, so the tail is joined back.
        let txt = f.get(9..).unwrap_or_default().join(";");
        let items: Vec<String> = txt
            .trim()
            .trim_matches('"')
            .split("\" \"")
            .map(avahi_unescape)
            .collect();
        let get = |keys: &[&str]| {
            items
                .iter()
                .find_map(|i| {
                    keys.iter()
                        .find_map(|k| i.strip_prefix(*k).and_then(|v| v.strip_prefix('=')))
                })
                .unwrap_or("")
        };
        let kind = f.get(4).copied().unwrap_or("");
        if matches!(kind, "_androidtvremote2._tcp" | "_airplay._tcp") {
            friendly.entry(ip).or_insert_with(|| avahi_unescape(f[3]));
        }
        if kind == "_googlecast._tcp" && !get(&["fn"]).is_empty() {
            friendly.entry(ip).or_insert_with(|| get(&["fn"]).to_string());
        }
        let e = out.entry(ip).or_default();
        if !e.services.iter().any(|s| s == kind) {
            e.services.push(kind.to_string());
        }
        // Cast: md; AirPlay: am/model; printers: ty; Thread border routers (Echo...): mn.
        let model = get(&["md", "am", "model", "ty", "mn"]);
        if e.model.is_empty() {
            e.model = model.to_string();
        }
        let name = host.trim_end_matches(".local").to_string();
        // A device can announce several names; Cast/Chromecast ones are a bare id (`a68fcf12-c716-…`), keep a readable one.
        let id_like =
            |n: &str| n.len() >= 32 && n.contains('-') && n.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
        if e.name.is_empty() || (id_like(&e.name) && !id_like(&name)) {
            e.name = name;
        }
    }
    for (ip, n) in friendly {
        out.entry(ip).or_default().name = n;
    }
    out
}

/// What one device announces over mDNS: a name, a model and the service types it offers (`_googlecast._tcp`...).
#[derive(Debug, Default, PartialEq)]
struct Mdns {
    name: String,
    model: String,
    services: Vec<String>,
}

/// A guess of what a device is, for the icon: 0 unknown, 1 router, 2 this computer, 3 TV or speaker, 4 printer,
/// 5 camera, 6 computer or server, 7 phone or tablet. shortcut: rules of thumb on ports, services and the MAC, never
/// certain; a MAC shared by several addresses stays 0 (a repeater or VM host, not a phone).
fn kind_of(role: i32, ports: &[(u16, String)], services: &[String], mac: &str, shared: bool) -> i32 {
    let has = |p: u16| ports.iter().any(|(x, _)| *x == p);
    let svc = |names: &[&str]| services.iter().any(|s| names.iter().any(|n| s.starts_with(n)));
    // `role` 2 is the router and 1 this computer; the kinds number them the other way round.
    if role == 2 {
        1
    } else if role == 1 {
        2
    } else if svc(&["_googlecast", "_androidtvremote"]) {
        3
    } else if has(9100) || svc(&["_ipp", "_printer", "_pdl-datastream"]) {
        4
    } else if has(554) && !has(445) && !has(139) {
        5
    } else if has(139) || has(445) || svc(&["_smb", "_workstation", "_sftp-ssh"]) {
        6
    // Computers announce these too (Spotify desktop, a Mac), so they only count once the signs of a computer are ruled out.
    } else if svc(&["_airplay", "_raop", "_spotify-connect"]) {
        3
    } else if !shared && u8::from_str_radix(mac.get(..2).unwrap_or(""), 16).is_ok_and(|b| b & 2 != 0) {
        7
    } else {
        0
    }
}

/// `Living\032Room` -> `Living Room`: avahi's `-p` output escapes bytes as `\ddd` (decimal).
fn avahi_unescape(s: &str) -> String {
    let (b, mut out, mut i) = (s.as_bytes(), Vec::new(), 0);
    while i < b.len() {
        let code = (b[i] == b'\\')
            .then(|| s.get(i + 1..i + 4)?.parse::<u8>().ok())
            .flatten();
        out.push(code.unwrap_or(b[i]));
        i += if code.is_some() { 4 } else { 1 };
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Maker of a MAC from nmap's `nmap-mac-prefixes` (`28EE52 TP-Link Technologies`). Random (locally administered)
/// addresses, as phones use, are not in it, so they stay empty.
fn vendor_of(table: &str, mac: &str) -> String {
    let oui: String = mac.split(':').take(3).collect::<String>().to_ascii_uppercase();
    table
        .lines()
        .find_map(|l| l.strip_prefix(oui.as_str()).and_then(|r| r.strip_prefix(' ')))
        .unwrap_or("")
        .to_string()
}

/// Fills `name`: the system resolver (`getent`: /etc/hosts, DNS), then what the network announces (mDNS through one
/// `avahi-browse` for phones, TVs, Linux, Macs), then NetBIOS (`nmblookup`: Windows and Samba). Also `vendor` from
/// nmap's prefix list when it is installed. The router's own device list (DHCP names) is not readable without logging
/// in to it. One thread per host, lookups capped at 3 s (6 s for the browse). Missing tools just add nothing.
fn named(mut hosts: Vec<Host>) -> Vec<Host> {
    let mdns = thread::scope(|s| {
        let browse = s.spawn(|| parse_avahi(&run("timeout", &["6", "avahi-browse", "-a", "-t", "-r", "-p"])));
        for h in &mut hosts {
            s.spawn(|| {
                let ip = h.ip.to_string();
                let found = run("getent", &["hosts", &ip])
                    .split_whitespace()
                    .nth(1)
                    .map(str::to_string);
                h.name = found.unwrap_or_default();
            });
        }
        browse.join().unwrap_or_default()
    });
    let table = std::fs::read_to_string("/usr/share/nmap/nmap-mac-prefixes").unwrap_or_default();
    // Other addresses with the same MAC: the rows stay separate (each has its own ports), this only warns.
    let macs: Vec<String> = hosts.iter().map(|h| h.mac.to_ascii_lowercase()).collect();
    thread::scope(|s| {
        for h in &mut hosts {
            let m = mdns.get(&h.ip);
            h.shared = if h.mac.is_empty() {
                0
            } else {
                macs.iter().filter(|x| **x == h.mac.to_ascii_lowercase()).count() - 1
            };
            h.model = m.map(|m| m.model.clone()).unwrap_or_default();
            h.vendor = vendor_of(&table, &h.mac);
            match m.map(|m| m.name.as_str()).filter(|n| !n.is_empty()) {
                Some(n) if h.name.is_empty() => h.name = n.to_string(),
                None if h.name.is_empty() => {
                    s.spawn(|| h.name = parse_netbios(&run("timeout", &["3", "nmblookup", "-A", &h.ip.to_string()])));
                }
                _ => {}
            }
            let services = m.map(|m| m.services.as_slice()).unwrap_or_default();
            h.kind = kind_of(h.role, &h.ports, services, &h.mac, h.shared > 0);
        }
    });
    hosts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn a_vpn_device_is_never_scanned() {
        // 65534 is what the kernel gives WireGuard and tun, 512 is ppp; the name does not matter.
        for (dev, kind) in [
            ("nordlynx", "65534"),
            ("proton0", "65534"),
            ("ppp0", "512"),
            ("tap1", "1"),
        ] {
            assert!(not_a_lan(dev, kind), "{dev}");
        }
        for (dev, kind) in [("wlp3s0", "1"), ("enp5s0", "1"), ("eth0", ""), ("br0", "1")] {
            assert!(!not_a_lan(dev, kind), "{dev}");
        }
    }

    #[test]
    fn reads_route_and_address() {
        let (gw, dev) = parse_default("default via 192.168.1.1 dev wlp3s0 proto dhcp metric 600\n").unwrap();
        assert_eq!((gw, dev.as_str()), (ip("192.168.1.1"), "wlp3s0"));
        assert!(parse_default("").is_none());
        assert_eq!(
            parse_addr("2: wlp3s0    inet 192.168.1.23/24 brd 192.168.1.255 scope global dynamic wlp3s0\n"),
            Some(ip("192.168.1.23"))
        );
        assert_eq!(cidr(ip("10.0.7.9")), "10.0.7.0/24");
    }

    #[test]
    fn neighbours_skip_failed_and_unresolved() {
        let t = "192.168.1.1 dev w lladdr aa:bb:cc:dd:ee:01 REACHABLE\n192.168.1.9 dev w FAILED\n\
                 192.168.1.7 dev w lladdr aa:bb:cc:dd:ee:07 FAILED\n";
        assert_eq!(
            parse_neigh(t),
            vec![(ip("192.168.1.1"), "aa:bb:cc:dd:ee:01".to_string())]
        );
    }

    #[test]
    fn merge_marks_roles_and_keeps_silent_arp_hosts() {
        let probed = vec![
            (
                ip("192.168.1.1"),
                true,
                vec![(80, "http".into()), (443, "https".into())],
            ),
            (ip("192.168.1.2"), false, vec![]),
            (ip("192.168.1.23"), false, vec![]),
            (ip("192.168.1.40"), true, vec![(23, "telnet".into())]),
        ];
        let neigh = vec![
            (ip("192.168.1.9"), "m9".to_string()),
            (ip("10.9.9.9"), "far".to_string()),
        ];
        let hosts = merge(ip("192.168.1.23"), ip("192.168.1.1"), probed, neigh);
        let got: Vec<(String, i32, usize)> = hosts
            .iter()
            .map(|h| (h.ip.to_string(), h.role, h.ports.len()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("192.168.1.1".into(), 2, 2),
                ("192.168.1.9".into(), 0, 0),
                ("192.168.1.23".into(), 1, 0),
                ("192.168.1.40".into(), 0, 1)
            ]
        );
        assert!(risky(23) && !risky(443));
        assert_eq!(port_label(&(23, "telnet".into())), "23 telnet");
        assert_eq!(port_label(&(9999, String::new())), "9999");
    }

    #[test]
    fn avahi_names_and_vendors() {
        let t = "+;eth0;IPv4;x;_http._tcp;local\n=;eth0;IPv4;TV;_x._tcp;local;Android.local;192.168.0.109;6466;\n\
                 =;eth0;IPv6;TV;_x._tcp;local;Android.local;fe80::1;6466;\n=;eth0;IPv4;b;_y._tcp;local;Android.local;192.168.0.109;1;\n";
        let m = parse_avahi(t);
        assert_eq!((m.len(), m[&ip("192.168.0.109")].name.as_str()), (1, "Android"));
        let tv = "=;e;IPv4;Living\\032Room\\032TV;_androidtvremote2._tcp;local;Android.local;10.0.0.3;1;\n\
                  =;e;IPv4;SpotifyConnect;_spotify-connect._tcp;local;linux.local;10.0.0.4;1;\n";
        let m = parse_avahi(tv);
        assert_eq!(
            (m[&ip("10.0.0.3")].name.as_str(), m[&ip("10.0.0.4")].name.as_str()),
            ("Living Room TV", "linux")
        );
        let id_first = "=;e;IPv4;a;t;local;a68fcf12-c716-b82e-ce21-e4661596a21d.local;10.0.0.2;1;\n=;e;IPv4;b;t;local;Android.local;10.0.0.2;2;\n";
        assert_eq!(parse_avahi(id_first)[&ip("10.0.0.2")].name, "Android");
        let table = "28EE52 TP-Link Technologies\n5CC9D3 Palladium Energy\n";
        assert_eq!(vendor_of(table, "5c:c9:d3:7a:d7:c2"), "Palladium Energy");
        assert_eq!(vendor_of(table, "5e:19:ff:10:ff:f1"), "");
        assert_eq!(vendor_of(table, ""), "");
    }

    #[test]
    fn avahi_real_output_gives_model_services_and_friendly_name() {
        // Raw `avahi-browse -a -t -r -p` lines from a home network (TXT quoted, spaces and \ddd escapes inside).
        let t = r#"=;enp5s0;IPv4;Smart-TV-Pro-a68fcf12c716b82ece21e4661596a21d;_googlecast._tcp;local;a68fcf12-c716-b82e-ce21-e4661596a21d.local;192.168.0.109;8009;"rs=" "fn=Living Room TV" "ic=/setup/icon.png" "md=Smart TV Pro" "ve=05"
=;enp5s0;IPv4;Living\032Room\032TV;_androidtvremote2._tcp;local;Android.local;192.168.0.109;6466;"bt=F0:35:75:A7:B9:9E"
=;enp5s0;IPv4;amazon\032\0350000;_meshcop._udp;local;linux.local;192.168.0.101;49154;"omr=@\253\209" "mn=echo" "vn=amazon"
=;enp5s0;IPv4;SpotifyConnect;_spotify-connect._tcp;local;linux.local;192.168.0.101;4070;"CPath=/spotifyConnect"
"#;
        let m = parse_avahi(t);
        let tv = &m[&ip("192.168.0.109")];
        assert_eq!(
            (tv.name.as_str(), tv.model.as_str()),
            ("Living Room TV", "Smart TV Pro")
        );
        assert_eq!(tv.services, ["_googlecast._tcp", "_androidtvremote2._tcp"]);
        let echo = &m[&ip("192.168.0.101")];
        assert_eq!((echo.name.as_str(), echo.model.as_str()), ("linux", "echo"));
    }

    #[test]
    fn kind_guess_follows_the_clues() {
        let p = |l: &[u16]| l.iter().map(|&n| (n, String::new())).collect::<Vec<_>>();
        let s = |l: &[&str]| l.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(kind_of(2, &p(&[80]), &[], "", false), 1);
        assert_eq!(
            kind_of(0, &p(&[]), &s(&["_googlecast._tcp"]), "f0:35:75:a7:b9:9d", false),
            3
        );
        assert_eq!(kind_of(0, &p(&[9100]), &[], "", false), 4);
        assert_eq!(kind_of(0, &p(&[445]), &s(&["_spotify-connect._tcp"]), "", false), 6);
        assert_eq!(kind_of(0, &p(&[]), &s(&["_spotify-connect._tcp"]), "", false), 3);
        assert_eq!(kind_of(0, &p(&[80, 554]), &[], "20:98:ed:47:2f:03", false), 5);
        assert_eq!(kind_of(0, &p(&[554, 445]), &[], "", false), 6);
        // A random (locally administered) MAC alone is a phone, unless several addresses share it.
        assert_eq!(kind_of(0, &p(&[]), &[], "5a:66:71:ea:8e:b3", false), 7);
        assert_eq!(kind_of(0, &p(&[]), &[], "5e:19:ff:10:ff:f1", true), 0);
        assert_eq!(kind_of(0, &p(&[]), &[], "28:ee:52:7d:87:84", false), 0);
    }

    #[test]
    fn netbios_name_skips_groups_and_silence() {
        let t = "Looking up status of 192.168.0.113\n\tWORKGROUP       <00> - <GROUP> B <ACTIVE>\n\tFLPN4301        <00> -         B <ACTIVE>\n";
        assert_eq!(parse_netbios(t), "FLPN4301");
        assert_eq!(
            parse_netbios("Looking up status of 1.2.3.4\nNo reply from 1.2.3.4\n"),
            ""
        );
    }

    #[test]
    fn nmap_grepable_keeps_extra_ports_and_silent_hosts() {
        let t = "# Nmap 7.94 scan initiated\nHost: 192.168.0.1 (_gateway)\tStatus: Up\n\
                 Host: 192.168.0.1 (_gateway)\tPorts: 22/open/tcp//ssh///, 1900/open/tcp//upnp///\tIgnored State: closed (98)\n\
                 Host: 192.168.0.101 ()\tStatus: Up\n# Nmap done\n";
        assert_eq!(
            parse_nmap(t),
            vec![
                (ip("192.168.0.1"), true, vec![(22, "ssh".into()), (1900, "upnp".into())]),
                (ip("192.168.0.101"), true, vec![]),
            ]
        );
    }
}
