use super::list_vlan_iface_ips;
use crate::state::SharedState;
use colored::Colorize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::Command;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const SCAN_PORTS: &[(u16, &str)] = &[
    (22, "ssh"),
    (80, "http"),
    (443, "https"),
    (3000, "grafana/web"),
    (5000, "web-app"),
    (5055, "overseerr"),
    (6767, "bazarr"),
    (6789, "nzbget"),
    (7878, "radarr"),
    (8000, "http-alt"),
    (8006, "proxmox"),
    (8080, "webui/http"),
    (8081, "sabnzbd"),
    (8096, "jellyfin"),
    (8112, "deluge"),
    (8123, "homeassistant"),
    (8181, "tautulli"),
    (8384, "syncthing"),
    (8443, "https-alt"),
    (8686, "lidarr"),
    (8787, "readarr"),
    (8989, "sonarr"),
    (9000, "portainer"),
    (9090, "prometheus/app"),
    (9091, "transmission"),
    (9117, "jackett"),
    (9696, "prowlarr"),
    (32400, "plex"),
];

pub const COMMON_CONTAINER_HOSTNAMES: &[&str] = &[
    "web",
    "api",
    "app-backend",
    "media",
    "sonarr",
    "radarr",
    "plex",
    "jellyfin",
    "prowlarr",
    "bazarr",
    "overseerr",
    "jellyseerr",
    "torrent-box",
    "sabnzbd",
    "transmission",
    "deluge",
    "nzbget",
    "tautulli",
    "lidarr",
    "readarr",
    "grafana",
    "prometheus",
    "homeassistant",
    "hass",
    "pihole",
    "adguard",
    "portainer",
    "nextcloud",
    "immich",
    "vaultwarden",
    "syncthing",
    "gitea",
];

fn reverse_lookup_ip(ip: Ipv4Addr) -> Option<String> {
    if let Ok(raw) = fs::read_to_string("/etc/hosts") {
        for line in raw.lines() {
            let clean = line.split('#').next().unwrap_or("").trim();
            let mut parts = clean.split_whitespace();
            if let (Some(ip_str), Some(host)) = (parts.next(), parts.next()) {
                if ip_str.parse::<Ipv4Addr>().ok() == Some(ip) {
                    let h = host.trim_end_matches(".local").to_string();
                    if !h.eq_ignore_ascii_case("localhost") {
                        return Some(h);
                    }
                }
            }
        }
    }
    if let Ok(out) = Command::new("getent").args(["hosts", &ip.to_string()]).output() {
        if out.status.success() {
            let line = String::from_utf8_lossy(&out.stdout);
            let mut parts = line.split_whitespace();
            let _ = parts.next();
            if let Some(host) = parts.next() {
                let h = host
                    .trim_end_matches('.')
                    .trim_end_matches(".local")
                    .trim_end_matches(".lan")
                    .trim_end_matches(".localdomain")
                    .to_string();
                if !h.is_empty() && h.parse::<Ipv4Addr>().is_err() {
                    return Some(h);
                }
            }
        }
    }
    None
}

fn identify_http_banner(
    default_name: &str,
    host: Option<&str>,
    port: u16,
    raw: &str,
) -> (String, Option<String>) {
    let lower = raw.to_ascii_lowercase();
    let mut title = None;
    if let Some(start) = lower.find("<title>") {
        if let Some(end) = lower[start + 7..].find("</title>") {
            let t = raw[start + 7..start + 7 + end].trim();
            if !t.is_empty() {
                title = Some(t.chars().take(40).collect::<String>());
            }
        }
    }
    let detected = if lower.contains("sonarr") || port == 8989 {
        "sonarr"
    } else if lower.contains("radarr") || port == 7878 {
        "radarr"
    } else if lower.contains("prowlarr") || port == 9696 {
        "prowlarr"
    } else if lower.contains("bazarr") || port == 6767 {
        "bazarr"
    } else if lower.contains("lidarr") || port == 8686 {
        "lidarr"
    } else if lower.contains("readarr") || port == 8787 {
        "readarr"
    } else if lower.contains("plex") || port == 32400 {
        "plex"
    } else if lower.contains("jellyfin") || port == 8096 {
        "jellyfin"
    } else if lower.contains("overseerr") || lower.contains("jellyseerr") || port == 5055 {
        "overseerr"
    } else if lower.contains("sabnzbd") || port == 8081 {
        "sabnzbd"
    } else if lower.contains("transmission") || port == 9091 {
        "transmission"
    } else if lower.contains("deluge") || port == 8112 {
        "deluge"
    } else if lower.contains("tautulli") || port == 8181 {
        "tautulli"
    } else if lower.contains("home assistant") || port == 8123 {
        "homeassistant"
    } else if lower.contains("grafana") {
        "grafana"
    } else if lower.contains("prometheus") {
        "prometheus"
    } else if let Some(h) = host {
        if default_name.contains('/') {
            h
        } else {
            default_name
        }
    } else {
        default_name
    };
    (detected.to_string(), title)
}

async fn probe_single_port(
    ip: Ipv4Addr,
    host: Option<String>,
    port: u16,
    default_name: &'static str,
) -> Option<crate::state::DiscoveredService> {
    let addr = SocketAddr::new(std::net::IpAddr::V4(ip), port);
    let t0 = std::time::Instant::now();
    let Ok(Ok(mut stream)) =
        tokio::time::timeout(Duration::from_millis(350), TcpStream::connect(addr)).await
    else {
        return None;
    };
    let latency_ms = t0.elapsed().as_secs_f64() * 1000.0;

    let mut service_name = default_name.to_string();
    let mut banner = None;

    if port == 22 {
        let mut buf = [0u8; 128];
        if let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_millis(200), stream.read(&mut buf)).await
        {
            if n > 0 {
                let s = String::from_utf8_lossy(&buf[..n])
                    .lines()
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if !s.is_empty() {
                    banner = Some(s.chars().take(36).collect());
                }
            }
        }
    } else {
        let host_hdr = host.clone().unwrap_or_else(|| ip.to_string());
        let req = format!(
            "GET / HTTP/1.0\r\nHost: {}\r\nUser-Agent: nfty-scanner/1.0\r\nConnection: close\r\n\r\n",
            host_hdr
        );
        if stream.write_all(req.as_bytes()).await.is_ok() {
            let mut buf = [0u8; 2048];
            if let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_millis(250), stream.read(&mut buf)).await
            {
                if n > 0 {
                    let raw = String::from_utf8_lossy(&buf[..n]);
                    let (det, title) =
                        identify_http_banner(default_name, host.as_deref(), port, &raw);
                    service_name = det;
                    banner = title.or_else(|| {
                        raw.lines()
                            .next()
                            .map(|l| l.trim().chars().take(36).collect())
                    });
                }
            }
        }
        if service_name.contains('/') {
            if let Some(h) = &host {
                service_name = h.clone();
            } else {
                service_name = service_name
                    .split('/')
                    .next()
                    .unwrap_or(&service_name)
                    .to_string();
            }
        }
    }

    Some(crate::state::DiscoveredService {
        index: 0,
        host,
        ip,
        port,
        service_name,
        banner: banner.unwrap_or_default(),
        latency_ms,
    })
}

pub fn scan_network_services(
    target_filter: Option<&str>,
    shared: &SharedState,
) -> Vec<crate::state::DiscoveredService> {
    let local_ips: BTreeSet<Ipv4Addr> = list_vlan_iface_ips().into_iter().collect();
    let mut host_map: BTreeMap<Ipv4Addr, Option<String>> = BTreeMap::new();

    if let Some(filter) = target_filter.map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if let Some((base_str, prefix_str)) = filter.split_once('/') {
            if let (Ok(base_ip), Ok(prefix)) =
                (base_str.parse::<Ipv4Addr>(), prefix_str.parse::<u8>())
            {
                let base_u32 = u32::from(base_ip);
                let host_bits = 32u8.saturating_sub(prefix.clamp(22, 32));
                let count = (1u32 << host_bits).min(256);
                let net_u32 = base_u32 & (!0u32 << host_bits);
                for offset in 1..count.saturating_sub(1).max(2) {
                    let ip = Ipv4Addr::from(net_u32 + offset);
                    if !local_ips.contains(&ip) {
                        host_map.insert(ip, None);
                    }
                }
            }
        } else if let Ok(ip) = filter.parse::<Ipv4Addr>() {
            host_map.insert(ip, reverse_lookup_ip(ip));
        } else if let Some(ip) = crate::parser::resolve_hostname_sync(filter) {
            host_map.insert(ip, Some(filter.to_string()));
        }
    } else {
        // 1. Collect from existing state (resolved_hosts + configured backends)
        if let Ok(st) = shared.read() {
            for (h, ips) in &st.resolved_hosts {
                for &ip in ips {
                    if !ip.is_loopback() && !local_ips.contains(&ip) {
                        host_map.insert(ip, Some(h.clone()));
                    }
                }
            }
            for svc in st
                .candidate
                .services
                .values()
                .chain(st.running.services.values())
            {
                for b in &svc.backends {
                    if !b.ip.is_loopback() && !local_ips.contains(&b.ip) {
                        let entry = host_map.entry(b.ip).or_insert(None);
                        if entry.is_none() && b.host.is_some() {
                            *entry = b.host.clone();
                        }
                    }
                }
            }
        }

        // 2. Collect from `/etc/hosts`
        if let Ok(raw) = fs::read_to_string("/etc/hosts") {
            for line in raw.lines() {
                let clean = line.split('#').next().unwrap_or("").trim();
                let mut parts = clean.split_whitespace();
                if let (Some(ip_str), Some(host)) = (parts.next(), parts.next()) {
                    if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                        if !ip.is_loopback() && !local_ips.contains(&ip) {
                            host_map.insert(ip, Some(host.trim_end_matches(".local").to_string()));
                        }
                    }
                }
            }
        }

        // 3. Collect from `/proc/net/arp`
        if let Ok(raw) = fs::read_to_string("/proc/net/arp") {
            for line in raw.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 4 && parts[2] != "0x0" {
                    if let Ok(ip) = parts[0].parse::<Ipv4Addr>() {
                        if !ip.is_loopback() && !local_ips.contains(&ip) {
                            host_map.entry(ip).or_insert(None);
                        }
                    }
                }
            }
        }

        // 4. Probe common homelab container names via DNS
        for &name in COMMON_CONTAINER_HOSTNAMES {
            if let Some(ip) = crate::parser::resolve_hostname_sync(name) {
                if !ip.is_loopback() && !local_ips.contains(&ip) {
                    host_map.entry(ip).or_insert_with(|| Some(name.to_string()));
                }
            }
        }
    }

    for (ip, host_opt) in host_map.iter_mut() {
        if host_opt.is_none() {
            *host_opt = reverse_lookup_ip(*ip);
        }
    }

    let targets: Vec<(Ipv4Addr, Option<String>)> = host_map.into_iter().collect();
    let run_scan = async move {
        let mut handles = Vec::new();
        for (ip, host_opt) in targets {
            for &(port, default_name) in SCAN_PORTS {
                let h_cl = host_opt.clone();
                handles.push(tokio::spawn(async move {
                    probe_single_port(ip, h_cl, port, default_name).await
                }));
            }
        }
        let mut results = Vec::new();
        for h in handles {
            if let Ok(Some(item)) = h.await {
                results.push(item);
            }
        }
        results
    };

    let mut discovered = if let Ok(handle) = tokio::runtime::Handle::try_current() {
        std::thread::scope(|s| {
            s.spawn(move || handle.block_on(run_scan))
                .join()
                .unwrap_or_default()
        })
    } else if let Ok(rt) = tokio::runtime::Runtime::new() {
        rt.block_on(run_scan)
    } else {
        Vec::new()
    };

    discovered.sort_by(|a, b| a.ip.cmp(&b.ip).then_with(|| a.port.cmp(&b.port)));
    for (idx, item) in discovered.iter_mut().enumerate() {
        item.index = idx + 1;
    }

    if let Ok(mut st) = shared.write() {
        for item in &discovered {
            if let Some(h) = &item.host {
                let entry = st.resolved_hosts.entry(h.clone()).or_default();
                if !entry.contains(&item.ip) {
                    entry.push(item.ip);
                }
            }
        }
        st.discovered_services = discovered.clone();
    }
    crate::unikernel::persist_to_storage(shared);

    discovered
}

pub fn print_scan_table(discovered: &[crate::state::DiscoveredService], shared: &SharedState) {
    let existing_backends: BTreeSet<(Ipv4Addr, u16)> = {
        let st = shared.read().unwrap();
        st.candidate
            .services
            .values()
            .chain(st.running.services.values())
            .flat_map(|s| s.backends.iter().map(|b| (b.ip, b.port)))
            .collect()
    };

    println!(
        "{:<4} {:<16} {:<16} {:<7} {:<16} {:<10} {:<24}",
        "#".bold().underline(),
        "HOST".bold().underline(),
        "IP".bold().underline(),
        "PORT".bold().underline(),
        "SERVICE".bold().underline(),
        "LATENCY".bold().underline(),
        "STATUS / ADOPT".bold().underline()
    );

    if discovered.is_empty() {
        println!(
            "  {}",
            "(No open container/LAN services discovered; try 'scan <hostname>' or 'scan 192.168.1.0/24')"
                .dimmed()
        );
        return;
    }

    for d in discovered {
        let host_col = d.host.as_deref().unwrap_or("-");
        let adopted = existing_backends.contains(&(d.ip, d.port));
        let status_col = if adopted {
            "[ADOPTED]".green().bold().to_string()
        } else {
            format!("adopt {}", d.index).cyan().to_string()
        };
        let banner_suffix = if d.banner.is_empty() {
            String::new()
        } else {
            format!(" ({})", d.banner.dimmed())
        };
        println!(
            "{:<4} {:<16} {:<16} {:<7} {:<16} {:<10} {}{}",
            format!("#{}", d.index).yellow().bold(),
            host_col.bold(),
            d.ip,
            d.port,
            d.service_name.green().bold(),
            format!("{:.1}ms", d.latency_ms),
            status_col,
            banner_suffix
        );
    }
    println!(
        "\n  {} Run {} to create a dedicated DHCP VIP on port 80, or {} to attach to an existing VIP.",
        "Tip:".cyan().bold(),
        "adopt <# | host:port>".bold(),
        "adopt <#> vip 192.168.1.4".bold()
    );
}
