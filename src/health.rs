use crate::ast::{Backend, HealthCheckConfig, HealthCheckKind};
use crate::compiler::{apply_vip_commands, generate_vip_commands, reload_kernel_from_state};
use crate::parser::expand_ip_wildcard_to_cidr;
use crate::state::{HealthState, SharedState};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Command;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpStream};

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProbeOutcome {
    pub endpoint: String,
    pub state: HealthState,
    pub latency_ms: Option<f64>,
    pub error: Option<String>,
}

pub async fn probe_backend(backend: &Backend, check: Option<&HealthCheckConfig>) -> ProbeOutcome {
    let endpoint = backend.endpoint();
    let kind = check
        .map(|c| c.kind.clone())
        .unwrap_or(HealthCheckKind::Tcp);
    let addr = SocketAddr::new(IpAddr::V4(backend.ip), backend.port);
    let timeout_dur = Duration::from_millis(1500);
    let start = Instant::now();

    match kind {
        HealthCheckKind::Tcp => {
            match tokio::time::timeout(timeout_dur, TcpStream::connect(addr)).await {
                Ok(Ok(_stream)) => ProbeOutcome {
                    endpoint,
                    state: HealthState::Up,
                    latency_ms: Some(start.elapsed().as_secs_f64() * 1000.0),
                    error: None,
                },
                Ok(Err(e)) => ProbeOutcome {
                    endpoint,
                    state: HealthState::Down,
                    latency_ms: None,
                    error: Some(e.to_string()),
                },
                Err(_) => ProbeOutcome {
                    endpoint,
                    state: HealthState::Down,
                    latency_ms: None,
                    error: Some("TCP connect timeout (1.5s)".to_string()),
                },
            }
        }
        HealthCheckKind::Http { path } => {
            match tokio::time::timeout(timeout_dur, async {
                let mut stream = TcpStream::connect(addr).await?;
                let req = format!(
                    "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: nfty/0.1\r\nConnection: close\r\n\r\n",
                    path, backend.ip
                );
                stream.write_all(req.as_bytes()).await?;
                let mut buf = [0u8; 256];
                let n = stream.read(&mut buf).await?;
                Ok::<String, std::io::Error>(String::from_utf8_lossy(&buf[..n]).to_string())
            })
            .await
            {
                Ok(Ok(resp)) => {
                    let first_line = resp.lines().next().unwrap_or("");
                    let ok = first_line.starts_with("HTTP/1.1 2")
                        || first_line.starts_with("HTTP/1.0 2")
                        || first_line.starts_with("HTTP/1.1 3")
                        || first_line.starts_with("HTTP/1.0 3");
                    if ok {
                        ProbeOutcome {
                            endpoint,
                            state: HealthState::Up,
                            latency_ms: Some(start.elapsed().as_secs_f64() * 1000.0),
                            error: None,
                        }
                    } else {
                        ProbeOutcome {
                            endpoint,
                            state: HealthState::Down,
                            latency_ms: Some(start.elapsed().as_secs_f64() * 1000.0),
                            error: Some(format!(
                                "HTTP check failed: {}",
                                if first_line.is_empty() {
                                    "empty response"
                                } else {
                                    first_line
                                }
                            )),
                        }
                    }
                }
                Ok(Err(e)) => ProbeOutcome {
                    endpoint,
                    state: HealthState::Down,
                    latency_ms: None,
                    error: Some(e.to_string()),
                },
                Err(_) => ProbeOutcome {
                    endpoint,
                    state: HealthState::Down,
                    latency_ms: None,
                    error: Some("HTTP check timeout (1.5s)".to_string()),
                },
            }
        }
        HealthCheckKind::Ping => {
            let ip_str = backend.ip.to_string();
            let res = tokio::task::spawn_blocking(move || {
                let t0 = Instant::now();
                let out = Command::new("ping")
                    .args(["-c", "1", "-W", "1", &ip_str])
                    .output();
                (out, t0.elapsed())
            })
            .await;

            match res {
                Ok((Ok(output), elapsed)) if output.status.success() => ProbeOutcome {
                    endpoint,
                    state: HealthState::Up,
                    latency_ms: Some(elapsed.as_secs_f64() * 1000.0),
                    error: None,
                },
                Ok((Ok(output), _)) => {
                    let err_str = String::from_utf8_lossy(&output.stderr).trim().to_string();
                    ProbeOutcome {
                        endpoint,
                        state: HealthState::Down,
                        latency_ms: None,
                        error: Some(if err_str.is_empty() {
                            "ICMP echo timeout".to_string()
                        } else {
                            err_str
                        }),
                    }
                }
                _ => ProbeOutcome {
                    endpoint,
                    state: HealthState::Down,
                    latency_ms: None,
                    error: Some("Failed to execute ping probe".to_string()),
                },
            }
        }
        HealthCheckKind::Disabled => ProbeOutcome {
            endpoint,
            state: HealthState::Up,
            latency_ms: None,
            error: None,
        },
    }
}

pub async fn run_all_probes_once(shared: &SharedState) -> Vec<ProbeOutcome> {
    run_probes_internal(shared, true).await
}

pub async fn run_due_probes_once(shared: &SharedState) -> Vec<ProbeOutcome> {
    run_probes_internal(shared, false).await
}

async fn run_probes_internal(shared: &SharedState, force_all: bool) -> Vec<ProbeOutcome> {
    let (targets, wg_targets): (
        Vec<(Backend, Option<HealthCheckConfig>)>,
        Vec<(String, String)>,
    ) = {
        let st = shared.read().unwrap();
        let cfg = st.active_config();
        let now = Instant::now();
        let mut list = Vec::new();
        for svc in cfg.services.values() {
            if matches!(
                svc.check.as_ref().map(|c| &c.kind),
                Some(HealthCheckKind::Disabled)
            ) || (svc.check.is_none() && svc.proto == crate::ast::Proto::Udp)
            {
                continue;
            }
            let interval_secs = svc.check.as_ref().map(|c| c.interval_secs.max(1)).unwrap_or(5);
            for b in &svc.backends {
                let due = force_all
                    || st
                        .runtime
                        .get(&b.endpoint())
                        .and_then(|rt| rt.last_checked)
                        .map(|last| now.duration_since(last).as_secs() >= interval_secs)
                        .unwrap_or(true);
                if due {
                    list.push((b.clone(), svc.check.clone()));
                }
            }
        }
        let mut wgs = Vec::new();
        for gw in cfg.gateways.values() {
            if matches!(
                gw.check.as_ref().map(|c| &c.kind),
                Some(HealthCheckKind::Disabled)
            ) {
                continue;
            }
            let interval_secs = gw.check.as_ref().map(|c| c.interval_secs.max(1)).unwrap_or(5);
            for t in &gw.tunnels {
                let ep_key = t.endpoint_key();
                let due = force_all
                    || st
                        .runtime
                        .get(&ep_key)
                        .and_then(|rt| rt.last_checked)
                        .map(|last| now.duration_since(last).as_secs() >= interval_secs)
                        .unwrap_or(true);
                if due {
                    wgs.push((ep_key, t.iface.clone()));
                }
            }
        }
        (list, wgs)
    };

    let mut handles = Vec::new();
    for (b, chk) in targets {
        handles.push(tokio::spawn(async move {
            probe_backend(&b, chk.as_ref()).await
        }));
    }
    for (ep_key, iface) in wg_targets {
        handles.push(tokio::spawn(async move {
            let (state, latency_ms, error) = crate::features::probe_wg_tunnel(&iface).await;
            ProbeOutcome {
                endpoint: ep_key,
                state,
                latency_ms,
                error,
            }
        }));
    }

    let mut outcomes = Vec::new();
    for h in handles {
        if let Ok(o) = h.await {
            outcomes.push(o);
        }
    }

    let mut health_changed = false;
    {
        let mut st = shared.write().unwrap();
        for o in &outcomes {
            let entry = st.runtime.entry(o.endpoint.clone()).or_default();
            if entry.health != o.state {
                health_changed = true;
            }
            entry.health = o.state;
            entry.latency_ms = o.latency_ms;
            entry.last_error = o.error.clone();
            entry.last_checked = Some(Instant::now());
        }
        for (vip_key, v) in &st.running.vips {
            if v.dhcp {
                let mv_iface = crate::compiler::dhcp_macvlan_iface_name(vip_key);
                let ip_file = format!("/run/nfty-dhcp-{}.ip", mv_iface);
                if let Ok(raw_ip) = fs::read_to_string(&ip_file) {
                    if let Ok(leased_ip) = raw_ip.trim().parse::<Ipv4Addr>() {
                        if v.leased_ip != Some(leased_ip) {
                            health_changed = true;
                        }
                    }
                }
            }
        }
        for (gw_key, gw) in &st.running.gateways {
            if let Some(v) = &gw.vip {
                if v.dhcp {
                    let mv_iface = crate::compiler::dhcp_macvlan_iface_name(gw_key);
                    let ip_file = format!("/run/nfty-dhcp-{}.ip", mv_iface);
                    if let Ok(raw_ip) = fs::read_to_string(&ip_file) {
                        if let Ok(leased_ip) = raw_ip.trim().parse::<Ipv4Addr>() {
                            if v.leased_ip != Some(leased_ip) || gw.listen_ip != leased_ip {
                                health_changed = true;
                            }
                        }
                    }
                }
            }
        }
        if health_changed && !st.running.is_empty() {
            let _ = reload_kernel_from_state(&mut st);
        }
    }

    outcomes
}

/// Continuously resolves hostnames and discovers wildcard host entries from:
/// 1. Explicit hostnames in `global_allow` and per-service `allow` lists (via async DNS)
/// 2. `/etc/hosts` and `/var/lib/misc/dnsmasq.leases` (for wildcard LAN domains like `*.office.lan`)
/// 3. Previously registered/known hostnames in `resolved_hosts`
/// Automatically reloads the kernel `nftables` allow-list sets if any resolved IP changes!
pub async fn refresh_allowlist_hosts(shared: &SharedState) {
    let mut discovered: BTreeMap<String, BTreeSet<Ipv4Addr>> = BTreeMap::new();

    // 1. Parse /etc/hosts so local wildcard patterns like `*.lan` or `*.local` match local entries
    if let Ok(hosts_txt) = fs::read_to_string("/etc/hosts") {
        for line in hosts_txt.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(ip) = parts[0].parse::<Ipv4Addr>() {
                    for host in &parts[1..] {
                        discovered
                            .entry(host.to_ascii_lowercase())
                            .or_default()
                            .insert(ip);
                    }
                }
            }
        }
    }

    // 2. Collect all explicit hostnames to resolve via DNS
    let hosts_to_query: BTreeSet<String> = {
        let st = shared.read().unwrap();
        let mut set = BTreeSet::new();
        for h in st.resolved_hosts.keys() {
            if !h.contains('*') {
                set.insert(h.clone());
            }
        }
        for entry in st
            .running
            .global_allow
            .iter()
            .chain(st.candidate.global_allow.iter())
            .chain(
                st.running
                    .services
                    .values()
                    .chain(st.candidate.services.values())
                    .flat_map(|s| s.allow.iter()),
            )
            .chain(
                st.running
                    .gateways
                    .values()
                    .chain(st.candidate.gateways.values())
                    .flat_map(|g| g.allow.iter()),
            )
        {
            if expand_ip_wildcard_to_cidr(entry).is_none() && !entry.contains('*') {
                set.insert(entry.to_ascii_lowercase());
            }
        }
        for svc in st.running.services.values().chain(st.candidate.services.values()) {
            for b in &svc.backends {
                if let Some(h) = &b.host {
                    set.insert(h.to_ascii_lowercase());
                }
            }
        }
        for gw in st.running.gateways.values().chain(st.candidate.gateways.values()) {
            for fwd in &gw.forwards {
                if let Some(h) = &fwd.backend.host {
                    set.insert(h.to_ascii_lowercase());
                }
            }
        }
        set
    };

    for host in hosts_to_query {
        if let Ok(Ok(addrs)) =
            tokio::time::timeout(Duration::from_millis(1200), lookup_host((host.as_str(), 80)))
                .await
        {
            for sock in addrs {
                if let IpAddr::V4(ip4) = sock.ip() {
                    discovered.entry(host.clone()).or_default().insert(ip4);
                }
            }
        }
    }

    // 3. Merge into AppState and reload nftables if any allow-list or backend hostname IP changed
    let mut st = shared.write().unwrap();
    let mut changed = false;
    for (host, ips_set) in discovered {
        let ips_vec: Vec<Ipv4Addr> = ips_set.into_iter().collect();
        if ips_vec.is_empty() {
            continue;
        }
        match st.resolved_hosts.get(&host) {
            Some(existing) if existing == &ips_vec => {}
            _ => {
                st.resolved_hosts.insert(host, ips_vec);
                changed = true;
            }
        }
    }

    // 4. Sync resolved IPs into any backend configured by hostname (`to plex:32400`)
    let resolved_map = st.resolved_hosts.clone();
    let st_ref = &mut *st;
    for svc in st_ref
        .running
        .services
        .values_mut()
        .chain(st_ref.candidate.services.values_mut())
    {
        for b in &mut svc.backends {
            if let Some(h) = &b.host {
                if let Some(ips) = resolved_map.get(&h.to_ascii_lowercase()) {
                    if let Some(&first_ip) = ips.first() {
                        if b.ip != first_ip {
                            b.ip = first_ip;
                            changed = true;
                        }
                    }
                }
            }
        }
    }

    for gw in st_ref
        .running
        .gateways
        .values_mut()
        .chain(st_ref.candidate.gateways.values_mut())
    {
        for fwd in &mut gw.forwards {
            if let Some(h) = &fwd.backend.host {
                if let Some(ips) = resolved_map.get(&h.to_ascii_lowercase()) {
                    if let Some(&first_ip) = ips.first() {
                        if fwd.backend.ip != first_ip {
                            fwd.backend.ip = first_ip;
                            changed = true;
                        }
                    }
                }
            }
        }
    }

    if changed {
        st.sync_runtime_entries();
        if !st.running.is_empty() {
            let _ = reload_kernel_from_state(&mut st);
        }
    }
}

pub fn poll_kernel_counters(shared: &SharedState, dt_secs: f64) {
    let output = match Command::new("nft")
        .args(["list", "table", "ip", "nfty"])
        .output()
    {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return,
    };

    let mut st = shared.write().unwrap();
    for line in output.lines() {
        if let Some(comment_idx) = line.find("nfty:backend=") {
            let after = &line[comment_idx + "nfty:backend=".len()..];
            let endpoint = after.split('"').next().unwrap_or("").to_string();
            let mut pkts = None;
            let mut bytes = None;
            let tokens: Vec<&str> = line.split_whitespace().collect();
            for i in 0..tokens.len() {
                if tokens[i] == "packets" && i + 1 < tokens.len() {
                    pkts = tokens[i + 1].parse::<u64>().ok();
                }
                if tokens[i] == "bytes" && i + 1 < tokens.len() {
                    bytes = tokens[i + 1].parse::<u64>().ok();
                }
            }
            if let (Some(p), Some(b)) = (pkts, bytes) {
                let rt = st.runtime.entry(endpoint).or_default();
                if dt_secs > 0.0 && p >= rt.packets && b >= rt.bytes {
                    rt.pps = (p - rt.packets) as f64 / dt_secs;
                    rt.bps = (b - rt.bytes) as f64 / dt_secs;
                }
                rt.packets = p;
                rt.bytes = b;
            }
        }
    }
}

pub fn spawn_background_tasks(shared: SharedState) {
    tokio::spawn(async move {
        // Initial host resolution pass
        refresh_allowlist_hosts(&shared).await;

        let mut tick_count: u64 = 0;
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            tick_count += 1;

            // 1. Sync any config updates from disk (/data/Nftyfile) and check commit-confirm rollback timer
            let mut reverted = false;
            {
                let mut st = shared.write().unwrap();
                st.sync_from_disk_if_changed();
                if let Some(pending) = &st.pending_confirm {
                    if Instant::now() >= pending.deadline {
                        let old_running = st.running.clone();
                        let revert_cfg = pending.revert_to.clone();
                        let vip_cmds = generate_vip_commands(&old_running, &revert_cfg);
                        let _ = apply_vip_commands(&vip_cmds);
                        st.running = revert_cfg.clone();
                        st.candidate = revert_cfg;
                        st.pending_confirm = None;
                        let _ = reload_kernel_from_state(&mut st);
                        reverted = true;
                    }
                }
            }
            if reverted {
                eprintln!(
                    "\n[nfty watchdog] Commit confirmation timer expired! Automatically rolled back to previous running configuration."
                );
            }

            // 2. Poll counters every 2 seconds
            if tick_count % 2 == 0 {
                poll_kernel_counters(&shared, 2.0);
            }

            // 3. Run due health checks every second (respecting per-service/gateway interval_secs) & DNS/wildcard allow-list sync every 5 seconds
            let _ = run_due_probes_once(&shared).await;
            if tick_count % 5 == 0 {
                refresh_allowlist_hosts(&shared).await;
            }
        }
    });
}
