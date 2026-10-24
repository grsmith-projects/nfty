use super::wireguard::resolve_tunnel_config;
use crate::ast::GatewayServiceKind;
use crate::state::{HealthState, SharedState};
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};

static GW_PROXY_RR_COUNTER: AtomicUsize = AtomicUsize::new(0);

pub async fn run_gateway_proxy_supervisor(shared: SharedState) {
    let _ = fs::write("/proc/sys/net/ipv4/ip_nonlocal_bind", "1\n");
    let mut active_tasks: HashMap<(Ipv4Addr, u16, GatewayServiceKind), tokio::task::JoinHandle<()>> =
        HashMap::new();

    loop {
        let mut desired: Vec<(String, Ipv4Addr, u16, GatewayServiceKind)> = Vec::new();
        {
            if let Ok(mut st) = shared.write() {
                st.sync_from_disk_if_changed();
                let cfg = st.active_config();
                for gw in cfg.gateways.values() {
                    for gs in &gw.services {
                        if matches!(
                            gs.kind,
                            GatewayServiceKind::Privoxy | GatewayServiceKind::Socks5
                        ) {
                            desired.push((gw.key.clone(), gw.listen_ip, gs.port, gs.kind));
                        }
                    }
                }
            }
        }

        // Stop listeners that were removed
        active_tasks.retain(|k, handle| {
            let keep = desired
                .iter()
                .any(|(_, ip, port, kind)| *ip == k.0 && *port == k.1 && *kind == k.2);
            if !keep {
                handle.abort();
            }
            keep
        });

        // Start new listeners
        for (gw_key, ip, port, kind) in desired {
            let key = (ip, port, kind);
            if !active_tasks.contains_key(&key) {
                let shared_cl = shared.clone();
                let handle = tokio::spawn(async move {
                    run_single_gateway_proxy(shared_cl, gw_key, ip, port, kind).await;
                });
                active_tasks.insert(key, handle);
            }
        }

        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

#[derive(Debug, Clone)]
enum GatewayRouteDecision {
    /// Gateway has no tunnels configured (or all tunnels are down and killswitch is off): route directly via host eth0
    DirectHost,
    /// Route through an active WireGuard tunnel `(iface, fwmark, ep_key, local_wg_ip)`
    ViaTunnel {
        iface: String,
        fwmark: u32,
        ep_key: String,
        local_ip: Option<Ipv4Addr>,
    },
    /// Gateway has tunnels configured with `killswitch on`, and all tunnels are currently DOWN
    KillswitchBlocked(String),
}

/// Selects the routing decision for a gateway: if a tunnel exists and is UP, routes via that tunnel.
fn select_gateway_tunnel(shared: &SharedState, gw_key: &str) -> GatewayRouteDecision {
    if let Ok(mut st) = shared.write() {
        st.sync_from_disk_if_changed();
    }
    let Ok(st) = shared.read() else {
        return GatewayRouteDecision::DirectHost;
    };
    let cfg = st.active_config();

    let mut base_idx = 0usize;
    for (k, gw) in &cfg.gateways {
        if k == gw_key {
            if gw.tunnels.is_empty() {
                return GatewayRouteDecision::DirectHost;
            }
            let mut active = Vec::new();
            for (local_i, t) in gw.tunnels.iter().enumerate() {
                let global_i = base_idx + local_i;
                let fwmark = (0x101 + global_i) as u32;
                let iface = if t.iface.is_empty() {
                    format!("wg{}", global_i)
                } else {
                    t.iface.clone()
                };
                let iface_exists = Path::new(&format!("/sys/class/net/{}", iface)).exists();
                let healthy = iface_exists
                    && st
                        .runtime
                        .get(&t.endpoint_key())
                        .map(|rt| !rt.drained && rt.health != HealthState::Down)
                        .unwrap_or(true);
                if healthy {
                    let local_ip = resolve_tunnel_config(t)
                        .ok()
                        .and_then(|p| p.address.split('/').next()?.trim().parse::<Ipv4Addr>().ok());
                    for _ in 0..t.weight.max(1) {
                        active.push((iface.clone(), fwmark, t.endpoint_key(), local_ip));
                    }
                }
            }
            // If runtime hasn't probed yet, check if any configured tunnel interface is present in kernel
            if active.is_empty() {
                for (local_i, t) in gw.tunnels.iter().enumerate() {
                    let global_i = base_idx + local_i;
                    let fwmark = (0x101 + global_i) as u32;
                    let iface = if t.iface.is_empty() {
                        format!("wg{}", global_i)
                    } else {
                        t.iface.clone()
                    };
                    if Path::new(&format!("/sys/class/net/{}", iface)).exists() {
                        let not_down = st
                            .runtime
                            .get(&t.endpoint_key())
                            .map(|rt| !rt.drained && rt.health != HealthState::Down)
                            .unwrap_or(true);
                        if not_down {
                            let local_ip = resolve_tunnel_config(t).ok().and_then(|p| {
                                p.address.split('/').next()?.trim().parse::<Ipv4Addr>().ok()
                            });
                            active.push((iface, fwmark, t.endpoint_key(), local_ip));
                        }
                    }
                }
            }
            if active.is_empty() {
                if gw.killswitch {
                    return GatewayRouteDecision::KillswitchBlocked(format!(
                        "Gateway {} killswitch is ON and no WireGuard tunnels are UP",
                        gw_key
                    ));
                } else {
                    return GatewayRouteDecision::DirectHost;
                }
            }
            let idx = GW_PROXY_RR_COUNTER.fetch_add(1, Ordering::Relaxed) % active.len();
            let (iface, fwmark, ep_key, local_ip) = active.swap_remove(idx);
            return GatewayRouteDecision::ViaTunnel {
                iface,
                fwmark,
                ep_key,
                local_ip,
            };
        }
        base_idx += gw.tunnels.len();
    }
    GatewayRouteDecision::DirectHost
}

async fn connect_via_gateway_tunnel(
    shared: &SharedState,
    gw_key: &str,
    target_host: &str,
    target_port: u16,
) -> Result<(TcpStream, Option<String>)> {
    let resolved_ip = crate::parser::resolve_hostname_sync(target_host)
        .ok_or_else(|| anyhow::anyhow!("Could not resolve '{}'", target_host))?;
    let target_addr = SocketAddr::new(std::net::IpAddr::V4(resolved_ip), target_port);

    let sock = TcpSocket::new_v4()?;
    let mut ep_key_opt = None;

    match select_gateway_tunnel(shared, gw_key) {
        GatewayRouteDecision::KillswitchBlocked(reason) => {
            bail!("{}", reason);
        }
        GatewayRouteDecision::ViaTunnel {
            iface,
            fwmark,
            ep_key,
            local_ip,
        } => {
            ep_key_opt = Some(ep_key);
            let fd = sock.as_raw_fd();
            unsafe {
                let mark_val: libc::c_uint = fwmark;
                let _ = libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    &mark_val as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
                );
                let mut iface_cstr = iface.into_bytes();
                iface_cstr.push(0);
                let _ = libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_BINDTODEVICE,
                    iface_cstr.as_ptr() as *const libc::c_void,
                    iface_cstr.len() as libc::socklen_t,
                );
            }
            if let Some(ip) = local_ip {
                let _ = sock.bind(SocketAddr::new(std::net::IpAddr::V4(ip), 0));
            }
        }
        GatewayRouteDecision::DirectHost => {}
    }

    let stream = tokio::time::timeout(Duration::from_secs(6), sock.connect(target_addr)).await??;
    Ok((stream, ep_key_opt))
}

async fn run_single_gateway_proxy(
    shared: SharedState,
    gw_key: String,
    listen_ip: Ipv4Addr,
    port: u16,
    kind: GatewayServiceKind,
) {
    let bind_addr = SocketAddr::new(std::net::IpAddr::V4(listen_ip), port);
    let listener = loop {
        match TcpListener::bind(bind_addr).await {
            Ok(l) => break l,
            Err(_) => {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    };

    loop {
        let Ok((client, _peer)) = listener.accept().await else {
            continue;
        };
        let shared_c = shared.clone();
        let gw_k = gw_key.clone();
        tokio::spawn(async move {
            match kind {
                GatewayServiceKind::Privoxy => {
                    let _ = handle_privoxy_client(client, shared_c, gw_k).await;
                }
                GatewayServiceKind::Socks5 => {
                    let _ = handle_socks5_client(client, shared_c, gw_k).await;
                }
                GatewayServiceKind::Ssh | GatewayServiceKind::Dns => {}
            }
        });
    }
}

async fn handle_privoxy_client(
    mut client: TcpStream,
    shared: SharedState,
    gw_key: String,
) -> Result<()> {
    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf)).await??;
    if n == 0 {
        return Ok(());
    }
    let req_str = String::from_utf8_lossy(&buf[..n]);
    let mut lines = req_str.lines();
    let first_line = lines.next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Ok(());
    }
    let method = parts[0];
    let raw_target = parts[1];
    let http_ver = parts.get(2).copied().unwrap_or("HTTP/1.1");

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = if let Some((h, p)) = raw_target.split_once(':') {
            (h, p.parse::<u16>().unwrap_or(443))
        } else {
            (raw_target, 443)
        };
        let (mut upstream, ep_opt) =
            connect_via_gateway_tunnel(&shared, &gw_key, host, port).await?;
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: nfty-privoxy\r\n\r\n")
            .await?;
        if let Ok((up_bytes, down_bytes)) =
            tokio::io::copy_bidirectional(&mut client, &mut upstream).await
        {
            if let Some(ep) = ep_opt {
                if let Ok(mut st) = shared.write() {
                    let rt = st.runtime.entry(ep).or_default();
                    rt.packets += 2;
                    rt.bytes += up_bytes + down_bytes;
                }
            }
        }
        return Ok(());
    }

    let without_scheme = raw_target.strip_prefix("http://").unwrap_or(raw_target);
    let (host_port, rel_path) = match without_scheme.find('/') {
        Some(idx) => (&without_scheme[..idx], &without_scheme[idx..]),
        None => (without_scheme, "/"),
    };
    let (host, port) = if let Some((h, p)) = host_port.split_once(':') {
        (h, p.parse::<u16>().unwrap_or(80))
    } else {
        (host_port, 80)
    };

    let (mut upstream, ep_opt) = connect_via_gateway_tunnel(&shared, &gw_key, host, port).await?;

    // Rebuild privacy-sanitized HTTP request (strip Proxy-Connection, Via, X-Forwarded-For)
    let mut sanitized = format!("{} {} {}\r\n", method, rel_path, http_ver);
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, _)) = line.split_once(':') {
            let kl = k.trim().to_ascii_lowercase();
            if matches!(
                kl.as_str(),
                "proxy-connection" | "proxy-authorization" | "x-forwarded-for" | "via"
            ) {
                continue;
            }
        }
        sanitized.push_str(line);
        sanitized.push_str("\r\n");
    }
    sanitized.push_str("Connection: close\r\n\r\n");

    upstream.write_all(sanitized.as_bytes()).await?;
    if let Ok((up_bytes, down_bytes)) =
        tokio::io::copy_bidirectional(&mut client, &mut upstream).await
    {
        if let Some(ep) = ep_opt {
            if let Ok(mut st) = shared.write() {
                let rt = st.runtime.entry(ep).or_default();
                rt.packets += 2;
                rt.bytes += up_bytes + down_bytes + (sanitized.len() as u64);
            }
        }
    }
    Ok(())
}

async fn handle_socks5_client(
    mut client: TcpStream,
    shared: SharedState,
    gw_key: String,
) -> Result<()> {
    let mut greet = [0u8; 258];
    let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut greet)).await??;
    if n < 2 || greet[0] != 0x05 {
        return Ok(());
    }
    client.write_all(&[0x05, 0x00]).await?;

    let mut req = [0u8; 512];
    let n = tokio::time::timeout(Duration::from_secs(5), client.read(&mut req)).await??;
    if n < 7 || req[0] != 0x05 || req[1] != 0x01 {
        return Ok(());
    }

    let (host, port) = match req[3] {
        0x01 if n >= 10 => {
            let ip = Ipv4Addr::new(req[4], req[5], req[6], req[7]);
            let port = u16::from_be_bytes([req[8], req[9]]);
            (ip.to_string(), port)
        }
        0x03 => {
            let dlen = req[4] as usize;
            if n < 5 + dlen + 2 {
                return Ok(());
            }
            let domain = std::str::from_utf8(&req[5..5 + dlen])?.to_string();
            let port = u16::from_be_bytes([req[5 + dlen], req[5 + dlen + 1]]);
            (domain, port)
        }
        _ => return Ok(()),
    };

    let (mut upstream, ep_opt) = connect_via_gateway_tunnel(&shared, &gw_key, &host, port).await?;
    client
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    if let Ok((up_bytes, down_bytes)) =
        tokio::io::copy_bidirectional(&mut client, &mut upstream).await
    {
        if let Some(ep) = ep_opt {
            if let Ok(mut st) = shared.write() {
                let rt = st.runtime.entry(ep).or_default();
                rt.packets += 2;
                rt.bytes += up_bytes + down_bytes;
            }
        }
    }
    Ok(())
}
