use super::wireguard::resolve_tunnel_config;
use crate::ast::GatewayServiceKind;
use crate::state::{HealthState, SharedState};
use anyhow::{bail, Context, Result};
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
    if let Err(e) = fs::write("/proc/sys/net/ipv4/ip_nonlocal_bind", "1\n") {
        eprintln!("nfty: cannot enable nonlocal proxy binding: {}", e);
    }
    let mut active_tasks: HashMap<(String, Ipv4Addr, u16, GatewayServiceKind), tokio::task::JoinHandle<()>> = HashMap::new();

    loop {
        let mut desired: Vec<(String, Ipv4Addr, u16, GatewayServiceKind)> = Vec::new();
        {
            if let Ok(mut st) = shared.write() {
                st.sync_from_disk_if_changed();
                let cfg = st.active_config();
                for gw in cfg.gateways.values() {
                    if gw.listen_ip.is_unspecified() {
                        continue;
                    }
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
                .any(|(gw, ip, port, kind)| *gw == k.0 && *ip == k.1 && *port == k.2 && *kind == k.3)
                && !handle.is_finished();
            if !keep {
                handle.abort();
            }
            keep
        });

        // Start new listeners
        for (gw_key, ip, port, kind) in desired {
            let key = (gw_key.clone(), ip, port, kind);
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
        return GatewayRouteDecision::KillswitchBlocked("Gateway state is unavailable".to_string());
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
                let iface = if t.iface.is_empty() {
                    format!("wg{}", global_i)
                } else {
                    t.iface.clone()
                };
                let route_idx = super::wireguard::wireguard_iface_index(&iface).unwrap_or(global_i);
                let fwmark = super::wireguard::wireguard_mark(route_idx) as u32;
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
    GatewayRouteDecision::KillswitchBlocked(format!("Gateway {} is no longer configured", gw_key))
}

async fn resolve_target_ipv4(target_host: &str, target_port: u16) -> Option<Ipv4Addr> {
    if let Ok(ip) = target_host.trim().parse::<Ipv4Addr>() {
        return Some(ip);
    }
    if let Ok(Ok(addrs)) = tokio::time::timeout(
        Duration::from_millis(2000),
        tokio::net::lookup_host((target_host.trim(), target_port)),
    )
    .await
    {
        for sa in addrs {
            if let std::net::IpAddr::V4(v4) = sa.ip() {
                return Some(v4);
            }
        }
    }
    crate::parser::resolve_hostname_sync(target_host)
}

pub fn is_forbidden_proxy_destination(shared: &SharedState, ip: Ipv4Addr) -> bool {
    if ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
    {
        return true;
    }
    if let Ok(st) = shared.read() {
        let cfg = st.active_config();
        for (k, vip) in &cfg.vips {
            if k.parse::<Ipv4Addr>().ok() == Some(ip) || vip.leased_ip == Some(ip) {
                return true;
            }
        }
        for svc in cfg.services.values() {
            if svc.listen_ip == Some(ip)
                || svc.vip.as_ref().and_then(|v| v.leased_ip) == Some(ip)
            {
                return true;
            }
        }
        for gw in cfg.gateways.values() {
            if gw.listen_ip == ip || gw.vip.as_ref().and_then(|v| v.leased_ip) == Some(ip) {
                return true;
            }
            if let Some(wg_in) = &gw.wg_ingress {
                if wg_in.address == ip {
                    return true;
                }
            }
        }
    }
    false
}

async fn connect_via_gateway_tunnel(
    shared: &SharedState,
    gw_key: &str,
    target_host: &str,
    target_port: u16,
) -> Result<(TcpStream, Option<String>)> {
    let decision = select_gateway_tunnel(shared, gw_key);
    let resolved_ip = match &decision {
        GatewayRouteDecision::ViaTunnel { .. } => {
            if let Ok(ip) = target_host.trim().parse::<Ipv4Addr>() {
                ip
            } else {
                let st = shared.read().map_err(|_| anyhow::anyhow!("Gateway state is unavailable"))?;
                st.resolved_hosts
                    .get(&target_host.trim().to_ascii_lowercase())
                    .and_then(|ips| ips.first().copied())
                    .ok_or_else(|| anyhow::anyhow!(
                        "Cannot resolve '{}' through the selected tunnel; use an IPv4 address or a cached host mapping",
                        target_host
                    ))?
            }
        }
        GatewayRouteDecision::KillswitchBlocked(reason) => bail!("{}", reason),
        GatewayRouteDecision::DirectHost => resolve_target_ipv4(target_host, target_port)
            .await
            .ok_or_else(|| anyhow::anyhow!("Could not resolve '{}'", target_host))?,
    };
    if is_forbidden_proxy_destination(shared, resolved_ip) {
        bail!(
            "Gateway proxy refuses connections to local or appliance-owned address {}",
            resolved_ip
        );
    }
    let target_addr = SocketAddr::new(std::net::IpAddr::V4(resolved_ip), target_port);

    let sock = TcpSocket::new_v4()?;
    let mut ep_key_opt = None;

    match decision {
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
                if libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    &mark_val as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
                ) != 0 {
                    return Err(std::io::Error::last_os_error()).context("Failed to set gateway socket mark");
                }
                let mut iface_cstr = iface.into_bytes();
                iface_cstr.push(0);
                if libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_BINDTODEVICE,
                    iface_cstr.as_ptr() as *const libc::c_void,
                    iface_cstr.len() as libc::socklen_t,
                ) != 0 {
                    return Err(std::io::Error::last_os_error()).context("Failed to bind gateway socket to tunnel");
                }
            }
            if let Some(ip) = local_ip {
                sock.bind(SocketAddr::new(std::net::IpAddr::V4(ip), 0))
                    .context("Failed to bind gateway socket to tunnel address")?;
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
            Err(e) => {
                eprintln!("nfty: gateway proxy could not bind {}: {}", bind_addr, e);
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    };

    loop {
        let Ok((client, peer)) = listener.accept().await else {
            continue;
        };
        let peer_ip = match peer.ip() {
            std::net::IpAddr::V4(v4) => v4,
            std::net::IpAddr::V6(_) => continue,
        };
        let allowed = {
            if let Ok(st) = shared.read() {
                let cfg = st.active_config();
                if let Some(gw) = cfg.gateways.get(&gw_key) {
                    st.is_ip_allowed(peer_ip, &gw.allow, &cfg.global_allow)
                } else {
                    false
                }
            } else {
                false
            }
        };
        if !allowed {
            continue;
        }
        let shared_c = shared.clone();
        let gw_k = gw_key.clone();
        tokio::spawn(async move {
            match kind {
                GatewayServiceKind::Privoxy => {
                    if let Err(e) = handle_privoxy_client(client, shared_c, gw_k).await {
                        eprintln!("[nfty gateway proxy] HTTP proxy request failed: {:#}", e);
                    }
                }
                GatewayServiceKind::Socks5 => {
                    if let Err(e) = handle_socks5_client(client, shared_c, gw_k).await {
                        eprintln!("[nfty gateway proxy] SOCKS5 request failed: {:#}", e);
                    }
                }
                GatewayServiceKind::Ssh
                | GatewayServiceKind::Dns
                | GatewayServiceKind::Api
                | GatewayServiceKind::Web => {}
            }
        });
    }
}

fn parse_proxy_authority(authority: &str, default_port: u16) -> Result<(&str, u16)> {
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, port.parse::<u16>().context("Invalid proxy target port")?),
        None => (authority, default_port),
    };
    if host.is_empty() || host.contains('[') || host.contains(']') || port == 0 {
        bail!("Invalid or unsupported proxy target");
    }
    Ok((host, port))
}

async fn handle_privoxy_client(
    mut client: TcpStream,
    shared: SharedState,
    gw_key: String,
) -> Result<()> {
    let buf = super::read_http_headers(&mut client, Duration::from_secs(5)).await?;
    let n = buf.len();
    let header_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .expect("HTTP headers were framed");
    let req_str = String::from_utf8_lossy(&buf[..header_end]);
    let mut lines = req_str.lines();
    let first_line = lines.next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() != 3 {
        client.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
        bail!("Invalid HTTP proxy request line");
    }
    let method = parts[0];
    let raw_target = parts[1];
    let http_ver = parts.get(2).copied().unwrap_or("HTTP/1.1");

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = match parse_proxy_authority(raw_target, 443) {
            Ok(target) => target,
            Err(e) => {
                client.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
                return Err(e);
            }
        };
        let (mut upstream, ep_opt) = match connect_via_gateway_tunnel(&shared, &gw_key, host, port).await {
            Ok(result) => result,
            Err(e) => {
                client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
                return Err(e);
            }
        };
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: nfty-privoxy\r\n\r\n")
            .await?;
        if header_end < n {
            upstream.write_all(&buf[header_end..n]).await?;
        }
        if let Ok((up_bytes, down_bytes)) =
            tokio::io::copy_bidirectional(&mut client, &mut upstream).await
        {
            if let Some(ep) = ep_opt {
                if let Ok(mut st) = shared.write() {
                    let rt = st.runtime.entry(ep).or_default();
                    rt.packets += 2;
                    rt.bytes += up_bytes + down_bytes + ((n - header_end) as u64);
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
    let (host, port) = match parse_proxy_authority(host_port, 80) {
        Ok(target) => target,
        Err(e) => {
            client.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
            return Err(e);
        }
    };

    let (mut upstream, ep_opt) = match connect_via_gateway_tunnel(&shared, &gw_key, host, port).await {
        Ok(result) => result,
        Err(e) => {
            client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
            return Err(e);
        }
    };

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
                "connection" | "proxy-connection" | "proxy-authorization" | "x-forwarded-for" | "via"
            ) || kl.starts_with("x-nfty-")
            {
                continue;
            }
        }
        sanitized.push_str(line);
        sanitized.push_str("\r\n");
    }
    sanitized.push_str("Connection: close\r\n\r\n");

    upstream.write_all(sanitized.as_bytes()).await?;
    if header_end < n {
        upstream.write_all(&buf[header_end..n]).await?;
    }
    if let Ok((up_bytes, down_bytes)) =
        tokio::io::copy_bidirectional(&mut client, &mut upstream).await
    {
        if let Some(ep) = ep_opt {
            if let Ok(mut st) = shared.write() {
                let rt = st.runtime.entry(ep).or_default();
                rt.packets += 2;
                rt.bytes += up_bytes
                    + down_bytes
                    + (sanitized.len() as u64)
                    + ((n - header_end) as u64);
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
    let mut buf = Vec::with_capacity(512);
    let mut tmp = [0u8; 512];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);

    while buf.len() < 2 {
        let n = tokio::time::timeout_at(deadline, client.read(&mut tmp)).await??;
        if n == 0 {
            bail!("Incomplete SOCKS5 greeting");
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    if buf[0] != 0x05 {
        return Ok(());
    }
    let nmethods = buf[1] as usize;
    let greet_len = 2 + nmethods;
    while buf.len() < greet_len {
        let n = tokio::time::timeout_at(deadline, client.read(&mut tmp)).await??;
        if n == 0 {
            bail!("Incomplete SOCKS5 authentication methods");
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    if !buf[2..greet_len].contains(&0x00) {
        client.write_all(&[0x05, 0xff]).await?;
        bail!("SOCKS5 client did not offer no-authentication mode");
    }
    client.write_all(&[0x05, 0x00]).await?;

    let mut req = buf.split_off(greet_len);
    while req.len() < 5 {
        let n = tokio::time::timeout_at(deadline, client.read(&mut tmp)).await??;
        if n == 0 {
            bail!("Incomplete SOCKS5 request");
        }
        req.extend_from_slice(&tmp[..n]);
    }
    if req[0] != 0x05 || req[1] != 0x01 || req[2] != 0x00 {
        client.write_all(&[0x05, 0x07, 0, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        bail!("Unsupported SOCKS5 request");
    }

    let req_hdr_len = match req[3] {
        0x01 => 10usize,
        0x03 => 5 + (req[4] as usize) + 2,
        _ => {
            client.write_all(&[0x05, 0x08, 0, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            bail!("Unsupported SOCKS5 address type");
        }
    };
    while req.len() < req_hdr_len {
        let n = tokio::time::timeout_at(deadline, client.read(&mut tmp)).await??;
        if n == 0 {
            bail!("Incomplete SOCKS5 destination");
        }
        req.extend_from_slice(&tmp[..n]);
    }

    let (host, port) = match req[3] {
        0x01 => {
            let ip = Ipv4Addr::new(req[4], req[5], req[6], req[7]);
            let port = u16::from_be_bytes([req[8], req[9]]);
            (ip.to_string(), port)
        }
        0x03 => {
            let dlen = req[4] as usize;
            let domain = std::str::from_utf8(&req[5..5 + dlen])?.to_string();
            let port = u16::from_be_bytes([req[5 + dlen], req[5 + dlen + 1]]);
            (domain, port)
        }
        _ => return Ok(()),
    };

    if host.is_empty() || port == 0 {
        client.write_all(&[0x05, 0x01, 0, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        bail!("Invalid SOCKS5 destination");
    }
    let (mut upstream, ep_opt) = match connect_via_gateway_tunnel(&shared, &gw_key, &host, port).await {
        Ok(result) => result,
        Err(e) => {
            client.write_all(&[0x05, 0x01, 0, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            return Err(e);
        }
    };
    let bound = match upstream.local_addr()? {
        SocketAddr::V4(addr) => addr,
        SocketAddr::V6(_) => bail!("Unexpected IPv6 SOCKS5 upstream"),
    };
    let ip = bound.ip().octets();
    let port = bound.port().to_be_bytes();
    client.write_all(&[0x05, 0x00, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], port[0], port[1]]).await?;

    let extra_payload = &req[req_hdr_len..];
    if !extra_payload.is_empty() {
        upstream.write_all(extra_payload).await?;
    }

    if let Ok((up_bytes, down_bytes)) =
        tokio::io::copy_bidirectional(&mut client, &mut upstream).await
    {
        if let Some(ep) = ep_opt {
            if let Ok(mut st) = shared.write() {
                let rt = st.runtime.entry(ep).or_default();
                rt.packets += 2;
                rt.bytes += up_bytes + down_bytes + (extra_payload.len() as u64);
            }
        }
    }
    Ok(())
}
