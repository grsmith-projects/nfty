use super::wireguard::resolve_tunnel_config;
use crate::ast::{DnsRecord, GatewayServiceKind};
use crate::state::{HealthState, SharedState};
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};

static GW_PROXY_RR_COUNTER: AtomicUsize = AtomicUsize::new(0);
static DNS_QUERY_TXID: AtomicU16 = AtomicU16::new(0x1337);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ProxyTargetOwner {
    Gateway(String),
    VipService(String),
}

pub async fn run_gateway_proxy_supervisor(shared: SharedState) {
    if let Err(e) = fs::write("/proc/sys/net/ipv4/ip_nonlocal_bind", "1\n") {
        eprintln!("nfty: cannot enable nonlocal proxy binding: {}", e);
    }
    let mut active_tasks: HashMap<(ProxyTargetOwner, Ipv4Addr, u16), tokio::task::JoinHandle<()>> =
        HashMap::new();

    loop {
        let mut desired: Vec<(ProxyTargetOwner, Ipv4Addr, u16)> = Vec::new();
        {
            if let Ok(mut st) = shared.write() {
                st.sync_from_disk_if_changed();
                let cfg = st.active_config();
                for gw in cfg.gateways.values() {
                    if gw.listen_ip.is_unspecified() {
                        continue;
                    }
                    for gs in &gw.services {
                        if gs.kind == GatewayServiceKind::Proxy {
                            desired.push((
                                ProxyTargetOwner::Gateway(gw.key.clone()),
                                gw.listen_ip,
                                gs.port,
                            ));
                        }
                    }
                }
                for svc in cfg.services.values() {
                    if !svc.is_local_proxy() {
                        continue;
                    }
                    let ip_opt = svc
                        .listen_ip
                        .or_else(|| svc.vip.as_ref().and_then(|v| v.leased_ip));
                    if let Some(ip) = ip_opt {
                        if !ip.is_unspecified() {
                            desired.push((
                                ProxyTargetOwner::VipService(svc.key.clone()),
                                ip,
                                svc.port,
                            ));
                        }
                    }
                }
            }
        }

        // Stop listeners that were removed
        active_tasks.retain(|k, handle| {
            let keep = desired
                .iter()
                .any(|(owner, ip, port)| *owner == k.0 && *ip == k.1 && *port == k.2)
                && !handle.is_finished();
            if !keep {
                handle.abort();
            }
            keep
        });

        // Start new listeners
        for (owner, ip, port) in desired {
            let key = (owner.clone(), ip, port);
            if !active_tasks.contains_key(&key) {
                let shared_cl = shared.clone();
                let handle = tokio::spawn(async move {
                    run_single_proxy_listener(shared_cl, owner, ip, port).await;
                });
                active_tasks.insert(key, handle);
            }
        }

        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

#[derive(Debug, Clone)]
enum GatewayRouteDecision {
    /// Route directly via host eth0
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

fn domain_matches_pattern(host: &str, pattern: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let p = pattern
        .trim()
        .trim_start_matches("*.")
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if h.is_empty() || p.is_empty() {
        return false;
    }
    h == p || h.ends_with(&format!(".{}", p))
}

fn is_host_blocked_by_dns(shared: &SharedState, host: &str) -> bool {
    let Ok(st) = shared.read() else {
        return false;
    };
    let cfg = st.active_config();
    let Some(dns) = &cfg.dns else {
        return false;
    };
    dns.blocks
        .iter()
        .any(|blk| domain_matches_pattern(host, blk))
}

fn lookup_local_dns_or_cached_host(shared: &SharedState, host: &str) -> Option<Ipv4Addr> {
    let clean = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let Ok(st) = shared.read() else {
        return None;
    };
    let cfg = st.active_config();
    if let Some(dns) = &cfg.dns {
        for rec in &dns.records {
            match rec {
                DnsRecord::A { name, ips } if name.trim_end_matches('.').eq_ignore_ascii_case(&clean) => {
                    if let Some(ip) = ips.first().copied() {
                        return Some(ip);
                    }
                }
                DnsRecord::Address { domain, ip } if domain_matches_pattern(&clean, domain) => {
                    return Some(*ip);
                }
                _ => {}
            }
        }
    }
    st.resolved_hosts
        .get(&clean)
        .and_then(|ips| ips.first().copied())
}

fn configured_dns_upstream_ips(shared: &SharedState) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    if let Ok(st) = shared.read() {
        let cfg = st.active_config();
        if let Some(dns) = &cfg.dns {
            for u in &dns.upstreams {
                let ip_part = u.split('#').next().unwrap_or(u).trim();
                if let Ok(ip) = ip_part.parse::<Ipv4Addr>() {
                    if !ip.is_loopback() && !ip.is_unspecified() {
                        out.push(ip);
                    }
                }
            }
        }
    }
    if out.is_empty() {
        out.push(Ipv4Addr::new(1, 1, 1, 1));
        out.push(Ipv4Addr::new(9, 9, 9, 9));
    }
    out
}

fn build_dns_a_query(txid: u16, host: &str) -> Result<Vec<u8>> {
    let clean = host.trim().trim_end_matches('.');
    if clean.is_empty() {
        bail!("Empty hostname");
    }
    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&txid.to_be_bytes());
    pkt.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in clean.split('.') {
        if label.is_empty() || label.len() > 63 {
            bail!("Invalid DNS label in '{}'", host);
        }
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0x00);
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN
    Ok(pkt)
}

fn skip_dns_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    let mut jumps = 0usize;
    loop {
        if pos >= buf.len() || jumps > 16 {
            return None;
        }
        let b = buf[pos];
        if b == 0 {
            return Some(pos + 1);
        }
        if (b & 0xC0) == 0xC0 {
            if pos + 1 >= buf.len() {
                return None;
            }
            return Some(pos + 2);
        }
        let len = (b & 0x3F) as usize;
        pos = pos.checked_add(1 + len)?;
        jumps += 1;
    }
}

fn parse_dns_a_response(txid: u16, buf: &[u8]) -> Option<Ipv4Addr> {
    if buf.len() < 12 {
        return None;
    }
    let resp_id = u16::from_be_bytes([buf[0], buf[1]]);
    if resp_id != txid || (buf[2] & 0x80) == 0 || (buf[3] & 0x0F) != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let mut pos = 12usize;
    for _ in 0..qdcount {
        pos = skip_dns_name(buf, pos)?;
        pos = pos.checked_add(4)?;
        if pos > buf.len() {
            return None;
        }
    }
    for _ in 0..ancount {
        pos = skip_dns_name(buf, pos)?;
        if pos + 10 > buf.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rclass = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > buf.len() {
            return None;
        }
        if rtype == 1 && rclass == 1 && rdlen == 4 {
            return Some(Ipv4Addr::new(
                buf[pos],
                buf[pos + 1],
                buf[pos + 2],
                buf[pos + 3],
            ));
        }
        pos += rdlen;
    }
    None
}

async fn resolve_via_tunnel_udp(
    shared: &SharedState,
    iface: &str,
    fwmark: u32,
    local_ip: Option<Ipv4Addr>,
    host: &str,
) -> Option<Ipv4Addr> {
    let txid = DNS_QUERY_TXID.fetch_add(1, Ordering::Relaxed);
    let query = build_dns_a_query(txid, host).ok()?;
    let upstreams = configured_dns_upstream_ips(shared);

    for ns_ip in upstreams {
        let bind_ip = local_ip.unwrap_or(Ipv4Addr::UNSPECIFIED);
        let Ok(std_sock) = std::net::UdpSocket::bind(SocketAddr::new(std::net::IpAddr::V4(bind_ip), 0)) else {
            continue;
        };
        let _ = std_sock.set_nonblocking(true);
        let fd = std_sock.as_raw_fd();
        let bind_ok = unsafe {
            let mark_val: libc::c_uint = fwmark;
            let r1 = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &mark_val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
            );
            let mut iface_cstr = iface.as_bytes().to_vec();
            iface_cstr.push(0);
            let r2 = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                iface_cstr.as_ptr() as *const libc::c_void,
                iface_cstr.len() as libc::socklen_t,
            );
            r1 == 0 && r2 == 0
        };
        if !bind_ok {
            continue;
        }
        let Ok(sock) = UdpSocket::from_std(std_sock) else {
            continue;
        };
        let target = SocketAddr::new(std::net::IpAddr::V4(ns_ip), 53);
        if sock.send_to(&query, target).await.is_err() {
            continue;
        }
        let mut resp = [0u8; 512];
        if let Ok(Ok((n, _))) =
            tokio::time::timeout(Duration::from_millis(1800), sock.recv_from(&mut resp)).await
        {
            if let Some(ip) = parse_dns_a_response(txid, &resp[..n]) {
                return Some(ip);
            }
        }
    }
    None
}

async fn resolve_target_ipv4(shared: &SharedState, target_host: &str, target_port: u16) -> Option<Ipv4Addr> {
    if let Ok(ip) = target_host.trim().parse::<Ipv4Addr>() {
        return Some(ip);
    }
    if let Some(ip) = lookup_local_dns_or_cached_host(shared, target_host) {
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

async fn connect_via_proxy_route(
    shared: &SharedState,
    owner: &ProxyTargetOwner,
    target_host: &str,
    target_port: u16,
) -> Result<(TcpStream, Option<String>)> {
    let decision = match owner {
        ProxyTargetOwner::Gateway(gw_key) => select_gateway_tunnel(shared, gw_key),
        ProxyTargetOwner::VipService(_) => GatewayRouteDecision::DirectHost,
    };
    let resolved_ip = match &decision {
        GatewayRouteDecision::ViaTunnel {
            iface,
            fwmark,
            local_ip,
            ..
        } => {
            if let Ok(ip) = target_host.trim().parse::<Ipv4Addr>() {
                ip
            } else if let Some(ip) = lookup_local_dns_or_cached_host(shared, target_host) {
                ip
            } else if let Some(ip) =
                resolve_via_tunnel_udp(shared, iface, *fwmark, *local_ip, target_host).await
            {
                ip
            } else {
                bail!(
                    "Could not resolve '{}' through tunnel {}",
                    target_host,
                    iface
                );
            }
        }
        GatewayRouteDecision::KillswitchBlocked(reason) => bail!("{}", reason),
        GatewayRouteDecision::DirectHost => resolve_target_ipv4(shared, target_host, target_port)
            .await
            .ok_or_else(|| anyhow::anyhow!("Could not resolve '{}'", target_host))?,
    };
    if is_forbidden_proxy_destination(shared, resolved_ip) {
        bail!(
            "Proxy refuses connections to local or appliance-owned address {}",
            resolved_ip
        );
    }
    let target_addr = SocketAddr::new(std::net::IpAddr::V4(resolved_ip), target_port);

    let sock = TcpSocket::new_v4()?;
    let mut ep_key_opt = match owner {
        ProxyTargetOwner::VipService(svc_key) => Some(format!("127.0.0.1:{}", target_port)).and_then(|_| {
            shared
                .read()
                .ok()
                .and_then(|st| st.active_config().services.get(svc_key)?.backends.first().map(|b| b.endpoint()))
        }),
        ProxyTargetOwner::Gateway(_) => None,
    };

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
                ) != 0
                {
                    return Err(std::io::Error::last_os_error())
                        .context("Failed to set gateway socket mark");
                }
                let mut iface_cstr = iface.into_bytes();
                iface_cstr.push(0);
                if libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_BINDTODEVICE,
                    iface_cstr.as_ptr() as *const libc::c_void,
                    iface_cstr.len() as libc::socklen_t,
                ) != 0
                {
                    return Err(std::io::Error::last_os_error())
                        .context("Failed to bind gateway socket to tunnel");
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

async fn run_single_proxy_listener(
    shared: SharedState,
    owner: ProxyTargetOwner,
    listen_ip: Ipv4Addr,
    port: u16,
) {
    let bind_addr = SocketAddr::new(std::net::IpAddr::V4(listen_ip), port);
    let listener = loop {
        match TcpListener::bind(bind_addr).await {
            Ok(l) => break l,
            Err(e) => {
                eprintln!("nfty: proxy could not bind {}: {}", bind_addr, e);
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
                match &owner {
                    ProxyTargetOwner::Gateway(gw_key) => {
                        if let Some(gw) = cfg.gateways.get(gw_key) {
                            st.is_ip_allowed(peer_ip, &gw.allow, &cfg.global_allow)
                        } else {
                            false
                        }
                    }
                    ProxyTargetOwner::VipService(svc_key) => {
                        if let Some(svc) = cfg.services.get(svc_key) {
                            st.is_ip_allowed(peer_ip, &svc.allow, &cfg.global_allow)
                        } else {
                            false
                        }
                    }
                }
            } else {
                false
            }
        };
        if !allowed {
            continue;
        }
        let shared_c = shared.clone();
        let owner_c = owner.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_proxy_client(client, shared_c, owner_c).await {
                eprintln!("[nfty proxy] HTTP proxy request failed: {:#}", e);
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

async fn handle_proxy_client(
    mut client: TcpStream,
    shared: SharedState,
    owner: ProxyTargetOwner,
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
        client
            .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await?;
        bail!("Invalid HTTP proxy request line");
    }
    let method = parts[0];
    let raw_target = parts[1];
    let http_ver = parts.get(2).copied().unwrap_or("HTTP/1.1");

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = match parse_proxy_authority(raw_target, 443) {
            Ok(target) => target,
            Err(e) => {
                client
                    .write_all(
                        b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await?;
                return Err(e);
            }
        };
        if is_host_blocked_by_dns(&shared, host) {
            client
                .write_all(
                    b"HTTP/1.1 403 Forbidden\r\nProxy-Agent: nfty-proxy\r\nContent-Type: text/plain\r\nContent-Length: 25\r\nConnection: close\r\n\r\nBlocked by nfty blocklist",
                )
                .await?;
            return Ok(());
        }
        let (mut upstream, ep_opt) = match connect_via_proxy_route(&shared, &owner, host, port).await {
            Ok(result) => result,
            Err(e) => {
                client
                    .write_all(
                        b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await?;
                return Err(e);
            }
        };
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: nfty-proxy\r\n\r\n")
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
            client
                .write_all(
                    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await?;
            return Err(e);
        }
    };
    if is_host_blocked_by_dns(&shared, host) {
        client
            .write_all(
                b"HTTP/1.1 403 Forbidden\r\nProxy-Agent: nfty-proxy\r\nContent-Type: text/plain\r\nContent-Length: 25\r\nConnection: close\r\n\r\nBlocked by nfty blocklist",
            )
            .await?;
        return Ok(());
    }

    let (mut upstream, ep_opt) = match connect_via_proxy_route(&shared, &owner, host, port).await {
        Ok(result) => result,
        Err(e) => {
            client
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await?;
            return Err(e);
        }
    };

    // Rebuild privacy-sanitized HTTP request (strip Proxy-Connection, Via, X-Forwarded-For, etc.)
    let mut sanitized = format!("{} {} {}\r\n", method, rel_path, http_ver);
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, _)) = line.split_once(':') {
            let kl = k.trim().to_ascii_lowercase();
            if matches!(
                kl.as_str(),
                "connection"
                    | "proxy-connection"
                    | "proxy-authorization"
                    | "x-forwarded-for"
                    | "x-real-ip"
                    | "client-ip"
                    | "from"
                    | "via"
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
