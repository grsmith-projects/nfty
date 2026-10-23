use super::cloudflare::{check_http_basic_auth, sanitize_authenticated_http_request};
use super::list_vlan_iface_ips;
use crate::state::SharedState;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn find_hostname_ip(shared: &SharedState, qname: &str) -> Option<Ipv4Addr> {
    let q = qname.trim_end_matches('.').to_ascii_lowercase();
    let st = shared.read().ok()?;
    let cfg = st.active_config();

    for (vip_key, vip_cfg) in &cfg.vips {
        if let Some(ip) = vip_cfg.leased_ip.or_else(|| vip_key.parse::<Ipv4Addr>().ok()) {
            let k_clean = vip_key.trim_end_matches('.').to_ascii_lowercase();
            let k_local = if k_clean.ends_with(".local") {
                k_clean.clone()
            } else {
                format!("{}.local", k_clean)
            };
            if q == k_clean || q == k_local {
                return Some(ip);
            }
        }
    }

    for svc in cfg.services.values() {
        if let Some(h) = &svc.hostname {
            let h_clean = h.trim_end_matches('.').to_ascii_lowercase();
            let h_local = if h_clean.ends_with(".local") {
                h_clean.clone()
            } else {
                format!("{}.local", h_clean)
            };
            if q == h_clean || q == h_local {
                if let Some(ip) = svc.listen_ip {
                    return Some(ip);
                }
            }
        }
    }

    for gw in cfg.gateways.values() {
        if let Some(h) = &gw.hostname {
            let h_clean = h.trim_end_matches('.').to_ascii_lowercase();
            let h_local = if h_clean.ends_with(".local") {
                h_clean.clone()
            } else {
                format!("{}.local", h_clean)
            };
            if q == h_clean || q == h_local {
                return Some(gw.listen_ip);
            }
        }
    }

    None
}

fn parse_dns_qname(pkt: &[u8], mut offset: usize) -> Option<(String, usize, u16, u16)> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut end_offset = offset;
    let mut steps = 0;

    loop {
        if offset >= pkt.len() || steps > 64 {
            return None;
        }
        steps += 1;
        let len = pkt[offset] as usize;
        if len == 0 {
            if !jumped {
                end_offset = offset + 1;
            }
            break;
        }
        if (len & 0xC0) == 0xC0 {
            if offset + 1 >= pkt.len() {
                return None;
            }
            let ptr = (((len & 0x3F) << 8) | (pkt[offset + 1] as usize)) as usize;
            if !jumped {
                end_offset = offset + 2;
                jumped = true;
            }
            offset = ptr;
            continue;
        }
        offset += 1;
        if offset + len > pkt.len() {
            return None;
        }
        let label = std::str::from_utf8(&pkt[offset..offset + len]).ok()?;
        labels.push(label.to_string());
        offset += len;
    }

    if end_offset + 4 > pkt.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([pkt[end_offset], pkt[end_offset + 1]]);
    let qclass = u16::from_be_bytes([pkt[end_offset + 2], pkt[end_offset + 3]]);
    Some((labels.join("."), end_offset + 4, qtype, qclass))
}

fn build_mdns_a_response(tx_id: u16, qname: &str, ip: Ipv4Addr) -> Vec<u8> {
    let mut resp = Vec::with_capacity(128);
    // Header: ID, Flags (0x8400 = QR + AA), QDCOUNT=0, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
    resp.extend_from_slice(&tx_id.to_be_bytes());
    resp.extend_from_slice(&0x8400u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());
    resp.extend_from_slice(&0u16.to_be_bytes());

    for label in qname.trim_end_matches('.').split('.') {
        let b = label.as_bytes();
        if !b.is_empty() && b.len() < 64 {
            resp.push(b.len() as u8);
            resp.extend_from_slice(b);
        }
    }
    resp.push(0);

    // Type A (1), Class IN + cache-flush (0x8001), TTL 60s, RDLENGTH 4, IPv4
    resp.extend_from_slice(&1u16.to_be_bytes());
    resp.extend_from_slice(&0x8001u16.to_be_bytes());
    resp.extend_from_slice(&60u32.to_be_bytes());
    resp.extend_from_slice(&4u16.to_be_bytes());
    resp.extend_from_slice(&ip.octets());
    resp
}

pub(crate) fn run_mdns_responder_loop(shared: SharedState) {
    let Ok(sock) = UdpSocket::bind("0.0.0.0:5353") else {
        return;
    };
    let mcast_group = Ipv4Addr::new(224, 0, 0, 251);
    let _ = sock.join_multicast_v4(&mcast_group, &Ipv4Addr::UNSPECIFIED);
    let _ = sock.set_multicast_loop_v4(false);
    let mcast_dest: SocketAddr = "224.0.0.251:5353".parse().unwrap();
    let mut buf = [0u8; 1500];
    let mut joined_ips: Vec<Ipv4Addr> = Vec::new();
    let mut last_join_check = std::time::Instant::now() - Duration::from_secs(30);

    loop {
        if last_join_check.elapsed() >= Duration::from_secs(15) {
            last_join_check = std::time::Instant::now();
            for ip in list_vlan_iface_ips() {
                if !joined_ips.contains(&ip) {
                    let _ = sock.join_multicast_v4(&mcast_group, &ip);
                    joined_ips.push(ip);
                }
            }
        }

        let Ok((n, peer)) = sock.recv_from(&mut buf) else {
            std::thread::sleep(Duration::from_millis(200));
            continue;
        };
        if n < 12 {
            continue;
        }
        // Ignore packets originating from our own local interface IPs to prevent mDNS repeater loops
        if let SocketAddr::V4(v4) = peer {
            if joined_ips.contains(v4.ip()) {
                continue;
            }
        }

        // Cross-VLAN mDNS Repeater: relay multicast mDNS packets across VLANs when multiple interfaces exist
        if joined_ips.len() > 1 {
            for &iface_ip in &joined_ips {
                if let SocketAddr::V4(v4) = peer {
                    if v4.ip().octets()[0..3] != iface_ip.octets()[0..3] {
                        if let Ok(tx_sock) =
                            UdpSocket::bind(SocketAddr::new(std::net::IpAddr::V4(iface_ip), 0))
                        {
                            let _ = tx_sock.set_multicast_loop_v4(false);
                            let _ = tx_sock.send_to(&buf[..n], mcast_dest);
                        }
                    }
                }
            }
        }

        let tx_id = u16::from_be_bytes([buf[0], buf[1]]);
        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        if (flags & 0x8000) != 0 {
            continue;
        }
        let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
        let mut offset = 12usize;
        for _ in 0..qdcount {
            let Some((qname, next_off, qtype, _qclass)) = parse_dns_qname(&buf[..n], offset) else {
                break;
            };
            offset = next_off;
            // Type 1 = A, Type 255 = ANY
            if qtype == 1 || qtype == 255 {
                if let Some(ip) = find_hostname_ip(&shared, &qname) {
                    let pkt = build_mdns_a_response(tx_id, &qname, ip);
                    let _ = sock.send_to(&pkt, peer);
                    let _ = sock.send_to(&pkt, mcast_dest);
                }
            }
        }
    }
}

/// Extracts either the HTTP `Host:` header or TLS ClientHello `SNI` hostname from the first packet.
pub fn extract_host_or_sni(buf: &[u8]) -> Option<String> {
    if buf.is_empty() {
        return None;
    }
    // 1. Check TLS ClientHello (0x16 = Handshake, 0x03 = SSL/TLS)
    if buf.len() > 43 && buf[0] == 0x16 && buf[1] == 0x03 {
        if let Some(sni) = parse_tls_sni(buf) {
            return Some(sni.to_ascii_lowercase());
        }
    }
    // 2. Check HTTP Host header
    let text = std::str::from_utf8(buf).ok()?;
    for line in text.lines().take(32) {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("host") {
                let host_port = v.trim();
                let host = host_port.split(':').next().unwrap_or(host_port).trim();
                if !host.is_empty() {
                    return Some(host.to_ascii_lowercase());
                }
            }
        }
    }
    None
}

fn parse_tls_sni(buf: &[u8]) -> Option<String> {
    // TLS record header (5 bytes) + Handshake header (4 bytes) + Version (2) + Random (32) = 43
    let mut pos = 43;
    if pos >= buf.len() {
        return None;
    }
    let session_id_len = buf[pos] as usize;
    pos += 1 + session_id_len;
    if pos + 2 > buf.len() {
        return None;
    }
    let cipher_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2 + cipher_len;
    if pos + 1 > buf.len() {
        return None;
    }
    let comp_len = buf[pos] as usize;
    pos += 1 + comp_len;
    if pos + 2 > buf.len() {
        return None;
    }
    let ext_total_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;
    let end = (pos + ext_total_len).min(buf.len());

    while pos + 4 <= end {
        let ext_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let ext_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > end {
            break;
        }
        if ext_type == 0x0000 && ext_len >= 5 {
            // Server Name Indication
            let name_type = buf[pos + 2];
            let name_len = u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]) as usize;
            if name_type == 0 && pos + 5 + name_len <= pos + ext_len {
                if let Ok(s) = std::str::from_utf8(&buf[pos + 5..pos + 5 + name_len]) {
                    return Some(s.to_string());
                }
            }
        }
        pos += ext_len;
    }
    None
}

static L7_VHOST_RR_COUNTER: AtomicUsize = AtomicUsize::new(0);

pub(crate) async fn run_l7_virtual_host_listener(shared: SharedState, listen_port: u16) {
    let bind_addr = format!("0.0.0.0:{}", listen_port);
    let listener = loop {
        match TcpListener::bind(&bind_addr).await {
            Ok(l) => break l,
            Err(_) => {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    };

    loop {
        let Ok((mut client, peer)) = listener.accept().await else {
            continue;
        };
        let local_dst_ip = client.local_addr().ok().and_then(|a| match a.ip() {
            std::net::IpAddr::V4(v4) => Some(v4),
            _ => None,
        });
        let shared_conn = shared.clone();
        tokio::spawn(async move {
            let mut peek_buf = [0u8; 2048];
            let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_secs(3), client.read(&mut peek_buf)).await
            else {
                return;
            };
            if n == 0 {
                return;
            }
            let Some(host) = extract_host_or_sni(&peek_buf[..n]) else {
                return;
            };

            let target_info: Option<(String, String, Vec<String>)> = {
                let st = shared_conn.read().unwrap();
                let cfg = st.active_config();
                // Prefer a service whose listen_ip matches the destination VIP IP, falling back to any service with that hostname
                let mut candidates: Vec<&crate::ast::Service> = cfg
                    .services
                    .values()
                    .filter(|svc| {
                        if let Some(svc_host) = &svc.hostname {
                            let sh = svc_host.trim_end_matches('.').to_ascii_lowercase();
                            let sh_short = sh.strip_suffix(".local").unwrap_or(&sh);
                            let req_short = host.strip_suffix(".local").unwrap_or(&host);
                            host == sh || req_short == sh_short
                        } else {
                            false
                        }
                    })
                    .collect();

                candidates.sort_by_key(|svc| {
                    let ip_match = match (local_dst_ip, svc.listen_ip) {
                        (Some(dst), Some(lip)) if dst == lip => 0,
                        _ => 1,
                    };
                    let port_match = if svc.port == listen_port { 0 } else { 1 };
                    (ip_match, port_match)
                });

                let mut found = None;
                if let Some(svc) = candidates.first() {
                    let active = st.active_backends_for_service(&svc.backends);
                    if !active.is_empty() {
                        let mut weighted_slots = Vec::new();
                        for b in &active {
                            for _ in 0..b.weight.max(1) {
                                weighted_slots.push(*b);
                            }
                        }
                        let idx = match svc.balance {
                            crate::ast::BalanceStrategy::RoundRobin => {
                                L7_VHOST_RR_COUNTER.fetch_add(1, Ordering::Relaxed)
                                    % weighted_slots.len()
                            }
                            crate::ast::BalanceStrategy::Sticky => {
                                let hash = match peer.ip() {
                                    std::net::IpAddr::V4(v4) => u32::from(v4) as usize,
                                    std::net::IpAddr::V6(_) => 0usize,
                                };
                                hash % weighted_slots.len()
                            }
                        };
                        let chosen = weighted_slots[idx];
                        let addr = format!("{}:{}", chosen.ip, chosen.port);
                        found = Some((addr, chosen.endpoint(), svc.auth.clone()));
                    }
                }
                found
            };

            if let Some((addr, ep_key, auth_rules)) = target_info {
                let first_line_http = std::str::from_utf8(&peek_buf[..n])
                    .map(|s| {
                        let u = s.trim_start();
                        u.starts_with("GET ")
                            || u.starts_with("POST ")
                            || u.starts_with("HEAD ")
                            || u.starts_with("PUT ")
                            || u.starts_with("DELETE ")
                            || u.starts_with("OPTIONS ")
                            || u.starts_with("PATCH ")
                    })
                    .unwrap_or(false);
                if !auth_rules.is_empty()
                    && first_line_http
                    && !check_http_basic_auth(&peek_buf[..n], &auth_rules)
                {
                    let resp = format!(
                        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"nfty ({})\"\r\nContent-Type: text/plain\r\nContent-Length: 26\r\nConnection: close\r\n\r\n401 Authentication Needed\n",
                        host
                    );
                    let _ = client.write_all(resp.as_bytes()).await;
                    return;
                }
                let forward_buf = if !auth_rules.is_empty() && first_line_http {
                    sanitize_authenticated_http_request(&peek_buf[..n])
                } else {
                    peek_buf[..n].to_vec()
                };
                if let Ok(Ok(mut upstream)) =
                    tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&addr)).await
                {
                    if upstream.write_all(&forward_buf).await.is_ok() {
                        if let Ok((up_b, down_b)) =
                            tokio::io::copy_bidirectional(&mut client, &mut upstream).await
                        {
                            if let Ok(mut st) = shared_conn.write() {
                                let rt = st.runtime.entry(ep_key).or_default();
                                rt.packets += 2;
                                rt.bytes += (forward_buf.len() as u64) + up_b + down_b;
                            }
                        }
                    }
                }
            }
        });
    }
}
