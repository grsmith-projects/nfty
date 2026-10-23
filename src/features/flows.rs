use crate::state::SharedState;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConntrackFlow {
    pub proto: String,
    pub state: String,
    pub src: String,
    pub dst: String,
    pub sport: u16,
    pub dport: u16,
    pub nat_target: Option<String>,
    pub mark: String,
    pub packets: u64,
    pub bytes: u64,
}

/// Reads active connections from `/proc/net/nf_conntrack` (or falls back to `/proc/net/tcp`).
pub fn read_active_flows(shared: &SharedState) -> Vec<ConntrackFlow> {
    let mut flows = Vec::new();
    let raw = fs::read_to_string("/proc/net/nf_conntrack")
        .or_else(|_| fs::read_to_string("/proc/net/ip_conntrack"))
        .unwrap_or_default();

    let (vip_ips, backend_ips) = {
        let st = shared.read().unwrap();
        let cfg = if !st.running.services.is_empty() || !st.running.gateways.is_empty() {
            &st.running
        } else {
            &st.candidate
        };
        let mut vips = Vec::new();
        let mut bips = Vec::new();
        for svc in cfg.services.values() {
            if let Some(ip) = svc.listen_ip {
                vips.push(ip.to_string());
            }
            for b in &svc.backends {
                bips.push(b.ip.to_string());
            }
        }
        for gw in cfg.gateways.values() {
            vips.push(gw.listen_ip.to_string());
        }
        (vips, bips)
    };

    for line in raw.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 6 {
            continue;
        }
        let proto = tokens[2].to_ascii_uppercase();
        if proto != "TCP" && proto != "UDP" {
            continue;
        }
        let state = if proto == "TCP" && !tokens[5].contains('=') {
            tokens[5].to_string()
        } else {
            "ACTIVE".to_string()
        };

        let mut orig_src = None;
        let mut orig_dst = None;
        let mut orig_sport = None;
        let mut orig_dport = None;
        let mut reply_src = None;
        let mut reply_sport = None;
        let mut packets = 0u64;
        let mut bytes = 0u64;
        let mut mark = "0".to_string();

        for tok in &tokens {
            if let Some((k, v)) = tok.split_once('=') {
                match k {
                    "src" => {
                        if orig_src.is_none() {
                            orig_src = Some(v.to_string());
                        } else if reply_src.is_none() {
                            reply_src = Some(v.to_string());
                        }
                    }
                    "dst" => {
                        if orig_dst.is_none() {
                            orig_dst = Some(v.to_string());
                        }
                    }
                    "sport" => {
                        if orig_sport.is_none() {
                            orig_sport = v.parse::<u16>().ok();
                        } else if reply_sport.is_none() {
                            reply_sport = v.parse::<u16>().ok();
                        }
                    }
                    "dport" => {
                        if orig_dport.is_none() {
                            orig_dport = v.parse::<u16>().ok();
                        }
                    }
                    "packets" => {
                        packets += v.parse::<u64>().unwrap_or(0);
                    }
                    "bytes" => {
                        bytes += v.parse::<u64>().unwrap_or(0);
                    }
                    "mark" => {
                        mark = v.to_string();
                    }
                    _ => {}
                }
            }
        }

        let (Some(src), Some(dst), Some(sport), Some(dport)) =
            (orig_src, orig_dst, orig_sport, orig_dport)
        else {
            continue;
        };

        // Skip API polling noise on :9090
        if dport == 9090 || sport == 9090 {
            continue;
        }

        let is_relevant = mark != "0"
            || vip_ips.iter().any(|ip| ip == &dst || ip == &src)
            || reply_src
                .as_ref()
                .map(|rs| backend_ips.iter().any(|ip| ip == rs))
                .unwrap_or(false);

        if !is_relevant && !vip_ips.is_empty() {
            continue;
        }

        let nat_target = match (&reply_src, reply_sport) {
            (Some(rs), Some(rsp)) if rs != &dst || rsp != dport => Some(format!("{}:{}", rs, rsp)),
            _ => None,
        };

        flows.push(ConntrackFlow {
            proto,
            state,
            src,
            dst,
            sport,
            dport,
            nat_target,
            mark,
            packets,
            bytes,
        });
    }

    // Fallback/supplement with `/proc/net/tcp` if `/proc/net/nf_conntrack` is not exposed in container procfs
    if flows.is_empty() {
        if let Ok(tcp_raw) = fs::read_to_string("/proc/net/tcp") {
            for line in tcp_raw.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 4 {
                    continue;
                }
                let Some((local_ip, local_port)) = parse_proc_net_addr(parts[1]) else {
                    continue;
                };
                let Some((rem_ip, rem_port)) = parse_proc_net_addr(parts[2]) else {
                    continue;
                };
                if rem_ip == Ipv4Addr::UNSPECIFIED || local_port == 9090 || rem_port == 9090 {
                    continue;
                }
                let state_str = match parts[3] {
                    "01" => "ESTABLISHED",
                    "02" => "SYN_SENT",
                    "03" => "SYN_RECV",
                    "06" => "TIME_WAIT",
                    _ => continue,
                };
                flows.push(ConntrackFlow {
                    proto: "TCP".to_string(),
                    state: state_str.to_string(),
                    src: rem_ip.to_string(),
                    dst: local_ip.to_string(),
                    sport: rem_port,
                    dport: local_port,
                    nat_target: None,
                    mark: "0".to_string(),
                    packets: 1,
                    bytes: 0,
                });
            }
        }
    }

    flows.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    flows.truncate(100);
    flows
}

fn parse_proc_net_addr(hex_pair: &str) -> Option<(Ipv4Addr, u16)> {
    let (ip_hex, port_hex) = hex_pair.split_once(':')?;
    let ip_u32 = u32::from_str_radix(ip_hex, 16).ok()?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    Some((Ipv4Addr::from(ip_u32.swap_bytes()), port))
}

pub fn print_flows_table(shared: &SharedState) {
    let flows = read_active_flows(shared);
    println!(
        "{:<6} {:<13} {:<22} {:<22} {:<24} {:<8} {:<14}",
        "PROTO".bold().underline(),
        "STATE".bold().underline(),
        "CLIENT (SRC)".bold().underline(),
        "VIP / DEST".bold().underline(),
        "NAT BACKEND / WG".bold().underline(),
        "MARK".bold().underline(),
        "TRAFFIC".bold().underline()
    );
    if flows.is_empty() {
        println!(
            "  {}",
            "(No active conntrack flows found matching configured VIPs/gateways)".dimmed()
        );
        return;
    }

    for f in flows {
        let src_col = format!("{}:{}", f.src, f.sport);
        let dst_col = format!("{}:{}", f.dst, f.dport);
        let nat_col = f.nat_target.unwrap_or_else(|| "direct".to_string());
        let mark_col = if f.mark == "0" {
            "-".to_string()
        } else {
            format!("0x{}", f.mark)
        };
        let state_colored = match f.state.as_str() {
            "ESTABLISHED" => f.state.green().bold().to_string(),
            "TIME_WAIT" | "CLOSE" => f.state.dimmed().to_string(),
            _ => f.state.yellow().to_string(),
        };
        println!(
            "{:<6} {:<22} {:<22} {:<22} {:<24} {:<8} {} pkts / {} B",
            f.proto.cyan(),
            state_colored,
            src_col,
            dst_col.bold(),
            nat_col.green(),
            mark_col,
            f.packets,
            f.bytes
        );
    }
}
