use crate::ast::{
    Backend, BalanceStrategy, Config, ForwardMode, Gateway, GatewayService, GatewayServiceKind,
    HealthCheckConfig, HealthCheckKind, Proto, RateLimit, RateUnit, Service, VipConfig, WgTunnel,
};
use anyhow::{anyhow, bail, Context, Result};
use std::net::Ipv4Addr;

pub fn parse_service_spec(raw: &str) -> Result<(String, Option<Ipv4Addr>, u16, Proto)> {
    let trimmed = raw.trim().trim_start_matches(':');
    if trimmed.is_empty() {
        bail!("Service specification cannot be empty");
    }

    let (addr_port_part, proto, proto_explicit) =
        if let Some((left, right)) = trimmed.split_once('/') {
            let p = match right.to_ascii_lowercase().as_str() {
                "tcp" => Proto::Tcp,
                "udp" => Proto::Udp,
                "both" | "tcp+udp" | "all" => Proto::Both,
                other => bail!("Unknown protocol '{}' (expected tcp, udp, or both)", other),
            };
            (left, p, true)
        } else {
            (trimmed, Proto::Tcp, false)
        };

    let (listen_ip, port) = if let Some((ip_str, port_str)) = addr_port_part.split_once(':') {
        let ip: Ipv4Addr = ip_str
            .parse()
            .with_context(|| format!("Invalid listen IPv4 address '{}'", ip_str))?;
        let port: u16 = port_str
            .parse()
            .with_context(|| format!("Invalid port number '{}'", port_str))?;
        if port == 0 {
            bail!("Port cannot be 0");
        }
        (Some(ip), port)
    } else {
        let port: u16 = addr_port_part
            .parse()
            .with_context(|| format!("Invalid service port '{}'", addr_port_part))?;
        if port == 0 {
            bail!("Port cannot be 0");
        }
        (None, port)
    };

    let mut key = match listen_ip {
        Some(ip) => format!("{}:{}", ip, port),
        None => format!("{}", port),
    };
    if proto_explicit && proto != Proto::Tcp {
        let suffix = match proto {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
            Proto::Both => "both",
        };
        key.push('/');
        key.push_str(suffix);
    }

    Ok((key, listen_ip, port, proto))
}

pub fn resolve_hostname_sync(host: &str) -> Option<Ipv4Addr> {
    let h_lower = host.trim().to_ascii_lowercase();
    if h_lower == "localhost" {
        return Some(Ipv4Addr::new(127, 0, 0, 1));
    }
    // 1. Check /data/hosts.json if present
    if let Ok(raw) = std::fs::read_to_string("/data/hosts.json") {
        if let Ok(map) =
            serde_json::from_str::<std::collections::BTreeMap<String, Vec<Ipv4Addr>>>(&raw)
        {
            if let Some(ips) = map.get(&h_lower) {
                if let Some(first) = ips.first() {
                    return Some(*first);
                }
            }
        }
    }
    // 2. Check /etc/hosts
    if let Ok(hosts_txt) = std::fs::read_to_string("/etc/hosts") {
        for line in hosts_txt.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(ip) = parts[0].parse::<Ipv4Addr>() {
                    if parts[1..].iter().any(|p| p.eq_ignore_ascii_case(&h_lower)) {
                        return Some(ip);
                    }
                }
            }
        }
    }
    // 3. Standard DNS lookup
    use std::net::ToSocketAddrs;
    if let Ok(addrs) = (h_lower.as_str(), 80u16).to_socket_addrs() {
        for sock in addrs {
            if let std::net::IpAddr::V4(ip4) = sock.ip() {
                return Some(ip4);
            }
        }
    }
    None
}

pub fn parse_backend(tokens: &[&str], default_port: u16) -> Result<Backend> {
    if tokens.is_empty() {
        bail!("Expected backend <IP|hostname>[:PORT] [weight <N>] [backup]");
    }
    let endpoint = tokens[0];
    let (host_or_ip, port) = if let Some((left, port_str)) = endpoint.split_once(':') {
        let port: u16 = port_str
            .parse()
            .with_context(|| format!("Invalid backend port '{}'", port_str))?;
        (left, port)
    } else {
        (endpoint, default_port)
    };

    let (host, ip) = if let Ok(ip4) = host_or_ip.parse::<Ipv4Addr>() {
        (None, ip4)
    } else {
        let valid_host = !host_or_ip.is_empty()
            && host_or_ip
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
        if !valid_host {
            bail!(
                "Invalid backend IPv4 or hostname '{}'",
                host_or_ip
            );
        }
        let h_lower = host_or_ip.to_ascii_lowercase();
        let resolved_ip = resolve_hostname_sync(&h_lower).unwrap_or(Ipv4Addr::UNSPECIFIED);
        (Some(h_lower), resolved_ip)
    };

    let mut weight = 1u32;
    let mut backup = false;
    let mut idx = 1;
    while idx < tokens.len() {
        match tokens[idx].to_ascii_lowercase().as_str() {
            "weight" => {
                idx += 1;
                if idx >= tokens.len() {
                    bail!("Expected number after 'weight'");
                }
                weight = tokens[idx]
                    .parse()
                    .with_context(|| format!("Invalid weight '{}'", tokens[idx]))?;
                if weight == 0 || weight > 100 {
                    bail!("Backend weight must be between 1 and 100");
                }
            }
            "backup" | "standby" => {
                backup = true;
            }
            other => bail!(
                "Unexpected token '{}' in backend definition (expected 'weight <N>' or 'backup')",
                other
            ),
        }
        idx += 1;
    }

    Ok(Backend {
        host,
        ip,
        port,
        weight,
        backup,
    })
}

pub fn parse_backends_line(tokens: &[&str], default_port: u16) -> Result<Vec<Backend>> {
    if tokens.is_empty() {
        bail!("Expected at least one backend IP[:PORT]");
    }
    if tokens
        .iter()
        .any(|t| matches!(t.to_ascii_lowercase().as_str(), "weight" | "backup" | "standby"))
    {
        return Ok(vec![parse_backend(tokens, default_port)?]);
    }

    let mut out = Vec::new();
    for tok in tokens {
        out.push(parse_backend(&[tok], default_port)?);
    }
    Ok(out)
}

pub fn parse_vlan_id(raw: &str) -> Result<u16> {
    let vid: u16 = raw
        .trim()
        .parse()
        .with_context(|| format!("Invalid VLAN ID '{}' (expected 1-4094)", raw))?;
    if !(1..=4094).contains(&vid) {
        bail!("VLAN ID must be between 1 and 4094 (got {})", vid);
    }
    Ok(vid)
}

fn split_iface_and_vlan(raw_iface: &str) -> (String, Option<u16>) {
    if let Some((base, suffix)) = raw_iface.rsplit_once('.') {
        if let Ok(vid) = suffix.parse::<u16>() {
            if (1..=4094).contains(&vid) {
                return (base.to_string(), Some(vid));
            }
        }
    }
    (raw_iface.to_string(), None)
}

pub fn parse_vip(raw: &str) -> Result<VipConfig> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("Expected interface name (e.g. 'vip eth0' or 'vip eth0/24')");
    }
    if let Some((iface, prefix)) = trimmed.split_once('/') {
        let p: u8 = prefix
            .parse()
            .with_context(|| format!("Invalid VIP prefix length '{}'", prefix))?;
        if p == 0 || p > 32 {
            bail!("VIP prefix length must be between 1 and 32");
        }
        let (base_iface, vlan) = split_iface_and_vlan(iface);
        Ok(VipConfig {
            interface: base_iface,
            prefix_len: p,
            dhcp: false,
            vlan,
            leased_ip: None,
        })
    } else {
        let (base_iface, vlan) = split_iface_and_vlan(trimmed);
        Ok(VipConfig {
            interface: base_iface,
            prefix_len: 32,
            dhcp: false,
            vlan,
            leased_ip: None,
        })
    }
}

/// Parses a `vip <ipv4[/cidr] | hostname> [dhcp [iface]] [vlan <id>]` header
pub fn parse_vip_header(tokens: &[&str]) -> Result<(String, Option<Ipv4Addr>, VipConfig)> {
    if tokens.is_empty() {
        bail!("Expected VIP IPv4 address or DHCP hostname (e.g. 'vip 192.168.1.4' or 'vip sonarr')");
    }
    let first = tokens[0].trim();
    let (key, ip_opt, mut vip_cfg) = if let Ok((ip, cidr_opt)) = parse_ip_and_optional_cidr(first) {
        (
            ip.to_string(),
            Some(ip),
            VipConfig {
                interface: "eth0".to_string(),
                prefix_len: cidr_opt.unwrap_or_else(crate::ast::default_eth0_prefix_len),
                dhcp: false,
                vlan: None,
                leased_ip: None,
            },
        )
    } else {
        let valid_name = !first.is_empty()
            && first
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
        if !valid_name {
            bail!(
                "Invalid VIP IPv4 or DHCP hostname '{}' (expected e.g. '192.168.1.4' or 'sonarr')",
                first
            );
        }
        (
            first.to_ascii_lowercase(),
            None,
            VipConfig {
                interface: "eth0".to_string(),
                prefix_len: 32,
                dhcp: true,
                vlan: None,
                leased_ip: None,
            },
        )
    };

    let mut idx = 1;
    while idx < tokens.len() {
        match tokens[idx].to_ascii_lowercase().as_str() {
            "dhcp" => {
                vip_cfg.dhcp = true;
                if idx + 1 < tokens.len()
                    && !matches!(
                        tokens[idx + 1].to_ascii_lowercase().as_str(),
                        "vlan" | "service" | "services" | "ssh"
                    )
                    && !tokens[idx + 1].starts_with("ssh:")
                {
                    idx += 1;
                    let (base, vid) = split_iface_and_vlan(tokens[idx]);
                    vip_cfg.interface = base;
                    if vid.is_some() {
                        vip_cfg.vlan = vid;
                    }
                }
            }
            "vlan" => {
                idx += 1;
                if idx >= tokens.len() {
                    bail!("Expected VLAN ID (1-4094) after 'vlan'");
                }
                vip_cfg.vlan = Some(parse_vlan_id(tokens[idx])?);
            }
            "dev" | "interface" | "vip" => {
                idx += 1;
                if idx >= tokens.len() {
                    bail!("Expected interface name after '{}'", tokens[idx - 1]);
                }
                let parsed = parse_vip(tokens[idx])?;
                vip_cfg.interface = parsed.interface;
                vip_cfg.prefix_len = parsed.prefix_len;
                if parsed.vlan.is_some() {
                    vip_cfg.vlan = parsed.vlan;
                }
            }
            _ => break,
        }
        idx += 1;
    }

    Ok((key, ip_opt, vip_cfg))
}

pub fn parse_duration_secs(raw: &str) -> Result<u64> {
    let s = raw.trim().to_ascii_lowercase();
    let num_str = s.strip_suffix('s').unwrap_or(&s);
    let secs: u64 = num_str
        .parse()
        .with_context(|| format!("Invalid interval '{}' (expected e.g. '5s')", raw))?;
    if secs == 0 {
        bail!("Health check interval must be at least 1s");
    }
    Ok(secs)
}

pub fn parse_health_check(tokens: &[&str]) -> Result<HealthCheckConfig> {
    if tokens.is_empty() {
        bail!("Expected health check type: 'tcp [5s]', 'http [/path] [5s]', or 'ping [5s]'");
    }
    match tokens[0].to_ascii_lowercase().as_str() {
        "tcp" => {
            let interval_secs = if tokens.len() >= 2 {
                parse_duration_secs(tokens[1])?
            } else {
                5
            };
            Ok(HealthCheckConfig {
                kind: HealthCheckKind::Tcp,
                interval_secs,
            })
        }
        "ping" | "icmp" => {
            let interval_secs = if tokens.len() >= 2 {
                parse_duration_secs(tokens[1])?
            } else {
                5
            };
            Ok(HealthCheckConfig {
                kind: HealthCheckKind::Ping,
                interval_secs,
            })
        }
        "http" => {
            let (path, interval_secs) = match tokens.len() {
                1 => ("/".to_string(), 5),
                2 => {
                    if tokens[1].starts_with('/') {
                        (tokens[1].to_string(), 5)
                    } else {
                        ("/".to_string(), parse_duration_secs(tokens[1])?)
                    }
                }
                _ => {
                    let p = if tokens[1].starts_with('/') {
                        tokens[1].to_string()
                    } else {
                        format!("/{}", tokens[1])
                    };
                    (p, parse_duration_secs(tokens[2])?)
                }
            };
            Ok(HealthCheckConfig {
                kind: HealthCheckKind::Http { path },
                interval_secs,
            })
        }
        other => bail!(
            "Unknown health check type '{}' (expected tcp, http, or ping)",
            other
        ),
    }
}

pub fn parse_rate_limit(tokens: &[&str]) -> Result<RateLimit> {
    if tokens.is_empty() {
        bail!("Expected rate limit, e.g. 'limit 100/sec per-ip' or 'limit 60/min burst 20 per-ip'");
    }
    let (rate_str, unit_str) = tokens[0]
        .split_once('/')
        .ok_or_else(|| anyhow!("Rate must be in '<number>/sec' or '<number>/min' format"))?;
    let rate: u32 = rate_str
        .parse()
        .with_context(|| format!("Invalid rate number '{}'", rate_str))?;
    if rate == 0 {
        bail!("Rate limit must be > 0");
    }
    let unit = match unit_str.to_ascii_lowercase().as_str() {
        "s" | "sec" | "second" | "seconds" => RateUnit::Second,
        "m" | "min" | "minute" | "minutes" => RateUnit::Minute,
        other => bail!("Invalid rate unit '{}' (expected 'sec' or 'min')", other),
    };

    let mut burst = None;
    let mut per_ip = true;
    let mut idx = 1;
    while idx < tokens.len() {
        match tokens[idx].to_ascii_lowercase().as_str() {
            "burst" => {
                idx += 1;
                if idx >= tokens.len() {
                    bail!("Expected number after 'burst'");
                }
                let b: u32 = tokens[idx]
                    .parse()
                    .with_context(|| format!("Invalid burst '{}'", tokens[idx]))?;
                burst = Some(b);
            }
            "per-ip" | "per_ip" | "source" => {
                per_ip = true;
            }
            "global" => {
                per_ip = false;
            }
            other => bail!(
                "Unexpected token '{}' in limit (expected 'burst <N>', 'per-ip', or 'global')",
                other
            ),
        }
        idx += 1;
    }

    Ok(RateLimit {
        rate,
        unit,
        burst,
        per_ip,
    })
}

/// Validates and normalizes an allow-list entry:
/// Supports:
/// - Exact IPv4: `192.168.1.50`
/// - CIDR: `192.168.1.0/24`
/// - IPv4 Wildcard: `192.168.1.*`, `10.0.*.*`, `*`
/// - Hostname: `admin.office.lan`, `plex.local`
/// - Hostname Wildcard: `*.office.lan`, `*.trusted.example.com`, `web-*.corp.lan`
pub fn validate_allow_entry(raw: &str) -> Result<String> {
    let trimmed = raw.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        bail!("Allow entry cannot be empty");
    }
    if trimmed == "*" || trimmed == "any" || trimmed == "all" {
        return Ok("*".to_string());
    }

    // 1. Check CIDR
    if let Some((ip_part, prefix_part)) = trimmed.split_once('/') {
        let ip: Ipv4Addr = ip_part
            .parse()
            .with_context(|| format!("Invalid IPv4 address '{}' in CIDR", ip_part))?;
        let prefix: u8 = prefix_part
            .parse()
            .with_context(|| format!("Invalid CIDR prefix '{}'", prefix_part))?;
        if prefix > 32 {
            bail!("IPv4 CIDR prefix cannot exceed 32");
        }
        return Ok(format!("{}/{}", ip, prefix));
    }

    // 2. Check exact IPv4
    if let Ok(ip) = trimmed.parse::<Ipv4Addr>() {
        return Ok(ip.to_string());
    }

    // 3. Check IPv4 wildcard (e.g. "192.168.1.*" or "10.*.*.*")
    let dot_parts: Vec<&str> = trimmed.split('.').collect();
    if dot_parts.len() == 4
        && dot_parts
            .iter()
            .all(|p| *p == "*" || p.parse::<u8>().is_ok())
    {
        return Ok(trimmed);
    }

    // 4. Validate hostname or wildcard hostname (e.g. "*.office.lan", "admin-*.corp.lan", "my-host.lan")
    let valid_chars = trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '*'));
    if !valid_chars || trimmed.starts_with('.') || trimmed.ends_with('.') {
        bail!(
            "Invalid allow-list host/IP/wildcard '{}'. Examples: '192.168.1.0/24', '192.168.1.*', '*.office.lan', 'laptop.lan'",
            raw
        );
    }

    Ok(trimmed)
}

/// Converts an IPv4 wildcard like `192.168.1.*` or `10.*.*.*` into a CIDR (`192.168.1.0/24`, `10.0.0.0/8`),
/// or returns `None` if it's a hostname / hostname wildcard.
pub fn expand_ip_wildcard_to_cidr(entry: &str) -> Option<String> {
    if entry == "*" {
        return Some("0.0.0.0/0".to_string());
    }
    if entry.contains('/') {
        return Some(entry.to_string());
    }
    if entry.parse::<Ipv4Addr>().is_ok() {
        return Some(entry.to_string());
    }
    let parts: Vec<&str> = entry.split('.').collect();
    if parts.len() == 4 && parts.iter().all(|p| *p == "*" || p.parse::<u8>().is_ok()) {
        match (parts[0], parts[1], parts[2], parts[3]) {
            ("*", "*", "*", "*") => Some("0.0.0.0/0".to_string()),
            (a, "*", "*", "*") => Some(format!("{}.0.0.0/8", a)),
            (a, b, "*", "*") => Some(format!("{}.{}.0.0/16", a, b)),
            (a, b, c, "*") => Some(format!("{}.{}.{}.0/24", a, b, c)),
            _ => None,
        }
    } else {
        None
    }
}

/// Wildcard glob matcher for hostnames (e.g. pattern `*.office.lan` or `web-*.corp.lan` against ` macbook.office.lan`)
pub fn wildcard_host_matches(pattern: &str, hostname: &str) -> bool {
    let pat = pattern.to_ascii_lowercase();
    let host = hostname.to_ascii_lowercase();
    if pat == "*" {
        return true;
    }
    if !pat.contains('*') {
        return pat == host;
    }
    // Simple glob matching supporting arbitrary '*' wildcards
    let parts: Vec<&str> = pat.split('*').collect();
    if parts.is_empty() {
        return true;
    }
    let mut pos = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 && !pat.starts_with('*') {
            if !host[pos..].starts_with(part) {
                return false;
            }
            pos += part.len();
        } else if i == parts.len() - 1 && !pat.ends_with('*') {
            return host[pos..].ends_with(part);
        } else if let Some(found) = host[pos..].find(part) {
            pos += found + part.len();
        } else {
            return false;
        }
    }
    true
}

/// Parses a full Nftyfile text into a `Config`
pub fn parse_nftyfile(input: &str) -> Result<Config> {
    let mut config = Config::new();

    #[derive(Debug)]
    enum ParseContext {
        Root,
        GlobalAllow,
        Vip(String),
        VipServices(String),
        VipServiceItem(String, Service, bool),
        VipServiceTo(String, Service, bool),
        VipServiceAllow(String, Service, bool),
        Service(Service),
        ServiceTo(Service),
        ServiceAllow(Service),
        Gateway(Gateway),
        GatewayTunnels(Gateway),
        GatewayService(Gateway),
        GatewayAllow(Gateway),
    }

    let mut ctx = ParseContext::Root;

    for (line_idx, raw_line) in input.lines().enumerate() {
        let line_no = line_idx + 1;
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        for stmt in line.split(';') {
            let stmt = stmt.trim();
            if stmt.is_empty() {
                continue;
            }

            ctx = match ctx {
                ParseContext::Root => {
                    if stmt == "allow {" || stmt == "allow" {
                        ParseContext::GlobalAllow
                    } else if stmt.starts_with("allow ") {
                        for tok in stmt.split_whitespace().skip(1) {
                            let entry = validate_allow_entry(tok)
                                .with_context(|| format!("Line {}", line_no))?;
                            if !config.global_allow.contains(&entry) {
                                config.global_allow.push(entry);
                            }
                        }
                        ParseContext::Root
                    } else {
                        let without_brace = stmt.strip_suffix('{').map(|s| s.trim()).unwrap_or(stmt);
                        let tokens: Vec<&str> = without_brace.split_whitespace().collect();
                        if tokens.is_empty() {
                            ParseContext::Root
                        } else if tokens[0].eq_ignore_ascii_case("vip") {
                            if tokens.len() < 2 {
                                bail!(
                                    "Line {}: expected VIP IPv4 address or DHCP hostname after 'vip' (e.g. 'vip 192.168.1.4' or 'vip sonarr')",
                                    line_no
                                );
                            }
                            let (vip_key, _ip_opt, parsed_vip) = parse_vip_header(&tokens[1..])
                                .with_context(|| format!("Line {}", line_no))?;
                            let entry = config
                                .vips
                                .entry(vip_key.clone())
                                .or_insert_with(|| parsed_vip.clone());
                            if parsed_vip.dhcp {
                                entry.dhcp = true;
                            }
                            if parsed_vip.vlan.is_some() {
                                entry.vlan = parsed_vip.vlan;
                            }
                            if tokens[1].contains('/') {
                                entry.prefix_len = parsed_vip.prefix_len;
                            }
                            ParseContext::Vip(vip_key)
                        } else if tokens[0].eq_ignore_ascii_case("gateway") {
                            if tokens.len() < 2 {
                                bail!(
                                    "Line {}: expected gateway IPv4 address or DHCP hostname after 'gateway'",
                                    line_no
                                );
                            }
                            let (gw_key, ip_opt, parsed_vip) = parse_vip_header(&tokens[1..])
                                .with_context(|| format!("Line {}: invalid gateway '{}'", line_no, tokens[1]))?;
                            let listen_ip = ip_opt.unwrap_or(Ipv4Addr::UNSPECIFIED);
                            let mut gw = config
                                .gateways
                                .remove(&gw_key)
                                .unwrap_or_else(|| Gateway::new_named(gw_key.clone(), listen_ip, parsed_vip.clone()));
                            let vip_ref = gw.vip.get_or_insert_with(|| parsed_vip.clone());
                            if parsed_vip.dhcp {
                                vip_ref.dhcp = true;
                            }
                            if parsed_vip.vlan.is_some() {
                                vip_ref.vlan = parsed_vip.vlan;
                            }
                            if tokens[1].contains('/') {
                                vip_ref.prefix_len = parsed_vip.prefix_len;
                            }
                            ParseContext::Gateway(gw)
                        } else {
                            let spec = if tokens[0].eq_ignore_ascii_case("service") {
                                if tokens.len() < 2 {
                                    bail!(
                                        "Line {}: expected service port/address after 'service'",
                                        line_no
                                    );
                                }
                                tokens[1]
                            } else {
                                tokens[0]
                            };
                            let (key, listen_ip, port, proto) = parse_service_spec(spec)
                                .with_context(|| format!("Line {}", line_no))?;
                            let svc = config
                                .services
                                .remove(&key)
                                .unwrap_or_else(|| Service::new(key, listen_ip, port, proto));
                            ParseContext::Service(svc)
                        }
                    }
                }
                ParseContext::Vip(vip_key) => {
                    if stmt == "}" {
                        ParseContext::Root
                    } else if stmt == "service {"
                        || stmt == "service"
                        || stmt == "services {"
                        || stmt == "services"
                    {
                        ParseContext::VipServices(vip_key)
                    } else {
                        let without_brace = stmt.strip_suffix('{').map(|s| s.trim()).unwrap_or(stmt);
                        let tokens: Vec<&str> = without_brace.split_whitespace().collect();
                        if tokens.is_empty() {
                            ParseContext::Vip(vip_key)
                        } else if matches!(tokens[0].to_ascii_lowercase().as_str(), "vip" | "interface" | "dev") {
                            if tokens.len() < 2 {
                                bail!("Line {}: expected interface[/cidr] after '{}'", line_no, tokens[0]);
                            }
                            let mut v = parse_vip(tokens[1]).with_context(|| format!("Line {}", line_no))?;
                            if let Some(existing) = config.vips.get(&vip_key) {
                                v.dhcp = existing.dhcp;
                                v.leased_ip = existing.leased_ip;
                                if v.vlan.is_none() {
                                    v.vlan = existing.vlan;
                                }
                            }
                            config.vips.insert(vip_key.clone(), v.clone());
                            for s in config.services.values_mut().filter(|s| s.belongs_to_vip(&vip_key)) {
                                s.vip = Some(v.clone());
                            }
                            ParseContext::Vip(vip_key)
                        } else if tokens[0].eq_ignore_ascii_case("dhcp") {
                            let entry = config
                                .vips
                                .entry(vip_key.clone())
                                .or_insert_with(|| VipConfig::new("eth0", 32));
                            if tokens.len() >= 2 && matches!(tokens[1].to_ascii_lowercase().as_str(), "off" | "false" | "no") {
                                entry.dhcp = false;
                            } else {
                                entry.dhcp = true;
                                if tokens.len() >= 2 && !matches!(tokens[1].to_ascii_lowercase().as_str(), "on" | "true" | "yes") {
                                    let (base, vid) = split_iface_and_vlan(tokens[1]);
                                    entry.interface = base;
                                    if vid.is_some() {
                                        entry.vlan = vid;
                                    }
                                }
                            }
                            let updated = entry.clone();
                            for s in config.services.values_mut().filter(|s| s.belongs_to_vip(&vip_key)) {
                                s.vip = Some(updated.clone());
                            }
                            ParseContext::Vip(vip_key)
                        } else if tokens[0].eq_ignore_ascii_case("vlan") {
                            if tokens.len() < 2 {
                                bail!("Line {}: expected VLAN ID (1-4094) after 'vlan'", line_no);
                            }
                            let vid = parse_vlan_id(tokens[1]).with_context(|| format!("Line {}", line_no))?;
                            let entry = config
                                .vips
                                .entry(vip_key.clone())
                                .or_insert_with(|| VipConfig::new("eth0", 24));
                            entry.vlan = Some(vid);
                            let updated = entry.clone();
                            for s in config.services.values_mut().filter(|s| s.belongs_to_vip(&vip_key)) {
                                s.vip = Some(updated.clone());
                            }
                            ParseContext::Vip(vip_key)
                        } else if tokens[0].eq_ignore_ascii_case("ssh")
                            || tokens[0].to_ascii_lowercase().starts_with("ssh:")
                            || (tokens[0].eq_ignore_ascii_case("local") && tokens.len() >= 2)
                        {
                            let spec = if tokens[0].eq_ignore_ascii_case("local") {
                                tokens[1]
                            } else if tokens[0].eq_ignore_ascii_case("ssh") && tokens.len() >= 2 && tokens[1].parse::<u16>().is_ok() {
                                &format!("ssh:{}", tokens[1])
                            } else {
                                tokens[0]
                            };
                            let key = create_or_find_vip_service_by_key(&mut config, &vip_key, spec)
                                .with_context(|| format!("Line {}", line_no))?;
                            if stmt.ends_with('{') {
                                let svc = config.services.remove(&key).unwrap();
                                ParseContext::VipServiceItem(vip_key, svc, false)
                            } else {
                                ParseContext::Vip(vip_key)
                            }
                        } else {
                            let spec_str = if tokens[0].eq_ignore_ascii_case("service") && tokens.len() >= 2 {
                                tokens[1..].join(" ")
                            } else {
                                without_brace.to_string()
                            };
                            let key = create_or_find_vip_service_by_key(&mut config, &vip_key, &spec_str)
                                .with_context(|| format!("Line {}", line_no))?;
                            if stmt.ends_with('{') {
                                let svc = config.services.remove(&key).unwrap();
                                ParseContext::VipServiceItem(vip_key, svc, false)
                            } else {
                                ParseContext::Vip(vip_key)
                            }
                        }
                    }
                }
                ParseContext::VipServices(vip_key) => {
                    if stmt == "}" {
                        ParseContext::Vip(vip_key)
                    } else {
                        let has_brace = stmt.ends_with('{');
                        let without_brace = stmt.strip_suffix('{').map(|s| s.trim()).unwrap_or(stmt);
                        let tokens: Vec<&str> = without_brace.split_whitespace().collect();
                        if tokens.is_empty() {
                            ParseContext::VipServices(vip_key)
                        } else {
                            let spec_str = if tokens[0].eq_ignore_ascii_case("service") && tokens.len() >= 2 {
                                tokens[1..].join(" ")
                            } else {
                                without_brace.to_string()
                            };
                            let key = create_or_find_vip_service_by_key(&mut config, &vip_key, &spec_str)
                                .with_context(|| format!("Line {}", line_no))?;
                            if has_brace {
                                let svc = config.services.remove(&key).unwrap();
                                ParseContext::VipServiceItem(vip_key, svc, true)
                            } else {
                                ParseContext::VipServices(vip_key)
                            }
                        }
                    }
                }
                ParseContext::VipServiceItem(vip_key, mut svc, in_sub) => {
                    if stmt == "}" {
                        if let Some(v) = config.vips.get(&vip_key).cloned() {
                            if svc.vip.is_none() {
                                svc.vip = Some(v);
                            }
                        }
                        insert_vip_service_disambiguated(&mut config, &vip_key, svc);
                        if in_sub {
                            ParseContext::VipServices(vip_key)
                        } else {
                            ParseContext::Vip(vip_key)
                        }
                    } else if stmt == "to {" || stmt == "to" {
                        ParseContext::VipServiceTo(vip_key, svc, in_sub)
                    } else if stmt == "allow {" || stmt == "allow" {
                        ParseContext::VipServiceAllow(vip_key, svc, in_sub)
                    } else {
                        apply_service_directive(&mut svc, stmt)
                            .with_context(|| format!("Line {}", line_no))?;
                        ParseContext::VipServiceItem(vip_key, svc, in_sub)
                    }
                }
                ParseContext::VipServiceTo(vip_key, mut svc, in_sub) => {
                    if stmt == "}" {
                        ParseContext::VipServiceItem(vip_key, svc, in_sub)
                    } else {
                        let tokens: Vec<&str> = stmt.split_whitespace().collect();
                        let b = parse_backend(&tokens, svc.port)
                            .with_context(|| format!("Line {}", line_no))?;
                        if !svc.backends.contains(&b) {
                            svc.backends.push(b);
                        }
                        ParseContext::VipServiceTo(vip_key, svc, in_sub)
                    }
                }
                ParseContext::VipServiceAllow(vip_key, mut svc, in_sub) => {
                    if stmt == "}" {
                        ParseContext::VipServiceItem(vip_key, svc, in_sub)
                    } else {
                        for tok in stmt.split_whitespace() {
                            let entry = validate_allow_entry(tok)
                                .with_context(|| format!("Line {}", line_no))?;
                            if !svc.allow.contains(&entry) {
                                svc.allow.push(entry);
                            }
                        }
                        ParseContext::VipServiceAllow(vip_key, svc, in_sub)
                    }
                }
                ParseContext::GlobalAllow => {
                    if stmt == "}" {
                        ParseContext::Root
                    } else {
                        for tok in stmt.split_whitespace() {
                            let entry = validate_allow_entry(tok)
                                .with_context(|| format!("Line {}", line_no))?;
                            if !config.global_allow.contains(&entry) {
                                config.global_allow.push(entry);
                            }
                        }
                        ParseContext::GlobalAllow
                    }
                }
                ParseContext::Service(mut svc) => {
                    if stmt == "}" {
                        config.services.insert(svc.key.clone(), svc);
                        ParseContext::Root
                    } else if stmt == "to {" || stmt == "to" {
                        ParseContext::ServiceTo(svc)
                    } else if stmt == "allow {" || stmt == "allow" {
                        ParseContext::ServiceAllow(svc)
                    } else {
                        apply_service_directive(&mut svc, stmt)
                            .with_context(|| format!("Line {}", line_no))?;
                        ParseContext::Service(svc)
                    }
                }
                ParseContext::ServiceTo(mut svc) => {
                    if stmt == "}" {
                        ParseContext::Service(svc)
                    } else {
                        let tokens: Vec<&str> = stmt.split_whitespace().collect();
                        let b = parse_backend(&tokens, svc.port)
                            .with_context(|| format!("Line {}", line_no))?;
                        if !svc.backends.contains(&b) {
                            svc.backends.push(b);
                        }
                        ParseContext::ServiceTo(svc)
                    }
                }
                ParseContext::ServiceAllow(mut svc) => {
                    if stmt == "}" {
                        ParseContext::Service(svc)
                    } else {
                        for tok in stmt.split_whitespace() {
                            let entry = validate_allow_entry(tok)
                                .with_context(|| format!("Line {}", line_no))?;
                            if !svc.allow.contains(&entry) {
                                svc.allow.push(entry);
                            }
                        }
                        ParseContext::ServiceAllow(svc)
                    }
                }
                ParseContext::Gateway(mut gw) => {
                    if stmt == "}" {
                        config.gateways.insert(gw.key.clone(), gw);
                        ParseContext::Root
                    } else if stmt == "tunnels {" || stmt == "tunnels" || stmt == "to {" || stmt == "to" {
                        ParseContext::GatewayTunnels(gw)
                    } else if stmt == "service {"
                        || stmt == "service"
                        || stmt == "services {"
                        || stmt == "services"
                    {
                        ParseContext::GatewayService(gw)
                    } else if stmt == "allow {" || stmt == "allow" {
                        ParseContext::GatewayAllow(gw)
                    } else {
                        apply_gateway_directive(&mut gw, stmt)
                            .with_context(|| format!("Line {}", line_no))?;
                        ParseContext::Gateway(gw)
                    }
                }
                ParseContext::GatewayService(mut gw) => {
                    if stmt == "}" {
                        ParseContext::Gateway(gw)
                    } else {
                        for tok in stmt.split_whitespace() {
                            let gs = parse_gateway_service(tok)
                                .with_context(|| format!("Line {}", line_no))?;
                            if let Some(existing) = gw.services.iter_mut().find(|x| x.kind == gs.kind) {
                                *existing = gs;
                            } else {
                                gw.services.push(gs);
                            }
                        }
                        ParseContext::GatewayService(gw)
                    }
                }
                ParseContext::GatewayTunnels(mut gw) => {
                    if stmt == "}" {
                        ParseContext::Gateway(gw)
                    } else {
                        let tokens: Vec<&str> = stmt.split_whitespace().collect();
                        let next_idx = gw.tunnels.len();
                        let t = parse_wg_tunnel(&tokens, next_idx)
                            .with_context(|| format!("Line {}", line_no))?;
                        if let Some(existing) = gw.tunnels.iter_mut().find(|x| x.name == t.name) {
                            *existing = t;
                        } else {
                            gw.tunnels.push(t);
                        }
                        ParseContext::GatewayTunnels(gw)
                    }
                }
                ParseContext::GatewayAllow(mut gw) => {
                    if stmt == "}" {
                        ParseContext::Gateway(gw)
                    } else {
                        for tok in stmt.split_whitespace() {
                            let entry = validate_allow_entry(tok)
                                .with_context(|| format!("Line {}", line_no))?;
                            if !gw.allow.contains(&entry) {
                                gw.allow.push(entry);
                            }
                        }
                        ParseContext::GatewayAllow(gw)
                    }
                }
            };
        }
    }

    match ctx {
        ParseContext::Root
        | ParseContext::GlobalAllow
        | ParseContext::Vip(_)
        | ParseContext::VipServices(_) => {}
        ParseContext::VipServiceItem(vip_key, svc, _)
        | ParseContext::VipServiceTo(vip_key, svc, _)
        | ParseContext::VipServiceAllow(vip_key, svc, _) => {
            insert_vip_service_disambiguated(&mut config, &vip_key, svc);
        }
        ParseContext::Service(svc)
        | ParseContext::ServiceTo(svc)
        | ParseContext::ServiceAllow(svc) => {
            config.services.insert(svc.key.clone(), svc);
        }
        ParseContext::Gateway(gw)
        | ParseContext::GatewayTunnels(gw)
        | ParseContext::GatewayService(gw)
        | ParseContext::GatewayAllow(gw) => {
            config.gateways.insert(gw.key.clone(), gw);
        }
    }

    // Hydrate any active DHCP leases from `/run/nfty-dhcp-*.ip` so SSH/CLI sessions immediately see leased IPs
    for (vip_key, vip_cfg) in config.vips.iter_mut() {
        if vip_cfg.dhcp && vip_cfg.leased_ip.is_none() {
            let mv_iface = crate::compiler::dhcp_macvlan_iface_name(vip_key);
            let ip_file = format!("/run/nfty-dhcp-{}.ip", mv_iface);
            if let Ok(raw_ip) = std::fs::read_to_string(&ip_file) {
                if let Ok(ip) = raw_ip.trim().parse::<Ipv4Addr>() {
                    vip_cfg.leased_ip = Some(ip);
                }
            }
        }
    }
    for (vip_key, vip_cfg) in &config.vips {
        if let Some(ip) = vip_cfg.leased_ip {
            for svc in config.services.values_mut() {
                if svc.belongs_to_vip(vip_key) {
                    svc.listen_ip = Some(ip);
                    if let Some(sv) = &mut svc.vip {
                        sv.leased_ip = Some(ip);
                    }
                }
            }
        }
    }
    for (gw_key, gw) in config.gateways.iter_mut() {
        if let Some(vip_cfg) = &mut gw.vip {
            if vip_cfg.dhcp && vip_cfg.leased_ip.is_none() {
                let mv_iface = crate::compiler::dhcp_macvlan_iface_name(gw_key);
                let ip_file = format!("/run/nfty-dhcp-{}.ip", mv_iface);
                if let Ok(raw_ip) = std::fs::read_to_string(&ip_file) {
                    if let Ok(ip) = raw_ip.trim().parse::<Ipv4Addr>() {
                        vip_cfg.leased_ip = Some(ip);
                        gw.listen_ip = ip;
                    }
                }
            }
        }
    }

    Ok(config)
}

pub fn parse_ip_and_optional_cidr(raw: &str) -> Result<(Ipv4Addr, Option<u8>)> {
    if let Some((ip_part, cidr_part)) = raw.trim().split_once('/') {
        let ip: Ipv4Addr = ip_part
            .parse()
            .with_context(|| format!("Invalid IPv4 address '{}'", ip_part))?;
        let p: u8 = cidr_part
            .parse()
            .with_context(|| format!("Invalid CIDR prefix length '{}'", cidr_part))?;
        if p == 0 || p > 32 {
            bail!("CIDR prefix length must be between 1 and 32");
        }
        Ok((ip, Some(p)))
    } else {
        let ip: Ipv4Addr = raw
            .trim()
            .parse()
            .with_context(|| format!("Invalid IPv4 address '{}'", raw))?;
        Ok((ip, None))
    }
}

/// Creates or looks up a service inside a `vip <ip> -> service` container from a spec such as:
/// - `plex:32400` or `gamble:9090` or `192.168.1.165:32400` (backend host/IP:port, listen port defaults to backend port)
/// - `ssh:22` or `ssh` (local SSH service on port 22 -> `127.0.0.1:22`)
/// - `80` or `53/udp` (listen port on the VIP)
pub fn insert_vip_service_disambiguated(
    config: &mut Config,
    vip_key: &str,
    mut svc: Service,
) -> String {
    if let Some(existing) = config.services.get(&svc.key) {
        let same_target = existing.name == svc.name && existing.hostname == svc.hostname;
        if !same_target && (!existing.backends.is_empty() || existing.hostname.is_some()) {
            let suffix = svc
                .hostname
                .clone()
                .or_else(|| svc.name.clone())
                .unwrap_or_else(|| format!("b{}", config.services.len()));
            svc.key = format!("{}:{}@{}", vip_key, svc.port, suffix);
        }
    }
    let key = svc.key.clone();
    config.services.insert(key.clone(), svc);
    key
}

pub fn create_or_find_vip_service(
    config: &mut Config,
    vip_ip: Ipv4Addr,
    raw_spec: &str,
) -> Result<String> {
    create_or_find_vip_service_by_key(config, &vip_ip.to_string(), raw_spec)
}

pub fn create_or_find_vip_service_by_key(
    config: &mut Config,
    vip_key: &str,
    raw_spec: &str,
) -> Result<String> {
    let spec = raw_spec.trim();
    if spec.is_empty() {
        bail!("Expected service target or port (e.g. '80 to sonarr:8989', 'plex:32400', 'ssh:22', or '80')");
    }

    let vip_ip_opt: Option<Ipv4Addr> = vip_key
        .parse::<Ipv4Addr>()
        .ok()
        .or_else(|| config.vips.get(vip_key).and_then(|v| v.leased_ip));

    let vip_cfg = config
        .vips
        .get(vip_key)
        .cloned()
        .or_else(|| {
            config
                .services
                .values()
                .find(|s| s.belongs_to_vip(vip_key) && s.vip.is_some())
                .and_then(|s| s.vip.clone())
        })
        .or_else(|| {
            if vip_key.parse::<Ipv4Addr>().is_ok() {
                Some(VipConfig::default_eth0())
            } else {
                Some(VipConfig {
                    interface: "eth0".to_string(),
                    prefix_len: 32,
                    dhcp: true,
                    vlan: None,
                    leased_ip: None,
                })
            }
        });

    // 0. Check for `<port[/proto]> to <target>` or `<port[/proto]> -> <target>` shorthand (e.g. "80 to sonarr:8989")
    let to_split = {
        let mut found = None;
        let tokens: Vec<&str> = spec.split_whitespace().collect();
        if tokens.len() >= 3
            && (tokens[1].eq_ignore_ascii_case("to") || tokens[1] == "->")
        {
            found = Some((tokens[0], tokens[2..].join(" ")));
        }
        found
    };
    if let Some((port_part, target_part)) = to_split {
        let clean_port = port_part.trim_start_matches(':');
        let (_, _, port, proto) = parse_service_spec(clean_port)?;
        let target_tokens: Vec<&str> = target_part.split_whitespace().collect();
        let b = parse_backend(&target_tokens, port)?;
        let target_label = b.to_string();

        // Check if an identical service already exists on this VIP
        for (k, existing) in &config.services {
            if existing.belongs_to_vip(vip_key)
                && existing.port == port
                && existing.proto == proto
                && (existing.backends.is_empty()
                    || existing.backends.first().map(|x| x.to_string()).as_deref()
                        == Some(target_label.as_str()))
            {
                let k_clone = k.clone();
                if let Some(s_mut) = config.services.get_mut(&k_clone) {
                    s_mut.name = Some(target_label);
                    if s_mut.backends.is_empty() {
                        s_mut.backends.push(b);
                    } else {
                        s_mut.backends[0] = b;
                    }
                }
                return Ok(k_clone);
            }
        }

        let mut svc = Service::new(String::new(), vip_ip_opt, port, proto);
        svc.vip_id = Some(vip_key.to_string());
        svc.rebuild_key();
        svc.name = Some(target_label);
        svc.vip = vip_cfg;
        svc.backends.push(b);
        return Ok(insert_vip_service_disambiguated(config, vip_key, svc));
    }

    // 1. Check if a service on this VIP already matches `spec` by name, display_name, or port
    let clean_spec = spec.trim_start_matches(':');
    for (k, svc) in &config.services {
        if svc.belongs_to_vip(vip_key) {
            if svc.display_name().eq_ignore_ascii_case(spec)
                || svc
                    .name
                    .as_deref()
                    .map(|n| n.eq_ignore_ascii_case(spec))
                    .unwrap_or(false)
                || k.eq_ignore_ascii_case(&format!("{}:{}", vip_key, clean_spec))
                || (svc.port.to_string() == clean_spec
                    && clean_spec.chars().all(|c| c.is_ascii_digit()))
            {
                return Ok(k.clone());
            }
        }
    }

    // 2. Built-in `ssh` / `ssh:22`
    let lower = spec.to_ascii_lowercase();
    if lower == "ssh" || lower.starts_with("ssh:") {
        let port = if let Some((_, p_str)) = lower.split_once(':') {
            p_str
                .parse::<u16>()
                .with_context(|| format!("Invalid SSH port '{}'", p_str))?
        } else {
            22
        };
        let key = format!("{}:{}", vip_key, port);
        let mut svc = Service::new(key.clone(), vip_ip_opt, port, Proto::Tcp);
        svc.vip_id = Some(vip_key.to_string());
        svc.name = Some(format!("ssh:{}", port));
        svc.vip = vip_cfg;
        svc.backends.push(Backend {
            host: None,
            ip: Ipv4Addr::new(127, 0, 0, 1),
            port: 22,
            weight: 1,
            backup: false,
        });
        config.services.insert(key.clone(), svc);
        return Ok(key);
    }

    // 3. Plain port or port/proto (e.g. `80`, `:80`, `53/udp`)
    let port_candidate = clean_spec.split('/').next().unwrap_or(clean_spec);
    if port_candidate.chars().all(|c| c.is_ascii_digit()) && !port_candidate.is_empty() {
        let (_, _, port, proto) = parse_service_spec(clean_spec)?;
        let mut svc = Service::new(String::new(), vip_ip_opt, port, proto);
        svc.vip_id = Some(vip_key.to_string());
        svc.rebuild_key();
        let key = svc.key.clone();
        svc.name = Some(clean_spec.to_string());
        svc.vip = vip_cfg;
        config.services.insert(key.clone(), svc);
        return Ok(key);
    }

    // 4. Target `<host_or_ip>:<port>` (e.g. `plex:32400`, `gamble:9090`, `192.168.1.165:32400`)
    let b = parse_backend(&[spec], 80)?;
    let port = b.port;
    let key = format!("{}:{}", vip_key, port);
    let mut svc = Service::new(key.clone(), vip_ip_opt, port, Proto::Tcp);
    svc.vip_id = Some(vip_key.to_string());
    svc.name = Some(spec.to_string());
    svc.vip = vip_cfg;
    svc.backends.push(b);
    Ok(insert_vip_service_disambiguated(config, vip_key, svc))
}

pub fn apply_service_directive(svc: &mut Service, stmt: &str) -> Result<()> {
    let tokens: Vec<&str> = stmt.split_whitespace().collect();
    if tokens.is_empty() {
        return Ok(());
    }
    match tokens[0].to_ascii_lowercase().as_str() {
        "port" | "listen" => {
            if tokens.len() < 2 {
                bail!("Expected external listen port after '{}' (e.g. 'port 80')", tokens[0]);
            }
            let p: u16 = tokens[1]
                .parse()
                .with_context(|| format!("Invalid port '{}'", tokens[1]))?;
            if p == 0 {
                bail!("Port cannot be 0");
            }
            svc.port = p;
            svc.rebuild_key();
        }
        "proto" | "protocol" => {
            if tokens.len() < 2 {
                bail!("Expected protocol ('tcp', 'udp', or 'both')");
            }
            svc.proto = match tokens[1].to_ascii_lowercase().as_str() {
                "tcp" => Proto::Tcp,
                "udp" => Proto::Udp,
                "both" => Proto::Both,
                other => bail!("Unknown protocol '{}' (expected tcp, udp, or both)", other),
            };
            svc.rebuild_key();
        }
        "to" => {
            let backends = parse_backends_line(&tokens[1..], svc.port)?;
            for b in backends {
                if let Some(existing) = svc.backends.iter_mut().find(|x| {
                    x.port == b.port
                        && ((b.host.is_some() && x.host == b.host)
                            || (b.host.is_none() && x.ip == b.ip))
                }) {
                    *existing = b;
                } else {
                    svc.backends.push(b);
                }
            }
        }
        "balance" => {
            if tokens.len() < 2 {
                bail!("Expected balance strategy: 'round-robin' or 'sticky'");
            }
            svc.balance = match tokens[1].to_ascii_lowercase().as_str() {
                "round-robin" | "rr" => BalanceStrategy::RoundRobin,
                "sticky" | "hash" | "ip-hash" | "source" => BalanceStrategy::Sticky,
                other => bail!(
                    "Unknown balance strategy '{}' (expected 'round-robin' or 'sticky')",
                    other
                ),
            };
        }
        "mode" => {
            if tokens.len() < 2 {
                bail!("Expected mode: 'nat' or 'transparent'");
            }
            svc.mode = match tokens[1].to_ascii_lowercase().as_str() {
                "nat" | "masquerade" | "snat" => ForwardMode::Nat,
                "transparent" | "dsr" | "preserve-ip" => ForwardMode::Transparent,
                other => bail!("Unknown mode '{}' (expected 'nat' or 'transparent')", other),
            };
        }
        "vip" | "interface" | "dev" => {
            if tokens.len() < 2 {
                bail!("Expected interface name after 'vip' / 'interface' (e.g. 'interface eth0/21')");
            }
            let mut v = parse_vip(tokens[1])?;
            if let Some(old_v) = &svc.vip {
                if v.vlan.is_none() {
                    v.vlan = old_v.vlan;
                }
                v.dhcp |= old_v.dhcp;
                if v.leased_ip.is_none() {
                    v.leased_ip = old_v.leased_ip;
                }
            }
            svc.vip = Some(v);
        }
        "dhcp" => {
            let mut v = if tokens.len() >= 2 {
                parse_vip(tokens[1])?
            } else {
                svc.vip.clone().unwrap_or_else(VipConfig::default_eth0)
            };
            v.dhcp = true;
            if let Some(old_v) = &svc.vip {
                if v.vlan.is_none() {
                    v.vlan = old_v.vlan;
                }
                if v.leased_ip.is_none() {
                    v.leased_ip = old_v.leased_ip;
                }
            }
            svc.vip = Some(v);
        }
        "vlan" => {
            if tokens.len() < 2 {
                bail!("Expected VLAN ID (1-4094) after 'vlan'");
            }
            let vid = parse_vlan_id(tokens[1])?;
            svc.vip
                .get_or_insert_with(VipConfig::default_eth0)
                .vlan = Some(vid);
        }
        "hostname" | "host" | "domain" | "mdns" => {
            if tokens.len() < 2 {
                bail!("Expected hostname (e.g. 'hostname plex.local')");
            }
            svc.hostname = Some(tokens[1].trim().to_ascii_lowercase());
        }
        "cloudflare-dns" | "cloudflare" | "cf" | "tunnel-dns" => {
            if tokens.len() < 2 {
                bail!("Expected public FQDN after 'cloudflare-dns' (e.g. 'cloudflare-dns sonarr.example.com')");
            }
            let fqdn = tokens[1]
                .trim()
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .trim_end_matches('/')
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if !fqdn.contains('.') {
                bail!(
                    "Invalid Cloudflare hostname '{}' (expected a full domain like 'sonarr.example.com')",
                    fqdn
                );
            }
            svc.cloudflare = Some(fqdn);
        }
        "cloudflare-auth" | "cf-auth" | "tunnel-auth" => {
            if tokens.len() < 2 {
                bail!(
                    "Expected email rule after '{}' (e.g. 'cloudflare-auth you@email.com' or 'cloudflare-auth *@smith.gr')",
                    tokens[0]
                );
            }
            for tok in &tokens[1..] {
                let entry = tok.trim().to_string();
                if !entry.is_empty() && !svc.cloudflare_auth.contains(&entry) {
                    svc.cloudflare_auth.push(entry);
                }
            }
        }
        "auth" | "basic-auth" => {
            if tokens.len() < 2 {
                bail!(
                    "Expected username:password or 'nfty' after '{}' (e.g. 'auth gsmith:secret' or 'auth nfty')",
                    tokens[0]
                );
            }
            let start_idx = if tokens[1].eq_ignore_ascii_case("basic") && tokens.len() >= 3 {
                2
            } else {
                1
            };
            for tok in &tokens[start_idx..] {
                let entry = tok.trim().to_string();
                if !entry.is_empty() && !svc.auth.contains(&entry) {
                    svc.auth.push(entry);
                }
            }
        }
        "check" => {
            svc.check = Some(parse_health_check(&tokens[1..])?);
        }
        "limit" => {
            svc.limit = Some(parse_rate_limit(&tokens[1..])?);
        }
        "allow" => {
            if tokens.len() < 2 {
                bail!("Expected host, wildcard, IP, or CIDR after 'allow'");
            }
            for tok in &tokens[1..] {
                let entry = validate_allow_entry(tok)?;
                if !svc.allow.contains(&entry) {
                    svc.allow.push(entry);
                }
            }
        }
        "no" | "delete" | "remove" => {
            apply_service_no_directive(svc, &tokens[1..])?;
        }
        other => bail!(
            "Unknown service directive '{}'. Valid directives: port, proto, to, hostname, cloudflare-dns, cloudflare-auth, auth, balance, mode, vip, check, limit, allow, no",
            other
        ),
    }
    Ok(())
}

pub fn apply_service_no_directive(svc: &mut Service, tokens: &[&str]) -> Result<()> {
    if tokens.is_empty() {
        bail!("Expected item to remove after 'no' (e.g. 'no vip', 'no cloudflare-dns', 'no cloudflare-auth', 'no auth', 'no check', 'no limit', 'no allow <host>', 'no to <ip>')");
    }
    match tokens[0].to_ascii_lowercase().as_str() {
        "vip" => svc.vip = None,
        "vlan" => {
            if let Some(v) = &mut svc.vip {
                v.vlan = None;
            }
        }
        "hostname" | "host" | "domain" | "mdns" => svc.hostname = None,
        "cloudflare-dns" | "cloudflare" | "cf" | "tunnel-dns" => svc.cloudflare = None,
        "cloudflare-auth" | "cf-auth" | "tunnel-auth" => {
            if tokens.len() == 1 {
                svc.cloudflare_auth.clear();
            } else {
                let target = tokens[1].trim();
                svc.cloudflare_auth.retain(|x| !x.eq_ignore_ascii_case(target));
            }
        }
        "auth" | "basic-auth" => {
            if tokens.len() == 1 {
                svc.auth.clear();
            } else {
                let target = tokens[1].trim();
                svc.auth.retain(|x| !x.eq_ignore_ascii_case(target));
            }
        }
        "check" => svc.check = None,
        "limit" => svc.limit = None,
        "balance" => svc.balance = BalanceStrategy::RoundRobin,
        "mode" => svc.mode = ForwardMode::Nat,
        "allow" => {
            if tokens.len() == 1 {
                svc.allow.clear();
            } else {
                let target =
                    validate_allow_entry(tokens[1]).unwrap_or_else(|_| tokens[1].to_string());
                svc.allow.retain(|x| x != &target);
            }
        }
        "to" => {
            if tokens.len() == 1 {
                svc.backends.clear();
            } else {
                remove_backend_from_service(svc, tokens[1])?;
            }
        }
        other => {
            remove_backend_from_service(svc, other)?;
        }
    }
    Ok(())
}

pub fn remove_backend_from_service(svc: &mut Service, raw_target: &str) -> Result<bool> {
    let b = parse_backend(&[raw_target], svc.port)?;
    let before = svc.backends.len();
    svc.backends.retain(|x| {
        let same_port = x.port == b.port;
        let same_target =
            (b.host.is_some() && x.host == b.host) || (b.host.is_none() && x.ip == b.ip);
        !(same_port && same_target)
    });
    Ok(svc.backends.len() < before)
}

pub fn parse_wg_tunnel(tokens: &[&str], index_hint: usize) -> Result<WgTunnel> {
    if tokens.is_empty() {
        bail!("Expected tunnel config name (e.g. 'mullvad-us-sea-001.conf') or inline tunnel definition");
    }
    let name = tokens[0].trim().to_string();
    let iface = if name.starts_with("wg")
        && name[2..].chars().all(|c| c.is_ascii_digit())
        && !name.ends_with(".conf")
    {
        name.clone()
    } else {
        format!("wg{}", index_hint)
    };

    let mut address = None;
    let mut private_key = None;
    let mut peer_pubkey = None;
    let mut endpoint = None;
    let mut weight = 1u32;

    let mut idx = 1;
    while idx < tokens.len() {
        match tokens[idx].to_ascii_lowercase().as_str() {
            "address" | "addr" | "ip" => {
                idx += 1;
                if idx >= tokens.len() {
                    bail!("Expected tunnel IPv4/CIDR after 'address'");
                }
                address = Some(tokens[idx].to_string());
            }
            "privkey" | "private-key" | "private_key" => {
                idx += 1;
                if idx >= tokens.len() {
                    bail!("Expected base64 private key after 'privkey'");
                }
                private_key = Some(tokens[idx].to_string());
            }
            "peer" | "pubkey" | "public-key" | "public_key" => {
                idx += 1;
                if idx >= tokens.len() {
                    bail!("Expected peer public key after 'peer'");
                }
                peer_pubkey = Some(tokens[idx].to_string());
            }
            "endpoint" | "server" => {
                idx += 1;
                if idx >= tokens.len() {
                    bail!("Expected endpoint host:port after 'endpoint'");
                }
                endpoint = Some(tokens[idx].to_string());
            }
            "weight" => {
                idx += 1;
                if idx >= tokens.len() {
                    bail!("Expected weight number after 'weight'");
                }
                weight = tokens[idx].parse()?;
            }
            other => bail!(
                "Unexpected token '{}' in tunnel definition (expected address, privkey, peer, endpoint, or weight)",
                other
            ),
        }
        idx += 1;
    }

    Ok(WgTunnel {
        name,
        iface,
        address,
        private_key,
        peer_pubkey,
        endpoint,
        weight,
    })
}

pub fn apply_gateway_directive(gw: &mut Gateway, stmt: &str) -> Result<()> {
    let tokens: Vec<&str> = stmt.split_whitespace().collect();
    if tokens.is_empty() {
        return Ok(());
    }
    match tokens[0].to_ascii_lowercase().as_str() {
        "vip" | "interface" | "dev" => {
            if tokens.len() < 2 {
                bail!("Expected interface name after 'vip' / 'interface' (e.g. 'interface eth0/21')");
            }
            let mut v = parse_vip(tokens[1])?;
            if let Some(old_v) = &gw.vip {
                if v.vlan.is_none() {
                    v.vlan = old_v.vlan;
                }
                v.dhcp |= old_v.dhcp;
                if v.leased_ip.is_none() {
                    v.leased_ip = old_v.leased_ip;
                }
            }
            gw.vip = Some(v);
        }
        "dhcp" => {
            let mut v = if tokens.len() >= 2 {
                parse_vip(tokens[1])?
            } else {
                gw.vip.clone().unwrap_or_else(VipConfig::default_eth0)
            };
            v.dhcp = true;
            if let Some(old_v) = &gw.vip {
                if v.vlan.is_none() {
                    v.vlan = old_v.vlan;
                }
                if v.leased_ip.is_none() {
                    v.leased_ip = old_v.leased_ip;
                }
            }
            gw.vip = Some(v);
        }
        "vlan" => {
            if tokens.len() < 2 {
                bail!("Expected VLAN ID (1-4094) after 'vlan'");
            }
            let vid = parse_vlan_id(tokens[1])?;
            gw.vip
                .get_or_insert_with(VipConfig::default_eth0)
                .vlan = Some(vid);
        }
        "hostname" | "host" | "domain" | "mdns" => {
            if tokens.len() < 2 {
                bail!("Expected hostname (e.g. 'hostname vpn.local')");
            }
            gw.hostname = Some(tokens[1].trim().to_ascii_lowercase());
        }
        "balance" => {
            if tokens.len() < 2 {
                bail!("Expected balance strategy: 'round-robin' or 'sticky'");
            }
            gw.balance = match tokens[1].to_ascii_lowercase().as_str() {
                "round-robin" | "rr" => BalanceStrategy::RoundRobin,
                "sticky" | "hash" | "ip-hash" | "source" => BalanceStrategy::Sticky,
                other => bail!("Unknown balance strategy '{}'", other),
            };
        }
        "killswitch" | "kill-switch" => {
            if tokens.len() < 2 {
                gw.killswitch = true;
            } else {
                gw.killswitch = matches!(
                    tokens[1].to_ascii_lowercase().as_str(),
                    "on" | "true" | "yes" | "1" | "enable" | "enabled"
                );
            }
        }
        "check" => {
            gw.check = Some(parse_health_check(&tokens[1..])?);
        }
        "allow" => {
            for tok in &tokens[1..] {
                let entry = validate_allow_entry(tok)?;
                if !gw.allow.contains(&entry) {
                    gw.allow.push(entry);
                }
            }
        }
        "tunnel" | "tunnels" | "to" => {
            if tokens.len() < 2 {
                bail!("Expected tunnel config filename or inline spec after 'tunnel'");
            }
            let next_idx = gw.tunnels.len();
            let t = parse_wg_tunnel(&tokens[1..], next_idx)?;
            if let Some(existing) = gw.tunnels.iter_mut().find(|x| x.name == t.name) {
                *existing = t;
            } else {
                gw.tunnels.push(t);
            }
        }
        "service" | "services" | "local" => {
            if tokens.len() < 2 {
                bail!("Expected gateway service (e.g. 'privoxy:8118', 'socks5:1080', or 'ssh:22')");
            }
            for tok in &tokens[1..] {
                let gs = parse_gateway_service(tok)?;
                if let Some(existing) = gw.services.iter_mut().find(|x| x.kind == gs.kind) {
                    *existing = gs;
                } else {
                    gw.services.push(gs);
                }
            }
        }
        "no" | "delete" | "remove" => {
            apply_gateway_no_directive(gw, &tokens[1..])?;
        }
        other => {
            if let Ok(gs) = parse_gateway_service(other) {
                if let Some(existing) = gw.services.iter_mut().find(|x| x.kind == gs.kind) {
                    *existing = gs;
                } else {
                    gw.services.push(gs);
                }
            } else {
                bail!(
                    "Unknown gateway directive '{}'. Valid directives: vip, hostname, balance, killswitch, check, privoxy:8118, socks5:1080, ssh:22, tunnel, allow, no",
                    other
                );
            }
        }
    }
    Ok(())
}

pub fn parse_gateway_service(raw: &str) -> Result<GatewayService> {
    let trimmed = raw.trim().to_ascii_lowercase();
    let (name_part, port_opt) = if let Some((l, r)) = trimmed.split_once(':') {
        let p: u16 = r
            .parse()
            .with_context(|| format!("Invalid port '{}' in gateway service '{}'", r, raw))?;
        if p == 0 {
            bail!("Port cannot be 0");
        }
        (l, Some(p))
    } else {
        (trimmed.as_str(), None)
    };

    match name_part {
        "privoxy" | "http-proxy" | "proxy" => Ok(GatewayService {
            kind: GatewayServiceKind::Privoxy,
            port: port_opt.unwrap_or(8118),
        }),
        "socks5" | "socks" => Ok(GatewayService {
            kind: GatewayServiceKind::Socks5,
            port: port_opt.unwrap_or(1080),
        }),
        "ssh" => Ok(GatewayService {
            kind: GatewayServiceKind::Ssh,
            port: port_opt.unwrap_or(22),
        }),
        other => bail!(
            "Unknown gateway service '{}' (valid gateway services: 'privoxy[:8118]', 'socks5[:1080]', 'ssh[:22]')",
            other
        ),
    }
}

pub fn apply_gateway_no_directive(gw: &mut Gateway, tokens: &[&str]) -> Result<()> {
    if tokens.is_empty() {
        bail!("Expected item after 'no' (e.g. 'no vip', 'no killswitch', 'no service privoxy', 'no tunnel <name>')");
    }
    match tokens[0].to_ascii_lowercase().as_str() {
        "vip" => gw.vip = None,
        "vlan" => {
            if let Some(v) = &mut gw.vip {
                v.vlan = None;
            }
        }
        "hostname" | "host" | "domain" | "mdns" => gw.hostname = None,
        "killswitch" | "kill-switch" => gw.killswitch = false,
        "check" => gw.check = None,
        "service" | "services" => {
            if tokens.len() == 1 {
                gw.services.clear();
            } else if let Ok(gs) = parse_gateway_service(tokens[1]) {
                gw.services.retain(|s| s.kind != gs.kind);
            }
        }
        "allow" => {
            if tokens.len() == 1 {
                gw.allow.clear();
            } else {
                let target =
                    validate_allow_entry(tokens[1]).unwrap_or_else(|_| tokens[1].to_string());
                gw.allow.retain(|x| x != &target);
            }
        }
        "tunnel" | "tunnels" | "to" => {
            if tokens.len() == 1 {
                gw.tunnels.clear();
            } else {
                let name = tokens[1];
                gw.tunnels.retain(|t| t.name != name && t.iface != name);
            }
        }
        other => {
            if let Ok(gs) = parse_gateway_service(other) {
                gw.services.retain(|s| s.kind != gs.kind);
            } else {
                gw.tunnels.retain(|t| t.name != other && t.iface != other);
            }
        }
    }
    Ok(())
}
