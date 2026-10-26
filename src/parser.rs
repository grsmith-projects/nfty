use crate::ast::{
    generate_api_key, ApiKey, ApiKeyScope, Backend, BalanceStrategy, Config, DnsBlocklist,
    DnsConfig, DnsForwardZone, DnsNftAction, DnsNftRule, DnsRecord, ForwardMode, Gateway,
    GatewayPortForward, GatewayService, GatewayServiceKind, HealthCheckConfig, HealthCheckKind,
    Proto, RateLimit, RateUnit, Service, VipConfig, WgTunnel,
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
    if let Ok(ip) = h_lower.parse::<Ipv4Addr>() {
        return Some(ip);
    }
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
        bail!("Expected VIP IPv4 address or DHCP hostname (e.g. 'vip 169.254.1.4' or 'vip sonarr')");
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
                "Invalid VIP IPv4 or DHCP hostname '{}' (expected e.g. '169.254.1.4' or 'sonarr')",
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
                        "vlan" | "service" | "services" | "ssh" | "dns" | "api" | "web"
                    )
                    && !tokens[idx + 1].starts_with("ssh:")
                    && !tokens[idx + 1].starts_with("dns:")
                    && !tokens[idx + 1].starts_with("api:")
                    && !tokens[idx + 1].starts_with("web:")
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
        "off" | "none" | "disable" | "disabled" => Ok(HealthCheckConfig {
            kind: HealthCheckKind::Disabled,
            interval_secs: 5,
        }),
        other => bail!(
            "Unknown health check type '{}' (expected tcp, http, ping, or off)",
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

/// Parses a `key` directive inside an `api:<port>` block on a VIP or Gateway:
/// - `key new` -> generates a new read-write API key
/// - `key new ro` -> generates a new read-only API key
/// - `key new rw` -> generates a new read-write API key
/// - `key <key>` -> adds an explicit read-write API key
/// - `key <key> ro` -> adds an explicit read-only API key
/// - `key <key> rw` -> adds an explicit read-write API key
/// Returns `(ApiKey, was_generated)`.
pub fn parse_api_key_directive(tokens: &[&str]) -> Result<(ApiKey, bool)> {
    if tokens.is_empty() {
        bail!("Expected 'key new [ro|rw]' or 'key <token> [ro|rw]'");
    }

    fn parse_scope(tok: &str) -> Option<ApiKeyScope> {
        match tok.trim().to_ascii_lowercase().as_str() {
            "ro" | "readonly" | "read-only" | "read_only" => Some(ApiKeyScope::ReadOnly),
            "rw" | "readwrite" | "read-write" | "read_write" => Some(ApiKeyScope::ReadWrite),
            _ => None,
        }
    }

    if tokens.len() == 1 {
        let t0 = tokens[0].trim();
        if matches!(t0.to_ascii_lowercase().as_str(), "new" | "generate" | "gen") {
            let scope = ApiKeyScope::ReadWrite;
            return Ok((
                ApiKey {
                    key: generate_api_key(scope),
                    scope,
                },
                true,
            ));
        }
        if let Some(scope) = parse_scope(t0) {
            return Ok((
                ApiKey {
                    key: generate_api_key(scope),
                    scope,
                },
                true,
            ));
        }
        return Ok((
            ApiKey {
                key: t0.to_string(),
                scope: ApiKeyScope::ReadWrite,
            },
            false,
        ));
    }

    let t0 = tokens[0].trim();
    let t1 = tokens[1].trim();

    if matches!(t0.to_ascii_lowercase().as_str(), "new" | "generate" | "gen") {
        let scope = parse_scope(t1).ok_or_else(|| {
            anyhow!(
                "Invalid API key scope '{}' (expected 'ro' or 'rw', e.g. 'key new ro' or 'key new rw')",
                t1
            )
        })?;
        return Ok((
            ApiKey {
                key: generate_api_key(scope),
                scope,
            },
            true,
        ));
    }

    if let Some(scope) = parse_scope(t0) {
        if matches!(t1.to_ascii_lowercase().as_str(), "new" | "generate" | "gen") {
            return Ok((
                ApiKey {
                    key: generate_api_key(scope),
                    scope,
                },
                true,
            ));
        }
        return Ok((
            ApiKey {
                key: t1.to_string(),
                scope,
            },
            false,
        ));
    }

    let scope = parse_scope(t1).ok_or_else(|| {
        anyhow!(
            "Invalid API key scope '{}' (expected 'ro' or 'rw', e.g. 'key <token> ro' or 'key <token> rw')",
            t1
        )
    })?;
    Ok((
        ApiKey {
            key: t0.to_string(),
            scope,
        },
        false,
    ))
}

/// Validates and normalizes an allow-list entry:
/// Supports:
/// - Exact IPv4: `169.254.1.50`
/// - CIDR: `169.254.1.0/24`
/// - IPv4 Wildcard: `169.254.1.*`, `10.0.*.*`, `*`
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

    // 3. Check IPv4 wildcard (e.g. "169.254.1.*" or "10.*.*.*")
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
            "Invalid allow-list host/IP/wildcard '{}'. Examples: '169.254.1.0/24', '169.254.1.*', '*.office.lan', 'laptop.lan'",
            raw
        );
    }

    Ok(trimmed)
}

/// Converts an IPv4 wildcard like `169.254.1.*` or `10.*.*.*` into a CIDR (`169.254.1.0/24`, `10.0.0.0/8`),
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

/// Parses an allow-list entry that names addresses directly (IPv4, CIDR, or IPv4 wildcard) into
/// its network and prefix length. Returns `None` for hostnames, hostname wildcards, and malformed entries.
pub fn parse_ip_allow_entry(entry: &str) -> Option<(Ipv4Addr, u8)> {
    let cidr = expand_ip_wildcard_to_cidr(entry.trim())?;
    let Some((network, prefix)) = cidr.split_once('/') else {
        return Some((cidr.parse().ok()?, 32));
    };
    let prefix = prefix.parse::<u8>().ok().filter(|prefix| *prefix <= 32)?;
    Some((network.parse().ok()?, prefix))
}

pub fn ipv4_in_network(ip: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
    u32::from(ip) & mask == u32::from(network) & mask
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

pub fn strip_inline_comment_preserving_quotes(raw_line: &str) -> &str {
    let mut in_quotes = false;
    let mut escaped = false;
    for (idx, ch) in raw_line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && in_quotes {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_quotes = !in_quotes;
            continue;
        }
        if ch == '#' && !in_quotes {
            return &raw_line[..idx];
        }
    }
    raw_line
}

pub fn split_statements_preserving_quotes(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut in_quotes = false;
    let mut escaped = false;
    for (idx, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && in_quotes {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_quotes = !in_quotes;
            continue;
        }
        if ch == ';' && !in_quotes {
            out.push(&line[start..idx]);
            start = idx + ch.len_utf8();
        }
    }
    out.push(&line[start..]);
    out
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
        GatewayServiceItem(Gateway, GatewayService, bool),
        GatewayAllow(Gateway),
        Dns,
    }

    let mut ctx = ParseContext::Root;

    for (line_idx, raw_line) in input.lines().enumerate() {
        let line_no = line_idx + 1;
        let line = strip_inline_comment_preserving_quotes(raw_line).trim();
        if line.is_empty() {
            continue;
        }

        for stmt in split_statements_preserving_quotes(line) {
            let stmt = stmt.trim();
            if stmt.is_empty() {
                continue;
            }

            ctx = match ctx {
                ParseContext::Root => {
                    if stmt == "allow {" || stmt == "allow" {
                        ParseContext::GlobalAllow
                    } else if stmt == "dns {" || stmt == "dns" {
                        config.dns.get_or_insert_with(DnsConfig::default);
                        ParseContext::Dns
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
                                    "Line {}: expected VIP IPv4 address or DHCP hostname after 'vip' (e.g. 'vip 169.254.1.4' or 'vip sonarr')",
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
                        } else if matches!(tokens[0].to_ascii_lowercase().as_str(), "ssh" | "dns" | "api" | "web")
                            || tokens[0].to_ascii_lowercase().starts_with("ssh:")
                            || tokens[0].to_ascii_lowercase().starts_with("dns:")
                            || tokens[0].to_ascii_lowercase().starts_with("api:")
                            || tokens[0].to_ascii_lowercase().starts_with("web:")
                            || (tokens[0].eq_ignore_ascii_case("local") && tokens.len() >= 2)
                        {
                            let spec_owned: String = if tokens[0].eq_ignore_ascii_case("local") {
                                tokens[1].to_string()
                            } else if matches!(tokens[0].to_ascii_lowercase().as_str(), "ssh" | "dns" | "api" | "web")
                                && tokens.len() >= 2
                                && tokens[1].parse::<u16>().is_ok()
                            {
                                format!("{}:{}", tokens[0].to_ascii_lowercase(), tokens[1])
                            } else {
                                tokens[0].to_string()
                            };
                            let key = create_or_find_vip_service_by_key(&mut config, &vip_key, &spec_owned)
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
                    } else if stmt.ends_with('{') {
                        let without_brace = stmt.strip_suffix('{').unwrap_or(stmt).trim();
                        let tokens: Vec<&str> = without_brace.split_whitespace().collect();
                        let svc_tok = if !tokens.is_empty()
                            && matches!(
                                tokens[0].to_ascii_lowercase().as_str(),
                                "service" | "services" | "local"
                            )
                            && tokens.len() >= 2
                        {
                            tokens[1..].join(":")
                        } else if tokens.len() == 2 && tokens[1].parse::<u16>().is_ok() {
                            format!("{}:{}", tokens[0], tokens[1])
                        } else {
                            without_brace.to_string()
                        };
                        let parsed = parse_gateway_service(&svc_tok)
                            .with_context(|| format!("Line {}", line_no))?;
                        let gs = if let Some(pos) = gw.services.iter().position(|x| x.kind == parsed.kind) {
                            let mut existing = gw.services.remove(pos);
                            existing.port = parsed.port;
                            existing
                        } else {
                            parsed
                        };
                        ParseContext::GatewayServiceItem(gw, gs, false)
                    } else {
                        apply_gateway_directive(&mut gw, stmt)
                            .with_context(|| format!("Line {}", line_no))?;
                        ParseContext::Gateway(gw)
                    }
                }
                ParseContext::GatewayService(mut gw) => {
                    if stmt == "}" {
                        ParseContext::Gateway(gw)
                    } else if stmt.ends_with('{') {
                        let without_brace = stmt.strip_suffix('{').unwrap_or(stmt).trim();
                        let parsed = parse_gateway_service(without_brace)
                            .with_context(|| format!("Line {}", line_no))?;
                        let gs = if let Some(pos) = gw.services.iter().position(|x| x.kind == parsed.kind) {
                            let mut existing = gw.services.remove(pos);
                            existing.port = parsed.port;
                            existing
                        } else {
                            parsed
                        };
                        ParseContext::GatewayServiceItem(gw, gs, true)
                    } else {
                        for tok in stmt.split_whitespace() {
                            let gs = parse_gateway_service(tok)
                                .with_context(|| format!("Line {}", line_no))?;
                            upsert_gateway_service(&mut gw, gs);
                        }
                        ParseContext::GatewayService(gw)
                    }
                }
                ParseContext::GatewayServiceItem(mut gw, mut gs, in_sub) => {
                    if stmt == "}" {
                        upsert_gateway_service(&mut gw, gs);
                        if in_sub {
                            ParseContext::GatewayService(gw)
                        } else {
                            ParseContext::Gateway(gw)
                        }
                    } else {
                        apply_gateway_service_directive(&mut gs, stmt)
                            .with_context(|| format!("Line {}", line_no))?;
                        ParseContext::GatewayServiceItem(gw, gs, in_sub)
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
                ParseContext::Dns => {
                    if stmt == "}" {
                        ParseContext::Root
                    } else {
                        let dns = config.dns.get_or_insert_with(DnsConfig::default);
                        apply_dns_directive(dns, stmt)
                            .with_context(|| format!("Line {}", line_no))?;
                        ParseContext::Dns
                    }
                }
            };
        }
    }

    match ctx {
        ParseContext::Root
        | ParseContext::GlobalAllow
        | ParseContext::Dns
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
        ParseContext::GatewayServiceItem(mut gw, gs, _) => {
            upsert_gateway_service(&mut gw, gs);
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
/// - `plex:32400` or `app-backend:9090` or `169.254.1.165:32400` (backend host/IP:port, listen port defaults to backend port)
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

    // 2. Built-in `ssh` / `ssh:22`, `dns` / `dns:53`, and `api` / `api:9090`
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
    if lower == "dns" || lower.starts_with("dns:") {
        let port = if let Some((_, p_str)) = lower.split_once(':') {
            p_str
                .parse::<u16>()
                .with_context(|| format!("Invalid DNS port '{}'", p_str))?
        } else {
            53
        };
        let key = format!("{}:{}/both", vip_key, port);
        let mut svc = Service::new(key.clone(), vip_ip_opt, port, Proto::Both);
        svc.vip_id = Some(vip_key.to_string());
        svc.name = Some(format!("dns:{}", port));
        svc.vip = vip_cfg;
        svc.backends.push(Backend {
            host: None,
            ip: Ipv4Addr::new(127, 0, 0, 1),
            port: 53,
            weight: 1,
            backup: false,
        });
        config.dns.get_or_insert_with(DnsConfig::default);
        config.services.insert(key.clone(), svc);
        return Ok(key);
    }
    if lower == "api" || lower.starts_with("api:") {
        let port = if let Some((_, p_str)) = lower.split_once(':') {
            p_str
                .parse::<u16>()
                .with_context(|| format!("Invalid API port '{}'", p_str))?
        } else {
            9090
        };
        if port == 0 {
            bail!("API port cannot be 0");
        }
        let key = format!("{}:{}", vip_key, port);
        if let Some(existing) = config.services.get_mut(&key) {
            existing.name = Some(format!("api:{}", port));
            return Ok(key);
        }
        let mut svc = Service::new(key.clone(), vip_ip_opt, port, Proto::Tcp);
        svc.vip_id = Some(vip_key.to_string());
        svc.name = Some(format!("api:{}", port));
        svc.vip = vip_cfg;
        svc.backends.push(Backend {
            host: None,
            ip: Ipv4Addr::new(127, 0, 0, 1),
            port,
            weight: 1,
            backup: false,
        });
        config.services.insert(key.clone(), svc);
        return Ok(key);
    }
    if lower == "web" || lower.starts_with("web:") {
        let port = if let Some((_, p_str)) = lower.split_once(':') {
            p_str
                .parse::<u16>()
                .with_context(|| format!("Invalid Web UI port '{}'", p_str))?
        } else {
            8000
        };
        if port == 0 {
            bail!("Web UI port cannot be 0");
        }
        let key = format!("{}:{}", vip_key, port);
        if let Some(existing) = config.services.get_mut(&key) {
            existing.name = Some(format!("web:{}", port));
            return Ok(key);
        }
        let mut svc = Service::new(key.clone(), vip_ip_opt, port, Proto::Tcp);
        svc.vip_id = Some(vip_key.to_string());
        svc.name = Some(format!("web:{}", port));
        svc.vip = vip_cfg;
        svc.backends.push(Backend {
            host: None,
            ip: Ipv4Addr::new(127, 0, 0, 1),
            port,
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

    // 4. Target `<host_or_ip>:<port>` (e.g. `plex:32400`, `app-backend:9090`, `169.254.1.165:32400`)
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
                    "Expected email rule after '{}' (e.g. 'cloudflare-auth you@example.com' or 'cloudflare-auth *@example.com')",
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
        "key" | "api-key" | "apikey" => {
            let (api_key, _generated) = parse_api_key_directive(&tokens[1..])?;
            if let Some(existing) = svc.api_keys.iter_mut().find(|k| k.key == api_key.key) {
                existing.scope = api_key.scope;
            } else {
                svc.api_keys.push(api_key);
            }
        }
        "no" | "delete" | "remove" => {
            apply_service_no_directive(svc, &tokens[1..])?;
        }
        other => bail!(
            "Unknown service directive '{}'. Valid directives: port, proto, to, hostname, cloudflare-dns, cloudflare-auth, auth, key, balance, mode, vip, check, limit, allow, no",
            other
        ),
    }
    Ok(())
}

pub fn apply_service_no_directive(svc: &mut Service, tokens: &[&str]) -> Result<()> {
    if tokens.is_empty() {
        bail!("Expected item to remove after 'no' (e.g. 'no vip', 'no key <key>', 'no cloudflare-dns', 'no cloudflare-auth', 'no auth', 'no check', 'no limit', 'no allow <host>', 'no to <ip>')");
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
        "key" | "api-key" | "apikey" => {
            if tokens.len() == 1 {
                svc.api_keys.clear();
            } else {
                let target = tokens[1].trim();
                svc.api_keys
                    .retain(|k| k.key != target && k.scope.as_str() != target);
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

    let any_inline =
        address.is_some() || private_key.is_some() || peer_pubkey.is_some() || endpoint.is_some();
    let all_inline =
        address.is_some() && private_key.is_some() && peer_pubkey.is_some() && endpoint.is_some();
    if any_inline && !all_inline {
        bail!(
            "Inline WireGuard tunnel '{}' requires all four parameters: address, privkey, peer, and endpoint",
            name
        );
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
                bail!("Expected gateway service (e.g. 'privoxy:8118', 'socks5:1080', 'ssh:22', 'dns:53', or 'api:9090')");
            }
            for tok in &tokens[1..] {
                let gs = parse_gateway_service(tok)?;
                upsert_gateway_service(gw, gs);
            }
        }
        "key" | "api-key" | "apikey" => {
            let (api_key, _generated) = parse_api_key_directive(&tokens[1..])?;
            let gs = if let Some(existing) = gw
                .services
                .iter_mut()
                .find(|s| s.kind == GatewayServiceKind::Api)
            {
                existing
            } else {
                gw.services
                    .push(GatewayService::new(GatewayServiceKind::Api, 9090));
                gw.services.last_mut().unwrap()
            };
            if let Some(existing_key) = gs.api_keys.iter_mut().find(|k| k.key == api_key.key) {
                existing_key.scope = api_key.scope;
            } else {
                gs.api_keys.push(api_key);
            }
        }
        "forward" | "port-forward" | "fwd" => {
            let fwd = parse_gateway_forward(&tokens[1..])?;
            if let Some(existing) = gw
                .forwards
                .iter_mut()
                .find(|x| x.listen_port == fwd.listen_port && x.proto == fwd.proto)
            {
                *existing = fwd;
            } else {
                gw.forwards.push(fwd);
            }
        }
        "no" | "delete" | "remove" => {
            apply_gateway_no_directive(gw, &tokens[1..])?;
        }
        other => {
            if let Ok(mut gs) = parse_gateway_service(other) {
                if tokens.len() >= 2 && matches!(tokens[1].to_ascii_lowercase().as_str(), "key" | "api-key" | "apikey") {
                    let (api_key, _gen) = parse_api_key_directive(&tokens[2..])?;
                    gs.api_keys.push(api_key);
                }
                upsert_gateway_service(gw, gs);
            } else if tokens.len() >= 2
                && tokens[1].parse::<u16>().is_ok()
                && parse_gateway_service(&format!("{}:{}", other, tokens[1])).is_ok()
            {
                let mut gs = parse_gateway_service(&format!("{}:{}", other, tokens[1]))?;
                if tokens.len() >= 3 && matches!(tokens[2].to_ascii_lowercase().as_str(), "key" | "api-key" | "apikey") {
                    let (api_key, _gen) = parse_api_key_directive(&tokens[3..])?;
                    gs.api_keys.push(api_key);
                }
                upsert_gateway_service(gw, gs);
            } else if let Ok(fwd) = parse_gateway_forward(&tokens) {
                if let Some(existing) = gw
                    .forwards
                    .iter_mut()
                    .find(|x| x.listen_port == fwd.listen_port && x.proto == fwd.proto)
                {
                    *existing = fwd;
                } else {
                    gw.forwards.push(fwd);
                }
            } else {
                bail!(
                    "Unknown gateway directive '{}'. Valid directives: vip, hostname, balance, killswitch, check, forward, privoxy:8118, socks5:1080, ssh:22, dns:53, api:9090, key, tunnel, allow, no",
                    other
                );
            }
        }
    }
    Ok(())
}

pub fn upsert_gateway_service(gw: &mut Gateway, gs: GatewayService) {
    if let Some(existing) = gw.services.iter_mut().find(|x| x.kind == gs.kind) {
        existing.port = gs.port;
        for k in gs.api_keys {
            if let Some(ek) = existing.api_keys.iter_mut().find(|x| x.key == k.key) {
                ek.scope = k.scope;
            } else {
                existing.api_keys.push(k);
            }
        }
    } else {
        gw.services.push(gs);
    }
}

pub fn apply_gateway_service_directive(
    gs: &mut GatewayService,
    stmt: &str,
) -> Result<Option<(ApiKey, bool)>> {
    let tokens: Vec<&str> = stmt.split_whitespace().collect();
    if tokens.is_empty() {
        return Ok(None);
    }
    match tokens[0].to_ascii_lowercase().as_str() {
        "port" | "listen" => {
            if tokens.len() < 2 {
                bail!("Expected port number after '{}'", tokens[0]);
            }
            let p: u16 = tokens[1]
                .parse()
                .with_context(|| format!("Invalid port '{}'", tokens[1]))?;
            if p == 0 {
                bail!("Port cannot be 0");
            }
            gs.port = p;
            Ok(None)
        }
        "key" | "api-key" | "apikey" => {
            let (api_key, generated) = parse_api_key_directive(&tokens[1..])?;
            if let Some(existing) = gs.api_keys.iter_mut().find(|k| k.key == api_key.key) {
                existing.scope = api_key.scope;
            } else {
                gs.api_keys.push(api_key.clone());
            }
            Ok(Some((api_key, generated)))
        }
        "no" | "delete" | "remove" => {
            if tokens.len() < 2 {
                bail!("Expected 'key [<token>]' after 'no'");
            }
            match tokens[1].to_ascii_lowercase().as_str() {
                "key" | "api-key" | "apikey" => {
                    if tokens.len() == 2 {
                        gs.api_keys.clear();
                    } else {
                        let target = tokens[2].trim();
                        gs.api_keys
                            .retain(|k| k.key != target && k.scope.as_str() != target);
                    }
                    Ok(None)
                }
                other => bail!("Unknown 'no {}' inside gateway service", other),
            }
        }
        other => bail!(
            "Unknown gateway service directive '{}' (expected 'key new [ro|rw]', 'key <token> [ro|rw]', 'no key [<token>]', or 'port <N>')",
            other
        ),
    }
}

pub fn parse_gateway_forward(tokens: &[&str]) -> Result<GatewayPortForward> {
    if tokens.is_empty() {
        bail!("Expected port forward spec (e.g. 'forward 51413 to peer-node:51413' or 'forward peer-node:51413')");
    }
    if tokens.len() >= 3 && tokens[1].eq_ignore_ascii_case("to") {
        let (port_str, proto) = if let Some((l, r)) = tokens[0].split_once('/') {
            let p = match r.to_ascii_lowercase().as_str() {
                "tcp" => Proto::Tcp,
                "udp" => Proto::Udp,
                "both" | "tcp+udp" | "all" => Proto::Both,
                other => bail!("Unknown protocol '{}' (expected tcp, udp, or both)", other),
            };
            (l, p)
        } else {
            (tokens[0], Proto::Both)
        };
        let listen_port: u16 = port_str
            .parse()
            .with_context(|| format!("Invalid forward port '{}'", port_str))?;
        if listen_port == 0 {
            bail!("Port cannot be 0");
        }
        let backend = parse_backend(&tokens[2..], listen_port)?;
        Ok(GatewayPortForward {
            listen_port,
            proto,
            backend,
        })
    } else if tokens.len() == 1 && tokens[0].contains(':') {
        let backend = parse_backend(tokens, 0)?;
        if backend.port == 0 {
            bail!("Expected port in gateway forward '{}'", tokens[0]);
        }
        Ok(GatewayPortForward {
            listen_port: backend.port,
            proto: Proto::Both,
            backend,
        })
    } else {
        bail!(
            "Invalid gateway forward '{}'. Expected 'forward <port[/tcp|/udp|/both]> to <host_or_ip[:port]>'",
            tokens.join(" ")
        )
    }
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
        "privoxy" | "http-proxy" | "proxy" => Ok(GatewayService::new(
            GatewayServiceKind::Privoxy,
            port_opt.unwrap_or(8118),
        )),
        "socks5" | "socks" => Ok(GatewayService::new(
            GatewayServiceKind::Socks5,
            port_opt.unwrap_or(1080),
        )),
        "ssh" => Ok(GatewayService::new(
            GatewayServiceKind::Ssh,
            port_opt.unwrap_or(22),
        )),
        "dns" | "dnsmasq" => Ok(GatewayService::new(
            GatewayServiceKind::Dns,
            port_opt.unwrap_or(53),
        )),
        "api" => Ok(GatewayService::new(
            GatewayServiceKind::Api,
            port_opt.unwrap_or(9090),
        )),
        "web" | "webui" | "ui" => Ok(GatewayService::new(
            GatewayServiceKind::Web,
            port_opt.unwrap_or(8000),
        )),
        other => bail!(
            "Unknown gateway service '{}' (valid gateway services: 'privoxy[:8118]', 'socks5[:1080]', 'ssh[:22]', 'dns[:53]', 'api[:9090]', 'web[:8000]')",
            other
        ),
    }
}

pub fn apply_gateway_no_directive(gw: &mut Gateway, tokens: &[&str]) -> Result<()> {
    if tokens.is_empty() {
        bail!("Expected item after 'no' (e.g. 'no vip', 'no killswitch', 'no service privoxy', 'no api', 'no key <key>', 'no tunnel <name>')");
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
        "key" | "api-key" | "apikey" => {
            for gs in gw.services.iter_mut() {
                if tokens.len() == 1 {
                    gs.api_keys.clear();
                } else {
                    let target = tokens[1].trim();
                    gs.api_keys
                        .retain(|k| k.key != target && k.scope.as_str() != target);
                }
            }
        }
        "service" | "services" => {
            if tokens.len() == 1 {
                gw.services.clear();
            } else if let Ok(gs) = parse_gateway_service(tokens[1]) {
                gw.services.retain(|s| s.kind != gs.kind);
            }
        }
        "forward" | "port-forward" | "fwd" => {
            if tokens.len() == 1 {
                gw.forwards.clear();
            } else {
                let target = tokens[1].split('/').next().unwrap_or(tokens[1]);
                if let Ok(port) = target.parse::<u16>() {
                    gw.forwards.retain(|f| f.listen_port != port);
                } else {
                    gw.forwards.retain(|f| {
                        !f.backend.to_string().eq_ignore_ascii_case(tokens[1])
                            && f.backend.host.as_deref() != Some(tokens[1])
                    });
                }
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

fn parse_bool_flag(raw: &str) -> Result<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "on" | "true" | "yes" | "1" | "enable" | "enabled" => Ok(true),
        "off" | "false" | "no" | "0" | "disable" | "disabled" => Ok(false),
        other => bail!("Expected 'on' or 'off' (got '{}')", other),
    }
}

pub fn apply_dns_directive(dns: &mut DnsConfig, stmt: &str) -> Result<()> {
    let tokens: Vec<&str> = stmt.split_whitespace().collect();
    if tokens.is_empty() {
        return Ok(());
    }
    match tokens[0].to_ascii_lowercase().as_str() {
        "listen" | "bind" => {
            if tokens.len() < 2 {
                bail!("Expected IP or IP:PORT after 'listen' (e.g. 'listen 169.254.10.10')");
            }
            for tok in &tokens[1..] {
                let s = tok.trim().to_string();
                if !s.is_empty() && !dns.listen.contains(&s) {
                    dns.listen.push(s);
                }
            }
        }
        "domain" | "local-domain" | "suffix" => {
            if tokens.len() < 2 {
                bail!("Expected domain suffix after 'domain' (e.g. 'domain lan')");
            }
            let d = tokens[1].trim().trim_start_matches('.').to_ascii_lowercase();
            dns.domain = if d == "none" || d == "off" {
                None
            } else {
                Some(d)
            };
        }
        "cache-size" | "cache" => {
            if tokens.len() < 2 {
                bail!("Expected number of entries after 'cache-size' (e.g. 'cache-size 10000')");
            }
            dns.cache_size = tokens[1]
                .parse()
                .with_context(|| format!("Invalid cache-size '{}'", tokens[1]))?;
        }
        "auto-vips" | "auto_vips" => {
            dns.auto_vips = if tokens.len() >= 2 {
                parse_bool_flag(tokens[1])?
            } else {
                true
            };
        }
        "auto-hosts" | "auto_hosts" => {
            dns.auto_hosts = if tokens.len() >= 2 {
                parse_bool_flag(tokens[1])?
            } else {
                true
            };
        }
        "health-aware" | "health_aware" => {
            dns.health_aware = if tokens.len() >= 2 {
                parse_bool_flag(tokens[1])?
            } else {
                true
            };
        }
        "all-servers" | "all_servers" | "fastest" => {
            dns.all_servers = if tokens.len() >= 2 {
                parse_bool_flag(tokens[1])?
            } else {
                true
            };
        }
        "bogus-priv" | "bogus_priv" => {
            dns.bogus_priv = if tokens.len() >= 2 {
                parse_bool_flag(tokens[1])?
            } else {
                true
            };
        }
        "domain-needed" | "domain_needed" => {
            dns.domain_needed = if tokens.len() >= 2 {
                parse_bool_flag(tokens[1])?
            } else {
                true
            };
        }
        "upstream" | "upstreams" | "server" | "nameserver" => {
            if tokens.len() < 2 {
                bail!("Expected upstream DNS IP[:PORT][@iface] after 'upstream' (e.g. 'upstream 1.1.1.1 9.9.9.9')");
            }
            // If replacing default upstreams on first explicit upstream command, allow clean list
            for tok in &tokens[1..] {
                if tok.eq_ignore_ascii_case("fastest") || tok.eq_ignore_ascii_case("all-servers") {
                    dns.all_servers = true;
                    continue;
                }
                let s = tok.trim().to_string();
                if !s.is_empty() && !dns.upstreams.contains(&s) {
                    dns.upstreams.push(s);
                }
            }
        }
        "forward" | "forward-zone" => {
            if tokens.len() < 3 {
                bail!("Usage: forward <domain> [to] <upstream-ip...> [via <gateway>]");
            }
            let domain = tokens[1]
                .trim()
                .trim_start_matches("*.")
                .trim_start_matches('.')
                .to_ascii_lowercase();
            let mut servers = Vec::new();
            let mut via_gateway = None;
            let mut idx = 2;
            if idx < tokens.len() && tokens[idx].eq_ignore_ascii_case("to") {
                idx += 1;
            }
            while idx < tokens.len() {
                if matches!(
                    tokens[idx].to_ascii_lowercase().as_str(),
                    "via" | "via-gateway" | "gateway"
                ) {
                    idx += 1;
                    if idx >= tokens.len() {
                        bail!("Expected gateway IP or name after 'via'");
                    }
                    via_gateway = Some(tokens[idx].to_string());
                } else {
                    servers.push(tokens[idx].to_string());
                }
                idx += 1;
            }
            if servers.is_empty() {
                bail!("Expected at least one upstream DNS server for 'forward {}'", domain);
            }
            let fz = DnsForwardZone {
                domain: domain.clone(),
                servers,
                via_gateway,
            };
            if let Some(existing) = dns.forward_zones.iter_mut().find(|x| x.domain == domain) {
                *existing = fz;
            } else {
                dns.forward_zones.push(fz);
            }
        }
        "a" | "host-record" => {
            if tokens.len() < 3 {
                bail!("Usage: a <hostname> <ipv4> [ipv4...]");
            }
            let name = tokens[1].trim().to_ascii_lowercase();
            let mut ips = Vec::new();
            for tok in &tokens[2..] {
                let ip: Ipv4Addr = tok
                    .parse()
                    .with_context(|| format!("Invalid IPv4 address '{}' in A record", tok))?;
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
            dns.records
                .retain(|r| !matches!(r, DnsRecord::A { name: n, .. } if n == &name));
            dns.records.push(DnsRecord::A { name, ips });
        }
        "aaaa" => {
            if tokens.len() < 3 {
                bail!("Usage: aaaa <hostname> <ipv6>");
            }
            let name = tokens[1].trim().to_ascii_lowercase();
            let ip = tokens[2].trim().to_string();
            dns.records
                .retain(|r| !matches!(r, DnsRecord::Aaaa { name: n, .. } if n == &name));
            dns.records.push(DnsRecord::Aaaa { name, ip });
        }
        "address" | "wildcard" => {
            if tokens.len() < 3 {
                bail!("Usage: address <domain-or-wildcard> <ipv4> (e.g. 'address *.k8s.lan 169.254.10.80')");
            }
            let domain = tokens[1].trim().to_ascii_lowercase();
            let ip: Ipv4Addr = tokens[2]
                .parse()
                .with_context(|| format!("Invalid IPv4 '{}' in address rule", tokens[2]))?;
            dns.records
                .retain(|r| !matches!(r, DnsRecord::Address { domain: d, .. } if d == &domain));
            dns.records.push(DnsRecord::Address { domain, ip });
        }
        "cname" => {
            if tokens.len() < 3 {
                bail!("Usage: cname <alias> <target>");
            }
            let alias = tokens[1].trim().to_ascii_lowercase();
            let target = tokens[2].trim().to_ascii_lowercase();
            dns.records
                .retain(|r| !matches!(r, DnsRecord::Cname { alias: a, .. } if a == &alias));
            dns.records.push(DnsRecord::Cname { alias, target });
        }
        "txt" | "txt-record" => {
            if tokens.len() < 3 {
                bail!("Usage: txt <name> <text...>");
            }
            let name = tokens[1].trim().to_ascii_lowercase();
            let raw_text = tokens[2..].join(" ");
            let trimmed_text = if (raw_text.starts_with('"') && raw_text.ends_with('"'))
                || (raw_text.starts_with('\'') && raw_text.ends_with('\''))
            {
                &raw_text[1..raw_text.len().saturating_sub(1)]
            } else {
                raw_text.as_str()
            };
            let mut text = String::with_capacity(trimmed_text.len());
            let mut chars = trimmed_text.chars();
            while let Some(ch) = chars.next() {
                if ch == '\\' {
                    if let Some(next_ch) = chars.next() {
                        text.push(next_ch);
                    } else {
                        text.push('\\');
                    }
                } else {
                    text.push(ch);
                }
            }
            dns.records
                .retain(|r| !matches!(r, DnsRecord::Txt { name: n, .. } if n == &name));
            dns.records.push(DnsRecord::Txt { name, text });
        }
        "srv" | "srv-host" => {
            if tokens.len() < 3 {
                bail!("Usage: srv <_service._proto.domain> <target:port> [priority] [weight]");
            }
            let service = tokens[1].trim().to_ascii_lowercase();
            let (target, port) = if let Some((t, p_str)) = tokens[2].rsplit_once(':') {
                let p: u16 = p_str
                    .parse()
                    .with_context(|| format!("Invalid SRV port '{}'", p_str))?;
                (t.to_ascii_lowercase(), p)
            } else if tokens.len() >= 4 {
                let p: u16 = tokens[3]
                    .parse()
                    .with_context(|| format!("Invalid SRV port '{}'", tokens[3]))?;
                let priority = tokens.get(4).and_then(|s| s.parse().ok()).unwrap_or(0);
                let weight = tokens.get(5).and_then(|s| s.parse().ok()).unwrap_or(0);
                dns.records
                    .retain(|r| !matches!(r, DnsRecord::Srv { service: s, .. } if s == &service));
                dns.records.push(DnsRecord::Srv {
                    service,
                    target: tokens[2].to_ascii_lowercase(),
                    port: p,
                    priority,
                    weight,
                });
                return Ok(());
            } else {
                bail!("Expected <target:port> in SRV record");
            };
            let mut priority: u16 = 0;
            let mut weight: u16 = 0;
            let mut positional_nums = Vec::new();
            let mut idx = 3;
            while idx < tokens.len() {
                match tokens[idx].to_ascii_lowercase().as_str() {
                    "priority" | "prio" | "pref" => {
                        idx += 1;
                        if let Some(v) = tokens.get(idx).and_then(|s| s.parse().ok()) {
                            priority = v;
                        }
                    }
                    "weight" | "w" => {
                        idx += 1;
                        if let Some(v) = tokens.get(idx).and_then(|s| s.parse().ok()) {
                            weight = v;
                        }
                    }
                    other => {
                        if let Ok(v) = other.parse::<u16>() {
                            positional_nums.push(v);
                        }
                    }
                }
                idx += 1;
            }
            if !positional_nums.is_empty() {
                priority = positional_nums[0];
                if positional_nums.len() >= 2 {
                    weight = positional_nums[1];
                }
            }
            dns.records
                .retain(|r| !matches!(r, DnsRecord::Srv { service: s, .. } if s == &service));
            dns.records.push(DnsRecord::Srv {
                service,
                target,
                port,
                priority,
                weight,
            });
        }
        "mx" | "mx-host" => {
            if tokens.len() < 3 {
                bail!("Usage: mx <domain> <mail-host> [preference]");
            }
            let domain = tokens[1].trim().to_ascii_lowercase();
            let target = tokens[2].trim().to_ascii_lowercase();
            let mut preference: u16 = 10;
            if let Some(tok3) = tokens.get(3) {
                if matches!(
                    tok3.to_ascii_lowercase().as_str(),
                    "priority" | "prio" | "preference" | "pref"
                ) {
                    if let Some(v) = tokens.get(4).and_then(|s| s.parse().ok()) {
                        preference = v;
                    }
                } else if let Ok(v) = tok3.parse::<u16>() {
                    preference = v;
                }
            }
            dns.records.retain(|r| {
                !matches!(r, DnsRecord::Mx { domain: d, target: t, .. } if d == &domain && t == &target)
            });
            dns.records.push(DnsRecord::Mx {
                domain,
                target,
                preference,
            });
        }
        "ptr" | "ptr-record" => {
            if tokens.len() < 3 {
                bail!("Usage: ptr <ipv4> <hostname>");
            }
            let ip: Ipv4Addr = tokens[1]
                .parse()
                .with_context(|| format!("Invalid IPv4 '{}' in PTR record", tokens[1]))?;
            let name = tokens[2].trim().to_ascii_lowercase();
            dns.records
                .retain(|r| !matches!(r, DnsRecord::Ptr { ip: i, .. } if *i == ip));
            dns.records.push(DnsRecord::Ptr { ip, name });
        }
        "route" | "bypass" => {
            let action = if tokens[0].eq_ignore_ascii_case("route") {
                DnsNftAction::Route
            } else {
                DnsNftAction::Bypass
            };
            let sep_pos = tokens.iter().position(|t| {
                matches!(
                    t.to_ascii_lowercase().as_str(),
                    "via" | "via-gateway" | "from" | "from-gateway" | "gateway" | "to"
                )
            });
            let Some(pos) = sep_pos else {
                bail!(
                    "Usage: {} <domain...> {} <gateway>",
                    tokens[0],
                    if action == DnsNftAction::Route { "via" } else { "from" }
                );
            };
            if pos < 2 || pos + 1 >= tokens.len() {
                bail!("Expected domain(s) and gateway IP/name");
            }
            let domains: Vec<String> = tokens[1..pos]
                .iter()
                .map(|d| d.trim().to_ascii_lowercase())
                .filter(|d| !d.is_empty())
                .collect();
            let gateway = tokens[pos + 1].trim().to_string();
            if let Some(existing) = dns
                .nft_rules
                .iter_mut()
                .find(|r| r.action == action && r.gateway == gateway)
            {
                for d in domains {
                    if !existing.domains.contains(&d) {
                        existing.domains.push(d);
                    }
                }
            } else {
                dns.nft_rules.push(DnsNftRule {
                    action,
                    domains,
                    gateway,
                });
            }
        }
        "block" | "sinkhole" => {
            if tokens.len() < 2 {
                bail!("Expected domain(s) after 'block' (e.g. 'block *.telemetry.example.com')");
            }
            for tok in &tokens[1..] {
                let d = tok.trim().to_ascii_lowercase();
                if !d.is_empty() && !dns.blocks.contains(&d) {
                    dns.blocks.push(d);
                }
            }
        }
        "blocklist" | "adblock" => {
            if tokens.len() < 3 {
                bail!("Usage: blocklist <name> <url-or-path>");
            }
            let name = tokens[1].trim().to_ascii_lowercase();
            let url = tokens[2].trim().to_string();
            if let Some(existing) = dns.blocklists.iter_mut().find(|b| b.name == name) {
                existing.url = url;
            } else {
                dns.blocklists.push(DnsBlocklist { name, url });
            }
        }
        "raw" | "dnsmasq" => {
            if tokens.len() < 2 {
                bail!("Expected raw dnsmasq option after 'raw' (e.g. 'raw localise-queries')");
            }
            let opt = tokens[1..].join(" ").trim_matches('"').trim().to_string();
            if opt.contains('\n') || opt.contains('\r') {
                bail!("Raw dnsmasq option cannot contain newlines");
            }
            let opt_key = opt
                .split(['=', ' ', '\t'])
                .next()
                .unwrap_or("")
                .trim_start_matches('-')
                .to_ascii_lowercase();
            if matches!(
                opt_key.as_str(),
                "dhcp-script"
                    | "dhcp-luascript"
                    | "conf-file"
                    | "conf-dir"
                    | "servers-file"
                    | "addn-hosts"
                    | "hostsdir"
                    | "user"
                    | "group"
                    | "pid-file"
            ) {
                bail!(
                    "Raw dnsmasq option '{}' is restricted for security reasons",
                    opt_key
                );
            }
            if !opt.is_empty() && !dns.raw_options.contains(&opt) {
                dns.raw_options.push(opt);
            }
        }
        "no" | "delete" | "remove" => {
            apply_dns_no_directive(dns, &tokens[1..])?;
        }
        other => bail!(
            "Unknown dns directive '{}'. Valid directives: listen, domain, cache-size, auto-vips, auto-hosts, health-aware, all-servers, upstream, forward, a, aaaa, address, cname, txt, srv, mx, ptr, route, bypass, block, blocklist, raw, no",
            other
        ),
    }
    Ok(())
}

pub fn apply_dns_no_directive(dns: &mut DnsConfig, tokens: &[&str]) -> Result<()> {
    if tokens.is_empty() {
        bail!("Expected item after 'no' (e.g. 'no listen', 'no upstream <ip>', 'no a <name>', 'no block <domain>')");
    }
    match tokens[0].to_ascii_lowercase().as_str() {
        "listen" | "bind" => {
            if tokens.len() == 1 {
                dns.listen.clear();
            } else {
                dns.listen.retain(|x| x != tokens[1]);
            }
        }
        "domain" => dns.domain = None,
        "auto-vips" | "auto_vips" => dns.auto_vips = false,
        "auto-hosts" | "auto_hosts" => dns.auto_hosts = false,
        "health-aware" | "health_aware" => dns.health_aware = false,
        "all-servers" | "all_servers" => dns.all_servers = false,
        "bogus-priv" | "bogus_priv" => dns.bogus_priv = false,
        "domain-needed" | "domain_needed" => dns.domain_needed = false,
        "upstream" | "upstreams" | "server" => {
            if tokens.len() == 1 {
                dns.upstreams.clear();
            } else {
                dns.upstreams.retain(|x| x != tokens[1]);
            }
        }
        "forward" | "forward-zone" => {
            if tokens.len() == 1 {
                dns.forward_zones.clear();
            } else {
                let dom = tokens[1].trim_start_matches("*.").trim_start_matches('.');
                dns.forward_zones
                    .retain(|x| !x.domain.eq_ignore_ascii_case(dom));
            }
        }
        "a" | "aaaa" | "address" | "cname" | "txt" | "srv" | "mx" | "ptr" | "record" => {
            if tokens.len() == 1 {
                dns.records.clear();
            } else {
                let target = tokens[1].to_ascii_lowercase();
                dns.records.retain(|r| match r {
                    DnsRecord::A { name, .. }
                    | DnsRecord::Aaaa { name, .. }
                    | DnsRecord::Txt { name, .. }
                    | DnsRecord::Ptr { name, .. } => name != &target && r.to_string() != target,
                    DnsRecord::Address { domain, .. } | DnsRecord::Mx { domain, .. } => {
                        domain != &target
                    }
                    DnsRecord::Cname { alias, .. } => alias != &target,
                    DnsRecord::Srv { service, .. } => service != &target,
                });
            }
        }
        "route" => {
            if tokens.len() == 1 {
                dns.nft_rules.retain(|r| r.action != DnsNftAction::Route);
            } else {
                let target = tokens[1].to_ascii_lowercase();
                for r in dns.nft_rules.iter_mut() {
                    if r.action == DnsNftAction::Route {
                        r.domains.retain(|d| d != &target);
                    }
                }
                dns.nft_rules
                    .retain(|r| !(r.action == DnsNftAction::Route && (r.domains.is_empty() || r.gateway == target)));
            }
        }
        "bypass" => {
            if tokens.len() == 1 {
                dns.nft_rules.retain(|r| r.action != DnsNftAction::Bypass);
            } else {
                let target = tokens[1].to_ascii_lowercase();
                for r in dns.nft_rules.iter_mut() {
                    if r.action == DnsNftAction::Bypass {
                        r.domains.retain(|d| d != &target);
                    }
                }
                dns.nft_rules
                    .retain(|r| !(r.action == DnsNftAction::Bypass && (r.domains.is_empty() || r.gateway == target)));
            }
        }
        "block" | "sinkhole" => {
            if tokens.len() == 1 {
                dns.blocks.clear();
            } else {
                dns.blocks
                    .retain(|b| !b.eq_ignore_ascii_case(tokens[1]));
            }
        }
        "blocklist" | "adblock" => {
            if tokens.len() == 1 {
                dns.blocklists.clear();
            } else {
                dns.blocklists
                    .retain(|b| !b.name.eq_ignore_ascii_case(tokens[1]));
            }
        }
        "raw" | "dnsmasq" => {
            if tokens.len() == 1 {
                dns.raw_options.clear();
            } else {
                let pat = tokens[1..].join(" ");
                dns.raw_options.retain(|r| !r.contains(&pat));
            }
        }
        other => bail!("Unknown 'no {}' target in dns block", other),
    }
    Ok(())
}
