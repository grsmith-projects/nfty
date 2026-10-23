use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
    Both,
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Proto::Tcp => write!(f, "tcp"),
            Proto::Udp => write!(f, "udp"),
            Proto::Both => write!(f, "tcp+udp"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BalanceStrategy {
    RoundRobin,
    Sticky,
}

impl fmt::Display for BalanceStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BalanceStrategy::RoundRobin => write!(f, "round-robin"),
            BalanceStrategy::Sticky => write!(f, "sticky"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ForwardMode {
    Nat,
    Transparent,
}

impl fmt::Display for ForwardMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ForwardMode::Nat => write!(f, "nat"),
            ForwardMode::Transparent => write!(f, "transparent"),
        }
    }
}

pub fn default_eth0_prefix_len() -> u8 {
    static CACHED: std::sync::OnceLock<u8> = std::sync::OnceLock::new();
    *CACHED.get_or_init(|| {
        if let Ok(out) = std::process::Command::new("ip")
            .args(["-o", "-f", "inet", "addr", "show", "dev", "eth0", "scope", "global"])
            .output()
        {
            let txt = String::from_utf8_lossy(&out.stdout);
            for line in txt.lines() {
                for tok in line.split_whitespace() {
                    if let Some((ip_part, prefix_part)) = tok.split_once('/') {
                        if ip_part.parse::<Ipv4Addr>().is_ok() {
                            if let Ok(p) = prefix_part.parse::<u8>() {
                                if (1..=31).contains(&p) {
                                    return p;
                                }
                            }
                        }
                    }
                }
            }
        }
        24
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VipConfig {
    pub interface: String,
    pub prefix_len: u8,
    #[serde(default)]
    pub dhcp: bool,
    #[serde(default)]
    pub vlan: Option<u16>,
    #[serde(default)]
    pub leased_ip: Option<Ipv4Addr>,
}

impl VipConfig {
    pub fn new(interface: &str, prefix_len: u8) -> Self {
        Self {
            interface: interface.to_string(),
            prefix_len,
            dhcp: false,
            vlan: None,
            leased_ip: None,
        }
    }

    pub fn default_eth0() -> Self {
        Self::new("eth0", default_eth0_prefix_len())
    }

    pub fn effective_base_iface(&self) -> String {
        if let Some(vid) = self.vlan {
            let suffix = format!(".{}", vid);
            if !self.interface.ends_with(&suffix) {
                return format!("{}.{}", self.interface, vid);
            }
        }
        self.interface.clone()
    }
}

impl fmt::Display for VipConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let base = self.effective_base_iface();
        if self.dhcp {
            if let Some(ip) = self.leased_ip {
                write!(f, "dhcp({}={})", base, ip)
            } else {
                write!(f, "dhcp({})", base)
            }
        } else if self.prefix_len == 32 {
            write!(f, "{}", base)
        } else {
            write!(f, "{}/{}", base, self.prefix_len)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum HealthCheckKind {
    Tcp,
    Http { path: String },
    Ping,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    pub kind: HealthCheckKind,
    pub interval_secs: u64,
}

impl fmt::Display for HealthCheckConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            HealthCheckKind::Tcp => write!(f, "tcp {}s", self.interval_secs),
            HealthCheckKind::Http { path } => write!(f, "http {} {}s", path, self.interval_secs),
            HealthCheckKind::Ping => write!(f, "ping {}s", self.interval_secs),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RateUnit {
    Second,
    Minute,
}

impl fmt::Display for RateUnit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RateUnit::Second => write!(f, "sec"),
            RateUnit::Minute => write!(f, "min"),
        }
    }
}

impl RateUnit {
    pub fn to_nft_unit(self) -> &'static str {
        match self {
            RateUnit::Second => "second",
            RateUnit::Minute => "minute",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimit {
    pub rate: u32,
    pub unit: RateUnit,
    pub burst: Option<u32>,
    pub per_ip: bool,
}

impl fmt::Display for RateLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.rate, self.unit)?;
        if let Some(b) = self.burst {
            write!(f, " burst {}", b)?;
        }
        if self.per_ip {
            write!(f, " per-ip")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Backend {
    #[serde(default)]
    pub host: Option<String>,
    pub ip: Ipv4Addr,
    pub port: u16,
    pub weight: u32,
    pub backup: bool,
}

impl Backend {
    pub fn endpoint(&self) -> String {
        match &self.host {
            Some(h) => format!("{}({}):{}", h, self.ip, self.port),
            None => format!("{}:{}", self.ip, self.port),
        }
    }

    pub fn target_label(&self) -> String {
        match &self.host {
            Some(h) => format!("{}:{}", h, self.port),
            None => format!("{}:{}", self.ip, self.port),
        }
    }
}

impl fmt::Display for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Some(h) => write!(f, "{}:{}", h, self.port)?,
            None => write!(f, "{}:{}", self.ip, self.port)?,
        }
        if self.weight != 1 {
            write!(f, " weight {}", self.weight)?;
        }
        if self.backup {
            write!(f, " backup")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Service {
    /// Canonical key, e.g. "9000", "192.168.1.240:443", "sonarr:80", "53/udp"
    pub key: String,
    /// Optional parent VIP key (e.g. "192.168.1.4" or DHCP VIP hostname "sonarr")
    #[serde(default)]
    pub vip_id: Option<String>,
    /// Optional human/target name inside a `vip <ip> -> service` container (e.g. "plex:32400", "gamble:9090", "ssh:22")
    #[serde(default)]
    pub name: Option<String>,
    pub listen_ip: Option<Ipv4Addr>,
    pub port: u16,
    pub proto: Proto,
    pub vip: Option<VipConfig>,
    /// Optional L7 virtual hostname (e.g. "plex.local") for mDNS announcement + HTTP Host / TLS SNI routing on :80/:443
    #[serde(default)]
    pub hostname: Option<String>,
    /// Optional Cloudflare Tunnel public hostname (e.g. "sonarr.example.com") provisioned via Cloudflare API + cloudflared
    #[serde(default)]
    pub cloudflare: Option<String>,
    /// Optional Cloudflare Tunnel / Access authentication rules (e.g. "user@domain.com", "*@smith.gr")
    #[serde(default)]
    pub cloudflare_auth: Vec<String>,
    /// Optional HTTP Basic Authentication rules (e.g. "user:pass", "nfty")
    #[serde(default)]
    pub auth: Vec<String>,
    pub balance: BalanceStrategy,
    pub mode: ForwardMode,
    pub check: Option<HealthCheckConfig>,
    pub limit: Option<RateLimit>,
    /// Allow-list entries: can be IP/CIDR ("192.168.1.0/24"), IP wildcard ("192.168.1.*"),
    /// hostname ("admin.office.lan"), or wildcard hostname ("*.trusted.lan", "*")
    pub allow: Vec<String>,
    pub backends: Vec<Backend>,
}

impl Service {
    pub fn new(key: String, listen_ip: Option<Ipv4Addr>, port: u16, proto: Proto) -> Self {
        Self {
            key,
            vip_id: listen_ip.map(|ip| ip.to_string()),
            name: None,
            listen_ip,
            port,
            proto,
            vip: None,
            hostname: None,
            cloudflare: None,
            cloudflare_auth: Vec::new(),
            auth: Vec::new(),
            balance: BalanceStrategy::RoundRobin,
            mode: ForwardMode::Nat,
            check: None,
            limit: None,
            allow: Vec::new(),
            backends: Vec::new(),
        }
    }

    pub fn belongs_to_vip(&self, vip_key: &str) -> bool {
        if let Some(vid) = &self.vip_id {
            if vid.eq_ignore_ascii_case(vip_key) {
                return true;
            }
        }
        if let Ok(ip) = vip_key.parse::<Ipv4Addr>() {
            if self.listen_ip == Some(ip) && self.vip_id.is_none() {
                return true;
            }
        }
        false
    }

    pub fn display_name(&self) -> String {
        if let Some(n) = &self.name {
            return n.clone();
        }
        if self.backends.len() == 1
            && self.backends[0].ip.is_loopback()
            && self.backends[0].port == 22
            && self.port == 22
        {
            return "ssh:22".to_string();
        }
        if self.backends.len() == 1 && self.backends[0].weight == 1 && !self.backends[0].backup {
            return self.backends[0].to_string();
        }
        if self.proto == Proto::Tcp {
            self.port.to_string()
        } else {
            format!("{}/{}", self.port, self.proto)
        }
    }

    pub fn rebuild_key(&mut self) {
        let base = if let Some(vid) = &self.vip_id {
            format!("{}:{}", vid, self.port)
        } else if let Some(ip) = self.listen_ip {
            format!("{}:{}", ip, self.port)
        } else {
            format!("{}", self.port)
        };
        self.key = match self.proto {
            Proto::Tcp => base,
            Proto::Udp => format!("{}/udp", base),
            Proto::Both => format!("{}/both", base),
        };
    }

    pub fn is_local_ssh(&self) -> bool {
        self.backends.len() == 1
            && self.backends[0].ip.is_loopback()
            && self.backends[0].port == 22
            && self.hostname.is_none()
            && self.cloudflare.is_none()
    }

    pub fn format_in_vip(&self) -> String {
        let single_simple_backend =
            self.backends.len() == 1 && self.backends[0].weight == 1 && !self.backends[0].backup;
        let port_prefix = if self.proto == Proto::Tcp {
            format!("{}", self.port)
        } else {
            format!("{}/{}", self.port, self.proto)
        };

        let (hdr, port_encoded_in_hdr, backend_encoded_in_hdr) = if single_simple_backend {
            let b_str = self.backends[0].to_string();
            if self.port != self.backends[0].port {
                (format!("{} to {}", port_prefix, b_str), true, true)
            } else if self.proto != Proto::Tcp {
                (format!("{} to {}", port_prefix, b_str), true, true)
            } else {
                (b_str, true, true)
            }
        } else {
            let d = self.display_name();
            let implied_port = d
                .rsplit_once(':')
                .and_then(|(_, p)| p.parse::<u16>().ok())
                .or_else(|| d.split('/').next()?.parse::<u16>().ok());
            (d, implied_port == Some(self.port), false)
        };

        let mut body = String::new();
        if !port_encoded_in_hdr {
            body.push_str(&format!("        port {}\n", self.port));
        }
        if self.proto != Proto::Tcp && !hdr.contains('/') {
            body.push_str(&format!("        proto {}\n", self.proto));
        }
        if let Some(h) = &self.hostname {
            body.push_str(&format!("        hostname {}\n", h));
        }
        if let Some(cf) = &self.cloudflare {
            body.push_str(&format!("        cloudflare-dns {}\n", cf));
        }
        if !self.cloudflare_auth.is_empty() {
            body.push_str(&format!(
                "        cloudflare-auth {}\n",
                self.cloudflare_auth.join(" ")
            ));
        }
        if !self.auth.is_empty() {
            body.push_str(&format!(
                "        auth {}\n",
                self.auth.join(" ")
            ));
        }
        if self.balance != BalanceStrategy::RoundRobin || self.backends.len() > 1 {
            body.push_str(&format!("        balance {}\n", self.balance));
        }
        if self.mode != ForwardMode::Nat {
            body.push_str(&format!("        mode {}\n", self.mode));
        }
        if let Some(check) = &self.check {
            body.push_str(&format!("        check {}\n", check));
        }
        if let Some(limit) = &self.limit {
            body.push_str(&format!("        limit {}\n", limit));
        }
        if !self.allow.is_empty() {
            body.push_str("        allow {\n");
            for entry in &self.allow {
                body.push_str(&format!("            {}\n", entry));
            }
            body.push_str("        }\n");
        }
        if !self.backends.is_empty() && !backend_encoded_in_hdr {
            body.push_str("        to {\n");
            for b in &self.backends {
                body.push_str(&format!("            {}\n", b));
            }
            body.push_str("        }\n");
        }
        if body.is_empty() {
            format!("    {}\n", hdr)
        } else {
            format!("    {} {{\n{}    }}\n", hdr, body)
        }
    }

    pub fn format_block(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("service {} {{\n", self.key));
        if let Some(vip) = &self.vip {
            out.push_str(&format!("    vip {}\n", vip));
        }
        if let Some(h) = &self.hostname {
            out.push_str(&format!("    hostname {}\n", h));
        }
        if let Some(cf) = &self.cloudflare {
            out.push_str(&format!("    cloudflare-dns {}\n", cf));
        }
        if !self.cloudflare_auth.is_empty() {
            out.push_str(&format!(
                "    cloudflare-auth {}\n",
                self.cloudflare_auth.join(" ")
            ));
        }
        if !self.auth.is_empty() {
            out.push_str(&format!(
                "    auth {}\n",
                self.auth.join(" ")
            ));
        }
        if self.balance != BalanceStrategy::RoundRobin || self.backends.len() > 1 {
            out.push_str(&format!("    balance {}\n", self.balance));
        }
        if self.mode != ForwardMode::Nat {
            out.push_str(&format!("    mode {}\n", self.mode));
        }
        if let Some(check) = &self.check {
            out.push_str(&format!("    check {}\n", check));
        }
        if let Some(limit) = &self.limit {
            out.push_str(&format!("    limit {}\n", limit));
        }
        if !self.allow.is_empty() {
            out.push_str("    allow {\n");
            for entry in &self.allow {
                out.push_str(&format!("        {}\n", entry));
            }
            out.push_str("    }\n");
        }
        if !self.backends.is_empty() {
            out.push_str("    to {\n");
            for b in &self.backends {
                out.push_str(&format!("        {}\n", b));
            }
            out.push_str("    }\n");
        }
        out.push_str("}\n");
        out
    }

    /// Safe identifier for nftables sets/chains/meters
    pub fn nft_id(&self) -> String {
        self.key
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WgTunnel {
    /// Config filename in `/data/wg/` (e.g. "mullvad-us-sea-001.conf") or tunnel identifier
    pub name: String,
    /// Assigned kernel interface name (e.g. "wg0", "wg1")
    pub iface: String,
    /// Optional inline tunnel IPv4/CIDR (e.g. "10.64.0.1/32")
    #[serde(default)]
    pub address: Option<String>,
    /// Optional inline WireGuard base64 private key
    #[serde(default)]
    pub private_key: Option<String>,
    /// Optional inline WireGuard peer public key
    #[serde(default)]
    pub peer_pubkey: Option<String>,
    /// Optional inline WireGuard peer endpoint ("ip:port" or "host:port")
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default = "default_weight")]
    pub weight: u32,
}

fn default_weight() -> u32 {
    1
}

impl WgTunnel {
    pub fn endpoint_key(&self) -> String {
        format!("wg:{}({})", self.name, self.iface)
    }
}

impl fmt::Display for WgTunnel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)?;
        if let (Some(addr), Some(pk), Some(peer), Some(ep)) = (
            &self.address,
            &self.private_key,
            &self.peer_pubkey,
            &self.endpoint,
        ) {
            write!(
                f,
                " address {} privkey {} peer {} endpoint {}",
                addr, pk, peer, ep
            )?;
        }
        if self.weight != 1 {
            write!(f, " weight {}", self.weight)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GatewayServiceKind {
    Privoxy,
    Socks5,
    Ssh,
}

impl fmt::Display for GatewayServiceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GatewayServiceKind::Privoxy => write!(f, "privoxy"),
            GatewayServiceKind::Socks5 => write!(f, "socks5"),
            GatewayServiceKind::Ssh => write!(f, "ssh"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayService {
    pub kind: GatewayServiceKind,
    pub port: u16,
}

impl fmt::Display for GatewayService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.kind, self.port)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gateway {
    /// Virtual Gateway IPv4 address (e.g. "192.168.1.5")
    pub key: String,
    pub listen_ip: Ipv4Addr,
    pub vip: Option<VipConfig>,
    #[serde(default)]
    pub hostname: Option<String>,
    pub balance: BalanceStrategy,
    pub killswitch: bool,
    pub check: Option<HealthCheckConfig>,
    #[serde(default)]
    pub allow: Vec<String>,
    /// Gateway-attached local services (e.g. `privoxy:8118`, `socks5:1080`, `ssh:22`)
    #[serde(default)]
    pub services: Vec<GatewayService>,
    pub tunnels: Vec<WgTunnel>,
}

impl Gateway {
    pub fn new(listen_ip: Ipv4Addr) -> Self {
        Self {
            key: listen_ip.to_string(),
            listen_ip,
            vip: Some(VipConfig::default_eth0()),
            hostname: None,
            balance: BalanceStrategy::RoundRobin,
            killswitch: true,
            check: Some(HealthCheckConfig {
                kind: HealthCheckKind::Ping,
                interval_secs: 5,
            }),
            allow: Vec::new(),
            services: Vec::new(),
            tunnels: Vec::new(),
        }
    }

    pub fn new_named(key: String, listen_ip: Ipv4Addr, vip: VipConfig) -> Self {
        Self {
            key,
            listen_ip,
            vip: Some(vip),
            hostname: None,
            balance: BalanceStrategy::RoundRobin,
            killswitch: true,
            check: Some(HealthCheckConfig {
                kind: HealthCheckKind::Ping,
                interval_secs: 5,
            }),
            allow: Vec::new(),
            services: Vec::new(),
            tunnels: Vec::new(),
        }
    }

    pub fn format_block(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("gateway {} {{\n", self.key));
        if let Some(vip) = &self.vip {
            if vip.dhcp {
                out.push_str(&format!("    dhcp {}\n", vip.interface));
            } else if vip.interface != "eth0" {
                if vip.prefix_len == 32 {
                    out.push_str(&format!("    interface {}\n", vip.interface));
                } else {
                    out.push_str(&format!("    interface {}/{}\n", vip.interface, vip.prefix_len));
                }
            }
            if let Some(vid) = vip.vlan {
                out.push_str(&format!("    vlan {}\n", vid));
            }
        }
        if let Some(h) = &self.hostname {
            out.push_str(&format!("    hostname {}\n", h));
        }
        out.push_str(&format!("    balance {}\n", self.balance));
        out.push_str(&format!(
            "    killswitch {}\n",
            if self.killswitch { "on" } else { "off" }
        ));
        if let Some(check) = &self.check {
            out.push_str(&format!("    check {}\n", check));
        }
        if !self.allow.is_empty() {
            out.push_str("    allow {\n");
            for entry in &self.allow {
                out.push_str(&format!("        {}\n", entry));
            }
            out.push_str("    }\n");
        }
        for s in &self.services {
            out.push_str(&format!("    {}\n", s));
        }
        if !self.tunnels.is_empty() {
            out.push_str("    tunnels {\n");
            for t in &self.tunnels {
                out.push_str(&format!("        {}\n", t));
            }
            out.push_str("    }\n");
        }
        out.push_str("}\n");
        out
    }

    pub fn nft_id(&self) -> String {
        self.key
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// Global allow-list of hosts/CIDRs/wildcards applied across services (or referenced by them)
    #[serde(default)]
    pub global_allow: Vec<String>,
    /// Explicitly defined VIP containers (`vip 192.168.1.4 { ... }` or `vip sonarr { dhcp eth0 ... }`)
    #[serde(default)]
    pub vips: BTreeMap<String, VipConfig>,
    pub services: BTreeMap<String, Service>,
    #[serde(default)]
    pub gateways: BTreeMap<String, Gateway>,
}

impl Config {
    pub fn new() -> Self {
        Self {
            global_allow: Vec::new(),
            vips: BTreeMap::new(),
            services: BTreeMap::new(),
            gateways: BTreeMap::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.vips.is_empty()
            && self.services.is_empty()
            && self.gateways.is_empty()
            && self.global_allow.is_empty()
    }

    pub fn format_vip_block(&self, vip_ip: Ipv4Addr) -> String {
        self.format_vip_block_by_key(&vip_ip.to_string())
    }

    pub fn format_vip_block_by_key(&self, vip_key: &str) -> String {
        let vip_cfg = self.vips.get(vip_key).cloned().or_else(|| {
            self.services
                .values()
                .find(|s| s.belongs_to_vip(vip_key) && s.vip.is_some())
                .and_then(|s| s.vip.clone())
        });
        let mut out = format!("vip {} {{\n", vip_key);
        if let Some(v) = vip_cfg {
            if v.dhcp {
                out.push_str(&format!("    dhcp {}\n", v.interface));
            } else if v.interface != "eth0" {
                if v.prefix_len == 32 {
                    out.push_str(&format!("    interface {}\n", v.interface));
                } else {
                    out.push_str(&format!("    interface {}/{}\n", v.interface, v.prefix_len));
                }
            }
            if let Some(vid) = v.vlan {
                out.push_str(&format!("    vlan {}\n", vid));
            }
        }
        for svc in self
            .services
            .values()
            .filter(|s| s.belongs_to_vip(vip_key) && s.is_local_ssh())
        {
            out.push_str(&format!("    ssh:{}\n", svc.port));
        }
        let svcs: Vec<&Service> = self
            .services
            .values()
            .filter(|s| s.belongs_to_vip(vip_key) && !s.is_local_ssh())
            .collect();
        for svc in svcs {
            out.push_str(&svc.format_in_vip());
        }
        out.push_str("}\n");
        out
    }

    pub fn format_nftyfile(&self) -> String {
        if self.is_empty() {
            return "# Empty Nftyfile\n".to_string();
        }
        let mut blocks = Vec::new();
        if !self.global_allow.is_empty() {
            let mut blk = String::from("allow {\n");
            for host in &self.global_allow {
                blk.push_str(&format!("    {}\n", host));
            }
            blk.push_str("}\n");
            blocks.push(blk);
        }
        let mut vip_keys = std::collections::BTreeSet::new();
        for k in self.vips.keys() {
            vip_keys.insert(k.clone());
        }
        for svc in self.services.values() {
            if let Some(vid) = &svc.vip_id {
                vip_keys.insert(vid.clone());
            } else if let Some(ip) = svc.listen_ip {
                vip_keys.insert(ip.to_string());
            }
        }
        for k in vip_keys {
            blocks.push(self.format_vip_block_by_key(&k));
        }
        for svc in self.services.values() {
            if svc.listen_ip.is_none() && svc.vip_id.is_none() {
                blocks.push(svc.format_block());
            }
        }
        for gw in self.gateways.values() {
            blocks.push(gw.format_block());
        }
        blocks.join("\n")
    }
}
