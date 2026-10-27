use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::net::Ipv4Addr;

use crate::parser::{ipv4_in_network, parse_ip_allow_entry};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    Disabled,
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
            HealthCheckKind::Disabled => write!(f, "off"),
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
        } else {
            write!(f, " global")?;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApiKeyScope {
    #[serde(rename = "ro", alias = "readonly", alias = "read-only")]
    ReadOnly,
    #[serde(rename = "rw", alias = "readwrite", alias = "read-write")]
    ReadWrite,
}

impl ApiKeyScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            ApiKeyScope::ReadOnly => "ro",
            ApiKeyScope::ReadWrite => "rw",
        }
    }
}

impl fmt::Display for ApiKeyScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ApiKey {
    pub key: String,
    pub scope: ApiKeyScope,
}

impl fmt::Display for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "key {} {}", self.key, self.scope)
    }
}

pub fn generate_api_key(scope: ApiKeyScope) -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 16] = rng.gen();
    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    format!("nfty_{}_{}", scope, hex)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Service {
    /// Canonical key, e.g. "9000", "192.168.1.240:443", "sonarr:80", "53/udp"
    pub key: String,
    /// Optional parent VIP key (e.g. "192.168.1.4" or DHCP VIP hostname "sonarr")
    #[serde(default)]
    pub vip_id: Option<String>,
    /// Optional human/target name inside a `vip <ip> -> service` container (e.g. "plex:32400", "app-backend:9090", "ssh:22", "api:9090")
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
    /// Optional Cloudflare Tunnel / Access authentication rules (e.g. "user@example.com", "*@example.com")
    #[serde(default)]
    pub cloudflare_auth: Vec<String>,
    /// Optional HTTP Basic Authentication rules (e.g. "user:pass", "nfty")
    #[serde(default)]
    pub auth: Vec<String>,
    /// Optional scoped API keys when this service is a local `api:<port>` control service
    #[serde(default)]
    pub api_keys: Vec<ApiKey>,
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
            api_keys: Vec::new(),
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
        if self.is_local_web() {
            return format!("web:{}", self.port);
        }
        if self.is_local_api() {
            return format!("api:{}", self.port);
        }
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
        if self.backends.len() == 1
            && self.backends[0].ip.is_loopback()
            && self.backends[0].port == 53
            && self.port == 53
        {
            return "dns:53".to_string();
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

    pub fn is_local_dns(&self) -> bool {
        self.backends.len() == 1
            && self.backends[0].ip.is_loopback()
            && self.backends[0].port == 53
            && self.hostname.is_none()
            && self.cloudflare.is_none()
    }

    pub fn is_local_api(&self) -> bool {
        self.name
            .as_deref()
            .map(|n| n.eq_ignore_ascii_case("api") || n.to_ascii_lowercase().starts_with("api:"))
            .unwrap_or(false)
            || (!self.is_local_web()
                && !self.api_keys.is_empty()
                && self.backends.len() == 1
                && self.backends[0].ip.is_loopback())
    }

    pub fn is_local_web(&self) -> bool {
        self.name
            .as_deref()
            .map(|n| n.eq_ignore_ascii_case("web") || n.to_ascii_lowercase().starts_with("web:"))
            .unwrap_or(false)
    }

    pub fn is_local_api_or_web(&self) -> bool {
        self.is_local_api() || self.is_local_web()
    }

    pub fn format_in_vip(&self) -> String {
        let is_web = self.is_local_web();
        let is_api = self.is_local_api();
        let is_ssh = self.is_local_ssh();
        let is_dns = self.is_local_dns();
        let single_simple_backend =
            self.backends.len() == 1 && self.backends[0].weight == 1 && !self.backends[0].backup;
        let port_prefix = if self.proto == Proto::Tcp {
            format!("{}", self.port)
        } else {
            format!("{}/{}", self.port, self.proto)
        };

        let (hdr, port_encoded_in_hdr, backend_encoded_in_hdr) = if is_web {
            (format!("web:{}", self.port), true, true)
        } else if is_api {
            (format!("api:{}", self.port), true, true)
        } else if is_ssh {
            (format!("ssh:{}", self.port), true, true)
        } else if is_dns {
            (format!("dns:{}", self.port), true, true)
        } else if single_simple_backend {
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
        if !is_dns
            && !is_ssh
            && !is_api
            && !is_web
            && self.proto != Proto::Tcp
            && !hdr.contains('/')
        {
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
        for k in &self.api_keys {
            body.push_str(&format!("        key {} {}\n", k.key, k.scope));
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
        for k in &self.api_keys {
            out.push_str(&format!("    key {} {}\n", k.key, k.scope));
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
        if !self.backends.is_empty() && !self.is_local_api_or_web() {
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
    Dns,
    Api,
    Web,
}

impl fmt::Display for GatewayServiceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GatewayServiceKind::Privoxy => write!(f, "privoxy"),
            GatewayServiceKind::Socks5 => write!(f, "socks5"),
            GatewayServiceKind::Ssh => write!(f, "ssh"),
            GatewayServiceKind::Dns => write!(f, "dns"),
            GatewayServiceKind::Api => write!(f, "api"),
            GatewayServiceKind::Web => write!(f, "web"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayService {
    pub kind: GatewayServiceKind,
    pub port: u16,
    #[serde(default)]
    pub api_keys: Vec<ApiKey>,
}

impl GatewayService {
    pub fn new(kind: GatewayServiceKind, port: u16) -> Self {
        Self {
            kind,
            port,
            api_keys: Vec::new(),
        }
    }

    pub fn format_block(&self) -> String {
        if self.api_keys.is_empty() {
            format!("{}:{}\n", self.kind, self.port)
        } else {
            let mut out = format!("{}:{} {{\n", self.kind, self.port);
            for k in &self.api_keys {
                out.push_str(&format!("    key {} {}\n", k.key, k.scope));
            }
            out.push_str("}\n");
            out
        }
    }
}

impl fmt::Display for GatewayService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.kind, self.port)
    }
}

fn default_forward_proto() -> Proto {
    Proto::Both
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayPortForward {
    pub listen_port: u16,
    #[serde(default = "default_forward_proto")]
    pub proto: Proto,
    pub backend: Backend,
}

impl fmt::Display for GatewayPortForward {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.proto == Proto::Both {
            write!(f, "forward {} to {}", self.listen_port, self.backend)
        } else {
            write!(
                f,
                "forward {}/{} to {}",
                self.listen_port, self.proto, self.backend
            )
        }
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
    /// Gateway-attached local services (e.g. `privoxy:8118`, `socks5:1080`, `ssh:22`, `api:9090`)
    #[serde(default)]
    pub services: Vec<GatewayService>,
    /// Inbound port forwards from the gateway's WireGuard tunnel interfaces to LAN backends (e.g. `forward 51413 to 192.168.20.10:51413`)
    #[serde(default)]
    pub forwards: Vec<GatewayPortForward>,
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
            forwards: Vec::new(),
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
            forwards: Vec::new(),
            tunnels: Vec::new(),
        }
    }

    pub fn format_block(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("gateway {} {{\n", self.key));
        if let Some(vip) = &self.vip {
            if vip.dhcp {
                out.push_str(&format!("    dhcp {}\n", vip.interface));
            } else if vip.interface != "eth0" || vip.prefix_len != default_eth0_prefix_len() {
                if vip.prefix_len == 32 && vip.interface != "eth0" {
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
        } else {
            out.push_str("    check off\n");
        }
        if !self.allow.is_empty() {
            out.push_str("    allow {\n");
            for entry in &self.allow {
                out.push_str(&format!("        {}\n", entry));
            }
            out.push_str("    }\n");
        }
        for s in &self.services {
            if matches!(s.kind, GatewayServiceKind::Api | GatewayServiceKind::Web)
                && !s.api_keys.is_empty()
            {
                out.push_str(&format!("    {}:{} {{\n", s.kind, s.port));
                for k in &s.api_keys {
                    out.push_str(&format!("        key {} {}\n", k.key, k.scope));
                }
                out.push_str("    }\n");
            } else {
                out.push_str(&format!("    {}\n", s));
            }
        }
        for fwd in &self.forwards {
            out.push_str(&format!("    {}\n", fwd));
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum DnsRecord {
    A {
        name: String,
        ips: Vec<Ipv4Addr>,
    },
    Aaaa {
        name: String,
        ip: String,
    },
    Address {
        domain: String,
        ip: Ipv4Addr,
    },
    Cname {
        alias: String,
        target: String,
    },
    Txt {
        name: String,
        text: String,
    },
    Srv {
        service: String,
        target: String,
        port: u16,
        priority: u16,
        weight: u16,
    },
    Mx {
        domain: String,
        target: String,
        preference: u16,
    },
    Ptr {
        ip: Ipv4Addr,
        name: String,
    },
}

impl fmt::Display for DnsRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsRecord::A { name, ips } => {
                let ip_strs: Vec<String> = ips.iter().map(|i| i.to_string()).collect();
                write!(f, "a {} {}", name, ip_strs.join(" "))
            }
            DnsRecord::Aaaa { name, ip } => write!(f, "aaaa {} {}", name, ip),
            DnsRecord::Address { domain, ip } => write!(f, "address {} {}", domain, ip),
            DnsRecord::Cname { alias, target } => write!(f, "cname {} {}", alias, target),
            DnsRecord::Txt { name, text } => {
                let escaped = text.replace('\\', "\\\\").replace('"', "\\\"");
                write!(f, "txt {} \"{}\"", name, escaped)
            }
            DnsRecord::Srv {
                service,
                target,
                port,
                priority,
                weight,
            } => {
                if *priority == 0 && *weight == 0 {
                    write!(f, "srv {} {}:{}", service, target, port)
                } else {
                    write!(
                        f,
                        "srv {} {}:{} {} {}",
                        service, target, port, priority, weight
                    )
                }
            }
            DnsRecord::Mx {
                domain,
                target,
                preference,
            } => write!(f, "mx {} {} {}", domain, target, preference),
            DnsRecord::Ptr { ip, name } => write!(f, "ptr {} {}", ip, name),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsForwardZone {
    pub domain: String,
    pub servers: Vec<String>,
    #[serde(default)]
    pub via_gateway: Option<String>,
}

impl fmt::Display for DnsForwardZone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "forward {} to {}", self.domain, self.servers.join(" "))?;
        if let Some(gw) = &self.via_gateway {
            write!(f, " via {}", gw)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsBlocklist {
    pub name: String,
    pub url: String,
}

impl DnsBlocklist {
    pub fn valid_name(name: &str) -> bool {
        !name.is_empty()
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            && name != "."
            && name != ".."
    }
}

impl fmt::Display for DnsBlocklist {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "blocklist {} {}", self.name, self.url)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnsNftAction {
    Route,
    Bypass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsNftRule {
    pub action: DnsNftAction,
    pub domains: Vec<String>,
    pub gateway: String,
}

impl fmt::Display for DnsNftRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.action {
            DnsNftAction::Route => write!(
                f,
                "route {} via {}",
                self.domains.join(" "),
                self.gateway
            ),
            DnsNftAction::Bypass => write!(
                f,
                "bypass {} from {}",
                self.domains.join(" "),
                self.gateway
            ),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_cache_size() -> u32 {
    10000
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsConfig {
    #[serde(default)]
    pub listen: Vec<String>,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default = "default_cache_size")]
    pub cache_size: u32,
    #[serde(default = "default_true")]
    pub auto_vips: bool,
    #[serde(default = "default_true")]
    pub auto_hosts: bool,
    #[serde(default = "default_true")]
    pub health_aware: bool,
    #[serde(default = "default_true")]
    pub all_servers: bool,
    #[serde(default = "default_true")]
    pub bogus_priv: bool,
    #[serde(default = "default_true")]
    pub domain_needed: bool,
    #[serde(default)]
    pub upstreams: Vec<String>,
    #[serde(default)]
    pub forward_zones: Vec<DnsForwardZone>,
    #[serde(default)]
    pub records: Vec<DnsRecord>,
    #[serde(default)]
    pub blocks: Vec<String>,
    #[serde(default)]
    pub blocklists: Vec<DnsBlocklist>,
    #[serde(default)]
    pub nft_rules: Vec<DnsNftRule>,
    #[serde(default)]
    pub raw_options: Vec<String>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            listen: Vec::new(),
            domain: Some("lan".to_string()),
            cache_size: 10000,
            auto_vips: true,
            auto_hosts: true,
            health_aware: true,
            all_servers: true,
            bogus_priv: true,
            domain_needed: true,
            upstreams: vec!["1.1.1.1".to_string(), "9.9.9.9".to_string()],
            forward_zones: Vec::new(),
            records: Vec::new(),
            blocks: Vec::new(),
            blocklists: Vec::new(),
            nft_rules: Vec::new(),
            raw_options: Vec::new(),
        }
    }
}

impl DnsConfig {
    pub fn format_block(&self) -> String {
        let mut out = String::from("dns {\n");
        if !self.listen.is_empty() {
            out.push_str(&format!("    listen {}\n", self.listen.join(" ")));
        }
        if let Some(dom) = &self.domain {
            out.push_str(&format!("    domain {}\n", dom));
        } else {
            out.push_str("    domain off\n");
        }
        if self.cache_size != 10000 {
            out.push_str(&format!("    cache-size {}\n", self.cache_size));
        }
        out.push_str(&format!(
            "    auto-vips {}\n",
            if self.auto_vips { "on" } else { "off" }
        ));
        out.push_str(&format!(
            "    auto-hosts {}\n",
            if self.auto_hosts { "on" } else { "off" }
        ));
        if !self.health_aware {
            out.push_str("    health-aware off\n");
        }
        if !self.all_servers {
            out.push_str("    all-servers off\n");
        }
        if !self.bogus_priv {
            out.push_str("    bogus-priv off\n");
        }
        if !self.domain_needed {
            out.push_str("    domain-needed off\n");
        }
        if !self.upstreams.is_empty() {
            out.push_str(&format!("    upstream {}\n", self.upstreams.join(" ")));
        } else {
            out.push_str("    no upstream\n");
        }
        for fz in &self.forward_zones {
            out.push_str(&format!("    {}\n", fz));
        }
        for rec in &self.records {
            out.push_str(&format!("    {}\n", rec));
        }
        for nr in &self.nft_rules {
            out.push_str(&format!("    {}\n", nr));
        }
        if !self.blocks.is_empty() {
            out.push_str(&format!("    block {}\n", self.blocks.join(" ")));
        }
        for bl in &self.blocklists {
            out.push_str(&format!("    {}\n", bl));
        }
        for raw in &self.raw_options {
            out.push_str(&format!("    raw {}\n", raw));
        }
        out.push_str("}\n");
        out
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlListenerKind {
    Api,
    Web,
}

/// A `web:<port>` or `api:<port>` listener and the allow-list/API keys that govern it.
#[derive(Debug, Clone)]
pub struct ControlListener<'a> {
    pub owner: String,
    pub kind: ControlListenerKind,
    pub port: u16,
    pub allow: &'a [String],
    pub api_keys: &'a [ApiKey],
}

impl fmt::Display for ControlListener<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.kind {
            ControlListenerKind::Api => "api",
            ControlListenerKind::Web => "web",
        };
        write!(f, "{}:{} ({})", kind, self.port, self.owner)
    }
}

/// Outcome of the IP allow-list check for a remote control-plane client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlAccess {
    /// Allow-listed, and the listener has no API keys, so the allow-list grants read-write access.
    Granted,
    /// Allow-listed, but the listener also requires an API key.
    KeyRequired,
    Denied(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// Global allow-list of hosts/CIDRs/wildcards applied across services (or referenced by them)
    #[serde(default)]
    pub global_allow: Vec<String>,
    /// Optional dnsmasq-backed programmable DNS endpoint configuration (`dns { ... }`)
    #[serde(default)]
    pub dns: Option<DnsConfig>,
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
            dns: None,
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
            && self.dns.is_none()
    }

    pub fn has_any_dns_enabled(&self) -> bool {
        self.dns.is_some()
            || self.services.values().any(|s| s.is_local_dns())
            || self
                .gateways
                .values()
                .any(|g| g.services.iter().any(|gs| gs.kind == GatewayServiceKind::Dns))
    }

    pub fn has_any_api_service(&self) -> bool {
        self.services.values().any(|s| s.is_local_api_or_web())
            || self.gateways.values().any(|g| {
                g.services.iter().any(|gs| {
                    matches!(gs.kind, GatewayServiceKind::Api | GatewayServiceKind::Web)
                })
            })
    }

    pub fn has_any_api_keys(&self) -> bool {
        self.services.values().any(|s| !s.api_keys.is_empty())
            || self
                .gateways
                .values()
                .any(|g| g.services.iter().any(|gs| !gs.api_keys.is_empty()))
    }

    /// Returns all configured API and Web UI ports across VIP services and gateways.
    pub fn api_ports(&self) -> Vec<u16> {
        let mut ports = std::collections::BTreeSet::new();
        for svc in self.services.values() {
            if svc.is_local_api_or_web() {
                ports.insert(svc.port);
            }
        }
        for gw in self.gateways.values() {
            for gs in &gw.services {
                if matches!(gs.kind, GatewayServiceKind::Api | GatewayServiceKind::Web) {
                    ports.insert(gs.port);
                }
            }
        }
        ports.into_iter().collect()
    }

    /// Returns true if `local_port` is configured as a `web:<port>` service on a VIP or Gateway.
    pub fn is_web_port(&self, local_port: Option<u16>) -> bool {
        let Some(lp) = local_port else {
            return false;
        };
        for svc in self.services.values() {
            if svc.is_local_web() && svc.port == lp {
                return true;
            }
        }
        for gw in self.gateways.values() {
            for gs in &gw.services {
                if gs.kind == GatewayServiceKind::Web && gs.port == lp {
                    return true;
                }
            }
        }
        false
    }

    /// Lists every `web:<port>` and `api:<port>` control listener declared on a VIP or gateway.
    /// Gateway listeners are governed by the gateway's `allow` list.
    pub fn control_listeners(&self) -> Vec<ControlListener<'_>> {
        let services = self.services.values().filter_map(|svc| {
            let kind = if svc.is_local_web() {
                ControlListenerKind::Web
            } else if svc.is_local_api() {
                ControlListenerKind::Api
            } else {
                return None;
            };
            Some(ControlListener {
                owner: format!("service {}", svc.key),
                kind,
                port: svc.port,
                allow: &svc.allow,
                api_keys: &svc.api_keys,
            })
        });
        let gateways = self.gateways.values().flat_map(|gw| {
            gw.services.iter().filter_map(move |gs| {
                let kind = match gs.kind {
                    GatewayServiceKind::Web => ControlListenerKind::Web,
                    GatewayServiceKind::Api => ControlListenerKind::Api,
                    _ => return None,
                };
                Some(ControlListener {
                    owner: format!("gateway {}", gw.key),
                    kind,
                    port: gs.port,
                    allow: &gw.allow,
                    api_keys: &gs.api_keys,
                })
            })
        });
        services.chain(gateways).collect()
    }

    /// Address entries (IP, CIDR, IPv4 wildcard) that govern a control listener: its own plus the
    /// global allow-list. Hostname entries are skipped because DHCP clients choose their own names.
    fn control_allow_networks<'a>(
        &'a self,
        own: &'a [String],
    ) -> impl Iterator<Item = (Ipv4Addr, u8)> + 'a {
        own.iter()
            .chain(&self.global_allow)
            .filter_map(|entry| parse_ip_allow_entry(entry))
    }

    /// Reasons this config must not be applied: every `web:`/`api:` listener needs an IP allow-list
    /// (its own or global), and its own allow entries must be addresses rather than hostnames.
    pub fn control_allow_list_errors(&self) -> Vec<String> {
        let mut errors = Vec::new();
        for listener in self.control_listeners() {
            for entry in listener.allow {
                if parse_ip_allow_entry(entry).is_none() {
                    errors.push(format!(
                        "{}: allow entry '{}' is not an IP, CIDR, or IPv4 wildcard (hostnames are not accepted for web:/api: access)",
                        listener, entry
                    ));
                }
            }
            if self.control_allow_networks(listener.allow).next().is_none() {
                errors.push(format!(
                    "{}: requires an IP allow-list (add 'allow <ip-or-cidr>' to it, or to the global allow-list)",
                    listener
                ));
            }
        }
        errors
    }

    pub fn control_allow_list_warnings(&self) -> Vec<String> {
        let listeners = self.control_listeners();
        if listeners.is_empty() {
            return Vec::new();
        }
        let mut warnings: Vec<String> = self
            .global_allow
            .iter()
            .filter(|entry| parse_ip_allow_entry(entry).is_none())
            .map(|entry| {
                format!(
                    "global allow entry '{}' is not an IP or CIDR and is ignored for web:/api: access",
                    entry
                )
            })
            .collect();
        for listener in &listeners {
            if self
                .control_allow_networks(listener.allow)
                .any(|(_, prefix)| prefix == 0)
            {
                warnings.push(format!(
                    "{}: allow-list includes 0.0.0.0/0, which admits every client",
                    listener
                ));
            }
        }
        let mut owners_by_port: BTreeMap<u16, Vec<String>> = BTreeMap::new();
        for listener in &listeners {
            owners_by_port
                .entry(listener.port)
                .or_default()
                .push(listener.to_string());
        }
        for (port, owners) in owners_by_port {
            if owners.len() > 1 {
                warnings.push(format!(
                    "port {} is shared by {}; clients must satisfy every one of their allow-lists",
                    port,
                    owners.join(", ")
                ));
            }
        }
        warnings
    }

    /// Decides whether a remote (non-loopback) client may reach the control listener on `local_port`.
    /// Fails closed: unknown ports, non-IPv4 clients, and listeners without an IP allow-list are denied.
    pub fn control_access(&self, peer_ip: Option<Ipv4Addr>, local_port: Option<u16>) -> ControlAccess {
        let Some(peer_ip) = peer_ip else {
            return ControlAccess::Denied(
                "Forbidden: web/API access requires an IPv4 client address".to_string(),
            );
        };
        let Some(port) = local_port else {
            return ControlAccess::Denied("Forbidden: unknown listener port".to_string());
        };
        let listeners: Vec<ControlListener<'_>> = self
            .control_listeners()
            .into_iter()
            .filter(|listener| listener.port == port)
            .collect();
        if listeners.is_empty() {
            return ControlAccess::Denied(format!(
                "Forbidden: port {} is not a configured web:/api: listener",
                port
            ));
        }
        for listener in &listeners {
            let permitted = self
                .control_allow_networks(listener.allow)
                .any(|(network, prefix)| ipv4_in_network(peer_ip, network, prefix));
            if !permitted {
                return ControlAccess::Denied(format!(
                    "Forbidden: client IP {} is not in the allow-list for {}",
                    peer_ip, listener
                ));
            }
        }
        if listeners.iter().any(|listener| !listener.api_keys.is_empty()) {
            ControlAccess::KeyRequired
        } else {
            ControlAccess::Granted
        }
    }

    /// Verifies a candidate API key against all configured `api:<port>` blocks across VIPs and Gateways.
    /// If the key matches multiple entries, returns the highest privilege scope (`ReadWrite` > `ReadOnly`).
    pub fn verify_api_key(&self, candidate_key: &str) -> Option<ApiKeyScope> {
        let trimmed = candidate_key.trim();
        if trimmed.is_empty() {
            return None;
        }
        let mut matched: Option<ApiKeyScope> = None;
        for svc in self.services.values() {
            for k in &svc.api_keys {
                if k.key == trimmed {
                    if k.scope == ApiKeyScope::ReadWrite {
                        return Some(ApiKeyScope::ReadWrite);
                    }
                    matched = Some(ApiKeyScope::ReadOnly);
                }
            }
        }
        for gw in self.gateways.values() {
            for gs in &gw.services {
                for k in &gs.api_keys {
                    if k.key == trimmed {
                        if k.scope == ApiKeyScope::ReadWrite {
                            return Some(ApiKeyScope::ReadWrite);
                        }
                        matched = Some(ApiKeyScope::ReadOnly);
                    }
                }
            }
        }
        matched
    }

    /// A shared port requires the key to be accepted by every keyed listener on that port.
    pub fn verify_api_key_for_port(
        &self,
        candidate_key: &str,
        port: u16,
    ) -> Option<ApiKeyScope> {
        let candidate_key = candidate_key.trim();
        if candidate_key.is_empty() {
            return None;
        }
        let mut matched = None;
        for listener in self.control_listeners().into_iter().filter(|listener| {
            listener.port == port && !listener.api_keys.is_empty()
        }) {
            let listener_scope = listener
                .api_keys
                .iter()
                .filter(|key| key.key == candidate_key)
                .map(|key| key.scope)
                .fold(None, |scope, next| match (scope, next) {
                    (Some(ApiKeyScope::ReadWrite), _) | (_, ApiKeyScope::ReadWrite) => {
                        Some(ApiKeyScope::ReadWrite)
                    }
                    _ => Some(ApiKeyScope::ReadOnly),
                })?;
            matched = Some(match (matched, listener_scope) {
                (Some(ApiKeyScope::ReadOnly), _) | (_, ApiKeyScope::ReadOnly) => {
                    ApiKeyScope::ReadOnly
                }
                _ => ApiKeyScope::ReadWrite,
            });
        }
        matched
    }

    /// Masks write-capable keys and other secrets in read-only configuration responses.
    pub fn redacted_for_readonly(&self) -> Self {
        let mut c = self.clone();
        for svc in c.services.values_mut() {
            for rule in &mut svc.auth {
                *rule = "<redacted>".to_string();
            }
            for rule in &mut svc.cloudflare_auth {
                *rule = "<redacted>".to_string();
            }
            for k in &mut svc.api_keys {
                if k.scope == ApiKeyScope::ReadWrite {
                    k.key = "<redacted-rw-key>".to_string();
                }
            }
        }
        for gw in c.gateways.values_mut() {
            for tunnel in &mut gw.tunnels {
                if tunnel.private_key.is_some() {
                    tunnel.private_key = Some("<redacted>".to_string());
                }
            }
            for gs in &mut gw.services {
                for k in &mut gs.api_keys {
                    if k.scope == ApiKeyScope::ReadWrite {
                        k.key = "<redacted-rw-key>".to_string();
                    }
                }
            }
        }
        c
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
            } else if v.interface != "eth0" || v.prefix_len != default_eth0_prefix_len() {
                if v.prefix_len == 32 && v.interface != "eth0" {
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
            out.push_str(&svc.format_in_vip());
        }
        for svc in self
            .services
            .values()
            .filter(|s| s.belongs_to_vip(vip_key) && s.is_local_dns())
        {
            out.push_str(&svc.format_in_vip());
        }
        let svcs: Vec<&Service> = self
            .services
            .values()
            .filter(|s| s.belongs_to_vip(vip_key) && !s.is_local_ssh() && !s.is_local_dns())
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
        if let Some(dns) = &self.dns {
            blocks.push(dns.format_block());
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
