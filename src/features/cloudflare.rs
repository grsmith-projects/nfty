use super::vhost_mdns::extract_host_or_sni;
use crate::ast::Config;
use crate::state::SharedState;
use anyhow::{bail, Context, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const CF_CONFIG_PATH: &str = "/data/cloudflare.json";
const CF_PID_FILE: &str = "/run/cloudflared.pid";
const CF_LOG_FILE: &str = "/run/cloudflared.log";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudflareConfig {
    #[serde(default)]
    pub api_token: Option<String>,
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub tunnel_id: Option<String>,
    #[serde(default = "default_cf_tunnel_name")]
    pub tunnel_name: String,
    #[serde(default)]
    pub tunnel_token: Option<String>,
    /// hostname -> (zone_id, record_id)
    #[serde(default)]
    pub managed_dns_records: BTreeMap<String, (String, String)>,
    /// hostname -> access_app_id
    #[serde(default)]
    pub managed_access_apps: BTreeMap<String, String>,
    #[serde(default)]
    pub access_api_enabled: Option<bool>,
    #[serde(default)]
    pub last_status: Option<String>,
}

fn default_cf_tunnel_name() -> String {
    "nfty-appliance".to_string()
}

impl Default for CloudflareConfig {
    fn default() -> Self {
        Self {
            api_token: None,
            account_id: None,
            tunnel_id: None,
            tunnel_name: default_cf_tunnel_name(),
            tunnel_token: None,
            managed_dns_records: BTreeMap::new(),
            managed_access_apps: BTreeMap::new(),
            access_api_enabled: None,
            last_status: None,
        }
    }
}

pub fn load_cloudflare_config() -> CloudflareConfig {
    fs::read_to_string(CF_CONFIG_PATH)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_cloudflare_config(cfg: &CloudflareConfig) -> Result<()> {
    let _ = fs::create_dir_all("/data");
    let json_str = serde_json::to_string_pretty(cfg)?;
    fs::write(CF_CONFIG_PATH, json_str)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(CF_CONFIG_PATH, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn cf_api_request(
    method: &str,
    path: &str,
    api_token: &str,
    body: Option<serde_json::Value>,
) -> Result<serde_json::Value> {
    let url = format!(
        "https://api.cloudflare.com/client/v4/{}",
        path.trim_start_matches('/')
    );
    let ipv4_resolver = |netloc: &str| -> std::io::Result<Vec<SocketAddr>> {
        use std::net::ToSocketAddrs;
        let addrs: Vec<SocketAddr> = netloc
            .to_socket_addrs()?
            .filter(|a| a.is_ipv4())
            .collect();
        if addrs.is_empty() {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "No IPv4 address found for api.cloudflare.com",
            ))
        } else {
            Ok(addrs)
        }
    };
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(10))
        .resolver(ipv4_resolver)
        .build();
    let req = agent
        .request(method, &url)
        .set("Authorization", &format!("Bearer {}", api_token.trim()))
        .set("Content-Type", "application/json");

    let resp = match body {
        Some(b) => req.send_json(b),
        None => req.call(),
    };

    let val: serde_json::Value = match resp {
        Ok(r) => r.into_json()?,
        Err(ureq::Error::Status(code, r)) => {
            let err_json: serde_json::Value = r
                .into_json()
                .unwrap_or_else(|_| serde_json::json!({"http_status": code}));
            bail!(
                "Cloudflare API {} {} returned HTTP {}: {}",
                method,
                path,
                code,
                err_json
            );
        }
        Err(e) => bail!("Cloudflare API request failed ({} {}): {}", method, path, e),
    };

    if val.get("success").and_then(|v| v.as_bool()) == Some(false) {
        let errs = val
            .get("errors")
            .cloned()
            .unwrap_or_else(|| serde_json::json!([]));
        bail!("Cloudflare API error on {} {}: {}", method, path, errs);
    }
    Ok(val)
}

/// Discovers Cloudflare Account ID and Zone list (`zone_name -> zone_id`) using the API token.
fn discover_cf_account_and_zones(
    api_token: &str,
) -> Result<(Option<String>, BTreeMap<String, String>)> {
    let mut zones = BTreeMap::new();
    let mut account_id = None;

    if let Ok(z_resp) = cf_api_request("GET", "zones?per_page=50", api_token, None) {
        if let Some(arr) = z_resp.get("result").and_then(|v| v.as_array()) {
            for item in arr {
                if let (Some(name), Some(zid)) = (
                    item.get("name").and_then(|v| v.as_str()),
                    item.get("id").and_then(|v| v.as_str()),
                ) {
                    zones.insert(name.to_ascii_lowercase(), zid.to_string());
                }
                if account_id.is_none() {
                    account_id = item
                        .get("account")
                        .and_then(|a| a.get("id"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
            }
        }
    }

    if account_id.is_none() {
        if let Ok(a_resp) = cf_api_request("GET", "accounts?per_page=10", api_token, None) {
            if let Some(arr) = a_resp.get("result").and_then(|v| v.as_array()) {
                if let Some(first) = arr.first() {
                    account_id = first
                        .get("id")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
            }
        }
    }

    Ok((account_id, zones))
}

pub const CF_LOCAL_AUTH_PORT: u16 = 18443;

fn base64_decode_simple(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u8;
    for &b in input.trim().as_bytes() {
        if b == b'=' {
            break;
        }
        let val = TABLE.iter().position(|&c| c == b)? as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

pub fn check_http_basic_auth(req_buf: &[u8], auth_rules: &[String]) -> bool {
    if auth_rules.is_empty() {
        return true;
    }
    let Ok(text) = std::str::from_utf8(req_buf) else {
        return false;
    };
    let mut provided_user_pass: Option<(String, String)> = None;
    for line in text.lines().take(48) {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("authorization") {
                let v_trim = v.trim();
                if let Some(b64) = v_trim
                    .strip_prefix("Basic ")
                    .or_else(|| v_trim.strip_prefix("basic "))
                {
                    if let Some(decoded_bytes) = base64_decode_simple(b64) {
                        if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
                            if let Some((u, p)) = decoded_str.split_once(':') {
                                provided_user_pass = Some((u.to_string(), p.to_string()));
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    let Some((user, pass)) = provided_user_pass else {
        return false;
    };

    for rule in auth_rules {
        if rule.eq_ignore_ascii_case("nfty") {
            if crate::ssh::verify_login(&user, &pass) {
                return true;
            }
        } else if let Some((ru, rp)) = rule.split_once(':') {
            if user == ru && pass == rp {
                return true;
            }
        } else if rule.contains('@') {
            // Fallback when Cloudflare Access API is not enabled on the Cloudflare account:
            // accept either the email username / 'nfty' with the nfty appliance password
            let email_prefix = rule.split('@').next().unwrap_or("");
            let auth_cfg = crate::ssh::load_auth_config();
            let pw_ok = auth_cfg.password_sha256 == crate::ssh::hash_password(&pass);
            if pw_ok
                && (user.eq_ignore_ascii_case(&auth_cfg.username)
                    || user.eq_ignore_ascii_case(rule)
                    || (!email_prefix.is_empty()
                        && email_prefix != "*"
                        && user.eq_ignore_ascii_case(email_prefix)))
            {
                return true;
            }
        }
    }
    false
}

/// Strips the nfty `Authorization: Basic ...` header before forwarding to the backend app,
/// and sets `Connection: close` on non-WebSocket HTTP requests so `cloudflared` does not pool
/// an authenticated TCP connection across different visitors.
pub fn sanitize_authenticated_http_request(req_buf: &[u8]) -> Vec<u8> {
    let Some(hdr_end) = req_buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return req_buf.to_vec();
    };
    let Ok(hdr_str) = std::str::from_utf8(&req_buf[..hdr_end]) else {
        return req_buf.to_vec();
    };
    let body = &req_buf[hdr_end + 4..];
    let is_websocket = hdr_str
        .lines()
        .any(|l| l.to_ascii_lowercase().contains("websocket"));

    let mut out = String::with_capacity(hdr_str.len() + 32);
    for (idx, line) in hdr_str.lines().enumerate() {
        if idx == 0 {
            out.push_str(line);
            out.push_str("\r\n");
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let kl = k.trim().to_ascii_lowercase();
            if kl == "authorization" && v.trim().to_ascii_lowercase().starts_with("basic ") {
                continue;
            }
            if kl == "connection" && !is_websocket {
                continue;
            }
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    if !is_websocket {
        out.push_str("Connection: close\r\n");
    }
    out.push_str("\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

pub(crate) async fn run_cf_auth_proxy_listener(shared: SharedState) {
    let bind_addr = format!("127.0.0.1:{}", CF_LOCAL_AUTH_PORT);
    let listener = loop {
        match TcpListener::bind(&bind_addr).await {
            Ok(l) => break l,
            Err(_) => {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    };

    loop {
        let Ok((mut client, _peer)) = listener.accept().await else {
            continue;
        };
        let shared_conn = shared.clone();
        tokio::spawn(async move {
            let mut peek_buf = [0u8; 4096];
            let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_secs(5), client.read(&mut peek_buf)).await
            else {
                return;
            };
            if n == 0 {
                return;
            }
            let Some(host) = extract_host_or_sni(&peek_buf[..n]) else {
                return;
            };

            let route_match: Option<(String, Vec<String>, String)> = {
                let st = shared_conn.read().unwrap();
                let cfg = st.active_config();
                cfg.services.values().find_map(|svc| {
                    let cf_host = svc.cloudflare.as_ref()?;
                    if cf_host.eq_ignore_ascii_case(&host) {
                        let b = svc.backends.first()?;
                        let addr = format!("{}:{}", b.ip, b.port);
                        let mut rules = svc.auth.clone();
                        for r in &svc.cloudflare_auth {
                            if !rules.contains(r) {
                                rules.push(r.clone());
                            }
                        }
                        Some((addr, rules, b.endpoint()))
                    } else {
                        None
                    }
                })
            };

            let Some((upstream_addr, auth_rules, ep_key)) = route_match else {
                let _ = client
                    .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 10\r\n\r\nNot Found\n")
                    .await;
                return;
            };

            if !check_http_basic_auth(&peek_buf[..n], &auth_rules) {
                let resp = format!(
                    "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"nfty ({})\"\r\nContent-Type: text/plain\r\nContent-Length: 26\r\nConnection: close\r\n\r\n401 Authentication Needed\n",
                    host
                );
                let _ = client.write_all(resp.as_bytes()).await;
                return;
            }

            let sanitized_req = sanitize_authenticated_http_request(&peek_buf[..n]);
            if let Ok(Ok(mut upstream)) =
                tokio::time::timeout(Duration::from_secs(4), TcpStream::connect(&upstream_addr))
                    .await
            {
                if upstream.write_all(&sanitized_req).await.is_ok() {
                    if let Ok((up_b, down_b)) =
                        tokio::io::copy_bidirectional(&mut client, &mut upstream).await
                    {
                        if let Ok(mut st) = shared_conn.write() {
                            let rt = st.runtime.entry(ep_key).or_default();
                            rt.packets += 2;
                            rt.bytes += (sanitized_req.len() as u64) + up_b + down_b;
                        }
                    }
                }
            }
        });
    }
}

pub fn service_uses_local_cf_auth_proxy(
    svc: &crate::ast::Service,
    access_api_enabled: Option<bool>,
) -> bool {
    if !svc.auth.is_empty() {
        return true;
    }
    if svc.cloudflare_auth.is_empty() {
        return false;
    }
    let has_local_rule = svc
        .cloudflare_auth
        .iter()
        .any(|r| r.eq_ignore_ascii_case("nfty") || r.contains(':'));
    has_local_rule || access_api_enabled == Some(false)
}

pub fn collect_cloudflare_routes(config: &Config) -> Vec<(String, String, String)> {
    let cf_cfg = load_cloudflare_config();
    let mut routes = Vec::new();
    for svc in config.services.values() {
        let Some(cf_host) = &svc.cloudflare else {
            continue;
        };
        let upstream = if service_uses_local_cf_auth_proxy(svc, cf_cfg.access_api_enabled) {
            format!("http://127.0.0.1:{}", CF_LOCAL_AUTH_PORT)
        } else if let Some(b) = svc.backends.first() {
            let scheme = if b.port == 443 || b.port == 8443 {
                "https"
            } else if b.port == 22 {
                "ssh"
            } else {
                "http"
            };
            format!("{}://{}:{}", scheme, b.ip, b.port)
        } else if let Some(lip) = svc.listen_ip {
            format!("http://{}:{}", lip, svc.port)
        } else {
            format!("http://127.0.0.1:{}", svc.port)
        };
        routes.push((svc.key.clone(), cf_host.clone(), upstream));
    }
    routes
}

pub fn cloudflared_running_pid() -> Option<u32> {
    let pid = fs::read_to_string(CF_PID_FILE)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())?;
    let cmdline_path = format!("/proc/{}/cmdline", pid);
    if let Ok(cmdline) = fs::read_to_string(cmdline_path) {
        if cmdline.contains("cloudflared") {
            return Some(pid);
        }
    }
    None
}

pub fn stop_cloudflared_daemon() {
    if let Some(pid) = cloudflared_running_pid() {
        unsafe {
            libc::kill(pid as i32, libc::SIGTERM);
        }
    }
    let _ = fs::remove_file(CF_PID_FILE);
}

pub fn start_or_ensure_cloudflared_daemon(tunnel_token: &str) -> Result<u32> {
    if let Some(pid) = cloudflared_running_pid() {
        return Ok(pid);
    }
    let bin = if Path::new("/bin/cloudflared").exists() {
        "/bin/cloudflared"
    } else if Path::new("/usr/bin/cloudflared").exists() {
        "/usr/bin/cloudflared"
    } else {
        bail!("cloudflared binary not found in /bin/cloudflared");
    };

    // Ensure /etc/resolv.conf and /etc/hosts exist for Go's DNS resolver inside the unikernel/container
    if !Path::new("/etc/resolv.conf").exists() {
        let _ = fs::write(
            "/etc/resolv.conf",
            "nameserver 1.1.1.1\nnameserver 9.9.9.9\n",
        );
    }
    if !fs::read_to_string("/etc/hosts")
        .unwrap_or_default()
        .contains("localhost")
    {
        let mut h = fs::read_to_string("/etc/hosts").unwrap_or_default();
        if !h.is_empty() && !h.ends_with('\n') {
            h.push('\n');
        }
        h.push_str("127.0.0.1 localhost\n");
        let _ = fs::write("/etc/hosts", h);
    }

    let log_file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(CF_LOG_FILE)?;
    let log_err = log_file.try_clone()?;

    let child = Command::new(bin)
        .args([
            "tunnel",
            "--metrics",
            "127.0.0.1:0",
            "--edge-ip-version",
            "4",
            "--no-autoupdate",
            "--protocol",
            "http2",
            "run",
            "--token",
            tunnel_token.trim(),
        ])
        .stdout(std::process::Stdio::from(log_file))
        .stderr(std::process::Stdio::from(log_err))
        .spawn()
        .with_context(|| "Failed to spawn cloudflared daemon")?;

    let pid = child.id();
    let _ = fs::write(CF_PID_FILE, format!("{}\n", pid));
    Ok(pid)
}

/// Reconciles Cloudflare Tunnel, ingress rules, DNS CNAME records, and the local `cloudflared` daemon.
pub fn reconcile_cloudflare_tunnel(config: &Config) -> Vec<String> {
    let mut logs = Vec::new();
    let routes = collect_cloudflare_routes(config);
    let mut cf_cfg = load_cloudflare_config();

    if routes.is_empty() && cf_cfg.managed_dns_records.is_empty() {
        if cloudflared_running_pid().is_some() {
            stop_cloudflared_daemon();
            logs.push(
                "Cloudflare: stopped cloudflared daemon (no cloudflare-dns services active)"
                    .to_string(),
            );
        }
        return logs;
    }

    if let Some(api_token) = cf_cfg.api_token.clone() {
        match reconcile_with_cf_api(config, &api_token, &routes, &mut cf_cfg) {
            Ok(mut api_logs) => {
                cf_cfg.last_status = Some("OK (synced with Cloudflare API)".to_string());
                let _ = save_cloudflare_config(&cf_cfg);
                logs.append(&mut api_logs);
            }
            Err(e) => {
                let err_msg = format!("ERROR: {}", e);
                cf_cfg.last_status = Some(err_msg);
                let _ = save_cloudflare_config(&cf_cfg);
                logs.push(format!("Cloudflare API sync failed: {}", e));
            }
        }
    } else if !routes.is_empty() && cf_cfg.tunnel_token.is_none() {
        logs.push(
            "Cloudflare: services have 'cloudflare-dns' configured, but no API token is set yet (run 'cf token <API_TOKEN>')".to_string(),
        );
        return logs;
    }

    if routes.is_empty() {
        stop_cloudflared_daemon();
    } else if let Some(tok) = &cf_cfg.tunnel_token {
        match start_or_ensure_cloudflared_daemon(tok) {
            Ok(pid) => {
                logs.push(format!(
                    "Cloudflare: cloudflared edge connector active (PID {}, {} route(s))",
                    pid,
                    routes.len()
                ));
            }
            Err(e) => {
                logs.push(format!("Cloudflare: failed to start cloudflared: {}", e));
            }
        }
    }

    logs
}

fn reconcile_with_cf_api(
    config: &Config,
    api_token: &str,
    _routes: &[(String, String, String)],
    cf_cfg: &mut CloudflareConfig,
) -> Result<Vec<String>> {
    let mut logs = Vec::new();
    let (discovered_acct, zones) = discover_cf_account_and_zones(api_token)?;
    if cf_cfg.account_id.is_none() {
        cf_cfg.account_id = discovered_acct;
    }
    let account_id = cf_cfg.account_id.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "Could not auto-discover Cloudflare Account ID from token; run 'cf token <TOKEN> <ACCOUNT_ID>'"
        )
    })?;

    // 0. Reconcile Cloudflare Zero-Trust Access Apps & Policies for services with email-based `cloudflare-auth`
    let mut active_access_hosts = BTreeSet::new();
    for svc in config.services.values() {
        let Some(hostname) = &svc.cloudflare else {
            continue;
        };
        let email_rules: Vec<&String> = svc
            .cloudflare_auth
            .iter()
            .filter(|r| r.contains('@'))
            .collect();
        if email_rules.is_empty() {
            continue;
        }
        active_access_hosts.insert(hostname.clone());

        let mut include_objs = Vec::new();
        for rule in &email_rules {
            if let Some(dom) = rule.strip_prefix("*@").or_else(|| rule.strip_prefix('@')) {
                include_objs.push(serde_json::json!({
                    "email_domain": { "domain": dom }
                }));
            } else {
                include_objs.push(serde_json::json!({
                    "email": { "email": *rule }
                }));
            }
        }

        let apps_path = format!("accounts/{}/access/apps", account_id);
        match cf_api_request("GET", &apps_path, api_token, None) {
            Ok(apps_resp) => {
                cf_cfg.access_api_enabled = Some(true);
                let existing_app_id = apps_resp
                    .get("result")
                    .and_then(|v| v.as_array())
                    .and_then(|arr| {
                        arr.iter().find(|a| {
                            a.get("domain")
                                .and_then(|d| d.as_str())
                                .map(|d| d.eq_ignore_ascii_case(hostname))
                                .unwrap_or(false)
                        })
                    })
                    .and_then(|a| a.get("id"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                // Discover or create a non-Cloudflare-account IdP (e.g. `onetimepin` or `google`) so visitors aren't asked for a Cloudflare account
                let idps_path = format!("accounts/{}/access/identity_providers", account_id);
                let mut allowed_idps: Vec<String> =
                    cf_api_request("GET", &idps_path, api_token, None)
                        .ok()
                        .and_then(|resp| {
                            resp.get("result")
                                .and_then(|v| v.as_array())
                                .map(|arr| {
                                    arr.iter()
                                        .filter(|item| {
                                            item.get("type").and_then(|t| t.as_str())
                                                != Some("cloudflare")
                                        })
                                        .filter_map(|item| {
                                            item.get("id")
                                                .and_then(|v| v.as_str())
                                                .map(|s| s.to_string())
                                        })
                                        .collect::<Vec<String>>()
                                })
                        })
                        .unwrap_or_default();
                if allowed_idps.is_empty() {
                    let otp_body = serde_json::json!({
                        "name": "One-time PIN",
                        "type": "onetimepin",
                        "config": {}
                    });
                    if let Ok(created_idp) =
                        cf_api_request("POST", &idps_path, api_token, Some(otp_body))
                    {
                        if let Some(idp_id) = created_idp
                            .get("result")
                            .and_then(|r| r.get("id"))
                            .and_then(|v| v.as_str())
                        {
                            allowed_idps.push(idp_id.to_string());
                        }
                    }
                }

                let app_body = if allowed_idps.is_empty() {
                    serde_json::json!({
                        "name": format!("nfty: {}", hostname),
                        "domain": hostname,
                        "type": "self_hosted",
                        "session_duration": "24h"
                    })
                } else {
                    serde_json::json!({
                        "name": format!("nfty: {}", hostname),
                        "domain": hostname,
                        "type": "self_hosted",
                        "session_duration": "24h",
                        "allowed_idps": allowed_idps,
                        "auto_redirect_to_identity": allowed_idps.len() == 1
                    })
                };

                let app_id = if let Some(aid) = existing_app_id {
                    let put_app = format!("accounts/{}/access/apps/{}", account_id, aid);
                    let _ = cf_api_request("PUT", &put_app, api_token, Some(app_body));
                    aid
                } else {
                    let created_app =
                        cf_api_request("POST", &apps_path, api_token, Some(app_body))?;
                    created_app
                        .get("result")
                        .and_then(|r| r.get("id"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string()
                };

                if !app_id.is_empty() {
                    cf_cfg
                        .managed_access_apps
                        .insert(hostname.clone(), app_id.clone());
                    let pols_path =
                        format!("accounts/{}/access/apps/{}/policies", account_id, app_id);
                    let existing_pol_id = cf_api_request("GET", &pols_path, api_token, None)
                        .ok()
                        .and_then(|p| {
                            p.get("result")
                                .and_then(|v| v.as_array())
                                .and_then(|arr| arr.first())
                                .and_then(|item| item.get("id"))
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string())
                        });
                    let pol_body = serde_json::json!({
                        "name": "nfty allow policy",
                        "decision": "allow",
                        "include": include_objs,
                        "precedence": 1
                    });
                    if let Some(pid) = existing_pol_id {
                        let put_pol = format!("{}/{}", pols_path, pid);
                        let _ = cf_api_request("PUT", &put_pol, api_token, Some(pol_body));
                    } else {
                        let _ = cf_api_request("POST", &pols_path, api_token, Some(pol_body));
                    }
                    logs.push(format!(
                        "Cloudflare Access: synced Zero-Trust policy for {} ({:?})",
                        hostname, email_rules
                    ));
                }
            }
            Err(e) => {
                cf_cfg.access_api_enabled = Some(false);
                let err_s = e.to_string();
                if err_s.contains("not_enabled") {
                    logs.push(format!(
                        "Cloudflare Auth: Access Zero-Trust is not enabled in Cloudflare dashboard yet — enabled local nfty Basic-Auth gate on '{}' (login with your 'nfty' password)",
                        hostname
                    ));
                } else {
                    logs.push(format!(
                        "Cloudflare Auth: Access API unavailable ({}) — enabled local nfty Basic-Auth gate on '{}'",
                        err_s, hostname
                    ));
                }
            }
        }
    }

    // Clean up removed Cloudflare Access Apps
    if cf_cfg.access_api_enabled == Some(true) {
        let stale_apps: Vec<String> = cf_cfg
            .managed_access_apps
            .keys()
            .filter(|h| !active_access_hosts.contains(*h))
            .cloned()
            .collect();
        for stale in stale_apps {
            if let Some(app_id) = cf_cfg.managed_access_apps.remove(&stale) {
                let del_path = format!("accounts/{}/access/apps/{}", account_id, app_id);
                let _ = cf_api_request("DELETE", &del_path, api_token, None);
                logs.push(format!(
                    "Cloudflare Access: removed Access Application for '{}'",
                    stale
                ));
            }
        }
    }

    // Recompute routes in case `access_api_enabled` changed to `Some(false)` (switching to local Basic-Auth proxy)
    let effective_routes: Vec<(String, String, String)> = config
        .services
        .values()
        .filter_map(|svc| {
            let cf_host = svc.cloudflare.as_ref()?;
            let upstream = if service_uses_local_cf_auth_proxy(svc, cf_cfg.access_api_enabled) {
                format!("http://127.0.0.1:{}", CF_LOCAL_AUTH_PORT)
            } else if let Some(b) = svc.backends.first() {
                let scheme = if b.port == 443 || b.port == 8443 {
                    "https"
                } else if b.port == 22 {
                    "ssh"
                } else {
                    "http"
                };
                format!("{}://{}:{}", scheme, b.ip, b.port)
            } else if let Some(lip) = svc.listen_ip {
                format!("http://{}:{}", lip, svc.port)
            } else {
                format!("http://127.0.0.1:{}", svc.port)
            };
            Some((svc.key.clone(), cf_host.clone(), upstream))
        })
        .collect();
    let routes = &effective_routes[..];

    // 1. Ensure Tunnel exists if we have routes
    if !routes.is_empty() {
        if cf_cfg.tunnel_id.is_none() {
            let list_path = format!(
                "accounts/{}/cfd_tunnel?name={}&is_deleted=false",
                account_id, cf_cfg.tunnel_name
            );
            let list_resp = cf_api_request("GET", &list_path, api_token, None)?;
            if let Some(existing) = list_resp
                .get("result")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
            {
                if let Some(tid) = existing.get("id").and_then(|v| v.as_str()) {
                    cf_cfg.tunnel_id = Some(tid.to_string());
                }
            }
        }

        if cf_cfg.tunnel_id.is_none() {
            let create_path = format!("accounts/{}/cfd_tunnel", account_id);
            let body = serde_json::json!({
                "name": cf_cfg.tunnel_name,
                "config_src": "cloudflare"
            });
            let create_resp = cf_api_request("POST", &create_path, api_token, Some(body))?;
            let tid = create_resp
                .get("result")
                .and_then(|r| r.get("id"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("Cloudflare tunnel creation returned no id"))?
                .to_string();
            if let Some(tok) = create_resp
                .get("result")
                .and_then(|r| r.get("token"))
                .and_then(|v| v.as_str())
            {
                cf_cfg.tunnel_token = Some(tok.to_string());
            }
            logs.push(format!(
                "Cloudflare: created tunnel '{}' ({})",
                cf_cfg.tunnel_name, tid
            ));
            cf_cfg.tunnel_id = Some(tid);
        }

        let tunnel_id = cf_cfg.tunnel_id.clone().unwrap();

        // Fetch tunnel connector token if not cached yet
        if cf_cfg.tunnel_token.is_none() {
            let tok_path = format!("accounts/{}/cfd_tunnel/{}/token", account_id, tunnel_id);
            let tok_resp = cf_api_request("GET", &tok_path, api_token, None)?;
            if let Some(tok) = tok_resp.get("result").and_then(|v| v.as_str()) {
                cf_cfg.tunnel_token = Some(tok.to_string());
            }
        }

        // 2. Push remotely-managed ingress rules
        let mut ingress = Vec::new();
        for (_svc_key, hostname, upstream) in routes {
            ingress.push(serde_json::json!({
                "hostname": hostname,
                "service": upstream,
                "originRequest": {
                    "noTLSVerify": true
                }
            }));
        }
        ingress.push(serde_json::json!({
            "service": "http_status:404"
        }));

        let cfg_path = format!(
            "accounts/{}/cfd_tunnel/{}/configurations",
            account_id, tunnel_id
        );
        let cfg_body = serde_json::json!({
            "config": {
                "ingress": ingress
            }
        });
        cf_api_request("PUT", &cfg_path, api_token, Some(cfg_body))?;
        logs.push(format!(
            "Cloudflare: synced {} ingress route(s) to tunnel {}",
            routes.len(),
            tunnel_id
        ));

        // 3. Upsert proxied DNS CNAME records for each route
        let cname_target = format!("{}.cfargotunnel.com", tunnel_id);
        for (_svc_key, hostname, upstream) in routes {
            let matched_zone = zones
                .iter()
                .filter(|(zname, _)| {
                    hostname == *zname || hostname.ends_with(&format!(".{}", zname))
                })
                .max_by_key(|(zname, _)| zname.len());

            let Some((_zname, zone_id)) = matched_zone else {
                logs.push(format!(
                    "Cloudflare Warning: no matching zone found in account for '{}' (available zones: {:?})",
                    hostname,
                    zones.keys().collect::<Vec<_>>()
                ));
                continue;
            };

            let list_dns_path = format!("zones/{}/dns_records?name={}", zone_id, hostname);
            let dns_list = cf_api_request("GET", &list_dns_path, api_token, None)?;
            let existing_rec = dns_list
                .get("result")
                .and_then(|v| v.as_array())
                .and_then(|a| a.first());

            let rec_body = serde_json::json!({
                "type": "CNAME",
                "name": hostname,
                "content": cname_target,
                "proxied": true,
                "ttl": 1,
                "comment": "Managed by nfty appliance"
            });

            if let Some(rec) = existing_rec {
                let rec_id = rec.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let cur_content = rec.get("content").and_then(|v| v.as_str()).unwrap_or("");
                let cur_type = rec.get("type").and_then(|v| v.as_str()).unwrap_or("");
                if cur_type != "CNAME" || !cur_content.eq_ignore_ascii_case(&cname_target) {
                    let put_path = format!("zones/{}/dns_records/{}", zone_id, rec_id);
                    cf_api_request("PUT", &put_path, api_token, Some(rec_body))?;
                    logs.push(format!(
                        "Cloudflare DNS: updated CNAME {} -> {} ({})",
                        hostname, cname_target, upstream
                    ));
                } else {
                    logs.push(format!(
                        "Cloudflare DNS: verified CNAME {} -> {} ({})",
                        hostname, cname_target, upstream
                    ));
                }
                cf_cfg
                    .managed_dns_records
                    .insert(hostname.clone(), (zone_id.clone(), rec_id.to_string()));
            } else {
                let post_path = format!("zones/{}/dns_records", zone_id);
                let created = cf_api_request("POST", &post_path, api_token, Some(rec_body))?;
                if let Some(rec_id) = created
                    .get("result")
                    .and_then(|r| r.get("id"))
                    .and_then(|v| v.as_str())
                {
                    cf_cfg
                        .managed_dns_records
                        .insert(hostname.clone(), (zone_id.clone(), rec_id.to_string()));
                }
                logs.push(format!(
                    "Cloudflare DNS: created proxied CNAME {} -> {} ({})",
                    hostname, cname_target, upstream
                ));
            }
        }
    }

    // 4. Clean up any managed DNS records that were removed from Nftyfile
    let active_hosts: BTreeSet<String> = routes.iter().map(|(_, h, _)| h.clone()).collect();
    let stale_hosts: Vec<String> = cf_cfg
        .managed_dns_records
        .keys()
        .filter(|h| !active_hosts.contains(*h))
        .cloned()
        .collect();
    for stale in stale_hosts {
        if let Some((zone_id, rec_id)) = cf_cfg.managed_dns_records.remove(&stale) {
            let del_path = format!("zones/{}/dns_records/{}", zone_id, rec_id);
            let _ = cf_api_request("DELETE", &del_path, api_token, None);
            logs.push(format!(
                "Cloudflare DNS: removed stale CNAME record '{}'",
                stale
            ));
        }
    }

    Ok(logs)
}

pub fn handle_cf_cli_command(args: &[&str], shared: &SharedState) -> Result<()> {
    let sub = args.first().map(|s| s.to_ascii_lowercase());
    match sub.as_deref() {
        None | Some("status") | Some("list") | Some("show") => {
            let cf_cfg = load_cloudflare_config();
            let st = shared.read().unwrap();
            let cfg = st.active_config();
            let routes = collect_cloudflare_routes(cfg);
            let pid_opt = cloudflared_running_pid();

            println!("{}", "Cloudflare Tunnel & Automated DNS Status:".bold().cyan());
            let tok_display = match &cf_cfg.api_token {
                Some(t) if t.len() > 8 => format!(
                    "{}...{} {}",
                    &t[..4],
                    &t[t.len() - 4..],
                    "(configured)".green()
                ),
                Some(_) => "(configured)".green().to_string(),
                None => "(not set — run 'cf token <API_TOKEN>')".yellow().to_string(),
            };
            println!("  API Token:      {}", tok_display);
            println!(
                "  Account ID:     {}",
                cf_cfg.account_id.as_deref().unwrap_or("-")
            );
            println!(
                "  Tunnel:         {} ({})",
                cf_cfg.tunnel_name.bold(),
                cf_cfg.tunnel_id.as_deref().unwrap_or("not created yet")
            );
            let daemon_str = match pid_opt {
                Some(pid) => format!("RUNNING (PID {})", pid).green().bold().to_string(),
                None => "STOPPED".dimmed().to_string(),
            };
            println!("  Connector:      {}", daemon_str);
            if let Some(status) = &cf_cfg.last_status {
                println!("  Last Sync:      {}", status);
            }

            println!(
                "\n  {:<22} {:<30} {:<26} {}",
                "SERVICE".bold().underline(),
                "PUBLIC CLOUDFLARE HOSTNAME".bold().underline(),
                "UPSTREAM TARGET".bold().underline(),
                "AUTH POLICY".bold().underline()
            );
            if routes.is_empty() {
                println!(
                    "  {}",
                    "(No services have 'cloudflare-dns <fqdn>' configured yet)".dimmed()
                );
            } else {
                for (svc_key, fqdn, upstream) in routes {
                    let auth_str = cfg
                        .services
                        .get(&svc_key)
                        .map(|s| {
                            let mut policies = Vec::new();
                            for r in &s.auth {
                                let masked = r.split(':').next().unwrap_or(r);
                                policies.push(format!("basic:{}", masked));
                            }
                            for r in &s.cloudflare_auth {
                                policies.push(r.clone());
                            }
                            if policies.is_empty() {
                                "open (none)".dimmed().to_string()
                            } else {
                                format!("🔒 {}", policies.join(", "))
                                    .yellow()
                                    .bold()
                                    .to_string()
                            }
                        })
                        .unwrap_or_else(|| "-".to_string());
                    println!(
                        "  {:<22} {:<30} {:<26} {}",
                        svc_key.yellow().bold(),
                        format!("https://{}", fqdn).green().bold(),
                        upstream,
                        auth_str
                    );
                }
            }
            Ok(())
        }
        Some("token") | Some("key") | Some("login") => {
            if args.len() < 2 {
                bail!("Usage: cf token <CLOUDFLARE_API_TOKEN> [ACCOUNT_ID]");
            }
            let api_token = args[1].trim().to_string();
            let explicit_acct = args.get(2).map(|s| s.trim().to_string());
            println!("Verifying Cloudflare API token...");
            let (disc_acct, zones) = discover_cf_account_and_zones(&api_token)?;
            let mut cf_cfg = load_cloudflare_config();
            cf_cfg.api_token = Some(api_token);
            if let Some(a) = explicit_acct.or(disc_acct) {
                cf_cfg.account_id = Some(a);
            }
            save_cloudflare_config(&cf_cfg)?;
            println!(
                "  {} Saved Cloudflare API token in {} (Account: {}, Zones discovered: {:?})",
                "✔".green().bold(),
                CF_CONFIG_PATH.bold(),
                cf_cfg.account_id.as_deref().unwrap_or("pending"),
                zones.keys().collect::<Vec<_>>()
            );
            let cfg_clone = shared.read().unwrap().active_config().clone();
            for log in reconcile_cloudflare_tunnel(&cfg_clone) {
                println!("  {} {}", "→".cyan(), log);
            }
            Ok(())
        }
        Some("tunnel-token") => {
            if args.len() < 2 {
                bail!("Usage: cf tunnel-token <EYJH...>");
            }
            let mut cf_cfg = load_cloudflare_config();
            cf_cfg.tunnel_token = Some(args[1].trim().to_string());
            save_cloudflare_config(&cf_cfg)?;
            let pid = start_or_ensure_cloudflared_daemon(args[1].trim())?;
            println!(
                "  {} Saved Cloudflare tunnel connector token & started cloudflared (PID {})",
                "✔".green().bold(),
                pid
            );
            Ok(())
        }
        Some("sync") | Some("apply") => {
            let cfg_clone = shared.read().unwrap().active_config().clone();
            let logs = reconcile_cloudflare_tunnel(&cfg_clone);
            if logs.is_empty() {
                println!("  (No Cloudflare Tunnel routes configured)");
            } else {
                for l in logs {
                    println!("  {} {}", "→".cyan(), l);
                }
            }
            Ok(())
        }
        Some("logs") | Some("log") => {
            let raw = fs::read_to_string(CF_LOG_FILE).unwrap_or_default();
            if raw.is_empty() {
                println!("  (No cloudflared logs in {} yet)", CF_LOG_FILE);
            } else {
                let lines: Vec<&str> = raw.lines().collect();
                let start = lines.len().saturating_sub(25);
                for l in &lines[start..] {
                    println!("  {}", l);
                }
            }
            Ok(())
        }
        Some("stop") | Some("clear") | Some("logout") => {
            stop_cloudflared_daemon();
            if sub.as_deref() != Some("stop") {
                let _ = fs::remove_file(CF_CONFIG_PATH);
                println!(
                    "  {} Stopped cloudflared and cleared {}",
                    "✔".green().bold(),
                    CF_CONFIG_PATH
                );
            } else {
                println!("  {} Stopped cloudflared daemon", "✔".green().bold());
            }
            Ok(())
        }
        Some(other) => bail!(
            "Unknown cf subcommand '{}'. Valid commands: 'cf status', 'cf token <API_TOKEN>', 'cf sync', 'cf logs', 'cf stop'",
            other
        ),
    }
}
