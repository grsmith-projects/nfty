use crate::ast::{ApiKeyScope, Service};
use crate::compiler::{
    apply_vip_commands, compile_nft_ruleset, generate_vip_commands, reload_kernel_from_state,
    validate_config,
};
use crate::health::{refresh_allowlist_hosts, run_all_probes_once};
use crate::parser::{parse_nftyfile, validate_allow_entry};
use crate::repl::{handle_line, ShellLevel};
use crate::state::SharedState;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, Deserialize)]
pub struct AllowListRequest {
    /// Optional service key (e.g. "9000" or "169.254.1.240:443"). If omitted, applies to global allow-list.
    pub service: Option<String>,
    /// List of hostnames, wildcard hostnames ("*.office.lan"), IP wildcards ("169.254.1.*"), or CIDRs
    pub hosts: Vec<String>,
    /// Whether to immediately apply changes to running config & kernel nftables (defaults to true)
    #[serde(default = "default_true")]
    pub apply: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct HostRegistrationRequest {
    pub host: String,
    pub ips: Vec<Ipv4Addr>,
}

#[derive(Debug, Deserialize)]
pub struct CliExecRequest {
    pub command: String,
}

#[derive(Debug, Deserialize)]
pub struct BackendToggleRequest {
    pub backend: String,
}

#[derive(Debug, Deserialize)]
pub struct WgUploadRequest {
    pub name: String,
    pub config: String,
}

#[derive(Debug, Deserialize)]
pub struct CloudflareConfigRequest {
    pub api_token: Option<String>,
    pub account_id: Option<String>,
    pub tunnel_name: Option<String>,
    pub tunnel_token: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AuthLoginRequest {
    pub username: Option<String>,
    pub password: Option<String>,
    pub key: Option<String>,
}

fn current_session_token() -> String {
    let auth = crate::ssh::load_auth_config();
    let short = auth.password_sha256.chars().take(32).collect::<String>();
    format!("nfty_session_{}", short)
}

fn verify_appliance_credential(candidate: &str) -> bool {
    let trimmed = candidate.trim();
    if trimmed.is_empty() {
        return false;
    }
    if trimmed == current_session_token() {
        return true;
    }
    if let Some((user, pass)) = trimmed.split_once(':') {
        if crate::ssh::verify_login(user.trim(), pass) {
            return true;
        }
    }
    let auth = crate::ssh::load_auth_config();
    crate::ssh::verify_login(&auth.username, trimmed)
}

#[derive(Debug, Serialize)]
pub struct AllowStatusResponse {
    pub global_allow: Vec<String>,
    pub service_allow: BTreeMap<String, Vec<String>>,
    pub resolved_hosts: BTreeMap<String, Vec<Ipv4Addr>>,
    pub expanded_service_sets: BTreeMap<String, Vec<String>>,
}

pub fn spawn_api_server(shared: SharedState, bind_addr: String) {
    let shared_main = shared.clone();
    tokio::spawn(async move {
        let listener = match TcpListener::bind(&bind_addr).await {
            Ok(l) => l,
            Err(_) => return,
        };
        loop {
            if let Ok((stream, _)) = listener.accept().await {
                let st = shared_main.clone();
                tokio::spawn(async move {
                    let _ = handle_http_connection(stream, st).await;
                });
            }
        }
    });

    // Dynamically bind any custom `api:<port>` ports configured on VIPs or Gateways
    tokio::spawn(async move {
        let mut bound_ports: HashSet<u16> = HashSet::new();
        bound_ports.insert(9090);
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let desired_ports = {
                let Ok(st) = shared.read() else { continue };
                st.active_config().api_ports()
            };
            for port in desired_ports {
                if bound_ports.contains(&port) {
                    continue;
                }
                let addr = format!("0.0.0.0:{}", port);
                if let Ok(listener) = TcpListener::bind(&addr).await {
                    bound_ports.insert(port);
                    let st_clone = shared.clone();
                    tokio::spawn(async move {
                        loop {
                            if let Ok((stream, _)) = listener.accept().await {
                                let s = st_clone.clone();
                                tokio::spawn(async move {
                                    let _ = handle_http_connection(stream, s).await;
                                });
                            }
                        }
                    });
                }
            }
        }
    });
}

fn extract_api_key_from_request(header_part: &str, query: &str) -> (Option<String>, bool) {
    let mut is_internal_ipc = false;
    let mut candidate_key: Option<String> = None;

    for line in header_part.lines().skip(1) {
        let Some((name, val)) = line.split_once(':') else {
            continue;
        };
        let name_lower = name.trim().to_ascii_lowercase();
        let val_trimmed = val.trim();
        match name_lower.as_str() {
            "x-nfty-internal-ipc" if val_trimmed == "1" => {
                is_internal_ipc = true;
            }
            "x-api-key" | "x-nfty-key" => {
                if !val_trimmed.is_empty() {
                    candidate_key = Some(val_trimmed.to_string());
                }
            }
            "authorization" => {
                if let Some(rest) = val_trimmed
                    .strip_prefix("Bearer ")
                    .or_else(|| val_trimmed.strip_prefix("bearer "))
                    .or_else(|| val_trimmed.strip_prefix("Token "))
                    .or_else(|| val_trimmed.strip_prefix("token "))
                {
                    let tok = rest.trim();
                    if !tok.is_empty() {
                        candidate_key = Some(tok.to_string());
                    }
                } else if let Some(b64) = val_trimmed
                    .strip_prefix("Basic ")
                    .or_else(|| val_trimmed.strip_prefix("basic "))
                {
                    if let Some(decoded) = decode_basic_auth_token(b64.trim()) {
                        candidate_key = Some(decoded);
                    }
                } else if !val_trimmed.is_empty() {
                    candidate_key = Some(val_trimmed.to_string());
                }
            }
            _ => {}
        }
    }

    if candidate_key.is_none() && !query.is_empty() {
        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if matches!(k, "key" | "api_key" | "token") && !v.trim().is_empty() {
                    candidate_key = Some(v.trim().to_string());
                    break;
                }
            }
        }
    }

    (candidate_key, is_internal_ipc)
}

fn decode_basic_auth_token(b64: &str) -> Option<String> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut vals = Vec::with_capacity(b64.len());
    for b in b64.bytes() {
        if b == b'=' {
            break;
        }
        let pos = TABLE.iter().position(|&c| c == b)?;
        vals.push(pos as u8);
    }
    let mut out = Vec::new();
    for chunk in vals.chunks(4) {
        if chunk.len() >= 2 {
            out.push((chunk[0] << 2) | (chunk[1] >> 4));
        }
        if chunk.len() >= 3 {
            out.push((chunk[1] << 4) | (chunk[2] >> 2));
        }
        if chunk.len() >= 4 {
            out.push((chunk[2] << 6) | chunk[3]);
        }
    }
    let s = String::from_utf8(out).ok()?;
    if let Some((_user, pass)) = s.split_once(':') {
        if !pass.is_empty() {
            return Some(pass.to_string());
        }
    }
    if !s.is_empty() {
        Some(s)
    } else {
        None
    }
}

pub fn authenticate_api_request(
    shared: &SharedState,
    peer_is_loopback: bool,
    is_internal_ipc: bool,
    candidate_key: Option<&str>,
) -> std::result::Result<ApiKeyScope, (u16, String)> {
    authenticate_api_request_with_context(
        shared,
        peer_is_loopback,
        is_internal_ipc,
        candidate_key,
        None,
        None,
    )
}

pub fn authenticate_api_request_with_context(
    shared: &SharedState,
    peer_is_loopback: bool,
    is_internal_ipc: bool,
    candidate_key: Option<&str>,
    peer_ip: Option<Ipv4Addr>,
    local_port: Option<u16>,
) -> std::result::Result<ApiKeyScope, (u16, String)> {
    if peer_is_loopback && is_internal_ipc {
        return Ok(ApiKeyScope::ReadWrite);
    }

    let st = shared.read().unwrap();
    let cfg = st.active_config();
    if let Some(ip) = peer_ip {
        if !cfg.is_peer_ip_allowed_for_port(ip, local_port, &st) {
            return Err((
                403,
                format!("Forbidden: client IP {} is not in the configured allow-list", ip),
            ));
        }
    }

    if let Some(key_str) = candidate_key {
        if let Some(scope) = cfg.verify_api_key(key_str) {
            return Ok(scope);
        }
        if verify_appliance_credential(key_str) {
            return Ok(ApiKeyScope::ReadWrite);
        }
        return Err((401, "Invalid API key or credentials".to_string()));
    }

    if let Some(ip) = peer_ip {
        if cfg.is_unkeyed_web_or_api_allowed(ip, local_port, &st) {
            return Ok(ApiKeyScope::ReadWrite);
        }
    }

    let any_keys = cfg.has_any_api_keys();
    if any_keys || !peer_is_loopback {
        return Err((
            401,
            "Authentication required (configure an allow-list on 'web:8000', or pass an API key / appliance login)".to_string(),
        ));
    }

    Ok(ApiKeyScope::ReadWrite)
}

async fn read_full_http_request(stream: &mut TcpStream) -> Result<Option<Vec<u8>>> {
    let mut buf = Vec::with_capacity(8192);
    let mut chunk = [0u8; 8192];
    let mut header_end: Option<usize> = None;
    let mut content_length: usize = 0;

    loop {
        let read_res = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut chunk)).await;
        let n = match read_res {
            Ok(Ok(n)) => n,
            _ => break,
        };
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 4 * 1024 * 1024 {
            anyhow::bail!("HTTP request payload exceeds 4MB limit");
        }

        if header_end.is_none() {
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let end = pos + 4;
                header_end = Some(end);
                let hdr_str = String::from_utf8_lossy(&buf[..pos]);
                for line in hdr_str.lines().skip(1) {
                    if let Some((k, v)) = line.split_once(':') {
                        if k.trim().eq_ignore_ascii_case("content-length") {
                            content_length = v.trim().parse::<usize>().unwrap_or(0);
                        }
                    }
                }
            }
        }

        if let Some(end) = header_end {
            if buf.len() >= end + content_length {
                break;
            }
        }
    }

    if buf.is_empty() {
        return Ok(None);
    }
    Ok(Some(buf))
}

async fn handle_http_connection(mut stream: TcpStream, shared: SharedState) -> Result<()> {
    let peer_addr = stream.peer_addr().ok();
    let peer_is_loopback = peer_addr.map(|a| a.ip().is_loopback()).unwrap_or(false);
    let peer_ip = peer_addr.and_then(|a| match a.ip() {
        std::net::IpAddr::V4(v4) => Some(v4),
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped(),
    });
    let local_port = stream.local_addr().ok().map(|a| a.port());

    let Some(buf) = read_full_http_request(&mut stream).await? else {
        return Ok(());
    };
    let raw = String::from_utf8_lossy(&buf);
    let (header_part, body_part) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
    let request_line = header_part.lines().next().unwrap_or("");
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        send_json(&mut stream, 400, &json!({"error": "Malformed HTTP request"})).await?;
        return Ok(());
    }
    let method = parts[0].to_ascii_uppercase();
    let full_path = parts[1];
    let (path, query) = full_path.split_once('?').unwrap_or((full_path, ""));

    if method == "OPTIONS" {
        let resp = "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\nAccess-Control-Allow-Headers: Authorization, X-API-Key, X-Nfty-Key, Content-Type\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    if let Some(ip) = peer_ip {
        let allowed = {
            let st = shared.read().unwrap();
            st.active_config()
                .is_peer_ip_allowed_for_port(ip, local_port, &st)
        };
        if !allowed {
            send_json(
                &mut stream,
                403,
                &json!({"ok": false, "error": format!("Forbidden: client IP {} is not in the configured allow-list", ip)}),
            )
            .await?;
            return Ok(());
        }
    }

    if method == "GET" && matches!(path, "/" | "/ui" | "/dashboard" | "/index.html") {
        send_html(&mut stream, 200, WEB_CONSOLE_HTML).await?;
        return Ok(());
    }

    if method == "POST" && path == "/api/v1/auth/login" {
        let req: AuthLoginRequest = match serde_json::from_str(body_part.trim()) {
            Ok(r) => r,
            Err(e) => {
                send_json(&mut stream, 400, &json!({"ok": false, "error": e.to_string()})).await?;
                return Ok(());
            }
        };
        if let Some(k) = req.key.as_deref() {
            let trimmed = k.trim();
            if !trimmed.is_empty() {
                let scope_opt = {
                    let st = shared.read().unwrap();
                    st.active_config().verify_api_key(trimmed)
                };
                if let Some(scope) = scope_opt {
                    send_json(
                        &mut stream,
                        200,
                        &json!({
                            "ok": true,
                            "token": trimmed,
                            "scope": scope.as_str(),
                            "mode": "api_key",
                        }),
                    )
                    .await?;
                    return Ok(());
                }
                if verify_appliance_credential(trimmed) {
                    send_json(
                        &mut stream,
                        200,
                        &json!({
                            "ok": true,
                            "token": current_session_token(),
                            "scope": "rw",
                            "mode": "appliance_login",
                        }),
                    )
                    .await?;
                    return Ok(());
                }
                send_json(
                    &mut stream,
                    401,
                    &json!({"ok": false, "error": "Invalid API key"}),
                )
                .await?;
                return Ok(());
            }
        }
        let user = req.username.as_deref().unwrap_or("nfty").trim();
        let pass = req.password.as_deref().unwrap_or("");
        if crate::ssh::verify_login(user, pass) {
            send_json(
                &mut stream,
                200,
                &json!({
                    "ok": true,
                    "token": current_session_token(),
                    "scope": "rw",
                    "username": user,
                    "mode": "appliance_login",
                }),
            )
            .await?;
        } else {
            send_json(
                &mut stream,
                401,
                &json!({"ok": false, "error": "Invalid username or password"}),
            )
            .await?;
        }
        return Ok(());
    }

    let (candidate_key, is_internal_ipc) = extract_api_key_from_request(header_part, query);
    let scope = match authenticate_api_request_with_context(
        &shared,
        peer_is_loopback,
        is_internal_ipc,
        candidate_key.as_deref(),
        peer_ip,
        local_port,
    ) {
        Ok(s) => s,
        Err((code, msg)) => {
            send_json(&mut stream, code, &json!({"ok": false, "error": msg})).await?;
            return Ok(());
        }
    };

    if method == "GET" && path == "/api/v1/auth/whoami" {
        let auth_mode = if candidate_key.is_some() {
            "token"
        } else {
            "allowlist"
        };
        send_json(
            &mut stream,
            200,
            &json!({
                "ok": true,
                "authenticated": true,
                "scope": scope.as_str(),
                "mode": auth_mode,
                "peer_ip": peer_ip.map(|ip| ip.to_string()),
                "local_port": local_port,
            }),
        )
        .await?;
        return Ok(());
    }

    let (status, resp_val) =
        route_api_request_scoped(&method, path, body_part.trim(), &shared, scope).await;
    if matches!(method.as_str(), "POST" | "PUT" | "DELETE") && status == 200 {
        crate::unikernel::persist_to_storage(&shared);
    }
    send_json(&mut stream, status, &resp_val).await?;
    Ok(())
}

pub async fn route_api_request(
    method: &str,
    path: &str,
    body: &str,
    shared: &SharedState,
) -> (u16, serde_json::Value) {
    route_api_request_scoped(method, path, body, shared, ApiKeyScope::ReadWrite).await
}

pub async fn route_api_request_scoped(
    method: &str,
    path: &str,
    body: &str,
    shared: &SharedState,
    scope: ApiKeyScope,
) -> (u16, serde_json::Value) {
    if scope == ApiKeyScope::ReadOnly && (method != "GET" || path == "/api/v1/scan") {
        return (
            403,
            json!({
                "ok": false,
                "error": "Forbidden: API key has read-only ('ro') scope; write and scan operations require a read-write ('rw') key"
            }),
        );
    }

    if let Ok(mut st) = shared.write() {
        st.sync_from_disk_if_changed();
    }
    match (method, path) {
        ("GET", "/api/v1/status") | ("GET", "/status") => {
            let flows = crate::features::read_active_flows(shared);
            let mut wg_configs = crate::features::list_saved_wg_configs();
            if scope == ApiKeyScope::ReadOnly {
                for res in wg_configs.values_mut() {
                    if let Ok(w) = res {
                        w.private_key = "<redacted>".to_string();
                        w.preshared_key = w.preshared_key.as_ref().map(|_| "<redacted>".to_string());
                    }
                }
            }
            let st = shared.read().unwrap();
            let cfg_raw = st.active_config();
            let cfg = if scope == ApiKeyScope::ReadOnly {
                cfg_raw.redacted_for_readonly()
            } else {
                cfg_raw.clone()
            };
            let running_cfg = if scope == ApiKeyScope::ReadOnly {
                st.running.redacted_for_readonly()
            } else {
                st.running.clone()
            };
            let candidate_cfg = if scope == ApiKeyScope::ReadOnly {
                st.candidate.redacted_for_readonly()
            } else {
                st.candidate.clone()
            };
            let nft = compile_nft_ruleset(&cfg, Some(&st));
            let mut active_map: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for (k, svc) in &cfg.services {
                active_map.insert(
                    k.clone(),
                    st.active_backends_for_service(&svc.backends)
                        .into_iter()
                        .map(|b| b.endpoint())
                        .collect(),
                );
            }
            (
                200,
                json!({
                    "running": running_cfg,
                    "candidate": candidate_cfg,
                    "active_config": cfg,
                    "nftyfile": cfg.format_nftyfile(),
                    "runtime": st.runtime,
                    "active_backends": active_map,
                    "resolved_hosts": st.resolved_hosts,
                    "flows": flows,
                    "wg_configs": wg_configs,
                    "kernel_applied": st.kernel_applied,
                    "nft_ruleset": nft,
                }),
            )
        }
        ("GET", "/api/v1/flows") => {
            let flows = crate::features::read_active_flows(shared);
            (200, json!({"ok": true, "flows": flows}))
        }
        ("GET", "/api/v1/scan") | ("POST", "/api/v1/scan") => {
            let filter = if body.is_empty() { None } else { Some(body) };
            let discovered = crate::features::scan_network_services(filter, shared);
            (200, json!({"ok": true, "discovered": discovered}))
        }
        ("GET", "/api/v1/wg") => {
            let mut wg_configs = crate::features::list_saved_wg_configs();
            if scope == ApiKeyScope::ReadOnly {
                for res in wg_configs.values_mut() {
                    if let Ok(w) = res {
                        w.private_key = "<redacted>".to_string();
                        w.preshared_key = w.preshared_key.as_ref().map(|_| "<redacted>".to_string());
                    }
                }
            }
            (200, json!({"ok": true, "wg_configs": wg_configs}))
        }
        ("GET", "/api/v1/cloudflare") | ("GET", "/api/v1/cf") => {
            let cf = crate::features::load_cloudflare_config();
            let routes = {
                let st = shared.read().unwrap();
                crate::features::collect_cloudflare_routes(st.active_config())
            };
            (
                200,
                json!({
                    "ok": true,
                    "api_token_configured": cf.api_token.as_ref().map(|t| !t.is_empty()).unwrap_or(false),
                    "account_id": cf.account_id,
                    "tunnel_name": cf.tunnel_name,
                    "tunnel_id": cf.tunnel_id,
                    "daemon_running": crate::features::cloudflared_running_pid().is_some(),
                    "daemon_pid": crate::features::cloudflared_running_pid(),
                    "provisioned_hostnames": cf.managed_dns_records.keys().collect::<Vec<_>>(),
                    "routes": routes,
                }),
            )
        }
        ("POST", "/api/v1/cloudflare") | ("POST", "/api/v1/cf") => {
            let req: CloudflareConfigRequest = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => return (400, json!({"ok": false, "error": e.to_string()})),
            };
            let mut cf = crate::features::load_cloudflare_config();
            if let Some(tok) = req.api_token {
                cf.api_token = Some(tok.trim().to_string());
            }
            if let Some(acc) = req.account_id {
                cf.account_id = Some(acc.trim().to_string());
            }
            if let Some(name) = req.tunnel_name {
                cf.tunnel_name = name.trim().to_string();
            }
            if let Some(tt) = req.tunnel_token {
                cf.tunnel_token = Some(tt.trim().to_string());
            }
            if let Err(e) = crate::features::save_cloudflare_config(&cf) {
                return (500, json!({"ok": false, "error": e.to_string()}));
            }
            let cfg = shared.read().unwrap().active_config().clone();
            let logs = crate::features::reconcile_cloudflare_tunnel(&cfg);
            (200, json!({"ok": true, "logs": logs}))
        }
        ("POST", "/api/v1/wg") => {
            let req: WgUploadRequest = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => return (400, json!({"ok": false, "error": e.to_string()})),
            };
            match crate::features::save_wg_config_file(&req.name, &req.config) {
                Ok((filename, parsed)) => (
                    200,
                    json!({
                        "ok": true,
                        "filename": filename,
                        "parsed": parsed,
                    }),
                ),
                Err(e) => (400, json!({"ok": false, "error": e.to_string()})),
            }
        }
        ("GET", "/api/v1/config") => {
            let st = shared.read().unwrap();
            let running_cfg = if scope == ApiKeyScope::ReadOnly {
                st.running.redacted_for_readonly()
            } else {
                st.running.clone()
            };
            let candidate_cfg = if scope == ApiKeyScope::ReadOnly {
                st.candidate.redacted_for_readonly()
            } else {
                st.candidate.clone()
            };
            (
                200,
                json!({
                    "running": running_cfg,
                    "candidate": candidate_cfg,
                    "nftyfile_running": running_cfg.format_nftyfile(),
                    "nftyfile_candidate": candidate_cfg.format_nftyfile(),
                }),
            )
        }
        ("PUT", "/api/v1/config") => match parse_nftyfile(body) {
            Ok(mut cfg) => {
                let prev = {
                    let st = shared.read().unwrap();
                    st.running.clone()
                };
                let _ = crate::compiler::reconcile_dhcp_and_vlan_vips(&mut cfg);
                let vip_cmds = generate_vip_commands(&prev, &cfg);
                let _ = apply_vip_commands(&vip_cmds);
                {
                    let mut st = shared.write().unwrap();
                    st.history.push(prev);
                    st.candidate = cfg.clone();
                    st.running = cfg;
                    st.sync_runtime_entries();
                    let _ = reload_kernel_from_state(&mut st);
                }
                refresh_allowlist_hosts(shared).await;
                let st = shared.read().unwrap();
                (
                    200,
                    json!({
                        "ok": true,
                        "running": st.running,
                    }),
                )
            }
            Err(e) => (400, json!({"ok": false, "error": e.to_string()})),
        },
        ("GET", "/api/v1/nft") => {
            let st = shared.read().unwrap();
            let cfg = st.active_config();
            (
                200,
                json!({
                    "nft": compile_nft_ruleset(cfg, Some(&st))
                }),
            )
        }
        ("GET", "/api/v1/allow") => {
            let st = shared.read().unwrap();
            let cfg = st.active_config();
            let mut service_allow = BTreeMap::new();
            let mut expanded_service_sets = BTreeMap::new();
            for (k, svc) in &cfg.services {
                service_allow.insert(k.clone(), svc.allow.clone());
                expanded_service_sets.insert(
                    k.clone(),
                    st.expand_allow_elements(&svc.allow, &cfg.global_allow),
                );
            }
            let resp = AllowStatusResponse {
                global_allow: cfg.global_allow.clone(),
                service_allow,
                resolved_hosts: st.resolved_hosts.clone(),
                expanded_service_sets,
            };
            (200, serde_json::to_value(resp).unwrap())
        }
        // Add or replace allow-list entries (supports wildcards like "*.office.lan", "169.254.1.*", hostnames, CIDRs)
        ("POST", "/api/v1/allow") | ("PUT", "/api/v1/allow") => {
            let req: AllowListRequest = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => return (400, json!({"ok": false, "error": e.to_string()})),
            };
            let replace_mode = method == "PUT";
            let mut validated = Vec::new();
            for h in &req.hosts {
                match validate_allow_entry(h) {
                    Ok(v) => validated.push(v),
                    Err(e) => return (400, json!({"ok": false, "error": e.to_string()})),
                }
            }

            {
                let mut st = shared.write().unwrap();
                if let Some(svc_key) = &req.service {
                    let Some(svc) = st.candidate.services.get_mut(svc_key) else {
                        return (
                            404,
                            json!({"ok": false, "error": format!("Service '{}' not found", svc_key)}),
                        );
                    };
                    if replace_mode {
                        svc.allow = validated.clone();
                    } else {
                        for v in validated {
                            if !svc.allow.contains(&v) {
                                svc.allow.push(v);
                            }
                        }
                    }
                } else if replace_mode {
                    st.candidate.global_allow = validated;
                } else {
                    for v in validated {
                        if !st.candidate.global_allow.contains(&v) {
                            st.candidate.global_allow.push(v);
                        }
                    }
                }

                if req.apply {
                    st.running = st.candidate.clone();
                    let _ = reload_kernel_from_state(&mut st);
                }
            }

            // Immediately run DNS & wildcard host resolution and update nftables
            refresh_allowlist_hosts(shared).await;
            let st = shared.read().unwrap();
            (
                200,
                json!({
                    "ok": true,
                    "global_allow": st.running.global_allow,
                    "resolved_hosts": st.resolved_hosts,
                }),
            )
        }
        ("DELETE", "/api/v1/allow") => {
            let req: AllowListRequest = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => return (400, json!({"ok": false, "error": e.to_string()})),
            };
            let targets: Vec<String> = req
                .hosts
                .iter()
                .map(|h| validate_allow_entry(h).unwrap_or_else(|_| h.to_ascii_lowercase()))
                .collect();

            {
                let mut st = shared.write().unwrap();
                if let Some(svc_key) = &req.service {
                    if let Some(svc) = st.candidate.services.get_mut(svc_key) {
                        svc.allow.retain(|x| !targets.contains(x));
                    }
                } else {
                    st.candidate.global_allow.retain(|x| !targets.contains(x));
                }
                if req.apply {
                    st.running = st.candidate.clone();
                    let _ = reload_kernel_from_state(&mut st);
                }
            }
            let st = shared.read().unwrap();
            (
                200,
                json!({
                    "ok": true,
                    "global_allow": st.running.global_allow,
                }),
            )
        }
        // Register or update a hostname -> IP mapping (e.g. for wildcard rules like `*.office.lan`)
        ("POST", "/api/v1/allow/hosts") | ("PUT", "/api/v1/allow/hosts") => {
            let req: HostRegistrationRequest = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => return (400, json!({"ok": false, "error": e.to_string()})),
            };
            let host = req.host.trim().to_ascii_lowercase();
            {
                let mut st = shared.write().unwrap();
                if req.ips.is_empty() {
                    st.resolved_hosts.remove(&host);
                } else {
                    st.resolved_hosts.insert(host.clone(), req.ips.clone());
                }
                if !st.running.services.is_empty() {
                    let _ = reload_kernel_from_state(&mut st);
                }
            }
            let st = shared.read().unwrap();
            (
                200,
                json!({
                    "ok": true,
                    "host": host,
                    "resolved_hosts": st.resolved_hosts,
                }),
            )
        }
        ("POST", "/api/v1/allow/refresh") => {
            refresh_allowlist_hosts(shared).await;
            let st = shared.read().unwrap();
            (
                200,
                json!({
                    "ok": true,
                    "resolved_hosts": st.resolved_hosts,
                }),
            )
        }
        // 1:1 CLI command execution over HTTP API
        ("POST", "/api/v1/cli") => {
            let req: CliExecRequest = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => return (400, json!({"ok": false, "error": e.to_string()})),
            };
            let level = Arc::new(Mutex::new(ShellLevel::ConfigRoot));
            for cmd in req.command.lines().flat_map(|l| l.split(';')) {
                let trimmed = cmd.trim();
                if !trimmed.is_empty() {
                    handle_line(trimmed, &level, shared).await;
                }
            }
            refresh_allowlist_hosts(shared).await;
            let st = shared.read().unwrap();
            (
                200,
                json!({
                    "ok": true,
                    "candidate": st.candidate,
                    "running": st.running,
                    "nftyfile": st.candidate.format_nftyfile(),
                }),
            )
        }
        ("POST", "/api/v1/apply") => {
            let report = {
                let st = shared.read().unwrap();
                validate_config(&st.candidate, Some(&st))
            };
            if !report.valid {
                return (400, serde_json::to_value(report).unwrap());
            }
            let (prev, next) = {
                let st = shared.read().unwrap();
                (st.running.clone(), st.candidate.clone())
            };
            let vip_cmds = generate_vip_commands(&prev, &next);
            let _ = apply_vip_commands(&vip_cmds);
            {
                let mut st = shared.write().unwrap();
                st.history.push(prev);
                st.running = next;
                st.sync_runtime_entries();
                let _ = reload_kernel_from_state(&mut st);
            }
            refresh_allowlist_hosts(shared).await;
            let _ = run_all_probes_once(shared).await;
            (200, json!({"ok": true, "message": "Configuration applied"}))
        }
        ("POST", "/api/v1/probe") => {
            let outcomes = run_all_probes_once(shared).await;
            (200, json!({"ok": true, "outcomes": outcomes}))
        }
        ("POST", "/api/v1/drain") => {
            let req: BackendToggleRequest = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => return (400, json!({"ok": false, "error": e.to_string()})),
            };
            let mut st = shared.write().unwrap();
            st.runtime.entry(req.backend.clone()).or_default().drained = true;
            let _ = reload_kernel_from_state(&mut st);
            (200, json!({"ok": true, "backend": req.backend, "drained": true}))
        }
        ("POST", "/api/v1/enable") => {
            let req: BackendToggleRequest = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => return (400, json!({"ok": false, "error": e.to_string()})),
            };
            let mut st = shared.write().unwrap();
            st.runtime.entry(req.backend.clone()).or_default().drained = false;
            let _ = reload_kernel_from_state(&mut st);
            (200, json!({"ok": true, "backend": req.backend, "drained": false}))
        }
        ("GET", "/api/v1/services") => {
            let st = shared.read().unwrap();
            let cfg = if scope == ApiKeyScope::ReadOnly {
                st.candidate.redacted_for_readonly()
            } else {
                st.candidate.clone()
            };
            (200, json!({"services": cfg.services}))
        }
        _ if path.starts_with("/api/v1/services/") => {
            let key = path.trim_start_matches("/api/v1/services/");
            match method {
                "GET" => {
                    let st = shared.read().unwrap();
                    let cfg = if scope == ApiKeyScope::ReadOnly {
                        st.candidate.redacted_for_readonly()
                    } else {
                        st.candidate.clone()
                    };
                    match cfg.services.get(key) {
                        Some(svc) => (200, serde_json::to_value(svc).unwrap()),
                        None => (404, json!({"error": "Service not found"})),
                    }
                }
                "PUT" | "POST" => match serde_json::from_str::<Service>(body) {
                    Ok(svc) => {
                        let mut st = shared.write().unwrap();
                        st.candidate.services.insert(svc.key.clone(), svc.clone());
                        st.running.services.insert(svc.key.clone(), svc);
                        st.sync_runtime_entries();
                        let _ = reload_kernel_from_state(&mut st);
                        (200, json!({"ok": true, "key": key}))
                    }
                    Err(e) => (400, json!({"ok": false, "error": e.to_string()})),
                },
                "DELETE" => {
                    let mut st = shared.write().unwrap();
                    st.candidate.services.remove(key);
                    st.running.services.remove(key);
                    let _ = reload_kernel_from_state(&mut st);
                    (200, json!({"ok": true, "deleted": key}))
                }
                _ => (405, json!({"error": "Method not allowed"})),
            }
        }
        _ => (404, json!({"error": format!("Endpoint {} {} not found", method, path)})),
    }
}

async fn send_json(
    stream: &mut TcpStream,
    status: u16,
    val: &serde_json::Value,
) -> Result<()> {
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Internal Server Error",
    };
    let body = serde_json::to_string_pretty(val)?;
    let resp = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n{}",
        status,
        status_text,
        body.len(),
        body
    );
    stream.write_all(resp.as_bytes()).await?;
    Ok(())
}

async fn send_html(stream: &mut TcpStream, status: u16, html: &str) -> Result<()> {
    let status_text = if status == 200 { "OK" } else { "Error" };
    let resp = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n{}",
        status,
        status_text,
        html.len(),
        html
    );
    stream.write_all(resp.as_bytes()).await?;
    Ok(())
}

const WEB_CONSOLE_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>nfty — L4/L7 Load Balancer, Programmable DNS &amp; WireGuard Gateway Console</title>
<style>
  :root {
    --bg: #080b12;
    --panel: #111827;
    --panel-alt: #1a2335;
    --panel-hover: #212d42;
    --border: #2a364b;
    --text: #f3f4f6;
    --muted: #9ca3af;
    --cyan: #06b6d4;
    --blue: #3b82f6;
    --green: #10b981;
    --red: #ef4444;
    --amber: #f59e0b;
    --purple: #8b5cf6;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, sans-serif;
    line-height: 1.45;
    display: flex;
    height: 100vh;
    overflow: hidden;
  }
  code, pre, .mono {
    font-family: "JetBrains Mono", "Fira Code", ui-monospace, SFMono-Regular, Menlo, monospace;
  }
  /* Sidebar */
  .sidebar {
    width: 245px;
    background: var(--panel);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    flex-shrink: 0;
  }
  .brand {
    padding: 18px 20px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .brand-title {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 1.25rem;
    font-weight: 800;
    letter-spacing: -0.02em;
    color: #fff;
  }
  .brand-dot {
    width: 10px; height: 10px; border-radius: 50%;
    background: var(--cyan);
    box-shadow: 0 0 10px var(--cyan);
  }
  .nav-list {
    padding: 12px 10px;
    flex: 1;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .nav-btn {
    background: transparent;
    border: 1px solid transparent;
    color: var(--muted);
    text-align: left;
    padding: 10px 12px;
    border-radius: 8px;
    font-size: 0.87rem;
    font-weight: 600;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: space-between;
    transition: all 0.12s ease;
  }
  .nav-btn:hover {
    background: var(--panel-alt);
    color: var(--text);
  }
  .nav-btn.active {
    background: rgba(6, 182, 212, 0.14);
    border-color: rgba(6, 182, 212, 0.4);
    color: var(--cyan);
  }
  .nav-count {
    font-size: 0.72rem;
    padding: 1px 7px;
    border-radius: 99px;
    background: var(--panel-alt);
    color: var(--muted);
    font-family: monospace;
  }
  .sidebar-footer {
    padding: 14px;
    border-top: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    gap: 8px;
    font-size: 0.78rem;
  }
  /* Main Layout */
  .main-wrap {
    flex: 1;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  .topbar {
    height: 60px;
    background: var(--panel);
    border-bottom: 1px solid var(--border);
    padding: 0 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-shrink: 0;
  }
  .topbar-left {
    display: flex;
    align-items: center;
    gap: 14px;
  }
  .topbar-right {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .content {
    flex: 1;
    overflow-y: auto;
    padding: 24px;
  }
  .tab-pane { display: none; }
  .tab-pane.active { display: block; }

  /* Badges & Pills */
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 3px 10px;
    border-radius: 999px;
    font-size: 0.74rem;
    font-weight: 700;
    letter-spacing: 0.02em;
  }
  .badge-rw { background: rgba(16, 185, 129, 0.16); color: var(--green); border: 1px solid rgba(16, 185, 129, 0.4); }
  .badge-ro { background: rgba(6, 182, 212, 0.16); color: var(--cyan); border: 1px solid rgba(6, 182, 212, 0.4); }
  .badge-warn { background: rgba(245, 158, 11, 0.16); color: var(--amber); border: 1px solid rgba(245, 158, 11, 0.45); }
  .badge-err { background: rgba(239, 68, 68, 0.16); color: var(--red); border: 1px solid rgba(239, 68, 68, 0.45); }
  .pill {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 2px 9px;
    border-radius: 999px;
    font-size: 0.74rem;
    font-weight: 600;
  }
  .pill-up { background: rgba(16, 185, 129, 0.15); color: var(--green); border: 1px solid rgba(16, 185, 129, 0.35); }
  .pill-down { background: rgba(239, 68, 68, 0.15); color: var(--red); border: 1px solid rgba(239, 68, 68, 0.35); }
  .pill-drain { background: rgba(245, 158, 11, 0.15); color: var(--amber); border: 1px solid rgba(245, 158, 11, 0.35); }
  .pill-unknown { background: rgba(156, 163, 175, 0.15); color: var(--muted); border: 1px solid rgba(156, 163, 175, 0.3); }
  .tag {
    display: inline-block;
    background: var(--panel-alt);
    border: 1px solid var(--border);
    padding: 2px 7px;
    border-radius: 5px;
    font-family: monospace;
    font-size: 0.76rem;
    margin: 2px;
    color: #e5e7eb;
  }

  /* Buttons & Inputs */
  .btn {
    background: var(--panel-alt);
    color: var(--text);
    border: 1px solid var(--border);
    padding: 7px 13px;
    border-radius: 7px;
    font-size: 0.82rem;
    font-weight: 600;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    transition: all 0.12s;
  }
  .btn:hover:not(:disabled) { background: var(--panel-hover); border-color: #4b5563; }
  .btn:disabled { opacity: 0.45; cursor: not-allowed; }
  .btn-primary { background: rgba(6, 182, 212, 0.18); border-color: var(--cyan); color: #67e8f9; }
  .btn-primary:hover:not(:disabled) { background: rgba(6, 182, 212, 0.3); }
  .btn-success { background: rgba(16, 185, 129, 0.18); border-color: var(--green); color: #6ee7b7; }
  .btn-success:hover:not(:disabled) { background: rgba(16, 185, 129, 0.3); }
  .btn-amber { background: rgba(245, 158, 11, 0.18); border-color: var(--amber); color: #fcd34d; }
  .btn-danger { background: rgba(239, 68, 68, 0.16); border-color: var(--red); color: #fca5a5; }
  .btn-sm { padding: 4px 9px; font-size: 0.75rem; border-radius: 5px; }

  input, select, textarea {
    background: #0b0f19;
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 7px;
    padding: 8px 11px;
    font-size: 0.85rem;
    outline: none;
  }
  input:focus, select:focus, textarea:focus { border-color: var(--cyan); }

  /* Cards & Sections */
  .cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(185px, 1fr));
    gap: 14px;
    margin-bottom: 22px;
  }
  .card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 15px 18px;
  }
  .card .label { font-size: 0.74rem; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); }
  .card .val { font-size: 1.75rem; font-weight: 700; margin-top: 4px; font-family: monospace; }
  .card .sub { font-size: 0.75rem; color: var(--muted); margin-top: 2px; }

  .section {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    margin-bottom: 22px;
    overflow: hidden;
  }
  .section-header {
    padding: 13px 18px;
    border-bottom: 1px solid var(--border);
    font-weight: 600;
    font-size: 0.92rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: rgba(255,255,255,0.02);
    flex-wrap: wrap;
    gap: 10px;
  }
  .section-body { padding: 18px; }
  .grid-2 {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(440px, 1fr));
    gap: 18px;
  }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  th, td { padding: 11px 16px; text-align: left; border-bottom: 1px solid var(--border); vertical-align: middle; }
  th { color: var(--muted); font-weight: 600; font-size: 0.73rem; text-transform: uppercase; letter-spacing: 0.05em; background: rgba(0,0,0,0.2); }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: rgba(255,255,255,0.015); }
  .empty { padding: 28px; text-align: center; color: var(--muted); font-size: 0.88rem; }

  /* Topology Graph */
  .topo-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(330px, 1fr));
    gap: 14px;
    padding: 16px;
  }
  .topo-vip-card {
    background: #0b101b;
    border: 1px solid var(--border);
    border-radius: 9px;
    padding: 14px;
  }
  .topo-vip-head {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding-bottom: 10px;
    margin-bottom: 10px;
    border-bottom: 1px dashed var(--border);
  }
  .topo-svc-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 7px 10px;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 6px;
    margin-bottom: 6px;
    font-size: 0.81rem;
  }

  /* Slide-up CLI Drawer */
  .cli-drawer {
    background: #05080f;
    border-top: 2px solid var(--cyan);
    height: 290px;
    display: none;
    flex-direction: column;
    flex-shrink: 0;
  }
  .cli-drawer.open { display: flex; }
  .cli-header {
    padding: 8px 18px;
    background: var(--panel);
    border-bottom: 1px solid var(--border);
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 0.82rem;
    font-weight: 600;
  }
  .cli-output {
    flex: 1;
    padding: 12px 18px;
    overflow-y: auto;
    font-family: monospace;
    font-size: 0.82rem;
    color: #d1d5db;
    white-space: pre-wrap;
  }
  .cli-input-row {
    display: flex;
    border-top: 1px solid var(--border);
    background: #090d16;
    align-items: center;
    padding: 6px 14px;
    gap: 10px;
  }
  .cli-prompt { color: var(--cyan); font-family: monospace; font-weight: 700; font-size: 0.85rem; }
  .cli-input-row input {
    flex: 1;
    border: none;
    background: transparent;
    font-family: monospace;
    font-size: 0.86rem;
    padding: 6px 4px;
  }

  /* Modal */
  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.72);
    display: none;
    align-items: center;
    justify-content: center;
    z-index: 100;
  }
  .modal-backdrop.open { display: flex; }
  .modal {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    width: 100%;
    max-width: 520px;
    padding: 22px;
    box-shadow: 0 20px 50px rgba(0,0,0,0.6);
  }
  .modal h3 { font-size: 1.08rem; margin-bottom: 6px; }
  .modal p { font-size: 0.83rem; color: var(--muted); margin-bottom: 16px; }
  .form-row { margin-bottom: 13px; display: flex; flex-direction: column; gap: 5px; }
  .form-row label { font-size: 0.78rem; color: var(--muted); font-weight: 600; }
  .toast {
    position: fixed;
    bottom: 20px;
    right: 20px;
    background: var(--panel-alt);
    border: 1px solid var(--cyan);
    color: #fff;
    padding: 11px 16px;
    border-radius: 8px;
    font-size: 0.84rem;
    z-index: 200;
    display: none;
    box-shadow: 0 10px 25px rgba(0,0,0,0.5);
  }
</style>
</head>
<body>

<!-- Sidebar Navigation -->
<aside class="sidebar">
  <div class="brand">
    <div class="brand-title">
      <span class="brand-dot"></span>
      <span>nfty</span>
    </div>
    <span class="tag">web console</span>
  </div>
  <div class="nav-list">
    <button class="nav-btn active" onclick="switchTab('overview', this)">
      <span>1. Overview &amp; Topology</span>
      <span class="nav-count" id="nav-cnt-overview">live</span>
    </button>
    <button class="nav-btn" onclick="switchTab('vips', this)">
      <span>2. VIPs &amp; Services</span>
      <span class="nav-count" id="nav-cnt-vips">0</span>
    </button>
    <button class="nav-btn" onclick="switchTab('gateways', this)">
      <span>3. WireGuard Gateways</span>
      <span class="nav-count" id="nav-cnt-gws">0</span>
    </button>
    <button class="nav-btn" onclick="switchTab('dns', this)">
      <span>4. Programmable DNS</span>
      <span class="nav-count" id="nav-cnt-dns">53</span>
    </button>
    <button class="nav-btn" onclick="switchTab('firewall', this)">
      <span>5. Allow-List &amp; CF</span>
      <span class="nav-count" id="nav-cnt-allow">0</span>
    </button>
    <button class="nav-btn" onclick="switchTab('flows', this)">
      <span>6. Conntrack Flows</span>
      <span class="nav-count" id="nav-cnt-flows">0</span>
    </button>
    <button class="nav-btn" onclick="switchTab('scanner', this)">
      <span>7. Network Scanner</span>
      <span class="nav-count" id="nav-cnt-scan">LAN</span>
    </button>
    <button class="nav-btn" onclick="switchTab('config', this)">
      <span>8. Nftyfile &amp; nftables</span>
      <span class="nav-count">AST</span>
    </button>
  </div>
  <div class="sidebar-footer">
    <div style="display:flex;justify-content:space-between;align-items:center">
      <span style="color:var(--muted)">Auth Scope:</span>
      <span id="auth-scope-badge" class="badge badge-ro">CHECKING</span>
    </div>
    <div id="auth-peer-info" style="color:var(--muted);font-family:monospace;font-size:0.74rem"></div>
    <button class="btn btn-sm" style="width:100%;justify-content:center;margin-top:4px" onclick="openAuthModal()">
      🔑 Switch Key / Login
    </button>
  </div>
</aside>

<!-- Main Workspace -->
<div class="main-wrap">
  <header class="topbar">
    <div class="topbar-left">
      <span id="kernel-badge" class="badge badge-rw">● KERNEL NFTABLES ACTIVE</span>
      <span id="diff-badge" class="badge badge-warn" style="display:none">● UNCOMMITTED CANDIDATE CHANGES</span>
      <span id="last-updated" style="font-size:0.8rem;color:var(--muted)">Connecting...</span>
    </div>
    <div class="topbar-right">
      <button class="btn btn-sm" onclick="triggerProbe()" id="btn-probe">⚡ Probe Health Now</button>
      <button class="btn btn-sm btn-success" onclick="applyCandidate()" id="btn-apply" style="display:none">✔ Apply Candidate</button>
      <button class="btn btn-sm btn-primary" onclick="toggleCliDrawer()">⌘ Web CLI (`)</button>
    </div>
  </header>

  <main class="content">
    <!-- TAB 1: OVERVIEW & TOPOLOGY -->
    <div id="tab-overview" class="tab-pane active">
      <div class="cards">
        <div class="card">
          <div class="label">VIPs &amp; Gateways</div>
          <div class="val" id="stat-vips" style="color:var(--cyan)">0</div>
          <div class="sub" id="stat-vips-sub">0 services configured</div>
        </div>
        <div class="card">
          <div class="label">Backends / Tunnels UP</div>
          <div class="val" id="stat-up" style="color:var(--green)">0</div>
          <div class="sub">Active in kernel verdict map</div>
        </div>
        <div class="card">
          <div class="label">Backends DOWN</div>
          <div class="val" id="stat-down" style="color:var(--red)">0</div>
          <div class="sub">Auto-removed from routing</div>
        </div>
        <div class="card">
          <div class="label">Backends DRAINED</div>
          <div class="val" id="stat-drained" style="color:var(--amber)">0</div>
          <div class="sub">Maintenance drain active</div>
        </div>
        <div class="card">
          <div class="label">Active Conntrack Flows</div>
          <div class="val" id="stat-flows" style="color:var(--purple)">0</div>
          <div class="sub" id="stat-hosts-sub">0 allow-list hosts resolved</div>
        </div>
      </div>

      <div class="section">
        <div class="section-header">
          <span>Live VIP, Service &amp; WireGuard Gateway Topology</span>
          <div style="display:flex;gap:8px">
            <button class="btn btn-sm rw-only" onclick="openAddServiceModal()">+ Add Service / VIP</button>
          </div>
        </div>
        <div id="topo-wrap" class="topo-grid">
          <div class="empty">Loading live topology...</div>
        </div>
      </div>

      <div class="section">
        <div class="section-header">
          <span>All Services &amp; Gateway Health Matrix</span>
        </div>
        <div id="overview-table-wrap">
          <div class="empty">Loading services...</div>
        </div>
      </div>
    </div>

    <!-- TAB 2: VIPS & SERVICES -->
    <div id="tab-vips" class="tab-pane">
      <div class="section">
        <div class="section-header">
          <span>Virtual IPs (VIPs), L4/L7 Services &amp; Backend Controls</span>
          <div style="display:flex;gap:8px">
            <button class="btn btn-sm btn-primary rw-only" onclick="openAddServiceModal()">+ Add VIP / Service</button>
          </div>
        </div>
        <div id="vips-detail-wrap">
          <div class="empty">Loading VIPs and services...</div>
        </div>
      </div>
    </div>

    <!-- TAB 3: WIREGUARD GATEWAYS -->
    <div id="tab-gateways" class="tab-pane">
      <div class="grid-2">
        <div class="section">
          <div class="section-header">
            <span>Upload / Save WireGuard Profile (<code>/data/wg/*.conf</code>)</span>
          </div>
          <div class="section-body">
            <div class="form-row">
              <label>Profile Filename (e.g. <code>mullvad-us-sea-001.conf</code>)</label>
              <input type="text" id="wg-upload-name" placeholder="mullvad-us-sea-001.conf">
            </div>
            <div class="form-row">
              <label>WireGuard Configuration (<code>[Interface]</code> &amp; <code>[Peer]</code>)</label>
              <textarea id="wg-upload-body" rows="6" class="mono" placeholder="[Interface]&#10;PrivateKey = ...&#10;Address = 10.64.0.1/32&#10;&#10;[Peer]&#10;PublicKey = ...&#10;Endpoint = 198.51.100.1:51820&#10;AllowedIPs = 0.0.0.0/0"></textarea>
            </div>
            <button class="btn btn-primary rw-only" onclick="uploadWgProfile()">Save WireGuard Profile</button>
          </div>
        </div>

        <div class="section">
          <div class="section-header">
            <span>Quick Gateway / Port-Forward Command Builder</span>
          </div>
          <div class="section-body">
            <div class="form-row">
              <label>Gateway IP or DHCP Name</label>
              <input type="text" id="gw-quick-ip" placeholder="192.168.1.10">
            </div>
            <div class="form-row">
              <label>Directive (e.g. <code>killswitch on</code>, <code>privoxy:8118</code>, <code>forward 51413 to 192.168.1.50:51413</code>, <code>tunnel ca-van.conf</code>)</label>
              <input type="text" id="gw-quick-cmd" placeholder="forward 51413 to 192.168.1.50:51413">
            </div>
            <button class="btn btn-success rw-only" onclick="runGatewayQuickCmd()">Apply to Gateway</button>
          </div>
        </div>
      </div>

      <div class="section">
        <div class="section-header">
          <span>Configured Virtual Gateways &amp; ECMP WireGuard Tunnels</span>
        </div>
        <div id="gateways-table-wrap">
          <div class="empty">Loading gateways...</div>
        </div>
      </div>

      <div class="section">
        <div class="section-header">
          <span>Saved WireGuard Profiles on Disk (<code>/data/wg</code>)</span>
        </div>
        <div id="wg-files-wrap">
          <div class="empty">Loading saved WireGuard configs...</div>
        </div>
      </div>
    </div>

    <!-- TAB 4: PROGRAMMABLE DNS -->
    <div id="tab-dns" class="tab-pane">
      <div class="grid-2">
        <div class="section">
          <div class="section-header">
            <span>Add Authoritative DNS Record / Split-Horizon Rule</span>
          </div>
          <div class="section-body">
            <div class="form-row">
              <label>DNS Directive Type</label>
              <select id="dns-cmd-type">
                <option value="a">A Record (a &lt;fqdn&gt; &lt;ipv4&gt;)</option>
                <option value="cname">CNAME Alias (cname &lt;alias&gt; &lt;target&gt;)</option>
                <option value="address">Wildcard Override (address &lt;*.domain&gt; &lt;ip&gt;)</option>
                <option value="txt">TXT Record (txt &lt;fqdn&gt; "&lt;value&gt;")</option>
                <option value="route">Policy Route via Gateway (route &lt;domain&gt; via &lt;gw&gt;)</option>
                <option value="bypass">Bypass Gateway (bypass &lt;domain&gt; from &lt;gw&gt;)</option>
                <option value="block">Adblock Sinkhole (block &lt;*.domain&gt;)</option>
                <option value="upstream">Upstream Resolver (upstream &lt;ip&gt;)</option>
                <option value="forward">Conditional Forward Zone (forward &lt;domain&gt; &lt;ip&gt;)</option>
              </select>
            </div>
            <div class="form-row">
              <label>Arguments (e.g. <code>nas.lan 192.168.1.50</code> or <code>*.netflix.com via 192.168.1.10</code>)</label>
              <input type="text" id="dns-cmd-args" placeholder="nas.lan 192.168.1.50">
            </div>
            <button class="btn btn-primary rw-only" onclick="addDnsDirective()">Add &amp; Apply DNS Rule</button>
          </div>
        </div>

        <div class="section">
          <div class="section-header">
            <span>Programmable DNS Engine Settings (<code>dnsmasq</code>)</span>
          </div>
          <div class="section-body" id="dns-settings-wrap">
            <div class="empty">Loading DNS settings...</div>
          </div>
        </div>
      </div>

      <div class="section">
        <div class="section-header">
          <span>Configured DNS Records, Policy Routes (<code>nftset</code>) &amp; Adblock Domains</span>
        </div>
        <div id="dns-records-wrap">
          <div class="empty">No custom DNS block configured yet.</div>
        </div>
      </div>
    </div>

    <!-- TAB 5: FIREWALL ALLOW-LIST & CLOUDFLARE -->
    <div id="tab-firewall" class="tab-pane">
      <div class="grid-2">
        <div class="section">
          <div class="section-header">
            <span>Add Firewall Allow-List Rule (CIDR, Hostname, or Wildcard)</span>
            <button class="btn btn-sm" onclick="refreshAllowlistDns()">🔄 Refresh DNS Now</button>
          </div>
          <div class="section-body">
            <div class="form-row">
              <label>Target Scope (leave empty for Global Allow-List, or enter Service Key like <code>192.168.1.4:8000</code>)</label>
              <input type="text" id="allow-service-key" placeholder="Global (or e.g. 192.168.1.4:8000)">
            </div>
            <div class="form-row">
              <label>Source CIDR / IP Wildcard / Hostname (e.g. <code>192.168.0.0/16</code>, <code>*.office.lan</code>, <code>10.0.0.0/8</code>)</label>
              <input type="text" id="allow-host-pattern" placeholder="192.168.0.0/16">
            </div>
            <button class="btn btn-primary rw-only" onclick="addAllowEntry()">+ Add to Allow-List &amp; Apply</button>
          </div>
        </div>

        <div class="section">
          <div class="section-header">
            <span>Register Dynamic Host -&gt; IP Mapping</span>
          </div>
          <div class="section-body">
            <div class="form-row">
              <label>Hostname (e.g. <code>laptop.office.lan</code>)</label>
              <input type="text" id="reg-host-name" placeholder="laptop.office.lan">
            </div>
            <div class="form-row">
              <label>IPv4 Address(es) (comma or space separated)</label>
              <input type="text" id="reg-host-ips" placeholder="192.168.1.99">
            </div>
            <button class="btn btn-success rw-only" onclick="registerHostMapping()">Register Host IP</button>
          </div>
        </div>
      </div>

      <div class="section">
        <div class="section-header">
          <span>Active Allow-Lists &amp; Resolved Host Table</span>
        </div>
        <div id="allow-table-wrap">
          <div class="empty">Loading allow-lists...</div>
        </div>
      </div>
    </div>

    <!-- TAB 6: LIVE CONNTRACK FLOWS -->
    <div id="tab-flows" class="tab-pane">
      <div class="section">
        <div class="section-header">
          <span>Live Kernel Conntrack Flows (<code>/proc/net/nf_conntrack</code>)</span>
          <div style="display:flex;gap:10px;align-items:center">
            <input type="text" id="flow-filter" placeholder="Filter by IP, port, proto, state..." oninput="renderFlowsTable()" style="width:260px">
            <button class="btn btn-sm" id="btn-pause-flows" onclick="toggleFlowsPause()">⏸ Pause</button>
          </div>
        </div>
        <div id="flows-table-wrap">
          <div class="empty">Loading active flows...</div>
        </div>
      </div>
    </div>

    <!-- TAB 7: NETWORK SCANNER -->
    <div id="tab-scanner" class="tab-pane">
      <div class="section">
        <div class="section-header">
          <span>LAN &amp; LXD Container Service Discovery</span>
          <div style="display:flex;gap:10px;align-items:center">
            <input type="text" id="scan-target" placeholder="Optional subnet/host (e.g. 192.168.1.0/24)" style="width:270px">
            <button class="btn btn-primary rw-only" id="btn-scan" onclick="runNetworkScan()">🔍 Scan Network</button>
          </div>
        </div>
        <div id="scan-table-wrap">
          <div class="empty">Click <strong>Scan Network</strong> to discover live containers, hosts, and open ports.</div>
        </div>
      </div>
    </div>

    <!-- TAB 8: CONFIG & NFTABLES -->
    <div id="tab-config" class="tab-pane">
      <div class="grid-2">
        <div class="section">
          <div class="section-header">
            <span>Declarative <code>Nftyfile</code> Configuration</span>
            <button class="btn btn-sm btn-success rw-only" onclick="saveAndApplyNftyfile()">💾 Save &amp; Apply Nftyfile</button>
          </div>
          <div style="padding:12px">
            <textarea id="nftyfile-editor" rows="24" class="mono" style="width:100%;background:#060911;color:#e5e7eb;font-size:0.82rem;line-height:1.45"></textarea>
          </div>
        </div>

        <div class="section">
          <div class="section-header">
            <span>Compiled Kernel <code>nftables</code> Ruleset (<code>table ip nfty</code>)</span>
          </div>
          <pre id="nft-box" style="padding:16px;overflow:auto;max-height:560px;font-size:0.8rem;background:#060911;color:#a7f3d0"></pre>
        </div>
      </div>
    </div>
  </main>

  <!-- Slide-Up Web CLI Drawer -->
  <div id="cli-drawer" class="cli-drawer">
    <div class="cli-header">
      <span>nfty Interactive Web CLI (executes against <code>POST /api/v1/cli</code>)</span>
      <div style="display:flex;gap:8px">
        <button class="btn btn-sm" onclick="runCliQuick('show')">show</button>
        <button class="btn btn-sm" onclick="runCliQuick('diff')">diff</button>
        <button class="btn btn-sm btn-success" onclick="runCliQuick('apply')">apply</button>
        <button class="btn btn-sm" onclick="toggleCliDrawer()">✕ Close</button>
      </div>
    </div>
    <div id="cli-output" class="cli-output"># Type any nfty CLI command below (e.g. 'vip 192.168.1.4; web:8000; allow 192.168.0.0/16; apply')</div>
    <div class="cli-input-row">
      <span class="cli-prompt">nfty(config)#</span>
      <input type="text" id="cli-input" placeholder="vip 192.168.1.4; web:8000; allow 192.168.0.0/16; apply" onkeydown="if(event.key==='Enter')sendCliCommand()">
      <button class="btn btn-sm btn-primary" onclick="sendCliCommand()">Run</button>
    </div>
  </div>
</div>

<!-- Auth / Login Modal -->
<div id="auth-modal" class="modal-backdrop">
  <div class="modal">
    <h3>Authenticate to nfty Web Console</h3>
    <p>If your IP is in the <code>web:&lt;port&gt;</code> allow-list, no key is required. You can also enter an API key (<code>nfty_ro_...</code> / <code>nfty_rw_...</code>) or sign in with the appliance password.</p>
    <div class="form-row">
      <label>API Key (Bearer / X-API-Key)</label>
      <input type="password" id="modal-api-key" placeholder="nfty_rw_... or nfty_ro_...">
    </div>
    <div style="text-align:center;color:var(--muted);font-size:0.76rem;margin:8px 0">— OR APPLIANCE LOGIN —</div>
    <div class="form-row">
      <label>Username</label>
      <input type="text" id="modal-username" value="nfty">
    </div>
    <div class="form-row">
      <label>Password</label>
      <input type="password" id="modal-password" placeholder="Appliance SSH/CLI password">
    </div>
    <div id="modal-auth-err" style="color:var(--red);font-size:0.8rem;margin-bottom:10px"></div>
    <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:14px">
      <button class="btn" onclick="clearSavedAuth()">Use IP Allow-List (Clear Key)</button>
      <button class="btn" onclick="closeAuthModal()">Cancel</button>
      <button class="btn btn-primary" onclick="submitAuthModal()">Sign In</button>
    </div>
  </div>
</div>

<!-- Add VIP / Service Modal -->
<div id="svc-modal" class="modal-backdrop">
  <div class="modal">
    <h3>Add or Update VIP Service</h3>
    <p>Configure a forwarded backend service, local <code>web:8000</code> console, <code>api:9090</code>, <code>ssh:22</code>, or <code>dns:53</code> on a Virtual IP.</p>
    <div class="form-row">
      <label>VIP Address or DHCP Name (e.g. <code>192.168.1.4</code> or <code>sonarr</code>)</label>
      <input type="text" id="svc-modal-vip" placeholder="192.168.1.4">
    </div>
    <div class="form-row">
      <label>Service Spec (e.g. <code>80 to 192.168.3.18:5055</code>, <code>web:8000</code>, <code>api:8080</code>, <code>ssh:22</code>)</label>
      <input type="text" id="svc-modal-spec" placeholder="80 to 192.168.3.18:5055">
    </div>
    <div class="form-row">
      <label>Optional Allow-List CIDR / Hostname (e.g. <code>192.168.0.0/16</code>)</label>
      <input type="text" id="svc-modal-allow" placeholder="192.168.0.0/16">
    </div>
    <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:16px">
      <button class="btn" onclick="closeAddServiceModal()">Cancel</button>
      <button class="btn btn-success" onclick="submitAddServiceModal()">Create &amp; Apply</button>
    </div>
  </div>
</div>

<div id="toast" class="toast"></div>

<script>
let stateData = null;
let currentScope = 'ro';
let flowsPaused = false;
let editorDirty = false;

function getAuthToken() {
  const params = new URLSearchParams(window.location.search);
  if (params.get('key')) return params.get('key');
  return sessionStorage.getItem('nfty_auth_token') || localStorage.getItem('nfty_auth_token') || '';
}

function setAuthToken(tok) {
  if (tok) {
    sessionStorage.setItem('nfty_auth_token', tok);
    localStorage.setItem('nfty_auth_token', tok);
  } else {
    sessionStorage.removeItem('nfty_auth_token');
    localStorage.removeItem('nfty_auth_token');
  }
}

async function apiFetch(path, options = {}) {
  const headers = Object.assign({ 'Content-Type': 'application/json' }, options.headers || {});
  const tok = getAuthToken();
  if (tok) {
    headers['Authorization'] = 'Bearer ' + tok;
  }
  const res = await fetch(path, Object.assign({}, options, { headers }));
  return res;
}

function showToast(msg, isError = false) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.style.borderColor = isError ? 'var(--red)' : 'var(--cyan)';
  el.style.display = 'block';
  clearTimeout(window._toastTimer);
  window._toastTimer = setTimeout(() => { el.style.display = 'none'; }, 3500);
}

function switchTab(tabId, btnEl) {
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  const target = document.getElementById('tab-' + tabId);
  if (target) target.classList.add('active');
  if (btnEl) btnEl.classList.add('active');
}

function toggleCliDrawer() {
  const d = document.getElementById('cli-drawer');
  d.classList.toggle('open');
  if (d.classList.contains('open')) {
    document.getElementById('cli-input').focus();
  }
}

document.addEventListener('keydown', (e) => {
  if (e.key === '`' && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName)) {
    e.preventDefault();
    toggleCliDrawer();
  }
});

function updateScopeUI(scope, mode, peerIp) {
  currentScope = scope || 'ro';
  const badge = document.getElementById('auth-scope-badge');
  if (currentScope === 'rw') {
    badge.className = 'badge badge-rw';
    badge.textContent = mode === 'allowlist' ? 'READ-WRITE (ALLOWLIST)' : 'READ-WRITE (RW)';
  } else {
    badge.className = 'badge badge-ro';
    badge.textContent = 'READ-ONLY (RO)';
  }
  const peerEl = document.getElementById('auth-peer-info');
  peerEl.textContent = peerIp ? `Client IP: ${peerIp}` : '';
  document.querySelectorAll('.rw-only').forEach(btn => {
    btn.disabled = (currentScope !== 'rw');
    btn.title = (currentScope !== 'rw') ? 'Requires Read-Write (rw) access' : '';
  });
}

async function checkWhoami() {
  try {
    const res = await apiFetch('/api/v1/auth/whoami');
    if (res.ok) {
      const info = await res.json();
      updateScopeUI(info.scope, info.mode, info.peer_ip);
      return true;
    } else if (res.status === 401) {
      openAuthModal();
      return false;
    }
  } catch (e) {}
  return false;
}

function openAuthModal() {
  document.getElementById('modal-auth-err').textContent = '';
  document.getElementById('modal-api-key').value = getAuthToken();
  document.getElementById('auth-modal').classList.add('open');
}

function closeAuthModal() {
  document.getElementById('auth-modal').classList.remove('open');
}

function clearSavedAuth() {
  setAuthToken('');
  closeAuthModal();
  refreshDashboard();
}

async function submitAuthModal() {
  const key = document.getElementById('modal-api-key').value.trim();
  const username = document.getElementById('modal-username').value.trim();
  const password = document.getElementById('modal-password').value;
  const payload = key ? { key } : { username, password };
  try {
    const res = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    if (!res.ok || !data.ok) {
      document.getElementById('modal-auth-err').textContent = data.error || 'Authentication failed';
      return;
    }
    setAuthToken(data.token);
    closeAuthModal();
    showToast(`Signed in with ${data.scope.toUpperCase()} access`);
    refreshDashboard();
  } catch (e) {
    document.getElementById('modal-auth-err').textContent = e.message;
  }
}

function openAddServiceModal(defaultVip = '') {
  if (defaultVip) document.getElementById('svc-modal-vip').value = defaultVip;
  document.getElementById('svc-modal').classList.add('open');
}
function closeAddServiceModal() {
  document.getElementById('svc-modal').classList.remove('open');
}
async function submitAddServiceModal() {
  const vip = document.getElementById('svc-modal-vip').value.trim();
  const spec = document.getElementById('svc-modal-spec').value.trim();
  const allow = document.getElementById('svc-modal-allow').value.trim();
  if (!vip || !spec) {
    showToast('VIP and Service Spec are required', true);
    return;
  }
  let cmd = `vip ${vip}; ${spec}`;
  if (allow) cmd += `; allow ${allow}`;
  cmd += `; apply`;
  await execCli(cmd);
  closeAddServiceModal();
}

async function execCli(command) {
  try {
    const res = await apiFetch('/api/v1/cli', {
      method: 'POST',
      body: JSON.stringify({ command })
    });
    const data = await res.json();
    if (!res.ok || data.ok === false) {
      showToast(data.error || 'Command failed', true);
      return null;
    }
    showToast('Applied: ' + command);
    const out = document.getElementById('cli-output');
    out.textContent += `\nnfty(config)# ${command}\n✔ OK (applied)\n`;
    out.scrollTop = out.scrollHeight;
    editorDirty = false;
    await refreshDashboard();
    return data;
  } catch (e) {
    showToast(e.message, true);
    return null;
  }
}

async function sendCliCommand() {
  const inp = document.getElementById('cli-input');
  const cmd = inp.value.trim();
  if (!cmd) return;
  inp.value = '';
  const data = await execCli(cmd);
  if (data && data.nftyfile && (cmd === 'show' || cmd.startsWith('show '))) {
    const out = document.getElementById('cli-output');
    out.textContent += data.nftyfile + '\n';
    out.scrollTop = out.scrollHeight;
  }
}

async function runCliQuick(cmd) {
  document.getElementById('cli-input').value = cmd;
  await sendCliCommand();
}

async function triggerProbe() {
  const res = await apiFetch('/api/v1/probe', { method: 'POST', body: '{}' });
  if (res.ok) {
    showToast('Active health probes completed');
    refreshDashboard();
  } else {
    const d = await res.json().catch(() => ({}));
    showToast(d.error || 'Probe requires RW scope', true);
  }
}

async function applyCandidate() {
  const res = await apiFetch('/api/v1/apply', { method: 'POST', body: '{}' });
  const d = await res.json().catch(() => ({}));
  if (res.ok) {
    showToast('Candidate configuration committed to kernel');
    editorDirty = false;
    refreshDashboard();
  } else {
    showToast(d.error || 'Failed to apply candidate', true);
  }
}

async function toggleBackendDrain(ep, currentlyDrained) {
  const path = currentlyDrained ? '/api/v1/enable' : '/api/v1/drain';
  const res = await apiFetch(path, {
    method: 'POST',
    body: JSON.stringify({ backend: ep })
  });
  if (res.ok) {
    showToast(`${currentlyDrained ? 'Enabled' : 'Drained'} backend ${ep}`);
    refreshDashboard();
  } else {
    const d = await res.json().catch(() => ({}));
    showToast(d.error || 'Operation failed', true);
  }
}

async function deleteService(svcKey) {
  const res = await apiFetch('/api/v1/services/' + encodeURIComponent(svcKey), { method: 'DELETE' });
  if (res.ok) {
    showToast(`Deleted service ${svcKey}`);
    refreshDashboard();
  } else {
    const d = await res.json().catch(() => ({}));
    showToast(d.error || 'Delete failed', true);
  }
}

async function generateServiceKey(vipKey, svcDisplay, scope) {
  await execCli(`vip ${vipKey}; ${svcDisplay}; key new ${scope}; apply`);
}

async function uploadWgProfile() {
  const name = document.getElementById('wg-upload-name').value.trim();
  const config = document.getElementById('wg-upload-body').value.trim();
  if (!name || !config) {
    showToast('Profile name and config content required', true);
    return;
  }
  const res = await apiFetch('/api/v1/wg', {
    method: 'POST',
    body: JSON.stringify({ name, config })
  });
  const d = await res.json().catch(() => ({}));
  if (res.ok && d.ok) {
    showToast(`Saved WireGuard profile ${d.filename}`);
    document.getElementById('wg-upload-body').value = '';
    refreshDashboard();
  } else {
    showToast(d.error || 'Failed to save WireGuard profile', true);
  }
}

async function runGatewayQuickCmd() {
  const gw = document.getElementById('gw-quick-ip').value.trim();
  const cmd = document.getElementById('gw-quick-cmd').value.trim();
  if (!gw || !cmd) {
    showToast('Gateway and directive required', true);
    return;
  }
  await execCli(`gateway ${gw}; ${cmd}; apply`);
}

async function addDnsDirective() {
  const t = document.getElementById('dns-cmd-type').value;
  const args = document.getElementById('dns-cmd-args').value.trim();
  if (!args) {
    showToast('DNS rule arguments required', true);
    return;
  }
  await execCli(`dns; ${t} ${args}; apply`);
  document.getElementById('dns-cmd-args').value = '';
}

async function addAllowEntry() {
  const svc = document.getElementById('allow-service-key').value.trim();
  const host = document.getElementById('allow-host-pattern').value.trim();
  if (!host) {
    showToast('CIDR or host pattern required', true);
    return;
  }
  const payload = { hosts: host.split(/[\s,]+/).filter(Boolean), apply: true };
  if (svc) payload.service = svc;
  const res = await apiFetch('/api/v1/allow', {
    method: 'POST',
    body: JSON.stringify(payload)
  });
  const d = await res.json().catch(() => ({}));
  if (res.ok && d.ok) {
    showToast(`Added ${host} to allow-list`);
    document.getElementById('allow-host-pattern').value = '';
    refreshDashboard();
  } else {
    showToast(d.error || 'Failed to update allow-list', true);
  }
}

async function removeAllowEntry(svcKey, entry) {
  const payload = { hosts: [entry], apply: true };
  if (svcKey) payload.service = svcKey;
  const res = await apiFetch('/api/v1/allow', {
    method: 'DELETE',
    body: JSON.stringify(payload)
  });
  if (res.ok) {
    showToast(`Removed ${entry} from allow-list`);
    refreshDashboard();
  }
}

async function registerHostMapping() {
  const host = document.getElementById('reg-host-name').value.trim();
  const ips = document.getElementById('reg-host-ips').value.trim().split(/[\s,]+/).filter(Boolean);
  if (!host || !ips.length) {
    showToast('Hostname and at least one IPv4 address required', true);
    return;
  }
  const res = await apiFetch('/api/v1/allow/hosts', {
    method: 'POST',
    body: JSON.stringify({ host, ips })
  });
  const d = await res.json().catch(() => ({}));
  if (res.ok && d.ok) {
    showToast(`Registered ${host} -> ${ips.join(', ')}`);
    refreshDashboard();
  } else {
    showToast(d.error || 'Failed to register host', true);
  }
}

async function refreshAllowlistDns() {
  const res = await apiFetch('/api/v1/allow/refresh', { method: 'POST', body: '{}' });
  if (res.ok) {
    showToast('Allow-list hostnames resolved & synced to kernel sets');
    refreshDashboard();
  }
}

function toggleFlowsPause() {
  flowsPaused = !flowsPaused;
  document.getElementById('btn-pause-flows').textContent = flowsPaused ? '▶ Resume' : '⏸ Pause';
}

async function runNetworkScan() {
  const btn = document.getElementById('btn-scan');
  const filter = document.getElementById('scan-target').value.trim();
  btn.disabled = true;
  btn.textContent = 'Scanning...';
  try {
    const res = await apiFetch('/api/v1/scan', {
      method: 'POST',
      body: filter
    });
    const data = await res.json();
    if (!res.ok || !data.ok) {
      showToast(data.error || 'Scan failed', true);
      return;
    }
    const list = data.discovered || [];
    document.getElementById('nav-cnt-scan').textContent = list.length;
    const wrap = document.getElementById('scan-table-wrap');
    if (list.length === 0) {
      wrap.innerHTML = `<div class="empty">No open services discovered on target subnet.</div>`;
    } else {
      const rows = list.map(d => `<tr>
        <td><code>#${d.index}</code></td>
        <td><strong>${d.host || d.ip}</strong> <span class="tag">${d.ip}</span></td>
        <td><span class="tag">${d.port}/${d.proto}</span></td>
        <td>${d.banner || '<span style="color:var(--muted)">tcp open</span>'}</td>
        <td>
          <button class="btn btn-sm btn-primary" onclick="adoptDiscovered(${d.index}, '${d.host || d.ip}', ${d.port})">+ Adopt into VIP</button>
        </td>
      </tr>`).join('');
      wrap.innerHTML = `<table>
        <thead><tr><th>#</th><th>Host / Container</th><th>Port</th><th>Service / Banner</th><th>Action</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
    }
  } catch (e) {
    showToast(e.message, true);
  } finally {
    btn.disabled = false;
    btn.textContent = '🔍 Scan Network';
  }
}

async function adoptDiscovered(idx, host, port) {
  const vip = prompt(`Adopt ${host}:${port} into which VIP (leave blank for auto DHCP VIP '${host}'):`, '');
  if (vip === null) return;
  const cmd = vip.trim() ? `adopt ${idx} vip ${vip.trim()}; apply` : `adopt ${idx}; apply`;
  await execCli(cmd);
}

async function saveAndApplyNftyfile() {
  const body = document.getElementById('nftyfile-editor').value;
  const res = await apiFetch('/api/v1/config', {
    method: 'PUT',
    body
  });
  const d = await res.json().catch(() => ({}));
  if (res.ok && d.ok) {
    editorDirty = false;
    showToast('Saved & applied Nftyfile configuration');
    refreshDashboard();
  } else {
    showToast(d.error || 'Failed to parse or apply Nftyfile', true);
  }
}

function renderFlowsTable() {
  if (!stateData) return;
  const flows = stateData.flows || [];
  const q = (document.getElementById('flow-filter').value || '').toLowerCase().trim();
  const filtered = q
    ? flows.filter(f => `${f.proto} ${f.state} ${f.src}:${f.sport} ${f.dst}:${f.dport} ${f.nat_target || ''}`.toLowerCase().includes(q))
    : flows;

  const wrap = document.getElementById('flows-table-wrap');
  if (filtered.length === 0) {
    wrap.innerHTML = `<div class="empty">No matching active conntrack flows.</div>`;
    return;
  }
  const rows = filtered.slice(0, 100).map(f => `<tr>
    <td><span class="tag">${f.proto}</span></td>
    <td><span class="pill ${f.state === 'ESTABLISHED' ? 'pill-up' : 'pill-unknown'}">${f.state}</span></td>
    <td><code>${f.src}:${f.sport}</code></td>
    <td><strong>${f.dst}:${f.dport}</strong></td>
    <td><code style="color:var(--green)">${f.nat_target || 'local / direct'}</code></td>
    <td><code>${f.mark && f.mark !== '0' ? '0x' + f.mark : '-'}</code></td>
    <td><code>${f.packets} pkts / ${f.bytes} B</code></td>
  </tr>`).join('');
  wrap.innerHTML = `<table>
    <thead>
      <tr>
        <th>Proto</th>
        <th>State</th>
        <th>Client (Source)</th>
        <th>VIP / Destination</th>
        <th>NAT Target / Tunnel</th>
        <th>FW Mark</th>
        <th>Traffic</th>
      </tr>
    </thead>
    <tbody>${rows}</tbody>
  </table>`;
}

async function refreshDashboard() {
  try {
    const res = await apiFetch('/api/v1/status');
    if (res.status === 401) {
      openAuthModal();
      return;
    }
    if (!res.ok) return;
    const data = await res.json();
    stateData = data;

    const cfg = data.active_config || { vips: {}, services: {}, gateways: {}, global_allow: [] };
    const services = Object.values(cfg.services || {});
    const gateways = Object.values(cfg.gateways || {});
    const vipsMap = cfg.vips || {};
    const runtime = data.runtime || {};
    const activeMap = data.active_backends || {};
    const resolvedHosts = data.resolved_hosts || {};
    const flows = data.flows || [];
    const wgConfigs = data.wg_configs || {};

    // Check candidate vs running diff
    const hasDiff = JSON.stringify(data.running) !== JSON.stringify(data.candidate);
    document.getElementById('diff-badge').style.display = hasDiff ? 'inline-flex' : 'none';
    document.getElementById('btn-apply').style.display = (hasDiff && currentScope === 'rw') ? 'inline-flex' : 'none';

    // Sidebar counts
    const allVipKeys = new Set(Object.keys(vipsMap));
    services.forEach(s => { if (s.vip_id) allVipKeys.add(s.vip_id); else if (s.listen_ip) allVipKeys.add(s.listen_ip); });
    document.getElementById('nav-cnt-vips').textContent = `${allVipKeys.size}/${services.length}`;
    document.getElementById('nav-cnt-gws').textContent = gateways.length;
    document.getElementById('nav-cnt-allow').textContent = (cfg.global_allow || []).length + Object.keys(resolvedHosts).length;
    document.getElementById('nav-cnt-flows').textContent = flows.length;

    // 1. Overview & Health Matrix
    let up = 0, down = 0, drained = 0;
    let matrixRows = '';

    for (const svc of services) {
      const activeEps = activeMap[svc.key] || [];
      const vipStr = svc.vip ? `${svc.vip.interface}/${svc.vip.prefix_len}` : 'any';
      const isWeb = svc.name && svc.name.startsWith('web:');
      const isApi = svc.name && svc.name.startsWith('api:');
      const typeBadge = isWeb
        ? `<span class="tag" style="border-color:var(--cyan);color:var(--cyan)">WEB UI</span>`
        : (isApi ? `<span class="tag" style="border-color:var(--purple);color:var(--purple)">CONTROL API</span>` : `<span class="tag">${svc.proto}</span>`);
      const allowRules = [...(cfg.global_allow || []), ...(svc.allow || [])];
      const allowTags = allowRules.length
        ? allowRules.map(a => `<span class="tag">${a}</span>`).join('')
        : '<span style="color:var(--muted)">any</span>';

      const backends = svc.backends || [];
      backends.forEach((b, idx) => {
        const ep = b.host ? `${b.host}(${b.ip}):${b.port}` : `${b.ip}:${b.port}`;
        const isLocal = b.ip === '127.0.0.1';
        const rt = runtime[ep] || { health: isLocal ? 'UP' : 'UNKNOWN', drained: false, packets: 0, bytes: 0, pps: 0 };
        const isRouting = isLocal || activeEps.includes(ep);

        let pill = '';
        if (rt.drained) {
          drained++;
          pill = `<span class="pill pill-drain">● DRAINED</span>`;
        } else if (rt.health === 'UP' || isLocal) {
          up++;
          const lat = rt.latency_ms != null ? ` (${rt.latency_ms.toFixed(1)}ms)` : '';
          pill = `<span class="pill pill-up">● UP${lat}</span>`;
        } else if (rt.health === 'DOWN') {
          down++;
          pill = `<span class="pill pill-down">● DOWN</span>`;
        } else {
          pill = `<span class="pill pill-unknown">● UNCHECKED</span>`;
        }

        const actionBtn = (!isLocal && currentScope === 'rw')
          ? `<button class="btn btn-sm ${rt.drained ? 'btn-success' : 'btn-amber'}" onclick="toggleBackendDrain('${ep}', ${rt.drained})">${rt.drained ? 'Enable' : 'Drain'}</button>`
          : '';

        matrixRows += `<tr>
          <td>${idx === 0 ? `<strong>${svc.key}</strong> ${typeBadge} ${svc.name ? `<span class="tag">${svc.name}</span>` : ''}` : ''}</td>
          <td>${idx === 0 ? `<span class="tag">${vipStr}</span>` : ''}</td>
          <td>${idx === 0 ? allowTags : ''}</td>
          <td><code>${isLocal ? 'local appliance (' + svc.port + ')' : ep}</code></td>
          <td>${pill}</td>
          <td>${isRouting ? '<span class="tag" style="color:var(--green);border-color:var(--green)">ROUTING</span>' : '<span class="tag">EXCLUDED</span>'}</td>
          <td><code>${rt.packets || 0} pkts / ${rt.bytes || 0} B</code></td>
          <td>${actionBtn}</td>
        </tr>`;
      });
    }

    for (const gw of gateways) {
      const vipStr = gw.vip ? `${gw.vip.interface}/${gw.vip.prefix_len}` : 'any';
      const tunnels = gw.tunnels || [];
      tunnels.forEach((t, idx) => {
        const ep = `wg:${t.name}(${t.iface})`;
        const rt = runtime[ep] || { health: 'UNKNOWN', packets: 0, bytes: 0 };
        if (rt.health === 'UP') up++; else if (rt.health === 'DOWN') down++;
        const lat = rt.latency_ms != null ? ` (${rt.latency_ms.toFixed(1)}ms)` : '';
        const pill = rt.health === 'UP'
          ? `<span class="pill pill-up">● UP${lat}</span>`
          : (rt.health === 'DOWN' ? `<span class="pill pill-down">● DOWN</span>` : `<span class="pill pill-unknown">● READY</span>`);
        matrixRows += `<tr>
          <td>${idx === 0 ? `<strong>gw:${gw.key}</strong> <span class="tag">wg-ecmp</span>` : ''}</td>
          <td>${idx === 0 ? `<span class="tag">${vipStr}</span>` : ''}</td>
          <td>${idx === 0 ? '<span class="tag">LAN</span>' : ''}</td>
          <td><code>${ep}</code></td>
          <td>${pill}</td>
          <td><span class="tag" style="color:var(--cyan)">ECMP TUNNEL</span></td>
          <td><code>${rt.packets || 0} pkts / ${rt.bytes || 0} B</code></td>
          <td></td>
        </tr>`;
      });
    }

    document.getElementById('stat-vips').textContent = allVipKeys.size + gateways.length;
    document.getElementById('stat-vips-sub').textContent = `${services.length} services, ${gateways.length} gateways`;
    document.getElementById('stat-up').textContent = up;
    document.getElementById('stat-down').textContent = down;
    document.getElementById('stat-drained').textContent = drained;
    document.getElementById('stat-flows').textContent = flows.length;
    document.getElementById('stat-hosts-sub').textContent = `${Object.keys(resolvedHosts).length} allow-list hosts resolved`;

    document.getElementById('overview-table-wrap').innerHTML = matrixRows
      ? `<table><thead><tr><th>Service / Gateway</th><th>Interface</th><th>Allow-List</th><th>Backend / Target</th><th>Health</th><th>Verdict</th><th>Traffic</th><th>Action</th></tr></thead><tbody>${matrixRows}</tbody></table>`
      : `<div class="empty">No services configured yet.</div>`;

    // Render Topology Cards
    let topoHtml = '';
    for (const vipKey of allVipKeys) {
      const vipSvcs = services.filter(s => s.vip_id === vipKey || s.listen_ip === vipKey);
      const svcsList = vipSvcs.map(s => {
        const bStr = (s.backends || []).map(b => b.ip === '127.0.0.1' ? 'local' : (b.host ? `${b.host}:${b.port}` : `${b.ip}:${b.port}`)).join(', ');
        const allowCount = (s.allow || []).length;
        return `<div class="topo-svc-row">
          <div><strong>${s.name || (':' + s.port)}</strong> <span class="tag">:${s.port}</span></div>
          <div style="color:var(--muted);font-family:monospace;font-size:0.76rem">→ ${bStr} ${allowCount ? `<span class="tag" style="color:var(--cyan)">allow:${allowCount}</span>` : ''}</div>
        </div>`;
      }).join('');
      topoHtml += `<div class="topo-vip-card">
        <div class="topo-vip-head">
          <div><strong style="color:var(--cyan);font-size:0.95rem">VIP ${vipKey}</strong></div>
          <button class="btn btn-sm" onclick="openAddServiceModal('${vipKey}')">+ Service</button>
        </div>
        ${svcsList || '<div style="color:var(--muted);font-size:0.8rem">No services attached</div>'}
      </div>`;
    }
    for (const gw of gateways) {
      const tList = (gw.tunnels || []).map(t => `<div class="topo-svc-row">
        <div><strong>${t.iface}</strong> <span class="tag">${t.name}</span></div>
        <div style="color:var(--green);font-family:monospace;font-size:0.75rem">ECMP w=${t.weight || 1}</div>
      </div>`).join('');
      const fList = (gw.forwards || []).map(f => `<div class="topo-svc-row">
        <div><strong>fwd :${f.listen_port}</strong></div>
        <div style="font-family:monospace;font-size:0.75rem">→ ${f.backend.host || f.backend.ip}:${f.backend.port}</div>
      </div>`).join('');
      topoHtml += `<div class="topo-vip-card" style="border-color:rgba(139,92,246,0.45)">
        <div class="topo-vip-head">
          <div><strong style="color:var(--purple);font-size:0.95rem">Gateway ${gw.key}</strong></div>
          <span class="tag">${gw.killswitch ? 'killswitch:on' : 'killswitch:off'}</span>
        </div>
        ${fList}${tList}
      </div>`;
    }
    document.getElementById('topo-wrap').innerHTML = topoHtml || `<div class="empty">No VIPs or Gateways configured.</div>`;

    // 2. Render VIPs & Services Detail Tab
    let vipsDetailHtml = '';
    for (const vipKey of allVipKeys) {
      const vipSvcs = services.filter(s => s.vip_id === vipKey || s.listen_ip === vipKey);
      const rows = vipSvcs.map(s => {
        const disp = s.name || `${s.port}`;
        const allowBadges = (s.allow || []).map(a => `<span class="tag">${a} <a href="#" onclick="removeAllowEntry('${s.key}','${a}');return false" style="color:var(--red);text-decoration:none">×</a></span>`).join(' ');
        const keysBadges = (s.api_keys || []).map(k => `<span class="tag"><code>${k.key}</code> (${k.scope})</span>`).join(' ');
        const isApiOrWeb = disp.startsWith('api:') || disp.startsWith('web:');
        const keyBtns = (isApiOrWeb && currentScope === 'rw')
          ? `<button class="btn btn-sm" onclick="generateServiceKey('${vipKey}','${disp}','ro')">+ RO Key</button>
             <button class="btn btn-sm" onclick="generateServiceKey('${vipKey}','${disp}','rw')">+ RW Key</button>`
          : '';
        return `<tr>
          <td><strong>${disp}</strong> <span class="tag">${s.key}</span></td>
          <td><code>:${s.port}/${s.proto}</code></td>
          <td>${(s.backends || []).map(b => `<code>${b.host ? b.host + '(' + b.ip + ')' : b.ip}:${b.port}</code>`).join(', ')}</td>
          <td>${allowBadges || '<span style="color:var(--muted)">none</span>'}</td>
          <td>${keysBadges || '<span style="color:var(--muted)">none (allow-list auth)</span>'}</td>
          <td style="display:flex;gap:6px;flex-wrap:wrap">
            ${keyBtns}
            ${currentScope === 'rw' ? `<button class="btn btn-sm btn-danger" onclick="deleteService('${s.key}')">Delete</button>` : ''}
          </td>
        </tr>`;
      }).join('');
      vipsDetailHtml += `<div style="padding:14px 18px;border-bottom:1px solid var(--border);background:rgba(6,182,212,0.05);display:flex;justify-content:space-between;align-items:center">
        <strong>VIP ${vipKey}</strong>
        <button class="btn btn-sm btn-primary" onclick="openAddServiceModal('${vipKey}')">+ Add Service on ${vipKey}</button>
      </div>
      <table>
        <thead><tr><th>Service</th><th>Listen</th><th>Backends</th><th>Allow-List</th><th>API / Web Keys</th><th>Actions</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="6" class="empty">No services on this VIP</td></tr>'}</tbody>
      </table>`;
    }
    document.getElementById('vips-detail-wrap').innerHTML = vipsDetailHtml || `<div class="empty">No VIPs configured.</div>`;

    // 3. Render Gateways & WireGuard Tab
    let gwHtml = '';
    for (const gw of gateways) {
      const svcs = (gw.services || []).map(s => `<span class="tag">${s.kind}:${s.port}</span>`).join(' ');
      const fwds = (gw.forwards || []).map(f => `<span class="tag">:${f.listen_port} → ${f.backend.host || f.backend.ip}:${f.backend.port}</span>`).join(' ');
      const tRows = (gw.tunnels || []).map(t => {
        const ep = `wg:${t.name}(${t.iface})`;
        const rt = runtime[ep] || {};
        return `<tr>
          <td><strong>${t.iface}</strong></td>
          <td><code>${t.name}</code></td>
          <td><span class="tag">weight ${t.weight || 1}</span></td>
          <td><span class="pill ${rt.health === 'UP' ? 'pill-up' : 'pill-unknown'}">● ${rt.health || 'READY'} ${rt.latency_ms != null ? '(' + rt.latency_ms.toFixed(1) + 'ms)' : ''}</span></td>
          <td><code>${rt.packets || 0} pkts / ${rt.bytes || 0} B</code></td>
        </tr>`;
      }).join('');
      gwHtml += `<div style="padding:14px 18px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center">
        <div><strong>Gateway ${gw.key}</strong> ${svcs} ${fwds}</div>
        <span class="badge ${gw.killswitch ? 'badge-rw' : 'badge-warn'}">Killswitch: ${gw.killswitch ? 'ON' : 'OFF'}</span>
      </div>
      <table>
        <thead><tr><th>Interface</th><th>Profile</th><th>Weight</th><th>Tunnel Health</th><th>Traffic</th></tr></thead>
        <tbody>${tRows || '<tr><td colspan="5" class="empty">Direct Gateway (no WireGuard tunnels attached)</td></tr>'}</tbody>
      </table>`;
    }
    document.getElementById('gateways-table-wrap').innerHTML = gwHtml || `<div class="empty">No WireGuard gateways configured.</div>`;

    const wgEntries = Object.entries(wgConfigs);
    document.getElementById('wg-files-wrap').innerHTML = wgEntries.length
      ? `<table><thead><tr><th>Filename</th><th>Interface Address</th><th>Endpoint</th><th>Private Key</th></tr></thead><tbody>${
          wgEntries.map(([name, res]) => {
            const w = res.Ok || {};
            return `<tr><td><strong>${name}</strong></td><td><code>${w.address || '-'}</code></td><td><code>${w.endpoint || '-'}</code></td><td><code>${w.private_key ? w.private_key.slice(0, 10) + '...' : '<redacted>'}</code></td></tr>`;
          }).join('')
        }</tbody></table>`
      : `<div class="empty">No WireGuard .conf files found in /data/wg</div>`;

    // 4. Programmable DNS Tab
    const dns = cfg.dns;
    if (dns) {
      document.getElementById('dns-settings-wrap').innerHTML = `
        <div style="display:flex;flex-wrap:wrap;gap:10px">
          <span class="tag">Domain: <strong>${dns.domain || 'lan'}</strong></span>
          <span class="tag">Cache: <strong>${dns.cache_size}</strong></span>
          <span class="tag">Auto-VIPs: <strong>${dns.auto_vips ? 'on' : 'off'}</strong></span>
          <span class="tag">Auto-Hosts: <strong>${dns.auto_hosts ? 'on' : 'off'}</strong></span>
          <span class="tag">Health-Aware: <strong>${dns.health_aware ? 'on' : 'off'}</strong></span>
          <span class="tag">Upstreams: <strong>${(dns.upstreams || []).join(', ')}</strong></span>
        </div>`;
      const recRows = [
        ...(dns.records || []).map(r => `<tr><td><span class="tag">RECORD</span></td><td><code>${JSON.stringify(r)}</code></td></tr>`),
        ...(dns.routes || []).map(r => `<tr><td><span class="tag" style="color:var(--cyan)">NFTSET ROUTE</span></td><td><code>${(r.domains || []).join(', ')} → via ${r.gateway}</code></td></tr>`),
        ...(dns.bypasses || []).map(b => `<tr><td><span class="tag" style="color:var(--amber)">BYPASS</span></td><td><code>${(b.domains || []).join(', ')} (bypass ${b.gateway})</code></td></tr>`),
        ...(dns.blocked_domains || []).map(d => `<tr><td><span class="tag" style="color:var(--red)">ADBLOCK</span></td><td><code>${d} → 0.0.0.0</code></td></tr>`)
      ].join('');
      document.getElementById('dns-records-wrap').innerHTML = recRows
        ? `<table><thead><tr><th>Type</th><th>Rule / Record</th></tr></thead><tbody>${recRows}</tbody></table>`
        : `<div class="empty">DNS engine enabled with auto-VIP &amp; auto-host synthesis.</div>`;
    } else {
      document.getElementById('dns-settings-wrap').innerHTML = `<div class="empty">DNS block not yet enabled. Add a rule on the left or run <code>dns; apply</code> in Web CLI.</div>`;
    }

    // 5. Firewall Allow-List Tab
    const globalAllow = (cfg.global_allow || []).map(a => `<span class="tag">${a} <a href="#" onclick="removeAllowEntry(null,'${a}');return false" style="color:var(--red);text-decoration:none">×</a></span>`).join(' ');
    const svcAllowRows = services.filter(s => (s.allow || []).length > 0).map(s => `<tr>
      <td><strong>${s.key}</strong> ${s.name ? `<span class="tag">${s.name}</span>` : ''}</td>
      <td>${s.allow.map(a => `<span class="tag">${a} <a href="#" onclick="removeAllowEntry('${s.key}','${a}');return false" style="color:var(--red);text-decoration:none">×</a></span>`).join(' ')}</td>
    </tr>`).join('');
    const hostRows = Object.entries(resolvedHosts).map(([h, ips]) => `<tr>
      <td><strong>${h}</strong></td>
      <td><code>${(ips || []).join(', ')}</code></td>
    </tr>`).join('');
    document.getElementById('allow-table-wrap').innerHTML = `
      <div style="padding:14px 18px;border-bottom:1px solid var(--border)">
        <strong>Global Allow-List:</strong> ${globalAllow || '<span style="color:var(--muted)">none (per-service allow-lists active)</span>'}
      </div>
      <table>
        <thead><tr><th>Service / Hostname</th><th>Allowed CIDRs / Resolved IPv4s</th></tr></thead>
        <tbody>
          ${svcAllowRows}
          ${hostRows}
        </tbody>
      </table>`;

    // 6. Conntrack Flows Tab
    if (!flowsPaused) {
      renderFlowsTable();
    }

    // 8. Nftyfile & nftables Tab
    const ed = document.getElementById('nftyfile-editor');
    if (!editorDirty && document.activeElement !== ed) {
      ed.value = data.nftyfile || '# Empty Nftyfile';
    }
    document.getElementById('nft-box').textContent = data.nft_ruleset || '';
    document.getElementById('last-updated').textContent = 'Live • ' + new Date().toLocaleTimeString();
  } catch (e) {
    document.getElementById('last-updated').textContent = 'Reconnecting...';
  }
}

document.getElementById('nftyfile-editor').addEventListener('input', () => {
  editorDirty = true;
});

(async function init() {
  await checkWhoami();
  await refreshDashboard();
  setInterval(refreshDashboard, 2500);
})();
</script>
</body>
</html>
"##;
