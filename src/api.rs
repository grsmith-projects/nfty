use crate::ast::{ApiKeyScope, Config, ControlAccess, Service};
use crate::compiler::{
    apply_config, compile_nft_ruleset, update_host_mapping, validate_config,
};
use crate::health::{refresh_allowlist_hosts, run_all_probes_once};
use crate::parser::{parse_nftyfile, validate_allow_entry, validate_host_mapping_name};
use crate::repl::{handle_line_checked, ShellLevel};
use crate::state::{AppState, SharedState};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, Deserialize)]
pub struct AllowListRequest {
    /// Optional service key (e.g. "9000" or "192.168.1.240:443"). If omitted, applies to global allow-list.
    pub service: Option<String>,
    /// List of hostnames, wildcard hostnames ("*.office.lan"), IP wildcards ("192.168.1.*"), or CIDRs
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
pub struct SshKeyUploadRequest {
    pub name: String,
    #[serde(alias = "public_key", alias = "config")]
    pub key: String,
}

#[derive(Debug, Deserialize)]
pub struct SshKeyDeleteRequest {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct CloudflareConfigRequest {
    pub api_token: Option<String>,
    pub account_id: Option<String>,
    pub tunnel_name: Option<String>,
    pub tunnel_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AllowStatusResponse {
    pub global_allow: Vec<String>,
    pub service_allow: BTreeMap<String, Vec<String>>,
    pub resolved_hosts: BTreeMap<String, Vec<Ipv4Addr>>,
    pub expanded_service_sets: BTreeMap<String, Vec<String>>,
}

pub fn spawn_api_server(shared: SharedState) {
    spawn_controller_socket(shared.clone());

    // Dynamically bind any custom `api:<port>` or `web:<port>` ports configured on VIPs or Gateways
    tokio::spawn(async move {
        let mut listeners: HashMap<u16, tokio::task::JoinHandle<()>> = HashMap::new();
        loop {
            let desired_ports = {
                let Ok(st) = shared.read() else {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                };
                st.active_config().api_ports()
            };
            listeners.retain(|port, handle| {
                let keep = desired_ports.contains(port) && !handle.is_finished();
                if !keep {
                    handle.abort();
                }
                keep
            });
            for port in desired_ports {
                if listeners.contains_key(&port) {
                    continue;
                }
                let addr = format!("0.0.0.0:{}", port);
                match TcpListener::bind(&addr).await {
                    Ok(listener) => {
                        listeners.insert(port, tokio::spawn(run_api_listener(listener, shared.clone())));
                    }
                    Err(e) => eprintln!("[nfty api] Failed to bind {}: {}", addr, e),
                }
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
}

async fn run_api_listener(listener: TcpListener, shared: SharedState) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let state = shared.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_http_connection(stream, state).await {
                        eprintln!("[nfty api] Connection failed: {:#}", e);
                    }
                });
            }
            Err(e) => {
                eprintln!("[nfty api] Accept failed: {}", e);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

fn extract_api_key_from_request(header_part: &str, query: &str) -> Option<String> {
    let mut candidate_key: Option<String> = None;

    for line in header_part.lines().skip(1) {
        let Some((name, val)) = line.split_once(':') else {
            continue;
        };
        let name_lower = name.trim().to_ascii_lowercase();
        let val_trimmed = val.trim();
        match name_lower.as_str() {
            "x-api-key" if !val_trimmed.is_empty() => {
                candidate_key = Some(val_trimmed.to_string());
            }
            "authorization" => {
                if let Some(tok) = val_trimmed
                    .strip_prefix("Bearer ")
                    .or_else(|| val_trimmed.strip_prefix("bearer "))
                    .map(str::trim)
                    .filter(|tok| !tok.is_empty())
                {
                    candidate_key = Some(tok.to_string());
                }
            }
            _ => {}
        }
    }

    if candidate_key.is_none() {
        candidate_key = query
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .find(|(k, v)| *k == "key" && !v.trim().is_empty())
            .map(|(_, v)| v.trim().to_string());
    }
    candidate_key
}

/// Rejects a config whose `web:`/`api:` listeners lack an IP allow-list; such configs are never applied.
fn control_allow_list_rejection(cfg: &Config) -> Option<(u16, serde_json::Value)> {
    let errors = cfg.control_allow_list_errors();
    if errors.is_empty() {
        return None;
    }
    Some((
        400,
        json!({
            "ok": false,
            "error": "Not applied: every web:/api: listener requires an IP allow-list",
            "errors": errors,
        }),
    ))
}

fn validate_and_apply(
    state: &mut AppState,
    config: Config,
) -> std::result::Result<(), (u16, serde_json::Value)> {
    if state.pending_confirm.is_some() {
        return Err((409, json!({"ok": false, "error": "Confirm or roll back the pending trial first"})));
    }
    if let Some(rejection) = control_allow_list_rejection(&config) {
        return Err(rejection);
    }
    let report = validate_config(&config, Some(state));
    if !report.valid {
        return Err((400, serde_json::to_value(report).unwrap()));
    }
    apply_config(state, config)
        .map(|_| ())
        .map_err(|error| (500, json!({"ok": false, "error": format!("{:#}", error)})))
}

fn decode_path_component(encoded: &str) -> Result<String> {
    let mut decoded = Vec::with_capacity(encoded.len());
    let mut bytes = encoded.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let high = bytes.next().ok_or_else(|| anyhow::anyhow!("Incomplete percent escape"))?;
            let low = bytes.next().ok_or_else(|| anyhow::anyhow!("Incomplete percent escape"))?;
            let digit = |b: u8| (b as char).to_digit(16);
            let high = digit(high).ok_or_else(|| anyhow::anyhow!("Invalid percent escape"))?;
            let low = digit(low).ok_or_else(|| anyhow::anyhow!("Invalid percent escape"))?;
            decoded.push(((high << 4) | low) as u8);
        } else {
            decoded.push(byte);
        }
    }
    Ok(String::from_utf8(decoded)?)
}

/// Every client, including loopback, must pass the listener's IP allow-list; keyed listeners also need a key.
pub fn authenticate_api_request_with_context(
    shared: &SharedState,
    candidate_key: Option<&str>,
    peer_ip: Option<Ipv4Addr>,
    local_port: Option<u16>,
) -> std::result::Result<ApiKeyScope, (u16, String)> {
    let st = shared.read().unwrap();
    let cfg = st.active_config();
    let access = match cfg.control_access(peer_ip, local_port) {
        ControlAccess::Denied(message) => return Err((403, message)),
        access => access,
    };
    if let Some(key) = candidate_key {
        return local_port
            .and_then(|port| cfg.verify_api_key_for_port(key, port))
            .ok_or((401, "Invalid API key".to_string()));
    }
    match access {
        ControlAccess::Granted => Ok(ApiKeyScope::ReadWrite),
        _ => Err((
            401,
            "Authentication required: this listener requires an API key".to_string(),
        )),
    }
}

/// Serves CLI/SSH-session updates on a 0600 Unix socket, accepting only root or the controller's own uid.
fn spawn_controller_socket(shared: SharedState) {
    let path = shared.read().unwrap().controller_socket.clone();
    tokio::spawn(async move {
        use std::os::unix::fs::PermissionsExt;
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
        let _ = std::fs::remove_file(&path);
        let listener = match tokio::net::UnixListener::bind(&path) {
            Ok(listener) => listener,
            Err(e) => {
                eprintln!("[nfty api] Failed to bind controller socket {}: {}", path.display(), e);
                return;
            }
        };
        if let Err(e) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)) {
            eprintln!("[nfty api] Failed to restrict controller socket {}: {}", path.display(), e);
            return;
        }
        let own_uid = unsafe { libc::geteuid() };
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            };
            let trusted = stream
                .peer_cred()
                .is_ok_and(|cred| cred.uid() == 0 || cred.uid() == own_uid);
            if !trusted {
                continue;
            }
            let state = shared.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_controller_connection(stream, state).await {
                    eprintln!("[nfty api] Controller request failed: {:#}", e);
                }
            });
        }
    });
}

async fn handle_controller_connection(stream: tokio::net::UnixStream, shared: SharedState) -> Result<()> {
    use tokio::io::AsyncBufReadExt;

    #[derive(Deserialize)]
    struct ControllerRequest {
        method: String,
        path: String,
        body: String,
    }

    let (reader, mut writer) = stream.into_split();
    let mut line = String::new();
    let limit = (MAX_HTTP_BODY_BYTES + 4096) as u64;
    tokio::time::timeout(
        Duration::from_secs(10),
        tokio::io::BufReader::new(reader).take(limit).read_line(&mut line),
    )
    .await
    .context("Controller request timed out")??;
    let req: ControllerRequest = serde_json::from_str(line.trim()).context("Malformed controller request")?;
    let (mut status, mut body) =
        route_api_request_scoped(&req.method, &req.path, &req.body, &shared, ApiKeyScope::ReadWrite).await;
    if status == 200 && request_persists_config(&req.method, &req.path, &body) {
        if let Err(e) = crate::unikernel::persist_to_storage(&shared) {
            status = 500;
            body = json!({"ok": false, "error": format!("Operation completed but persistence failed: {:#}", e)});
        }
    }
    let mut resp = json!({"status": status, "body": body}).to_string();
    resp.push('\n');
    writer.write_all(resp.as_bytes()).await?;
    Ok(())
}
const MAX_HTTP_HEADER_BYTES: usize = 64 * 1024;
const MAX_HTTP_BODY_BYTES: usize = 4 * 1024 * 1024;

fn http_content_length(header: &[u8]) -> Result<usize> {
    let header = std::str::from_utf8(header)?;
    let mut lines = header.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() != 3
        || !parts[1].starts_with('/')
        || !matches!(parts[2], "HTTP/1.0" | "HTTP/1.1")
    {
        anyhow::bail!("Malformed HTTP request line");
    }

    let mut content_length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            anyhow::bail!("Malformed HTTP header");
        };
        if name.is_empty()
            || !name.bytes().all(|b| {
                b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
            })
        {
            anyhow::bail!("Malformed HTTP header name");
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            anyhow::bail!("HTTP transfer encoding is not supported");
        }
        if name.eq_ignore_ascii_case("content-length") {
            let value = value.trim();
            if content_length.is_some()
                || value.is_empty()
                || !value.bytes().all(|b| b.is_ascii_digit())
            {
                anyhow::bail!("Invalid or duplicate Content-Length");
            }
            let length = value.parse::<usize>()?;
            if length > MAX_HTTP_BODY_BYTES {
                anyhow::bail!("HTTP request body exceeds 4MB limit");
            }
            content_length = Some(length);
        }
    }
    Ok(content_length.unwrap_or(0))
}

#[cfg(test)]
mod http_framing_tests {
    use super::*;

    #[test]
    fn rejects_ambiguous_request_framing() {
        for header in [
            "POST /api/v1/config HTTP/1.1\r\nContent-Length: nope",
            "POST /api/v1/config HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1",
            "POST /api/v1/config HTTP/1.1\r\nTransfer-Encoding: chunked",
            "POST /api/v1/config HTTP/1.1\r\nContent-Length : 1",
        ] {
            assert!(http_content_length(header.as_bytes()).is_err());
        }
        assert_eq!(
            http_content_length(b"POST /api/v1/config HTTP/1.1\r\nContent-Length: 4")
                .unwrap(),
            4
        );
    }

    #[test]
    fn only_committed_configuration_requests_need_config_persistence() {
        let applied = json!({"applied": true});
        let staged = json!({"applied": false});
        assert!(request_persists_config("PUT", "/api/v1/config", &applied));
        assert!(request_persists_config("POST", "/api/v1/apply", &applied));
        assert!(request_persists_config("DELETE", "/api/v1/services/example", &applied));
        assert!(request_persists_config("POST", "/api/v1/allow", &applied));
        assert!(!request_persists_config("POST", "/api/v1/allow", &staged));
        for path in [
            "/api/v1/allow/hosts",
            "/api/v1/drain",
            "/api/v1/wg",
            "/api/v1/cloudflare",
            "/api/v1/cli",
        ] {
            assert!(!request_persists_config("POST", path, &applied));
        }
    }

    #[tokio::test]
    async fn rejects_truncated_request_body() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            stream
                .write_all(b"PUT /api/v1/config HTTP/1.1\r\nContent-Length: 4\r\n\r\nabc")
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        });
        let (mut stream, _) = listener.accept().await.unwrap();
        assert!(read_full_http_request(&mut stream).await.is_err());
        client.await.unwrap();
    }
}

async fn read_full_http_request(stream: &mut TcpStream) -> Result<Option<Vec<u8>>> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut buf = Vec::with_capacity(8192);
        let mut chunk = [0u8; 8192];
        let mut request_end = None;

        loop {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                if buf.is_empty() {
                    return Ok(None);
                }
                anyhow::bail!("Incomplete HTTP request");
            }
            buf.extend_from_slice(&chunk[..n]);
            if request_end.is_none() {
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let header_end = pos + 4;
                    if header_end > MAX_HTTP_HEADER_BYTES {
                        anyhow::bail!("HTTP request headers exceed 64KB limit");
                    }
                    request_end = Some(header_end + http_content_length(&buf[..pos])?);
                } else if buf.len() > MAX_HTTP_HEADER_BYTES {
                    anyhow::bail!("HTTP request headers exceed 64KB limit");
                }
            }
            if let Some(end) = request_end {
                if buf.len() >= end {
                    buf.truncate(end);
                    return Ok(Some(buf));
                }
            }
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("HTTP request deadline exceeded"))?
}

async fn handle_http_connection(mut stream: TcpStream, shared: SharedState) -> Result<()> {
    let peer_addr = stream.peer_addr().ok();
    let peer_ip = peer_addr.and_then(|a| match a.ip() {
        std::net::IpAddr::V4(v4) => Some(v4),
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped(),
    });
    let local_port = stream.local_addr().ok().map(|a| a.port());

    let buf = match read_full_http_request(&mut stream).await {
        Ok(Some(buf)) => buf,
        Ok(None) => return Ok(()),
        Err(e) => {
            send_json(&mut stream, 400, &json!({"ok": false, "error": e.to_string()})).await?;
            return Ok(());
        }
    };
    let raw = match std::str::from_utf8(&buf) {
        Ok(raw) => raw,
        Err(_) => {
            send_json(&mut stream, 400, &json!({"ok": false, "error": "HTTP request is not UTF-8"})).await?;
            return Ok(());
        }
    };
    let (header_part, body_part) = raw.split_once("\r\n\r\n").expect("request was framed");
    let request_line = header_part.lines().next().unwrap_or("");
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        send_json(&mut stream, 400, &json!({"error": "Malformed HTTP request"})).await?;
        return Ok(());
    }
    let method = parts[0].to_ascii_uppercase();
    let full_path = parts[1];
    let (path, query) = full_path.split_once('?').unwrap_or((full_path, ""));

    let candidate_key = extract_api_key_from_request(header_part, query);

    {
        let mut host_hdr: Option<&str> = None;
        let mut origin_hdr: Option<&str> = None;
        let mut sec_fetch_site: Option<&str> = None;
        let mut content_type: Option<&str> = None;
        for line in header_part.lines().skip(1) {
            if let Some((k, v)) = line.split_once(':') {
                let kl = k.trim().to_ascii_lowercase();
                let vt = v.trim();
                match kl.as_str() {
                    "host" => host_hdr = Some(vt),
                    "origin" => origin_hdr = Some(vt),
                    "sec-fetch-site" => sec_fetch_site = Some(vt),
                    "content-type" => content_type = Some(vt),
                    _ => {}
                }
            }
        }

        if let Some(sfs) = sec_fetch_site {
            if sfs.eq_ignore_ascii_case("cross-site") {
                send_json(
                    &mut stream,
                    403,
                    &json!({"ok": false, "error": "Forbidden: cross-site browser requests are not permitted"}),
                )
                .await?;
                return Ok(());
            }
        }

        let (host_ok, orig_ok) = {
            let st = shared.read().unwrap();
            let cfg = st.active_config();
            let h_ok = host_hdr
                .map(|h| cfg.is_trusted_control_authority(h, &st.resolved_hosts))
                .unwrap_or(true);
            let o_ok = origin_hdr
                .map(|orig| {
                    let orig_auth = orig
                        .strip_prefix("http://")
                        .or_else(|| orig.strip_prefix("https://"))
                        .unwrap_or("");
                    !orig_auth.is_empty()
                        && cfg.is_trusted_control_authority(orig_auth, &st.resolved_hosts)
                        && host_hdr
                            .map(|h| {
                                let h_host = h.split(':').next().unwrap_or(h);
                                let o_host = orig_auth.split(':').next().unwrap_or(orig_auth);
                                h_host.eq_ignore_ascii_case(o_host)
                            })
                            .unwrap_or(true)
                })
                .unwrap_or(true);
            (h_ok, o_ok)
        };
        if !host_ok {
            send_json(
                &mut stream,
                403,
                &json!({"ok": false, "error": "Forbidden: untrusted Host header (DNS rebinding protection)"}),
            )
            .await?;
            return Ok(());
        }
        if !orig_ok {
            send_json(
                &mut stream,
                403,
                &json!({"ok": false, "error": "Forbidden: cross-origin requests are not permitted"}),
            )
            .await?;
            return Ok(());
        }

        if matches!(method.as_str(), "POST" | "PUT" | "DELETE")
            && (origin_hdr.is_some() || sec_fetch_site.is_some())
            && !body_part.trim().is_empty()
            && !(method == "PUT" && path == "/api/v1/config")
        {
            let is_json = content_type
                .map(|ct| ct.to_ascii_lowercase().starts_with("application/json"))
                .unwrap_or(false);
            if !is_json {
                send_json(
                    &mut stream,
                    400,
                    &json!({"ok": false, "error": "Content-Type: application/json is required for state-changing requests"}),
                )
                .await?;
                return Ok(());
            }
        }
    }

    if method == "OPTIONS" {
        let resp = "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\nAccess-Control-Allow-Headers: Authorization, X-API-Key, Content-Type\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(resp.as_bytes()).await?;
        return Ok(());
    }

    let access = {
        let st = shared.read().unwrap();
        st.active_config().control_access(peer_ip, local_port)
    };
    if let ControlAccess::Denied(message) = access {
        send_json(&mut stream, 403, &json!({"ok": false, "error": message})).await?;
        return Ok(());
    }

    let is_web_listener = {
        let st = shared.read().unwrap();
        st.active_config().is_web_port(local_port)
    };

    if method == "GET" && matches!(path, "/" | "/ui" | "/dashboard" | "/index.html") {
        if is_web_listener {
            send_html(&mut stream, 200, WEB_CONSOLE_HTML).await?;
            return Ok(());
        } else {
            send_json(
                &mut stream,
                404,
                &json!({
                    "ok": false,
                    "error": "Web UI is not enabled on this API port (configure 'web:<port>' on a VIP or gateway for the web interface, or query '/api/v1/status')"
                }),
            )
            .await?;
            return Ok(());
        }
    }

    let scope = match authenticate_api_request_with_context(
        &shared,
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
    if status == 200 && request_persists_config(&method, path, &resp_val) {
        if let Err(e) = crate::unikernel::persist_to_storage(&shared) {
            send_json(
                &mut stream,
                500,
                &json!({"ok": false, "error": format!("Operation completed but persistence failed: {:#}", e)}),
            )
            .await?;
            return Ok(());
        }
    }
    send_json(&mut stream, status, &resp_val).await?;
    Ok(())
}

fn request_persists_config(method: &str, path: &str, response: &serde_json::Value) -> bool {
    match (method, path) {
        ("PUT", "/api/v1/config") | ("POST", "/api/v1/apply") => true,
        ("POST" | "PUT" | "DELETE", "/api/v1/allow") => {
            response.get("applied").and_then(|value| value.as_bool()) == Some(true)
        }
        ("POST" | "PUT" | "DELETE", service_path)
            if service_path.starts_with("/api/v1/services/") => true,
        _ => false,
    }
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
    if scope == ApiKeyScope::ReadOnly && method != "GET" {
        return (
            403,
            json!({
                "ok": false,
                "error": "Forbidden: API key has read-only ('ro') scope; write operations require a read-write ('rw') key"
            }),
        );
    }

    if let Ok(mut st) = shared.write() {
        st.controller_is_authoritative = true;
        st.sync_from_disk_if_changed();
    }
    match (method, path) {
        ("GET", "/api/v1/status") => {
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
            let ssh_keys = crate::ssh::list_saved_ssh_keys();
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
                    "ssh_keys": ssh_keys,
                    "kernel_applied": st.kernel_applied,
                    "nft_ruleset": nft,
                }),
            )
        }
        ("GET", "/api/v1/flows") => {
            let flows = crate::features::read_active_flows(shared);
            (200, json!({"ok": true, "flows": flows}))
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
        ("GET", "/api/v1/ssh") => {
            let ssh_keys = crate::ssh::list_saved_ssh_keys();
            (200, json!({"ok": true, "ssh_keys": ssh_keys}))
        }
        ("POST", "/api/v1/ssh") => {
            let req: SshKeyUploadRequest = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => return (400, json!({"ok": false, "error": e.to_string()})),
            };
            match crate::ssh::save_ssh_pubkey_file(&req.name, &req.key) {
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
        ("DELETE", "/api/v1/ssh") => {
            let req: SshKeyDeleteRequest = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => return (400, json!({"ok": false, "error": e.to_string()})),
            };
            match crate::ssh::delete_ssh_pubkey_file(&req.name) {
                Ok(filename) => (200, json!({"ok": true, "deleted": filename})),
                Err(e) => (400, json!({"ok": false, "error": e.to_string()})),
            }
        }
        ("GET", "/api/v1/cloudflare") => {
            let cf = match crate::features::load_cloudflare_config() {
                Ok(cf) => cf,
                Err(e) => return (500, json!({"ok": false, "error": format!("{:#}", e)})),
            };
            let routes = {
                let st = shared.read().unwrap();
                match crate::features::collect_cloudflare_routes(st.active_config()) {
                    Ok(routes) => routes,
                    Err(e) => return (500, json!({"ok": false, "error": format!("{:#}", e)})),
                }
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
        ("POST", "/api/v1/cloudflare") => {
            let req: CloudflareConfigRequest = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => return (400, json!({"ok": false, "error": e.to_string()})),
            };
            let st = shared.read().unwrap();
            match crate::features::cloudflare::update_cloudflare_config_and_reconcile(
                st.active_config(),
                move |cf| {
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
                },
            ) {
                Ok(logs) => (200, json!({"ok": true, "logs": logs})),
                Err(e) => (500, json!({"ok": false, "error": e.to_string()})),
            }
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
            Ok(cfg) => {
                {
                    let mut st = shared.write().unwrap();
                    if let Err(rejection) = validate_and_apply(&mut st, cfg) {
                        return rejection;
                    }
                    st.candidate = st.running.clone();
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
        // Add or replace allow-list entries (supports wildcards like "*.office.lan", "192.168.1.*", hostnames, CIDRs)
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
                    let next = st.candidate.clone();
                    if let Err(rejection) = validate_and_apply(&mut st, next) {
                        return rejection;
                    }
                    st.candidate = st.running.clone();
                }
            }

            // Immediately run DNS & wildcard host resolution and update nftables
            refresh_allowlist_hosts(shared).await;
            let st = shared.read().unwrap();
            (
                200,
                json!({
                    "ok": true,
                    "applied": req.apply,
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
                    let next = st.candidate.clone();
                    if let Err(rejection) = validate_and_apply(&mut st, next) {
                        return rejection;
                    }
                    st.candidate = st.running.clone();
                }
            }
            let st = shared.read().unwrap();
            (
                200,
                json!({
                    "ok": true,
                    "applied": req.apply,
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
            let host = match validate_host_mapping_name(&req.host) {
                Ok(host) => host,
                Err(e) => return (400, json!({"ok": false, "error": e.to_string()})),
            };
            {
                let mut st = shared.write().unwrap();
                if let Err(e) = update_host_mapping(&mut st, &host, &req.ips) {
                    return (500, json!({"ok": false, "error": format!("{:#}", e)}));
                }
                if let Err(e) = crate::unikernel::persist_host_mapping(&host, &req.ips) {
                    return (500, json!({
                        "ok": false,
                        "error": format!("Host mapping was updated but could not be persisted: {:#}", e)
                    }));
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
            for cmd in req.command.lines().flat_map(crate::parser::split_statements_preserving_quotes) {
                let trimmed = cmd.trim();
                if !trimmed.is_empty() {
                    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
                    let command = tokens[0].to_ascii_lowercase();
                    if matches!(command.as_str(), "save" | "load") && tokens.len() > 1 {
                        return (
                            400,
                            json!({"ok": false, "error": "Custom file paths for save/load are not permitted over the HTTP API"}),
                        );
                    }
                    match crate::repl::run_non_interactive(handle_line_checked(trimmed, &level, shared)).await {
                        Ok(true) => break,
                        Ok(false) => {}
                        Err(e) => return (400, json!({"ok": false, "error": format!("{:#}", e)})),
                    }
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
            {
                let mut st = shared.write().unwrap();
                let next = st.candidate.clone();
                if let Err(rejection) = validate_and_apply(&mut st, next) {
                    return rejection;
                }
                st.candidate = st.running.clone();
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
            if !st.has_runtime_endpoint(&req.backend) {
                return (404, json!({"ok": false, "error": "Backend not found"}));
            }
            if let Err(e) = crate::compiler::set_backend_drain_state(&mut st, &[req.backend.clone()], true) {
                return (500, json!({"ok": false, "error": format!("{:#}", e)}));
            }
            (200, json!({"ok": true, "backend": req.backend, "drained": true}))
        }
        ("POST", "/api/v1/enable") => {
            let req: BackendToggleRequest = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => return (400, json!({"ok": false, "error": e.to_string()})),
            };
            let mut st = shared.write().unwrap();
            if !st.has_runtime_endpoint(&req.backend) {
                return (404, json!({"ok": false, "error": "Backend not found"}));
            }
            if let Err(e) = crate::compiler::set_backend_drain_state(&mut st, &[req.backend.clone()], false) {
                return (500, json!({"ok": false, "error": format!("{:#}", e)}));
            }
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
            let key = match decode_path_component(path.trim_start_matches("/api/v1/services/")) {
                Ok(key) => key,
                Err(e) => return (400, json!({"ok": false, "error": e.to_string()})),
            };
            match method {
                "GET" => {
                    let st = shared.read().unwrap();
                    let cfg = if scope == ApiKeyScope::ReadOnly {
                        st.candidate.redacted_for_readonly()
                    } else {
                        st.candidate.clone()
                    };
                    match cfg.services.get(&key) {
                        Some(svc) => (200, serde_json::to_value(svc).unwrap()),
                        None => (404, json!({"error": "Service not found"})),
                    }
                }
                "PUT" | "POST" => match serde_json::from_str::<Service>(body) {
                    Ok(svc) => {
                        if svc.key != key {
                            return (400, json!({"ok": false, "error": "Service key does not match the request path"}));
                        }
                        let mut st = shared.write().unwrap();
                        let mut next = st.running.clone();
                        next.services.insert(svc.key.clone(), svc.clone());
                        if let Err(rejection) = validate_and_apply(&mut st, next) {
                            return rejection;
                        }
                        st.candidate.services.insert(svc.key.clone(), svc);
                        st.sync_runtime_entries();
                        (200, json!({"ok": true, "key": key}))
                    }
                    Err(e) => (400, json!({"ok": false, "error": e.to_string()})),
                },
                "DELETE" => {
                    let mut st = shared.write().unwrap();
                    if !st.running.services.contains_key(&key)
                        && !st.candidate.services.contains_key(&key)
                    {
                        return (404, json!({"ok": false, "error": "Service not found"}));
                    }
                    let mut next = st.running.clone();
                    next.services.remove(&key);
                    if let Err(rejection) = validate_and_apply(&mut st, next) {
                        return rejection;
                    }
                    st.candidate.services.remove(&key);
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
        409 => "Conflict",
        _ => "Internal Server Error",
    };
    let body = serde_json::to_string_pretty(val)?;
    let resp = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{}",
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

const WEB_CONSOLE_HTML: &str = include_str!("web/index.html");
