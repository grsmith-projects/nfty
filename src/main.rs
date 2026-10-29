pub mod api;
pub mod ast;
pub mod compiler;
pub mod features;
pub mod health;
pub mod parser;
pub mod repl;
pub mod ssh;
pub mod state;
pub mod unikernel;

use crate::api::spawn_api_server;
use crate::ast::Config;
use crate::compiler::{
    apply_config, compile_nft_ruleset, validate_config,
};
use crate::health::{refresh_allowlist_hosts, spawn_background_tasks};
use crate::parser::parse_nftyfile;
use crate::repl::{handle_line_checked, print_status_table, run_repl, ShellLevel};
use crate::ssh::{enforce_first_login_password_change_if_needed, spawn_ssh_server};
use crate::state::{AppState, SharedState};
use crate::unikernel::{
    init_unikernel_appliance, persist_and_notify_controller, persist_to_storage,
};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "nfty",
    version,
    about = "L4 Service Load Balancer & Port Router shell, API, and Unikernel for nftables"
)]
struct Cli {
    /// Path to Nftyfile configuration
    #[arg(short, long, default_value = "Nftyfile")]
    file: PathBuf,

    /// Bind address for the embedded SSH2 appliance server
    #[arg(long, default_value = "0.0.0.0:22")]
    ssh_bind: String,

    /// Internal flag for an interactive SSH session (enforces first-login password change)
    #[arg(long, hide = true)]
    ssh_session: bool,

    /// Boot in Unikernel / Appliance mode (mounts /proc, /sys, /data if PID 1 and runs the appliance controller)
    #[arg(long)]
    unikernel: bool,

    /// Execute shell commands non-interactively (separated by ';' or newlines)
    #[arg(short, long)]
    command: Option<String>,

    #[command(subcommand)]
    subcommand: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the interactive drill-down configuration shell + background API & health-checker (default)
    Shell,
    /// Run as a headless standalone daemon / unikernel appliance (API + health-checker + DNS allow-list sync)
    Daemon,
    /// Show service & backend status table
    Status,
    /// Validate Nftyfile and run nftables dry-run check
    Validate,
    /// Compile and print the generated nftables ruleset
    Compile,
    /// Apply Nftyfile to kernel nftables and bind configured VIPs
    Apply,
}

#[tokio::main]
async fn main() -> Result<()> {
    // If invoked as /bin/sh, /bin/bash, or su by `lxc shell` / `lxc exec`, strip login flags
    // and default to `/data/Nftyfile` if present so `lxc exec <ct> -- sh` drops straight into `nfty>`!
    let raw_args: Vec<String> = std::env::args().collect();
    let argv0 = raw_args
        .first()
        .and_then(|s| Path::new(s).file_name())
        .and_then(|s| s.to_str())
        .unwrap_or("nfty");
    if argv0 == "udhcpc-hook" {
        let action = raw_args.get(1).map(|s| s.as_str()).unwrap_or("");
        crate::unikernel::handle_udhcpc_hook(action);
        return Ok(());
    }
    let cleaned_args: Vec<String> = if matches!(argv0, "sh" | "bash" | "ash" | "su") {
        vec!["nfty".to_string()]
    } else {
        raw_args
    };

    let cli = Cli::parse_from(cleaned_args);
    let is_pid1 = std::process::id() == 1;
    let runs_appliance_controller = is_pid1
        || (cli.unikernel
            && cli.command.is_none()
            && !cli.ssh_session
            && matches!(
                cli.subcommand.as_ref(),
                None | Some(Commands::Shell) | Some(Commands::Daemon)
            ));

    let mut effective_file = cli.file.clone();
    if runs_appliance_controller {
        if let Some(persistent_path) = init_unikernel_appliance() {
            if cli.file == Path::new("Nftyfile") {
                effective_file = persistent_path;
            }
        }
    } else if effective_file == Path::new("Nftyfile") && !effective_file.exists() {
        if Path::new("/data/Nftyfile").exists() {
            effective_file = PathBuf::from("/data/Nftyfile");
        } else if Path::new("/etc/nfty/Nftyfile").exists() {
            effective_file = PathBuf::from("/etc/nfty/Nftyfile");
        }
    }

    let mut loaded_invalid_config = false;
    let initial_cfg = if effective_file.exists() {
        let raw = fs::read_to_string(&effective_file)
            .with_context(|| format!("Failed to read {}", effective_file.display()))?;
        match parse_nftyfile(&raw) {
            Ok(cfg) => cfg,
            // PID 1 must not exit on a bad config: keep SSH reachable and preserve the file for repair.
            Err(e) if runs_appliance_controller => {
                loaded_invalid_config = true;
                let backup = effective_file.with_extension("invalid");
                if !backup.exists() || !raw.trim().is_empty() {
                    let _ = fs::copy(&effective_file, &backup);
                }
                eprintln!(
                    "[nfty] Failed to parse {}: {:#}\n[nfty] Booting with an empty config; original saved to {}",
                    effective_file.display(),
                    e,
                    backup.display()
                );
                Config::new()
            }
            Err(e) => {
                return Err(e).with_context(|| format!("Failed to parse {}", effective_file.display()))
            }
        }
    } else {
        Config::new()
    };

    let mut app_state = AppState::new(initial_cfg, effective_file.clone());
    app_state.controller_is_authoritative = runs_appliance_controller
        || (cli.command.is_none()
            && !cli.ssh_session
            && !crate::unikernel::pid1_is_nfty()
            && matches!(
                cli.subcommand.as_ref(),
                None | Some(Commands::Shell) | Some(Commands::Daemon)
            ));
    if app_state.controller_is_authoritative {
        app_state.running = Config::new();
    }
    if !cli.ssh_session && cli.command.is_none() {
        // Boot still applies the dataplane; listeners without an allow-list stay locked at request time.
        for error in app_state.candidate.control_allow_list_errors() {
            eprintln!("nfty: web/API access blocked: {}", error);
        }
    }

    // Load persisted wildcard host resolutions from /data/hosts.json if present
    app_state.resolved_hosts =
        crate::unikernel::read_persisted_hosts(Path::new("/data/hosts.json"))?;

    let shared: SharedState = Arc::new(RwLock::new(app_state));

    if runs_appliance_controller {
        spawn_ssh_server(cli.ssh_bind.clone(), effective_file.clone());
        // Auto-apply initial config on unikernel boot before starting background tasks
        if !matches!(cli.subcommand.as_ref(), Some(Commands::Daemon)) {
            let mut st = shared.write().unwrap();
            let next = st.candidate.clone();
            if let Err(e) = apply_config(&mut st, next) {
                eprintln!("[nfty-unikernel] Initial kernel apply failed; kernel state may require manual recovery: {:#}", e);
            }
        }
        crate::features::spawn_advanced_feature_daemons(shared.clone());
    } else if shared.read().unwrap().controller_is_authoritative {
        crate::features::spawn_advanced_feature_daemons(shared.clone());
    }
    if shared.read().unwrap().controller_is_authoritative {
        spawn_reload_handler(shared.clone())?;
    }
    if shared.read().unwrap().controller_is_authoritative {
        spawn_background_tasks(shared.clone());
        spawn_api_server(shared.clone());
    }

    if cli.ssh_session {
        enforce_first_login_password_change_if_needed()?;
    }

    if let Some(script) = cli.command {
        let level = Arc::new(Mutex::new(ShellLevel::Operational));
        for cmd in script.lines().flat_map(crate::parser::split_statements_preserving_quotes) {
            let trimmed = cmd.trim();
            if !trimmed.is_empty() && handle_line_checked(trimmed, &level, &shared).await? {
                break;
            }
        }
        return Ok(());
    }

    match cli.subcommand.unwrap_or(Commands::Shell) {
        Commands::Shell => {
            if is_pid1 {
                // In PID 1 unikernel mode, never let the init process exit; respawn shell or idle if no TTY
                loop {
                    let _ = run_repl(shared.clone()).await;
                    eprintln!("[nfty-unikernel] Respawning console shell in 2s...");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            } else {
                run_repl(shared.clone()).await?;
            }
        }
        Commands::Daemon => {
            refresh_allowlist_hosts(&shared).await;
            {
                let mut st = shared.write().unwrap();
                let next = st.candidate.clone();
                apply_config(&mut st, next)?;
            }
            if !loaded_invalid_config {
                persist_to_storage(&shared)?;
            }
            println!("nfty daemon running (Config: {})", effective_file.display());
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        }
        Commands::Status => {
            print_status_table(&shared);
        }
        Commands::Validate => {
            refresh_allowlist_hosts(&shared).await;
            let st = shared.read().unwrap();
            let report = validate_config(&st.candidate, Some(&st));
            for w in &report.warnings {
                eprintln!("Warning: {}", w);
            }
            for e in &report.errors {
                eprintln!("Error: {}", e);
            }
            if report.valid {
                println!("OK: {}", report.nft_message);
            } else {
                std::process::exit(1);
            }
        }
        Commands::Compile => {
            refresh_allowlist_hosts(&shared).await;
            let st = shared.read().unwrap();
            print!("{}", compile_nft_ruleset(&st.candidate, Some(&st)));
        }
        Commands::Apply => {
            refresh_allowlist_hosts(&shared).await;
            let allow_list_errors = shared.read().unwrap().candidate.control_allow_list_errors();
            if !allow_list_errors.is_empty() {
                anyhow::bail!(
                    "not applied: every web:/api: listener requires an IP allow-list\n  {}",
                    allow_list_errors.join("\n  ")
                );
            }
            let result = {
                let mut st = shared.write().unwrap();
                let next = st.candidate.clone();
                apply_config(&mut st, next)?
            };
            persist_and_notify_controller(&shared)?;
            for log in result.logs {
                println!("{}", log);
            }
            println!("{}", result.message);
        }
    }

    Ok(())
}

#[cfg(unix)]
fn spawn_reload_handler(shared: SharedState) -> Result<()> {
    let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .context("Failed to install SIGHUP reload handler")?;
    tokio::spawn(async move {
        while signal.recv().await.is_some() {
            let result = (|| -> Result<()> {
                let path = shared.read().unwrap().config_path.clone();
                let raw = fs::read_to_string(&path)
                    .with_context(|| format!("Failed to read {}", path.display()))?;
                let next = parse_nftyfile(&raw)
                    .with_context(|| format!("Failed to parse {}", path.display()))?;
                let mut st = shared.write().unwrap();
                if st.pending_confirm.is_some() {
                    anyhow::bail!("Cannot reload during a pending confirmed apply");
                }
                let candidate = st.candidate.format_nftyfile();
                if candidate != st.running.format_nftyfile() && candidate != next.format_nftyfile() {
                    anyhow::bail!("Cannot reload over uncommitted candidate changes");
                }
                let report = validate_config(&next, Some(&st));
                if !report.valid {
                    anyhow::bail!("Invalid configuration: {}", report.errors.join("; "));
                }
                for warning in report.warnings {
                    eprintln!("nfty: reload warning: {}", warning);
                }
                let applied = apply_config(&mut st, next)?;
                st.candidate = st.running.clone();
                st.last_disk_nftyfile = raw;
                for log in applied.logs {
                    eprintln!("nfty: {}", log);
                }
                eprintln!("nfty: reload complete: {}", applied.message);
                Ok(())
            })();
            if let Err(e) = result {
                eprintln!("nfty: SIGHUP reload failed: {:#}", e);
            }
        }
    });
    Ok(())
}

#[cfg(not(unix))]
fn spawn_reload_handler(_shared: SharedState) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::route_api_request;
    use crate::compiler::generate_vip_commands;
    use crate::repl::handle_line;
    use crate::state::HealthState;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_drill_down_shell_flow() {
        let shared: SharedState = Arc::new(RwLock::new(AppState::new(
            Config::new(),
            PathBuf::from("Nftyfile"),
        )));
        let level = Arc::new(Mutex::new(ShellLevel::Operational));

        handle_line("configure", &level, &shared).await;
        assert_eq!(*level.lock().unwrap(), ShellLevel::ConfigRoot);

        handle_line("service 9000", &level, &shared).await;
        assert_eq!(
            *level.lock().unwrap(),
            ShellLevel::Service("9000".to_string())
        );

        handle_line("to", &level, &shared).await;
        assert_eq!(
            *level.lock().unwrap(),
            ShellLevel::ServiceTo("9000".to_string())
        );

        handle_line("192.168.1.60:9000", &level, &shared).await;
        handle_line("192.168.1.61 weight 2", &level, &shared).await;
        handle_line("192.168.1.62:9000 backup", &level, &shared).await;

        handle_line("..", &level, &shared).await;
        assert_eq!(
            *level.lock().unwrap(),
            ShellLevel::Service("9000".to_string())
        );

        handle_line("balance sticky", &level, &shared).await;
        handle_line("check http /healthz 5s", &level, &shared).await;
        handle_line("limit 100/sec burst 50 per-ip", &level, &shared).await;
        handle_line("mode transparent", &level, &shared).await;

        let st = shared.read().unwrap();
        let svc = st.candidate.services.get("9000").expect("service 9000");
        assert_eq!(svc.backends.len(), 3);
        assert_eq!(svc.backends[0].endpoint(), "192.168.1.60:9000");
        assert_eq!(svc.backends[1].endpoint(), "192.168.1.61:9000");
        assert_eq!(svc.backends[1].weight, 2);
        assert!(svc.backends[2].backup);

        let nft = compile_nft_ruleset(&st.candidate, Some(&st));
        assert!(nft.contains("set meter_9000"));
        assert!(nft.contains("jhash ip saddr mod 3 map"));
        assert!(nft.contains("mode transparent"));
        assert!(!nft.contains("0 : 192.168.1.62") && !nft.contains("2 : 192.168.1.62"));
    }

    #[tokio::test]
    async fn test_wildcard_allowlist_and_api_parity() {
        let shared: SharedState = Arc::new(RwLock::new(AppState::new(
            Config::new(),
            PathBuf::from("Nftyfile"),
        )));

        let (code, _) = route_api_request(
            "POST",
            "/api/v1/cli",
            r#"{"command": "service 9000; to; 192.168.1.60:9000; ..; apply"}"#,
            &shared,
        )
        .await;
        assert_eq!(code, 200);

        let (code, _) = route_api_request(
            "POST",
            "/api/v1/allow",
            r#"{"service": "9000", "hosts": ["*.office.lan", "192.168.50.*"], "apply": true}"#,
            &shared,
        )
        .await;
        assert_eq!(code, 200);

        let (code, _) = route_api_request(
            "POST",
            "/api/v1/allow/hosts",
            r#"{"host": "macbook.office.lan", "ips": ["10.20.30.40"]}"#,
            &shared,
        )
        .await;
        assert_eq!(code, 200);
        let (code, _) = route_api_request(
            "POST",
            "/api/v1/allow/hosts",
            r#"{"host": "workstation.office.lan", "ips": ["10.20.30.41"]}"#,
            &shared,
        )
        .await;
        assert_eq!(code, 200);

        let st = shared.read().unwrap();
        let nft = compile_nft_ruleset(&st.running, Some(&st));
        assert!(nft.contains("set allow_9000"));
        assert!(nft.contains("10.20.30.40"));
        assert!(nft.contains("10.20.30.41"));
        assert!(nft.contains("192.168.50.0/24"));
    }

    #[test]
    fn test_backup_failover_and_vip_generation() {
        let raw = r#"
service 192.168.1.240:443 {
    vip eth0/24
    balance round-robin
    check tcp 5s
    limit 50/sec per-ip
    allow {
        192.168.0.0/16
    }
    to {
        192.168.1.101:443
        192.168.1.102:443 backup
    }
}
"#;
        let cfg = parse_nftyfile(raw).expect("parse Nftyfile");
        let vip_cmds = generate_vip_commands(&Config::new(), &cfg);
        assert_eq!(
            vip_cmds,
            vec!["ip addr replace 192.168.1.240/24 dev eth0".to_string()]
        );

        let mut state = AppState::new(cfg, PathBuf::from("Nftyfile"));
        let nft1 = compile_nft_ruleset(&state.running, Some(&state));
        assert!(nft1.contains("dnat to 192.168.1.101:443"));

        state
            .runtime
            .entry("192.168.1.101:443".to_string())
            .or_default()
            .health = HealthState::Down;
        let nft2 = compile_nft_ruleset(&state.running, Some(&state));
        assert!(nft2.contains("dnat to 192.168.1.102:443"));
    }

    #[tokio::test]
    async fn test_vip_service_container_flow() {
        let shared: SharedState = Arc::new(RwLock::new(AppState::new(
            Config::new(),
            PathBuf::from("Nftyfile"),
        )));
        let level = Arc::new(Mutex::new(ShellLevel::Operational));

        handle_line("configure", &level, &shared).await;
        handle_line("vip 192.168.1.4/21", &level, &shared).await;
        assert_eq!(
            *level.lock().unwrap(),
            ShellLevel::Vip("192.168.1.4".to_string())
        );

        handle_line("service", &level, &shared).await;
        assert_eq!(
            *level.lock().unwrap(),
            ShellLevel::VipService("192.168.1.4".to_string())
        );

        handle_line("192.168.1.165:32400", &level, &shared).await;
        assert_eq!(
            *level.lock().unwrap(),
            ShellLevel::Service("192.168.1.4:32400".to_string())
        );
        handle_line("hostname plex.local", &level, &shared).await;
        handle_line("exit", &level, &shared).await;
        assert_eq!(
            *level.lock().unwrap(),
            ShellLevel::Vip("192.168.1.4".to_string())
        );

        handle_line("80 to 192.168.3.165:9090", &level, &shared).await;
        assert_eq!(
            *level.lock().unwrap(),
            ShellLevel::Service("192.168.1.4:80".to_string())
        );
        handle_line("hostname app.local", &level, &shared).await;

        let formatted = {
            let st = shared.read().unwrap();
            st.candidate.format_nftyfile()
        };
        assert!(formatted.contains("vip 192.168.1.4 {"));
        assert!(formatted.contains("interface eth0/21"));
        assert!(formatted.contains("192.168.1.165:32400 {"));
        assert!(formatted.contains("80 to 192.168.3.165:9090 {"));

        let reparsed = parse_nftyfile(&formatted).expect("reparse formatted vip Nftyfile");
        assert_eq!(reparsed.vips["192.168.1.4"].prefix_len, 21);
        assert!(reparsed.services.contains_key("192.168.1.4:32400"));
        assert!(reparsed.services.contains_key("192.168.1.4:80"));
        assert_eq!(
            reparsed.services["192.168.1.4:80"].backends[0].port,
            9090
        );
    }

    #[tokio::test]
    async fn test_dhcp_vip_and_vlan_flow() {
        let shared: SharedState = Arc::new(RwLock::new(AppState::new(
            Config::new(),
            PathBuf::from("Nftyfile"),
        )));
        let level = Arc::new(Mutex::new(ShellLevel::Operational));

        handle_line("configure", &level, &shared).await;
        handle_line("vip sonarr", &level, &shared).await;
        assert_eq!(
            *level.lock().unwrap(),
            ShellLevel::Vip("sonarr".to_string())
        );

        handle_line("vlan 20", &level, &shared).await;
        handle_line("80 to 192.168.2.215:8989", &level, &shared).await;
        assert_eq!(
            *level.lock().unwrap(),
            ShellLevel::Service("sonarr:80".to_string())
        );

        let formatted = {
            let st = shared.read().unwrap();
            st.candidate.format_nftyfile()
        };
        assert!(formatted.contains("vip sonarr {"));
        assert!(formatted.contains("dhcp eth0"));
        assert!(formatted.contains("vlan 20"));
        assert!(formatted.contains("80 to 192.168.2.215:8989"));

        let reparsed = parse_nftyfile(&formatted).expect("reparse dhcp + vlan Nftyfile");
        assert!(reparsed.vips["sonarr"].dhcp);
        assert_eq!(reparsed.vips["sonarr"].vlan, Some(20));
        assert!(reparsed.services.contains_key("sonarr:80"));
        assert_eq!(reparsed.services["sonarr:80"].backends[0].port, 8989);
    }

    #[test]
    fn test_multi_vhost_and_dhcp_gateway() {
        let raw = r#"
vip 192.168.1.4 {
    80 to 192.168.2.215:8989 {
        hostname sonarr.local
    }
    80 to 192.168.2.215:7878 {
        hostname radarr.local
    }
}
gateway mullvad {
    dhcp eth0
    vlan 30
}
"#;
        let cfg = parse_nftyfile(raw).expect("parse multi-vhost + dhcp gateway");
        assert_eq!(cfg.services.len(), 2);
        assert!(cfg.gateways["mullvad"].vip.as_ref().unwrap().dhcp);
        assert_eq!(cfg.gateways["mullvad"].vip.as_ref().unwrap().vlan, Some(30));

        let nft = compile_nft_ruleset(&cfg, None);
        assert!(nft.contains("redirect to :80"));
    }

    #[tokio::test]
    async fn test_cloudflare_dns_directive_and_routes() {
        let shared: SharedState = Arc::new(RwLock::new(AppState::new(
            Config::new(),
            PathBuf::from("Nftyfile"),
        )));
        let level = Arc::new(Mutex::new(ShellLevel::ConfigRoot));

        handle_line("vip sonarr", &level, &shared).await;
        handle_line("80 to 192.168.2.215:8989", &level, &shared).await;
        handle_line("cloudflare-dns sonarr.example.com", &level, &shared).await;

        let formatted = {
            let st = shared.read().unwrap();
            st.candidate.format_nftyfile()
        };
        assert!(formatted.contains("cloudflare-dns sonarr.example.com"));

        let reparsed = parse_nftyfile(&formatted).expect("reparse cloudflare-dns Nftyfile");
        assert_eq!(
            reparsed.services["sonarr:80"].cloudflare.as_deref(),
            Some("sonarr.example.com")
        );

        let routes = crate::features::collect_cloudflare_routes(&reparsed).unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].1, "sonarr.example.com");
        assert_eq!(routes[0].2, "http://192.168.2.215:8989");
    }

    #[tokio::test]
    async fn test_gateway_port_forward_compilation() {
        let raw = r#"
gateway 192.168.10.20 {
    balance round-robin
    killswitch on
    forward 51413 to 192.168.20.15:51413
    tunnels {
        wg-exit-01.conf
        wg-exit-02.conf
    }
}
"#;
        let cfg = parse_nftyfile(raw).expect("parse gateway port forward");
        let gw = &cfg.gateways["192.168.10.20"];
        assert_eq!(gw.forwards.len(), 1);
        assert_eq!(gw.forwards[0].listen_port, 51413);
        assert_eq!(gw.forwards[0].backend.ip, Ipv4Addr::new(192, 168, 20, 15));
        assert_eq!(gw.forwards[0].backend.port, 51413);

        let nft = compile_nft_ruleset(&cfg, None);
        let iface0 = &gw.tunnels[0].iface;
        let iface1 = &gw.tunnels[1].iface;
        let mark0 = crate::features::wireguard::wireguard_mark(
            crate::features::wireguard::wireguard_iface_index(iface0).unwrap(),
        );
        let mark1 = crate::features::wireguard::wireguard_mark(
            crate::features::wireguard::wireguard_iface_index(iface1).unwrap(),
        );
        assert!(nft.contains(&format!("iifname \"{}\" ct state new ct mark set 0x{:x} accept", iface0, mark0)));
        assert!(nft.contains(&format!("iifname \"{}\" ct state new ct mark set 0x{:x} accept", iface1, mark1)));
        assert!(nft.contains(&format!("iifname {{ \"{}\", \"{}\" }} tcp dport 51413 counter dnat to 192.168.20.15:51413", iface0, iface1)));
        assert!(nft.contains(&format!("iifname {{ \"{}\", \"{}\" }} udp dport 51413 counter dnat to 192.168.20.15:51413", iface0, iface1)));

        let roundtrip = parse_nftyfile(&cfg.format_nftyfile()).expect("roundtrip gateway forward");
        assert_eq!(roundtrip.gateways["192.168.10.20"].forwards.len(), 1);
    }

    #[tokio::test]
    async fn test_dns_endpoint_and_nftset_compilation() {
        let raw = r#"
vip 192.168.1.4/24 {
    dns:53
    80 to 192.168.20.10:8989 {
        hostname sonarr.local
    }
}
gateway 192.168.1.10/24 {
    dns:53
    tunnels {
        wg-exit-01.conf
    }
}
dns {
    domain lan
    cache-size 10000
    auto-vips on
    auto-hosts on
    health-aware on
    upstream 1.1.1.1
    upstream 9.9.9.9
    forward corp.internal 192.168.99.1 via 192.168.1.10
    a nas.lan 192.168.1.50
    aaaa nas.lan fd00::50
    address *.k8s.lan 192.168.1.100
    cname media.lan sonarr.lan
    txt _acme-challenge.example.com "token-xyz"
    srv _minecraft._tcp.lan mc.lan:25565 priority 0 weight 5
    mx lan mail.lan priority 10
    ptr 192.168.1.50 nas.lan
    route linuxisos.org tracker.example.org via 192.168.1.10
    bypass plex.tv netflix.com from 192.168.1.10
    block doubleclick.net *.ads.example.com
}
"#;
        let cfg = parse_nftyfile(raw).expect("parse dns endpoint Nftyfile");
        assert!(cfg.has_any_dns_enabled());
        let dns = cfg.dns.as_ref().expect("dns config present");
        assert_eq!(dns.domain.as_deref(), Some("lan"));
        assert_eq!(dns.upstreams, vec!["1.1.1.1", "9.9.9.9"]);
        assert_eq!(dns.forward_zones.len(), 1);
        assert_eq!(dns.records.len(), 8);
        assert_eq!(dns.nft_rules.len(), 2);
        assert_eq!(dns.blocks.len(), 2);

        let (conf_txt, hosts_txt) = crate::features::compile_dnsmasq_config(&cfg, None);
        assert!(conf_txt.contains("listen-address=127.0.0.1"));
        assert!(conf_txt.contains("listen-address=192.168.1.4"));
        assert!(conf_txt.contains("listen-address=192.168.1.10"));
        assert!(conf_txt.contains("server=1.1.1.1"));
        let wg_iface = &cfg.gateways["192.168.1.10"].tunnels[0].iface;
        assert!(conf_txt.contains(&format!("server=/corp.internal/192.168.99.1@{}", wg_iface)));
        assert!(conf_txt.contains("host-record=nas.lan,192.168.1.50"));
        assert!(conf_txt.contains("host-record=nas.lan,fd00::50"));
        assert!(conf_txt.contains("address=/k8s.lan/192.168.1.100"));
        assert!(conf_txt.contains("cname=media.lan,sonarr.lan"));
        assert!(conf_txt.contains("txt-record=_acme-challenge.example.com,\"token-xyz\""));
        assert!(conf_txt.contains("srv-host=_minecraft._tcp.lan,mc.lan,25565,0,5"));
        assert!(conf_txt.contains("mx-host=lan,mail.lan,10"));
        assert!(conf_txt.contains("nftset=/linuxisos.org/tracker.example.org/4#ip#nfty#dns_route_192_168_1_10"));
        assert!(conf_txt.contains("nftset=/plex.tv/netflix.com/4#ip#nfty#dns_bypass_192_168_1_10"));
        assert!(conf_txt.contains("address=/doubleclick.net/0.0.0.0"));
        assert!(hosts_txt.contains("sonarr sonarr.lan sonarr.local"));

        let nft = compile_nft_ruleset(&cfg, None);
        assert!(nft.contains("set dns_route_192_168_1_10 {"));
        assert!(nft.contains("set dns_bypass_192_168_1_10 {"));
        assert!(nft.contains("ip daddr @dns_bypass_192_168_1_10 counter accept"));
        assert!(nft.contains("ip daddr @dns_route_192_168_1_10 jump mark_wg_0 accept"));

        let roundtrip = parse_nftyfile(&cfg.format_nftyfile()).expect("roundtrip dns Nftyfile");
        assert!(roundtrip.dns.is_some());
        assert_eq!(roundtrip.dns.as_ref().unwrap().records.len(), 8);
        assert_eq!(roundtrip.dns.as_ref().unwrap().nft_rules.len(), 2);
    }

    #[tokio::test]
    async fn test_scoped_api_service_and_keys_on_vip_and_gateway() {
        let shared: SharedState = Arc::new(RwLock::new(AppState::new(
            Config::new(),
            PathBuf::from("Nftyfile"),
        )));
        let level = Arc::new(Mutex::new(ShellLevel::Operational));

        handle_line("configure", &level, &shared).await;
        handle_line("vip 192.168.1.4/24", &level, &shared).await;
        handle_line("api:9090", &level, &shared).await;
        assert_eq!(
            *level.lock().unwrap(),
            ShellLevel::Service("192.168.1.4:9090".to_string())
        );
        handle_line("key new ro", &level, &shared).await;
        handle_line("key new rw", &level, &shared).await;
        handle_line("exit", &level, &shared).await;
        handle_line("exit", &level, &shared).await;

        handle_line("gateway 192.168.1.10/24", &level, &shared).await;
        handle_line("api:9091", &level, &shared).await;
        assert_eq!(
            *level.lock().unwrap(),
            ShellLevel::GatewayApi("192.168.1.10".to_string(), 9091)
        );
        handle_line("key nfty_ro_custom_gw_token ro", &level, &shared).await;
        handle_line("exit", &level, &shared).await;
        handle_line("exit", &level, &shared).await;

        let (ro_key, rw_key, formatted) = {
            let mut st = shared.write().unwrap();
            st.running = st.candidate.clone();
            let svc = &st.running.services["192.168.1.4:9090"];
            assert!(svc.is_local_api());
            assert_eq!(svc.api_keys.len(), 2);
            assert_eq!(svc.api_keys[0].scope, crate::ast::ApiKeyScope::ReadOnly);
            assert_eq!(svc.api_keys[1].scope, crate::ast::ApiKeyScope::ReadWrite);
            assert!(svc.api_keys[0].key.starts_with("nfty_ro_"));
            assert!(svc.api_keys[1].key.starts_with("nfty_rw_"));
            (
                svc.api_keys[0].key.clone(),
                svc.api_keys[1].key.clone(),
                st.running.format_nftyfile(),
            )
        };

        assert!(formatted.contains("api:9090 {"));
        assert!(formatted.contains(&format!("key {} ro", ro_key)));
        assert!(formatted.contains(&format!("key {} rw", rw_key)));
        assert!(formatted.contains("api:9091 {"));
        assert!(formatted.contains("key nfty_ro_custom_gw_token ro"));

        let reparsed = parse_nftyfile(&formatted).expect("roundtrip api:port Nftyfile");
        assert_eq!(
            reparsed.verify_api_key(&ro_key),
            Some(crate::ast::ApiKeyScope::ReadOnly)
        );
        assert_eq!(
            reparsed.verify_api_key(&rw_key),
            Some(crate::ast::ApiKeyScope::ReadWrite)
        );
        assert_eq!(
            reparsed.verify_api_key("nfty_ro_custom_gw_token"),
            Some(crate::ast::ApiKeyScope::ReadOnly)
        );

        // Verify read-only scope blocks write endpoints and redacts rw keys in GET /api/v1/config
        let (code_ro_get, body_ro_get) = crate::api::route_api_request_scoped(
            "GET",
            "/api/v1/config",
            "",
            &shared,
            crate::ast::ApiKeyScope::ReadOnly,
        )
        .await;
        assert_eq!(code_ro_get, 200);
        let body_ro_str = body_ro_get.to_string();
        assert!(body_ro_str.contains(&ro_key));
        assert!(!body_ro_str.contains(&rw_key));

        let (code_ro_post, _) = crate::api::route_api_request_scoped(
            "POST",
            "/api/v1/cli",
            r#"{"command": "status"}"#,
            &shared,
            crate::ast::ApiKeyScope::ReadOnly,
        )
        .await;
        assert_eq!(code_ro_post, 403);

        // Verify read-write scope allows writes and views all keys
        let (code_rw_get, body_rw_get) = crate::api::route_api_request_scoped(
            "GET",
            "/api/v1/config",
            "",
            &shared,
            crate::ast::ApiKeyScope::ReadWrite,
        )
        .await;
        assert_eq!(code_rw_get, 200);
        let body_rw_str = body_rw_get.to_string();
        assert!(body_rw_str.contains(&ro_key));
        assert!(body_rw_str.contains(&rw_key));
    }

    #[test]
    fn test_lossless_ast_roundtrip_edge_cases() {
        let raw = r#"
vip 192.168.1.4/20 {
    ssh:22 {
        limit 20/min burst 5 global
        allow {
            192.168.1.0/24
        }
    }
    dns:53 {
        limit 500/sec global
    }
    8080 to 192.168.2.50:8080 {
        check off
        limit 100/sec burst 10 global
    }
}
gateway 192.168.1.10/20 {
    balance sticky
    killswitch on
    check off
}
dns {
    domain off
    auto-vips on
    auto-hosts off
    no upstream
    txt _acme-challenge.example.com "v=spf1; include:example.com #1"
    block ads.example.com
}
"#;
        let cfg = parse_nftyfile(raw).expect("parse edge-case Nftyfile");
        assert_eq!(cfg.vips["192.168.1.4"].prefix_len, 20);
        assert_eq!(
            cfg.services["192.168.1.4:22"]
                .limit
                .as_ref()
                .unwrap()
                .per_ip,
            false
        );
        assert_eq!(
            cfg.services["192.168.1.4:22"].allow,
            vec!["192.168.1.0/24".to_string()]
        );
        assert_eq!(
            cfg.services["192.168.1.4:8080"].check,
            Some(crate::ast::HealthCheckConfig {
                kind: crate::ast::HealthCheckKind::Disabled,
                interval_secs: 5,
            })
        );
        let dns = cfg.dns.as_ref().expect("dns present");
        assert!(dns.domain.is_none());
        assert!(!dns.auto_hosts);
        assert!(dns.upstreams.is_empty());
        assert_eq!(
            dns.records,
            vec![crate::ast::DnsRecord::Txt {
                name: "_acme-challenge.example.com".to_string(),
                text: "v=spf1; include:example.com #1".to_string(),
            }]
        );

        let formatted = cfg.format_nftyfile();
        let reparsed = parse_nftyfile(&formatted).expect("reparse edge-case Nftyfile");
        assert_eq!(cfg, reparsed);

        let (dnsmasq_conf, _) = crate::features::compile_dnsmasq_config(&reparsed, None);
        assert!(dnsmasq_conf.contains("no-hosts\n"));
        assert!(!dnsmasq_conf.contains("server=1.1.1.1"));
        assert!(dnsmasq_conf.contains("address=/ads.example.com/0.0.0.0\n"));
        assert!(dnsmasq_conf.contains("address=/ads.example.com/::\n"));
    }

    #[test]
    fn test_partial_inline_wg_tunnel_rejected() {
        let bad = r#"
gateway 192.168.1.10 {
    tunnels {
        tun0 address 10.64.0.2/32 privkey AAAA
    }
}
"#;
        let res = parse_nftyfile(bad);
        assert!(res.is_err());
        let err_msg = format!("{:#}", res.unwrap_err());
        assert!(err_msg.contains("requires all four parameters"));
    }

    #[test]
    fn test_drained_backends_fail_closed() {
        let raw = r#"
service 192.168.1.240:80 {
    to {
        192.168.1.101:80
        192.168.1.102:80 backup
    }
}
"#;
        let cfg = parse_nftyfile(raw).expect("parse service");
        let mut st = AppState::new(cfg.clone(), PathBuf::from("Nftyfile"));
        let svc = &cfg.services["192.168.1.240:80"];

        // Drain primary -> should fail over to non-drained backup
        st.runtime
            .entry("192.168.1.101:80".to_string())
            .or_default()
            .drained = true;
        let active1 = st.active_backends_for_service(&svc.backends);
        assert_eq!(active1.len(), 1);
        assert_eq!(active1[0].endpoint(), "192.168.1.102:80");

        // Drain backup too -> must return empty (fail-closed) and never route to drained backends
        st.runtime
            .entry("192.168.1.102:80".to_string())
            .or_default()
            .drained = true;
        let active2 = st.active_backends_for_service(&svc.backends);
        assert!(active2.is_empty());
    }

    #[test]
    fn test_down_backends_are_not_selected() {
        let cfg = parse_nftyfile(
            "service 80 {\n to {\n  192.0.2.1:80\n  192.0.2.2:80 backup\n }\n}\n",
        )
        .unwrap();
        let mut st = AppState::new(cfg.clone(), PathBuf::from("Nftyfile"));
        let svc = &cfg.services["80"];
        st.runtime.get_mut("192.0.2.1:80").unwrap().health = HealthState::Down;
        assert_eq!(st.active_backends_for_service(&svc.backends)[0].endpoint(), "192.0.2.2:80");
        st.runtime.get_mut("192.0.2.2:80").unwrap().health = HealthState::Down;
        assert!(st.active_backends_for_service(&svc.backends).is_empty());
    }

    #[test]
    fn test_empty_running_config_does_not_activate_candidate() {
        let mut st = AppState::new(Config::new(), PathBuf::from("Nftyfile"));
        st.candidate = parse_nftyfile("service 80 {\n to 192.0.2.1:80\n}\n").unwrap();
        assert!(st.active_config().is_empty());
    }

    #[test]
    fn test_api_keys_are_scoped_to_listener_ports() {
        let cfg = parse_nftyfile(
            "allow 192.0.2.0/24\n\
             vip 192.0.2.10 {\n\
               api:8001 {\n key first rw\n }\n\
               api:8002 {\n key second ro\n }\n\
             }\n",
        )
        .unwrap();
        assert_eq!(
            cfg.verify_api_key_for_port("first", 8001),
            Some(crate::ast::ApiKeyScope::ReadWrite)
        );
        assert_eq!(cfg.verify_api_key_for_port("first", 8002), None);
        assert_eq!(
            cfg.verify_api_key_for_port("second", 8002),
            Some(crate::ast::ApiKeyScope::ReadOnly)
        );
    }

    #[test]
    fn test_readonly_config_redacts_inline_secrets() {
        let cfg = parse_nftyfile(
            "service 80 {\n to 192.0.2.1:80\n cloudflare-auth ops@example.com\n}\n\
             gateway 192.0.2.5 {\n tunnels {\n\
             tunnel address 10.0.0.2/32 privkey private-secret peer peer-key endpoint 192.0.2.2:51820\n\
             }\n}\n",
        )
        .unwrap();
        let redacted = cfg.redacted_for_readonly();
        let json = serde_json::to_string(&redacted).unwrap();
        let text = redacted.format_nftyfile();
        for secret in ["ops@example.com", "private-secret"] {
            assert!(!json.contains(secret));
            assert!(!text.contains(secret));
        }
    }

    #[test]
    fn test_unclosed_blocks_are_rejected() {
        for raw in [
            "dns {\n upstream 192.0.2.53\n",
            "vip 192.0.2.4 {\n",
            "service 80 {\n to {\n 192.0.2.1:80\n }\n",
            "gateway 192.0.2.5 {\n tunnels {\n",
        ] {
            assert!(parse_nftyfile(raw).is_err(), "accepted {raw:?}");
        }
    }

    #[test]
    fn test_explicit_dns_upstreams_replace_defaults() {
        let cfg = parse_nftyfile(
            "dns {\n upstream 1.1.1.1 9.9.9.9\n upstream 192.0.2.53\n}\n",
        )
        .unwrap();
        assert_eq!(
            cfg.dns.as_ref().unwrap().upstreams,
            vec!["1.1.1.1", "9.9.9.9", "192.0.2.53"]
        );
        let custom = parse_nftyfile("dns {\n upstream 192.0.2.53\n}\n").unwrap();
        assert_eq!(custom.dns.unwrap().upstreams, vec!["192.0.2.53"]);
    }

    #[test]
    fn test_uncommitted_candidate_api_key_not_authenticated() {
        let committed = parse_nftyfile(
            r#"
vip 192.168.1.4 {
    api:9090 {
        allow {
            10.0.0.0/8
        }
        key nfty_rw_committed_token rw
    }
}
"#,
        )
        .unwrap();
        let candidate = parse_nftyfile(
            r#"
vip 192.168.1.4 {
    api:9090 {
        allow {
            10.0.0.0/8
        }
        key nfty_rw_committed_token rw
        key nfty_rw_uncommitted_candidate rw
    }
}
"#,
        )
        .unwrap();
        let mut app_state = AppState::new(committed, PathBuf::from("Nftyfile"));
        app_state.candidate = candidate;
        let shared: SharedState = Arc::new(RwLock::new(app_state));

        let client = Some("10.0.0.5".parse().unwrap());
        assert_eq!(
            crate::api::authenticate_api_request_with_context(
                &shared,
                Some("nfty_rw_committed_token"),
                client,
                Some(9090),
            ),
            Ok(crate::ast::ApiKeyScope::ReadWrite)
        );
        assert!(crate::api::authenticate_api_request_with_context(
            &shared,
            Some("nfty_rw_uncommitted_candidate"),
            client,
            Some(9090),
        )
        .is_err());
    }

    #[test]
    fn test_web_service_with_allowlist_and_roundtrip() {
        let raw = r#"
vip 192.168.1.4 {
    ssh:22
    web:8000 {
        allow {
            192.168.0.0/16
        }
    }
    api:8080 {
        allow {
            192.168.0.0/16
        }
        key nfty_ro_5a2d949e15250c395c4b9683833c5bc3 ro
    }
}
"#;
        let cfg = parse_nftyfile(raw).unwrap();
        let formatted = cfg.format_nftyfile();
        assert!(formatted.contains("web:8000 {"));
        assert!(formatted.contains("192.168.0.0/16"));
        let reparsed = parse_nftyfile(&formatted).unwrap();
        assert_eq!(cfg, reparsed);

        let app_state = AppState::new(cfg.clone(), PathBuf::from("Nftyfile"));
        let shared: SharedState = Arc::new(RwLock::new(app_state));

        // 1. Client inside 192.168.0.0/16 accessing web:8000 without API key -> ReadWrite allowed
        assert_eq!(
            crate::api::authenticate_api_request_with_context(
                &shared,
                None,
                Some("192.168.1.50".parse().unwrap()),
                Some(8000),
            ),
            Ok(crate::ast::ApiKeyScope::ReadWrite)
        );

        // 2. Client outside 192.168.0.0/16 accessing web:8000 -> 403 Forbidden
        assert_eq!(
            crate::api::authenticate_api_request_with_context(
                &shared,
                None,
                Some("10.0.0.50".parse().unwrap()),
                Some(8000),
            )
            .unwrap_err()
            .0,
            403
        );

        // 3. Client accessing keyed api:8080 without key -> 401 Unauthorized
        assert_eq!(
            crate::api::authenticate_api_request_with_context(
                &shared,
                None,
                Some("192.168.1.50".parse().unwrap()),
                Some(8080),
            )
            .unwrap_err()
            .0,
            401
        );

        // 4. Strict separation: port 8000 is a web port, port 8080 is an API-only port
        assert!(cfg.is_web_port(Some(8000)));
        assert!(!cfg.is_web_port(Some(8080)));

        // 5. Compiled nftables ruleset enforces @allow_192_168_1_4_8000 on tcp dport 8000
        let st = shared.read().unwrap();
        let nft = compile_nft_ruleset(&cfg, Some(&st));
        assert!(nft.contains("set allow_192_168_1_4_8000"));
        assert!(nft.contains("elements = { 192.168.0.0/16 }"));
        assert!(nft.contains("ip daddr 192.168.1.4 tcp dport 8000 ip saddr @allow_192_168_1_4_8000 counter redirect to :8000"));
    }

    fn control_auth(
        shared: &SharedState,
        peer: &str,
        port: u16,
    ) -> std::result::Result<crate::ast::ApiKeyScope, (u16, String)> {
        let peer: Ipv4Addr = peer.parse().unwrap();
        crate::api::authenticate_api_request_with_context(
            shared,
            None,
            Some(peer),
            Some(port),
        )
    }

    fn shared_from(raw: &str) -> SharedState {
        let cfg = parse_nftyfile(raw).unwrap();
        Arc::new(RwLock::new(AppState::new(cfg, PathBuf::from("Nftyfile"))))
    }

    #[test]
    fn test_web_and_api_listeners_require_ip_allow_list() {
        // No allow-list anywhere: not appliable, and remote clients are denied at runtime.
        let open = r#"
vip 192.168.1.4 {
    web:8000
    api:8080
}
"#;
        let cfg = parse_nftyfile(open).unwrap();
        let errors = cfg.control_allow_list_errors();
        assert_eq!(errors.len(), 2, "{errors:?}");
        assert!(errors.iter().all(|e| e.contains("requires an IP allow-list")));
        let shared = shared_from(open);
        assert_eq!(control_auth(&shared, "192.168.1.50", 8000).unwrap_err().0, 403);
        assert_eq!(control_auth(&shared, "192.168.1.50", 8080).unwrap_err().0, 403);
        // Loopback gets no implicit trust; local tooling uses the controller Unix socket.
        assert_eq!(control_auth(&shared, "127.0.0.1", 8000).unwrap_err().0, 403);

        // Hostname entries are rejected for web/api listeners and never grant access.
        let hostname = r#"
vip 192.168.1.4 {
    web:8000 {
        allow {
            *.office.lan
        }
    }
}
"#;
        let cfg = parse_nftyfile(hostname).unwrap();
        let errors = cfg.control_allow_list_errors();
        assert!(errors.iter().any(|e| e.contains("'*.office.lan' is not an IP")), "{errors:?}");
        assert!(errors.iter().any(|e| e.contains("requires an IP allow-list")), "{errors:?}");
        let shared = shared_from(hostname);
        shared
            .write()
            .unwrap()
            .resolved_hosts
            .insert("laptop.office.lan".to_string(), vec!["192.168.1.50".parse().unwrap()]);
        assert_eq!(control_auth(&shared, "192.168.1.50", 8000).unwrap_err().0, 403);

        // A global IP allow-list satisfies the requirement.
        let global = r#"
allow 192.168.0.0/16
vip 192.168.1.4 {
    web:8000
    api:8080 {
        key nfty_ro_5a2d949e15250c395c4b9683833c5bc3 ro
    }
}
"#;
        let cfg = parse_nftyfile(global).unwrap();
        assert!(cfg.control_allow_list_errors().is_empty());
        let shared = shared_from(global);
        assert_eq!(
            control_auth(&shared, "192.168.1.50", 8000),
            Ok(crate::ast::ApiKeyScope::ReadWrite)
        );
        assert_eq!(control_auth(&shared, "10.0.0.50", 8000).unwrap_err().0, 403);
        // Allow-listed but keyed: a key is still required.
        assert_eq!(control_auth(&shared, "192.168.1.50", 8080).unwrap_err().0, 401);
        // A port with no web/api listener is closed to remote clients.
        assert_eq!(control_auth(&shared, "192.168.1.50", 9090).unwrap_err().0, 403);
    }

    #[test]
    fn test_validate_rejects_web_listener_without_allow_list() {
        let cfg = parse_nftyfile("vip 192.168.1.4 {\n    web:8000\n}\n").unwrap();
        let report = validate_config(&cfg, None);
        assert!(!report.valid);
        assert!(report.errors.iter().any(|e| e.contains("web:8000") && e.contains("requires an IP allow-list")));
    }

    #[test]
    fn test_tunnel_identity_is_stable_across_gateways_and_order() {
        let a = crate::parser::parse_wg_tunnel(&["exit.conf"], "gateway-a").unwrap();
        let b = crate::parser::parse_wg_tunnel(&["exit.conf"], "gateway-b").unwrap();
        let a_again = crate::parser::parse_wg_tunnel(&["exit.conf"], "gateway-a").unwrap();
        assert_eq!(a.iface, a_again.iface);
        assert_ne!(a.iface, b.iface);
        let explicit = crate::parser::parse_wg_tunnel(&["wg153"], "gateway-a").unwrap();
        assert_eq!(explicit.iface, "wg153");
        let index = crate::features::wireguard::wireguard_iface_index(&explicit.iface).unwrap();
        assert_ne!(crate::features::wireguard::wireguard_table_id(index), 254);
    }

    #[test]
    fn test_removed_service_auth_directives_are_rejected() {
        let error = parse_nftyfile(
            "service 192.0.2.10:80 {\n to 192.0.2.20:8080\n auth alice:secret\n}\n",
        ).err().unwrap();
        assert!(format!("{:#}", error).contains("removed"));
        for rule in ["nfty", "alice:secret", "example.com", "a@b@example.com"] {
            let raw = format!("service 192.0.2.10:80 {{\n cloudflare-auth {}\n}}\n", rule);
            assert!(parse_nftyfile(&raw).is_err(), "{} should be rejected", rule);
        }
        let cfg = parse_nftyfile(
            "service 192.0.2.10:80 {\n cloudflare-auth ops@example.com *@example.org\n}\n",
        ).unwrap();
        let svc = cfg.services.values().next().unwrap();
        assert_eq!(svc.cloudflare_auth, vec!["ops@example.com", "*@example.org"]);
    }
    #[test]
    fn test_down_service_only_shares_healthy_l7_routing_on_tcp() {
        fn service(
            key: &str,
            port: u16,
            proto: crate::ast::Proto,
            ip: Ipv4Addr,
        ) -> crate::ast::Service {
            let mut svc = crate::ast::Service::new(
                key.to_string(),
                Some(Ipv4Addr::new(192, 0, 2, 10)),
                port,
                proto,
            );
            svc.hostname = Some(format!("{}.example", key));
            svc.backends.push(crate::ast::Backend {
                host: None,
                ip,
                port,
                weight: 1,
                backup: false,
            });
            svc
        }

        let mut cfg = Config::new();
        cfg.services.insert(
            "a".to_string(),
            service("a", 1234, crate::ast::Proto::Tcp, Ipv4Addr::new(192, 0, 2, 21)),
        );
        cfg.services.insert(
            "b".to_string(),
            service("b", 1234, crate::ast::Proto::Tcp, Ipv4Addr::new(192, 0, 2, 22)),
        );
        let mut state = AppState::new(cfg.clone(), PathBuf::from("Nftyfile"));
        state.runtime.get_mut(&cfg.services["a"].backends[0].endpoint()).unwrap().health =
            HealthState::Down;
        let rules = compile_nft_ruleset(&cfg, Some(&state));
        assert!(rules.contains("tcp dport 1234 counter drop"));

        cfg.services.insert(
            "a".to_string(),
            service("a", 80, crate::ast::Proto::Both, Ipv4Addr::new(192, 0, 2, 21)),
        );
        cfg.services.insert(
            "b".to_string(),
            service("b", 80, crate::ast::Proto::Tcp, Ipv4Addr::new(192, 0, 2, 22)),
        );
        let mut state = AppState::new(cfg.clone(), PathBuf::from("Nftyfile"));
        state.runtime.get_mut(&cfg.services["a"].backends[0].endpoint()).unwrap().health =
            HealthState::Down;
        let rules = compile_nft_ruleset(&cfg, Some(&state));
        let down_section = rules
            .split("# service a (no eligible backends)")
            .nth(1)
            .unwrap()
            .split("# --- service b ---")
            .next()
            .unwrap();
        assert!(down_section.contains("udp dport 80 counter drop"));
        assert!(!down_section.contains("tcp dport 80 counter drop"));
        assert!(rules.contains("redirect to :80"));

        cfg.services.insert(
            "a".to_string(),
            service("a", 80, crate::ast::Proto::Tcp, Ipv4Addr::new(192, 0, 2, 21)),
        );
        cfg.services.insert(
            "b".to_string(),
            service("b", 80, crate::ast::Proto::Udp, Ipv4Addr::new(192, 0, 2, 22)),
        );
        let state = AppState::new(cfg.clone(), PathBuf::from("Nftyfile"));
        let rules = compile_nft_ruleset(&cfg, Some(&state));
        assert!(!rules.contains("redirect to :80"));
    }

    #[test]
    fn test_dns_blocklist_name_cannot_escape_list_directory() {
        assert!(parse_nftyfile("dns {\n blocklist ../outside https://example.com/list\n}\n").is_err());
        assert!(parse_nftyfile("dns {\n blocklist ads.example https://example.com/list\n}\n").is_ok());
    }

    #[test]
    fn test_dhcp_interface_name_collisions_are_rejected() {
        let cfg = parse_nftyfile("vip a.b {\n dhcp eth0\n}\nvip ab {\n dhcp eth0\n}\n").unwrap();
        let mut state = AppState::new(Config::new(), PathBuf::from("Nftyfile"));
        let error = apply_config(&mut state, cfg).err().unwrap().to_string();
        assert!(error.contains("collide on interface"));
        assert!(state.running.is_empty());
    }

    #[test]
    fn test_host_mapping_requires_a_concrete_hostname() {
        assert_eq!(
            crate::parser::validate_host_mapping_name("Node.Example").unwrap(),
            "node.example"
        );
        for invalid in ["", "*.example", "192.0.2.1", "a..example", "x\n0.0.0.0"] {
            assert!(crate::parser::validate_host_mapping_name(invalid).is_err());
        }
    }

    #[test]
    fn test_default_dhcp_rejects_non_primary_interface() {
        let cfg = parse_nftyfile("gateway default {\n dhcp eth1\n}\n").unwrap();
        let mut state = AppState::new(Config::new(), PathBuf::from("Nftyfile"));
        let error = apply_config(&mut state, cfg).err().unwrap().to_string();
        assert!(error.contains("must be eth0"));
        assert!(state.running.is_empty());
    }

    #[test]
    fn test_dns_does_not_fall_back_when_gateway_is_down() {
        let cfg = parse_nftyfile(
            "gateway 192.0.2.10 {\n dns:53\n tunnels {\n exit.conf\n }\n}\n\
             dns {\n upstream 1.1.1.1\n forward corp.internal 192.0.2.53 via 192.0.2.10\n}\n",
        ).unwrap();
        let mut state = AppState::new(cfg.clone(), PathBuf::from("Nftyfile"));
        let tunnel = &cfg.gateways["192.0.2.10"].tunnels[0];
        state.runtime.get_mut(&tunnel.endpoint_key()).unwrap().health = HealthState::Down;
        let (config, _) = crate::features::compile_dnsmasq_config(&cfg, Some(&state));
        assert!(!config.contains("server=1.1.1.1"));
        assert!(!config.contains("server=/corp.internal/192.0.2.53"));
        assert!(config.contains("local=/corp.internal/"));
    }

    #[test]
    fn test_cloudflare_access_verification_is_per_host() {
        let cfg = parse_nftyfile(
            "service 192.0.2.10:80 {\n to 192.0.2.20:8080\n cloudflare-dns app.example.com\n cloudflare-auth ops@example.com\n}\n",
        ).unwrap();
        let mut cf = crate::features::CloudflareConfig::default();
        cf.protected_access_hosts.insert("other.example.com".to_string());
        let routes = crate::features::cloudflare::collect_cloudflare_routes_with_config(&cfg, &cf);
        assert_eq!(routes[0].2, "http_status:403");
        cf.protected_access_hosts.insert("app.example.com".to_string());
        let routes = crate::features::cloudflare::collect_cloudflare_routes_with_config(&cfg, &cf);
        assert_eq!(routes[0].2, "http://192.0.2.20:8080");
    }

    #[test]
    fn test_default_dhcp_gateway_and_lan_anti_loop_rules() {
        assert_eq!(crate::compiler::dhcp_macvlan_iface_name("default"), "eth0");
        assert_eq!(crate::compiler::dhcp_macvlan_iface_name("my-gw"), "mv-my-gw");

        let raw = r#"
gateway default {
    dhcp eth0
    ssh:22
}
gateway 192.168.1.10 {
    killswitch on
    tunnels {
        wg0.conf
    }
}
"#;
        let cfg = parse_nftyfile(raw).unwrap();
        assert!(cfg.gateways.contains_key("default"));
        let nft = compile_nft_ruleset(&cfg, None);
        assert!(nft.contains("meta pkttype { broadcast, multicast } accept"));
        assert!(nft.contains("ip daddr { 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 255.255.255.255 } accept"));
        assert!(nft.contains("meta pkttype { broadcast, multicast } drop"));
        assert!(nft.contains("oifname { \"eth0\", \"mv-*\" } ip daddr { 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 255.255.255.255 } drop"));
        assert!(nft.contains("oifname \"eth0\" ip saddr != 127.0.0.0/8 ip daddr != { 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 255.255.255.255 } counter masquerade comment \"nfty:direct-gw-nat\""));
    }

    #[tokio::test]
    async fn test_debug_mode_and_non24_prefix_persistence() {
        let state = AppState::new(Config::new(), PathBuf::from("Nftyfile"));

        let shared: SharedState = Arc::new(RwLock::new(state));
        let level = Arc::new(Mutex::new(ShellLevel::Operational));

        handle_line("debug", &level, &shared).await;
        assert_eq!(*level.lock().unwrap(), ShellLevel::Debug);
        assert_eq!(level.lock().unwrap().prompt(), "nfty(debug)# ");

        handle_line("..", &level, &shared).await;
        assert_eq!(*level.lock().unwrap(), ShellLevel::Operational);

        handle_line("debug", &level, &shared).await;
        assert_eq!(*level.lock().unwrap(), ShellLevel::Debug);

        handle_line("configure", &level, &shared).await;
        assert_eq!(*level.lock().unwrap(), ShellLevel::ConfigRoot);

        handle_line("vip 192.168.1.4/21", &level, &shared).await;
        handle_line("ssh:22", &level, &shared).await;
        handle_line("..", &level, &shared).await;
        handle_line("gateway 192.168.1.10/21", &level, &shared).await;
        handle_line("ssh:22", &level, &shared).await;

        let formatted = shared.read().unwrap().candidate.format_nftyfile();
        assert!(
            formatted.contains("interface eth0/21"),
            "Formatted Nftyfile must always preserve non-/24 prefix: {formatted}"
        );
    }

    #[tokio::test]
    async fn test_wireguard_ingress_endpoint_and_qr_generation() {
        let state = AppState::new(Config::new(), PathBuf::from("Nftyfile"));
        let shared: SharedState = Arc::new(RwLock::new(state));
        let level = Arc::new(Mutex::new(ShellLevel::Operational));

        handle_line("configure", &level, &shared).await;
        handle_line("gateway 169.254.10.10/24", &level, &shared).await;
        handle_line("dns:53", &level, &shared).await;
        handle_line("wg-in:51820", &level, &shared).await;
        assert_eq!(
            *level.lock().unwrap(),
            ShellLevel::GatewayWgIngress("169.254.10.10".to_string(), 51820)
        );
        handle_line("subnet 10.99.0.1/24", &level, &shared).await;
        handle_line("endpoint vpn.example.com:51820", &level, &shared).await;
        handle_line("split-tunnel full", &level, &shared).await;
        handle_line("peer add laptop", &level, &shared).await;
        let (_, ext_pubkey) = crate::features::generate_wg_keypair();
        handle_line(&format!("peer add phone pubkey {}", ext_pubkey), &level, &shared).await;

        let formatted = {
            let st = shared.read().unwrap();
            let gw = &st.candidate.gateways["169.254.10.10"];
            let wg_in = gw.wg_ingress.as_ref().expect("wg_ingress configured");
            assert_eq!(wg_in.port, 51820);
            assert_eq!(wg_in.peers.len(), 2);
            assert_eq!(wg_in.peers[0].name, "laptop");
            assert_eq!(wg_in.peers[0].ip, Ipv4Addr::new(10, 99, 0, 2));
            assert_eq!(wg_in.peers[1].name, "phone");
            assert_eq!(wg_in.peers[1].ip, Ipv4Addr::new(10, 99, 0, 3));
            assert_eq!(wg_in.peers[1].public_key, ext_pubkey);

            let client_conf =
                crate::features::build_client_wg_conf(&st.candidate, gw, "laptop").unwrap();
            assert!(client_conf.contains("Address = 10.99.0.2/24"));
            assert!(client_conf.contains("DNS = 10.99.0.1"));
            assert!(client_conf.contains("Endpoint = vpn.example.com:51820"));
            assert!(client_conf.contains("AllowedIPs = 0.0.0.0/0"));
            assert!(!client_conf.contains("<INSERT_CLIENT_PRIVATE_KEY>"));

            let qr = crate::features::render_qr_unicode(&client_conf).unwrap();
            assert!(qr.contains('█'));

            let nft = compile_nft_ruleset(&st.candidate, None);
            assert!(nft.contains("iifname \"ig*\" counter accept comment \"nfty:wg-ingress-forward\""));
            assert!(nft.contains("oifname \"ig*\" ct state established,related counter accept"));
            assert!(nft.contains("iifname \"ig*\" oifname { \"eth0\", \"mv-*\" } counter masquerade comment \"nfty:wg-ingress-nat\""));

            let (dns_conf, _) = crate::features::compile_dnsmasq_config(&st.candidate, None);
            assert!(dns_conf.contains("listen-address=10.99.0.1"));

            st.candidate.format_nftyfile()
        };

        let reparsed = parse_nftyfile(&formatted).expect("round-trip parse");
        assert_eq!(reparsed.format_nftyfile(), formatted);
    }

    #[tokio::test]
    async fn test_security_review_hardening_regressions() {
        // 1. Loopback is subject to the listener IP allow-list
        let shared = shared_from("vip 192.168.1.4 {\n    web:8000 {\n        allow 192.168.1.0/24\n    }\n}\n");
        assert_eq!(
            crate::api::authenticate_api_request_with_context(
                &shared,
                None,
                Some(Ipv4Addr::LOCALHOST),
                Some(8000),
            )
            .unwrap_err()
            .0,
            403
        );

        // 2. Gateway allow emits nfty:gw-policy-drop for ssh:22 and web:8000
        let gw_cfg = parse_nftyfile(
            "gateway 192.168.1.10 {\n    allow 192.168.1.0/24\n    ssh:22\n    web:8000\n}\n",
        )
        .unwrap();
        let gw_nft = compile_nft_ruleset(&gw_cfg, None);
        assert!(gw_nft.contains("nfty:gw-policy-drop=192.168.1.10:22"));
        assert!(gw_nft.contains("nfty:gw-policy-drop=192.168.1.10:8000"));

        // 3. cloudflare-dns on web:/api: control listeners is rejected
        let cf_web = parse_nftyfile(
            "vip 192.168.1.4 {\n    web:8000 {\n        allow 192.168.1.0/24\n        cloudflare-dns nfty.example.com\n    }\n}\n",
        )
        .unwrap();
        assert!(cf_web
            .control_allow_list_errors()
            .iter()
            .any(|e| e.contains("cloudflare-dns cannot be used on a web:/api: control listener")));

        // 4. Host / Origin authority validation blocks DNS rebinding domains
        let st = shared.read().unwrap();
        assert!(st
            .active_config()
            .is_trusted_control_authority("192.168.1.4:8000", &st.resolved_hosts));
        assert!(st
            .active_config()
            .is_trusted_control_authority("nfty.local:8000", &st.resolved_hosts));
        assert!(!st
            .active_config()
            .is_trusted_control_authority("evil.attacker.example:8000", &st.resolved_hosts));
        drop(st);

        // 5. /api/v1/cli blocks custom save/load paths and every stdin prompt (key paste, password)
        for blocked_cmd in [
            r#"{"command":"save /data/auth.json"}"#,
            r#"{"command":"load /etc/passwd"}"#,
            r#"{"command":"ssh add workstation"}"#,
            r#"{"command":"wg add mullvad"}"#,
            r#"{"command":"gateway gw1; tunnels; add mullvad"}"#,
            r#"{"command":"password"}"#,
        ] {
            let (status, _) =
                crate::api::route_api_request("POST", "/api/v1/cli", blocked_cmd, &shared).await;
            assert_eq!(status, 400, "expected 400 for {blocked_cmd}");
        }

        // 6. Iterated salted PBKDF-v2 password hashing and legacy v1 verification
        let h1 = crate::ssh::hash_password("hunter2");
        let h2 = crate::ssh::hash_password("hunter2");
        assert!(h1.starts_with("nfty-pbkdf-v2$"));
        assert_ne!(h1, h2, "random salt should produce distinct hashes");
        assert!(crate::ssh::verify_password_hash("hunter2", &h1));
        assert!(!crate::ssh::verify_password_hash("wrong", &h1));
    }
}
