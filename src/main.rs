pub mod api;
pub mod ast;
pub mod compiler;
pub mod features;
pub mod health;
pub mod parser;
pub mod repl;
pub mod ssh;
pub mod state;
pub mod tui;
pub mod unikernel;

use crate::api::spawn_api_server;
use crate::ast::Config;
use crate::compiler::{
    apply_vip_commands, compile_nft_ruleset, generate_vip_commands, reconcile_dhcp_and_vlan_vips,
    reload_kernel_from_state, validate_config,
};
use crate::health::{refresh_allowlist_hosts, run_all_probes_once, spawn_background_tasks};
use crate::parser::parse_nftyfile;
use crate::repl::{handle_line, print_status_table, run_repl, ShellLevel};
use crate::ssh::{enforce_first_login_password_change_if_needed, spawn_ssh_server};
use crate::state::{AppState, SharedState};
use crate::tui::run_watch_dashboard;
use crate::unikernel::{init_unikernel_appliance, persist_to_storage, spawn_unikernel_dataplane};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::collections::BTreeMap;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "nfty",
    version = "0.1.0",
    about = "Caddy-style L4 Service Load Balancer & Port Router shell, API, and Unikernel for nftables"
)]
struct Cli {
    /// Path to Nftyfile configuration
    #[arg(short, long, default_value = "Nftyfile")]
    file: PathBuf,

    /// Bind address for the 1:1 HTTP/JSON Control API
    #[arg(long, default_value = "0.0.0.0:9090")]
    api_bind: String,

    /// Bind address for the embedded SSH2 appliance server
    #[arg(long, default_value = "0.0.0.0:22")]
    ssh_bind: String,

    /// Internal flag for an interactive SSH session (enforces first-login password change)
    #[arg(long, hide = true)]
    ssh_session: bool,

    /// Boot in Unikernel / Appliance mode (mounts /proc, /sys, /data if PID 1, enables native Rust L4 dataplane)
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
    /// Open the live terminal dashboard (TUI)
    Watch,
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
    let is_unikernel = cli.unikernel || is_pid1;

    let mut effective_file = cli.file.clone();
    if is_unikernel {
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

    let initial_cfg = if effective_file.exists() {
        let raw = fs::read_to_string(&effective_file)
            .with_context(|| format!("Failed to read {}", effective_file.display()))?;
        parse_nftyfile(&raw)
            .with_context(|| format!("Failed to parse {}", effective_file.display()))?
    } else {
        Config::new()
    };

    let mut app_state = AppState::new(initial_cfg, effective_file.clone());
    app_state.api_bind = cli.api_bind.clone();

    // Load persisted wildcard host resolutions from /data/hosts.json if present
    if Path::new("/data/hosts.json").exists() {
        if let Ok(raw_hosts) = fs::read_to_string("/data/hosts.json") {
            if let Ok(parsed_hosts) =
                serde_json::from_str::<BTreeMap<String, Vec<Ipv4Addr>>>(&raw_hosts)
            {
                app_state.resolved_hosts = parsed_hosts;
            }
        }
    }

    let shared: SharedState = Arc::new(RwLock::new(app_state));

    if is_unikernel {
        spawn_ssh_server(cli.ssh_bind.clone());
        // Auto-apply initial config on unikernel boot before starting background tasks
        let kernel_nft_active = {
            let mut st = shared.write().unwrap();
            let _ = reconcile_dhcp_and_vlan_vips(&mut st.candidate);
            let vip_cmds = generate_vip_commands(&Config::new(), &st.candidate);
            let _ = apply_vip_commands(&vip_cmds);
            st.running = st.candidate.clone();
            let _ = reload_kernel_from_state(&mut st);
            st.kernel_applied
        };
        if !kernel_nft_active {
            spawn_unikernel_dataplane(shared.clone());
        }
        crate::features::spawn_advanced_feature_daemons(shared.clone());
    }
    spawn_background_tasks(shared.clone());
    spawn_api_server(shared.clone(), cli.api_bind.clone());

    if cli.ssh_session {
        enforce_first_login_password_change_if_needed()?;
    }

    if let Some(script) = cli.command {
        let level = Arc::new(Mutex::new(ShellLevel::Operational));
        for cmd in script.lines().flat_map(|l| l.split(';')) {
            let trimmed = cmd.trim();
            if !trimmed.is_empty() && handle_line(trimmed, &level, &shared).await {
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
                let vip_cmds = generate_vip_commands(&Config::new(), &st.candidate);
                let _ = apply_vip_commands(&vip_cmds);
                st.running = st.candidate.clone();
                let _ = reload_kernel_from_state(&mut st);
            }
            persist_to_storage(&shared);
            println!(
                "nfty daemon running (API: http://{}, Config: {})",
                cli.api_bind,
                effective_file.display()
            );
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        }
        Commands::Watch => {
            run_watch_dashboard(shared).await?;
        }
        Commands::Status => {
            refresh_allowlist_hosts(&shared).await;
            let _ = run_all_probes_once(&shared).await;
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
            {
                let mut st = shared.write().unwrap();
                let vip_cmds = generate_vip_commands(&Config::new(), &st.candidate);
                for log in apply_vip_commands(&vip_cmds) {
                    println!("{}", log);
                }
                st.running = st.candidate.clone();
                let msg = reload_kernel_from_state(&mut st)?;
                println!("{}", msg);
            }
            persist_to_storage(&shared);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::route_api_request;
    use crate::state::HealthState;

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

        handle_line("80 to 169.254.3.165:9090", &level, &shared).await;
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
        assert!(!formatted.contains("vip eth0/21"));
        assert!(formatted.contains("192.168.1.165:32400 {"));
        assert!(formatted.contains("80 to 169.254.3.165:9090 {"));

        let reparsed = parse_nftyfile(&formatted).expect("reparse formatted vip Nftyfile");
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

    #[tokio::test]
    async fn test_multi_vhost_and_adopt_and_dhcp_gateway() {
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
    privoxy:8118
}
"#;
        let cfg = parse_nftyfile(raw).expect("parse multi-vhost + dhcp gateway");
        assert_eq!(cfg.services.len(), 2);
        assert!(cfg.gateways["mullvad"].vip.as_ref().unwrap().dhcp);
        assert_eq!(cfg.gateways["mullvad"].vip.as_ref().unwrap().vlan, Some(30));

        let nft = compile_nft_ruleset(&cfg, None);
        assert!(nft.contains("redirect to :80"));

        let shared: SharedState = Arc::new(RwLock::new(AppState::new(
            Config::new(),
            PathBuf::from("Nftyfile"),
        )));
        {
            let mut st = shared.write().unwrap();
            st.discovered_services.push(crate::state::DiscoveredService {
                index: 1,
                host: Some("app-backend".to_string()),
                ip: Ipv4Addr::new(169, 254, 2, 215),
                port: 8989,
                service_name: "sonarr".to_string(),
                banner: "Sonarr".to_string(),
                latency_ms: 0.4,
            });
        }
        let level = Arc::new(Mutex::new(ShellLevel::ConfigRoot));
        handle_line("adopt 1", &level, &shared).await;
        let st = shared.read().unwrap();
        assert!(st.candidate.vips.contains_key("sonarr"));
        assert!(st.candidate.vips["sonarr"].dhcp);
        assert!(st.candidate.services.contains_key("sonarr:80"));
        assert_eq!(st.candidate.services["sonarr:80"].backends[0].port, 8989);
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

        let routes = crate::features::collect_cloudflare_routes(&reparsed);
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].1, "sonarr.example.com");
        assert_eq!(routes[0].2, "http://192.168.2.215:8989");
    }

    #[tokio::test]
    async fn test_gateway_port_forward_compilation() {
        let raw = r#"
gateway 169.254.10.20 {
    balance round-robin
    killswitch on
    forward 51413 to 169.254.20.15:51413
    tunnels {
        wg-exit-01.conf
        wg-exit-02.conf
    }
}
"#;
        let cfg = parse_nftyfile(raw).expect("parse gateway port forward");
        let gw = &cfg.gateways["169.254.10.20"];
        assert_eq!(gw.forwards.len(), 1);
        assert_eq!(gw.forwards[0].listen_port, 51413);
        assert_eq!(gw.forwards[0].backend.ip, Ipv4Addr::new(169, 254, 20, 15));
        assert_eq!(gw.forwards[0].backend.port, 51413);

        let nft = compile_nft_ruleset(&cfg, None);
        assert!(nft.contains("iifname \"wg0\" ct state new ct mark set 0x101 accept"));
        assert!(nft.contains("iifname \"wg1\" ct state new ct mark set 0x102 accept"));
        assert!(nft.contains("iifname { \"wg0\", \"wg1\" } tcp dport 51413 counter dnat to 169.254.20.15:51413"));
        assert!(nft.contains("iifname { \"wg0\", \"wg1\" } udp dport 51413 counter dnat to 169.254.20.15:51413"));

        let roundtrip = parse_nftyfile(&cfg.format_nftyfile()).expect("roundtrip gateway forward");
        assert_eq!(roundtrip.gateways["169.254.10.20"].forwards.len(), 1);
    }

    #[tokio::test]
    async fn test_dns_endpoint_and_nftset_compilation() {
        let raw = r#"
vip 169.254.1.4/24 {
    dns:53
    80 to 169.254.20.10:8989 {
        hostname sonarr.local
    }
}
gateway 169.254.1.10/24 {
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
    forward corp.internal 169.254.99.1 via 169.254.1.10
    a nas.lan 169.254.1.50
    aaaa nas.lan fd00::50
    address *.k8s.lan 169.254.1.100
    cname media.lan sonarr.lan
    txt _acme-challenge.example.com "token-xyz"
    srv _minecraft._tcp.lan mc.lan:25565 priority 0 weight 5
    mx lan mail.lan priority 10
    ptr 169.254.1.50 nas.lan
    route linuxisos.org tracker.example.org via 169.254.1.10
    bypass plex.tv netflix.com from 169.254.1.10
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
        assert!(conf_txt.contains("listen-address=169.254.1.4"));
        assert!(conf_txt.contains("listen-address=169.254.1.10"));
        assert!(conf_txt.contains("server=1.1.1.1"));
        assert!(conf_txt.contains("server=/corp.internal/169.254.99.1@wg0"));
        assert!(conf_txt.contains("host-record=nas.lan,169.254.1.50"));
        assert!(conf_txt.contains("host-record=nas.lan,fd00::50"));
        assert!(conf_txt.contains("address=/k8s.lan/169.254.1.100"));
        assert!(conf_txt.contains("cname=media.lan,sonarr.lan"));
        assert!(conf_txt.contains("txt-record=_acme-challenge.example.com,\"token-xyz\""));
        assert!(conf_txt.contains("srv-host=_minecraft._tcp.lan,mc.lan,25565,0,5"));
        assert!(conf_txt.contains("mx-host=lan,mail.lan,10"));
        assert!(conf_txt.contains("nftset=/linuxisos.org/tracker.example.org/4#ip#nfty#dns_route_169_254_1_10"));
        assert!(conf_txt.contains("nftset=/plex.tv/netflix.com/4#ip#nfty#dns_bypass_169_254_1_10"));
        assert!(conf_txt.contains("address=/doubleclick.net/0.0.0.0"));
        assert!(hosts_txt.contains("sonarr sonarr.lan sonarr.local"));

        let nft = compile_nft_ruleset(&cfg, None);
        assert!(nft.contains("set dns_route_169_254_1_10 {"));
        assert!(nft.contains("set dns_bypass_169_254_1_10 {"));
        assert!(nft.contains("ip daddr @dns_bypass_169_254_1_10 counter accept"));
        assert!(nft.contains("ip daddr @dns_route_169_254_1_10 jump mark_wg_0 accept"));

        let roundtrip = parse_nftyfile(&cfg.format_nftyfile()).expect("roundtrip dns Nftyfile");
        assert!(roundtrip.dns.is_some());
        assert_eq!(roundtrip.dns.as_ref().unwrap().records.len(), 8);
        assert_eq!(roundtrip.dns.as_ref().unwrap().nft_rules.len(), 2);
    }
}
