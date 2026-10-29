use super::ShellLevel;
use crate::state::SharedState;
use anyhow::{bail, Result};
use colored::Colorize;
use std::io::{BufRead, BufReader};
use std::net::ToSocketAddrs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn validate_target_token(tok: &str, label: &str) -> Result<String> {
    let trimmed = tok.trim();
    if trimmed.is_empty() {
        bail!("Missing {}", label);
    }
    if trimmed.starts_with('-') {
        bail!("Invalid {} '{}' (must not start with '-')", label, trimmed);
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '_'))
    {
        bail!("Invalid characters in {} '{}'", label, trimmed);
    }
    Ok(trimmed.to_string())
}

fn stream_command_output(mut cmd: Command) -> Result<()> {
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn()?;

    let stdout_handle = child.stdout.take().map(|out| {
        std::thread::spawn(move || {
            let reader = BufReader::new(out);
            for line in reader.lines().map_while(Result::ok) {
                println!("  {}", line);
            }
        })
    });

    let stderr_handle = child.stderr.take().map(|err| {
        std::thread::spawn(move || {
            let reader = BufReader::new(err);
            for line in reader.lines().map_while(Result::ok) {
                eprintln!("  {}", line);
            }
        })
    });

    let _ = child.wait();
    if let Some(h) = stdout_handle {
        let _ = h.join();
    }
    if let Some(h) = stderr_handle {
        let _ = h.join();
    }
    Ok(())
}

/// Runs `ping -c 5 -W 2 [-I <source>] <target>` (hard-capped at 5 ICMP echo requests).
pub fn run_ping_command(args: &[&str]) -> Result<()> {
    if args.is_empty() {
        bail!("Usage: ping <host|ip> [source <ip|interface>]");
    }

    let mut target: Option<String> = None;
    let mut source: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "source" | "src" | "from" | "-I" | "interface" | "dev" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    bail!("Expected IP or interface name after '{}'", args[i - 1]);
                };
                source = Some(validate_target_token(val, "source IP/interface")?);
            }
            tok if tok.starts_with('-') => {
                // Ignore user-supplied count/flood flags; ping is always capped at 5 packets
                if matches!(tok, "-c" | "-W" | "-w" | "-i" | "-s") {
                    i += 1;
                }
            }
            tok => {
                if target.is_none() {
                    target = Some(validate_target_token(tok, "target host/IP")?);
                }
            }
        }
        i += 1;
    }

    let Some(target) = target else {
        bail!("Usage: ping <host|ip> [source <ip|interface>]");
    };

    println!(
        "{}",
        format!(
            "Pinging {} (5 packets{})...",
            target,
            source
                .as_ref()
                .map(|s| format!(", source {}", s))
                .unwrap_or_default()
        )
        .cyan()
    );

    let mut cmd = if Path::new("/bin/ping").exists() {
        Command::new("/bin/ping")
    } else if Path::new("/bin/busybox").exists() {
        let mut c = Command::new("/bin/busybox");
        c.arg("ping");
        c
    } else {
        Command::new("ping")
    };

    cmd.args(["-c", "5", "-W", "2"]);
    if let Some(src) = &source {
        cmd.args(["-I", src]);
    }
    cmd.arg(&target);

    stream_command_output(cmd)
}

/// Runs `traceroute -w 2 -q 1 -m 20 <target>` and streams each hop live.
pub fn run_traceroute_command(args: &[&str]) -> Result<()> {
    if args.is_empty() {
        bail!("Usage: traceroute <host|ip> [source <ip|interface>]");
    }

    let mut target: Option<String> = None;
    let mut source: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i] {
            "source" | "src" | "from" | "-i" | "-s" | "interface" | "dev" => {
                i += 1;
                let Some(val) = args.get(i) else {
                    bail!("Expected IP or interface name after '{}'", args[i - 1]);
                };
                source = Some(validate_target_token(val, "source IP/interface")?);
            }
            tok if tok.starts_with('-') => {
                if matches!(tok, "-m" | "-q" | "-w") {
                    i += 1;
                }
            }
            tok => {
                if target.is_none() {
                    target = Some(validate_target_token(tok, "target host/IP")?);
                }
            }
        }
        i += 1;
    }

    let Some(target) = target else {
        bail!("Usage: traceroute <host|ip> [source <ip|interface>]");
    };

    println!(
        "{}",
        format!(
            "Tracing route to {} (max 20 hops{})...",
            target,
            source
                .as_ref()
                .map(|s| format!(", source {}", s))
                .unwrap_or_default()
        )
        .cyan()
    );

    let mut cmd = if Path::new("/bin/busybox").exists() {
        let mut c = Command::new("/bin/busybox");
        c.arg("traceroute");
        c
    } else if Path::new("/usr/bin/traceroute").exists() {
        Command::new("/usr/bin/traceroute")
    } else if Path::new("/bin/traceroute").exists() {
        Command::new("/bin/traceroute")
    } else {
        Command::new("traceroute")
    };

    cmd.args(["-w", "2", "-q", "1", "-m", "20"]);
    if let Some(src) = &source {
        if src.parse::<std::net::Ipv4Addr>().is_ok() {
            cmd.args(["-s", src]);
        } else {
            cmd.args(["-i", src]);
        }
    }
    cmd.arg(&target);

    stream_command_output(cmd)
}

/// Sends 3 ARP probes (`arping -c 3 -w 2 -I <iface> <ip>`) on the local L2 segment.
pub fn run_arping_command(args: &[&str]) -> Result<()> {
    if args.is_empty() {
        bail!("Usage: arping <ipv4> [interface]");
    }
    let ip = validate_target_token(args[0], "target IPv4")?;
    let iface = if let Some(dev) = args.get(1) {
        validate_target_token(dev, "interface")?
    } else {
        "eth0".to_string()
    };

    println!(
        "{}",
        format!("Sending 3 ARP probes to {} on {}...", ip, iface).cyan()
    );

    let mut cmd = if Path::new("/bin/busybox").exists() {
        let mut c = Command::new("/bin/busybox");
        c.arg("arping");
        c
    } else {
        Command::new("arping")
    };
    cmd.args(["-c", "3", "-w", "2", "-I", &iface, &ip]);
    stream_command_output(cmd)
}

/// Tests a TCP connection handshake to `<host:port>` or `<host> <port>` with a 2-second timeout.
pub async fn run_tcp_probe_command(args: &[&str]) -> Result<()> {
    if args.is_empty() {
        bail!("Usage: tcp <host:port> (or 'tcp <host> <port>')");
    }

    let (host, port): (String, u16) = if let Some((h, p)) = args[0].rsplit_once(':') {
        (
            validate_target_token(h, "host")?,
            p.parse::<u16>()
                .map_err(|_| anyhow::anyhow!("Invalid TCP port '{}'", p))?,
        )
    } else if args.len() >= 2 {
        (
            validate_target_token(args[0], "host")?,
            args[1]
                .parse::<u16>()
                .map_err(|_| anyhow::anyhow!("Invalid TCP port '{}'", args[1]))?,
        )
    } else {
        bail!("Usage: tcp <host:port> (or 'tcp <host> <port>')");
    };

    let spec = format!("{}:{}", host, port);
    let addr = match spec.to_socket_addrs() {
        Ok(mut iter) => match iter.next() {
            Some(a) => a,
            None => bail!("Could not resolve '{}'", spec),
        },
        Err(e) => bail!("Failed to resolve '{}': {}", spec, e),
    };

    let t0 = Instant::now();
    match tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => {
            let ms = t0.elapsed().as_secs_f64() * 1000.0;
            println!(
                "  {} TCP {}:{} ({}) -> {} ({:.2}ms)",
                "✔".green().bold(),
                host.bold(),
                port,
                addr.ip(),
                "OPEN".green().bold(),
                ms
            );
        }
        Ok(Err(e)) => {
            println!(
                "  {} TCP {}:{} ({}) -> {} ({})",
                "✖".red().bold(),
                host.bold(),
                port,
                addr.ip(),
                "CLOSED/REFUSED".red().bold(),
                e
            );
        }
        Err(_) => {
            println!(
                "  {} TCP {}:{} ({}) -> {} (2.0s timeout)",
                "✖".red().bold(),
                host.bold(),
                port,
                addr.ip(),
                "TIMEOUT".red().bold()
            );
        }
    }
    Ok(())
}

pub fn run_interfaces_command() -> Result<()> {
    println!("{}", "Kernel Network Interfaces & IPv4 Addresses:".bold().cyan());
    let mut cmd = if Path::new("/sbin/ip").exists() {
        Command::new("/sbin/ip")
    } else {
        Command::new("ip")
    };
    cmd.args(["-4", "addr", "show"]);
    stream_command_output(cmd)
}

pub fn run_routes_command(args: &[&str]) -> Result<()> {
    if args.len() >= 2 && args[0].eq_ignore_ascii_case("table") {
        let tbl = validate_target_token(args[1], "routing table")?;
        println!(
            "{}",
            format!("Kernel IPv4 Routing Table '{}':", tbl).bold().cyan()
        );
        let mut cmd = if Path::new("/sbin/ip").exists() {
            Command::new("/sbin/ip")
        } else {
            Command::new("ip")
        };
        cmd.args(["-4", "route", "show", "table", &tbl]);
        return stream_command_output(cmd);
    }

    println!("{}", "Main IPv4 Routing Table:".bold().cyan());
    let ip_bin = if Path::new("/sbin/ip").exists() {
        "/sbin/ip"
    } else {
        "ip"
    };
    let _ = stream_command_output({
        let mut c = Command::new(ip_bin);
        c.args(["-4", "route", "show"]);
        c
    });

    println!("\n{}", "Policy Routing Rules (ip rule):".bold().cyan());
    let _ = stream_command_output({
        let mut c = Command::new(ip_bin);
        c.args(["-4", "rule", "show"]);
        c
    });

    for table_id in 101..=116 {
        let tbl_str = table_id.to_string();
        if let Ok(out) = Command::new(ip_bin)
            .args(["-4", "route", "show", "table", &tbl_str])
            .output()
        {
            let txt = String::from_utf8_lossy(&out.stdout);
            if !txt.trim().is_empty() {
                println!(
                    "\n{}",
                    format!("WireGuard Policy Routing Table {}:", table_id)
                        .bold()
                        .cyan()
                );
                for line in txt.lines() {
                    println!("  {}", line);
                }
            }
        }
    }
    Ok(())
}

pub fn run_arp_table_command() -> Result<()> {
    println!("{}", "Kernel ARP / IPv4 Neighbor Table:".bold().cyan());
    let mut cmd = if Path::new("/sbin/ip").exists() {
        Command::new("/sbin/ip")
    } else {
        Command::new("ip")
    };
    cmd.args(["-4", "neigh", "show"]);
    stream_command_output(cmd)
}

pub fn run_sockets_command() -> Result<()> {
    println!("{}", "Listening TCP/UDP Sockets:".bold().cyan());
    if Path::new("/bin/busybox").exists() {
        let mut cmd = Command::new("/bin/busybox");
        cmd.args(["netstat", "-tulnp"]);
        return stream_command_output(cmd);
    }
    let mut cmd = Command::new("ss");
    cmd.args(["-tulnp"]);
    stream_command_output(cmd)
}

pub fn run_wg_debug_command() -> Result<()> {
    println!("{}", "Live WireGuard Interface Status (wg show):".bold().cyan());
    let wg_bin = if Path::new("/usr/bin/wg").exists() {
        "/usr/bin/wg"
    } else {
        "wg"
    };
    if let Ok(out) = Command::new(wg_bin).arg("show").output() {
        let stdout = String::from_utf8_lossy(&out.stdout);
        if stdout.trim().is_empty() {
            println!("  (No active WireGuard interfaces up in kernel)");
        } else {
            for line in stdout.lines() {
                println!("  {}", line);
            }
        }
    } else {
        println!("  (wg binary not found in PATH)");
    }
    Ok(())
}

pub fn run_nft_debug_command() -> Result<()> {
    println!(
        "{}",
        "Active Kernel nftables Ruleset & Counters (table ip nfty):"
            .bold()
            .cyan()
    );
    let nft_bin = if Path::new("/usr/sbin/nft").exists() {
        "/usr/sbin/nft"
    } else if Path::new("/sbin/nft").exists() {
        "/sbin/nft"
    } else {
        "nft"
    };
    let mut cmd = Command::new(nft_bin);
    cmd.args(["list", "table", "ip", "nfty"]);
    stream_command_output(cmd)
}

pub fn run_dmesg_command() -> Result<()> {
    println!("{}", "Recent Kernel Log Messages (dmesg):".bold().cyan());
    let out = if Path::new("/bin/busybox").exists() {
        Command::new("/bin/busybox").arg("dmesg").output()
    } else {
        Command::new("dmesg").output()
    };
    match out {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            let lines: Vec<&str> = stdout.lines().collect();
            let start = lines.len().saturating_sub(40);
            for l in &lines[start..] {
                println!("  {}", l);
            }
        }
        Err(e) => bail!("Failed to read dmesg: {}", e),
    }
    Ok(())
}

pub async fn handle_debug_command(
    line: &str,
    level: &Arc<Mutex<ShellLevel>>,
    shared: &SharedState,
) -> Result<()> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.is_empty() {
        return Ok(());
    }
    let cmd = tokens[0].to_ascii_lowercase();
    let args = &tokens[1..];

    match cmd.as_str() {
        "configure" => {
            *level.lock().unwrap() = ShellLevel::ConfigRoot;
            Ok(())
        }
        "ping" => run_ping_command(args),
        "traceroute" => run_traceroute_command(args),
        "arping" => run_arping_command(args),
        "tcp" => run_tcp_probe_command(args).await,
        "dns" => {
            if args.is_empty() {
                crate::features::handle_dns_cli_command(&["status"], shared)
            } else if matches!(
                args[0].to_ascii_lowercase().as_str(),
                "status" | "test" | "config" | "reload"
            ) {
                crate::features::handle_dns_cli_command(args, shared)
            } else {
                let mut lookup_args = vec!["test"];
                lookup_args.extend_from_slice(args);
                crate::features::handle_dns_cli_command(&lookup_args, shared)
            }
        }
        "interfaces" => run_interfaces_command(),
        "routes" => run_routes_command(args),
        "arp" => run_arp_table_command(),
        "sockets" => run_sockets_command(),
        "wg" => {
            if args.is_empty() {
                run_wg_debug_command()
            } else {
                let _ = crate::features::handle_wg_cli_command(args)?;
                Ok(())
            }
        }
        "nft" => run_nft_debug_command(),
        "flows" => {
            crate::features::print_flows_table(shared);
            Ok(())
        }
        "dmesg" => run_dmesg_command(),
        _ => bail!(
            "Unknown debug command '{}'. Type '?' for available troubleshooting tools (ping, traceroute, tcp, dns, arping, interfaces, routes, arp, sockets, wg, nft, flows, dmesg).",
            cmd
        ),
    }
}
