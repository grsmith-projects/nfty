use super::ShellLevel;
use colored::Colorize;

pub fn print_context_help(level: &ShellLevel) {
    match level {
        ShellLevel::Operational => {
            println!("{}", "Operational Mode Commands:".bold().cyan());
            println!(
                "  {:<26} Bootstrap VIP + base SSH service config",
                "bootstrap <ip[/24]>...".yellow()
            );
            println!("  {:<26} Enter configuration mode", "configure".yellow());
            println!(
                "  {:<26} Enter troubleshooting & diagnostics mode",
                "debug".yellow()
            );
            println!(
                "  {:<26} Send 5 ICMP echo pings (supports -I <src>)",
                "ping <host>".yellow()
            );
            println!(
                "  {:<26} Trace route hops to destination host",
                "traceroute <host>".yellow()
            );
            println!(
                "  {:<26} Show service, gateway & backend health table",
                "status".yellow()
            );
            println!(
                "  {:<26} Show live active conntrack flows & bandwidth",
                "flows".yellow()
            );
            println!(
                "  {:<26} Inspect / test dnsmasq DNS endpoint",
                "dns [status|test <host>|config]".yellow()
            );
            println!(
                "  {:<26} List saved WireGuard configs (/data/wg)",
                "wg".yellow()
            );
            println!(
                "  {:<26} Paste a WireGuard .conf (terminal only)",
                "wg add <name>".yellow()
            );
            println!(
                "  {:<26} List saved SSH authorized keys (/data/ssh)",
                "ssh".yellow()
            );
            println!(
                "  {:<26} Add an SSH public key (inline, or paste on a terminal)",
                "ssh add <name> [pubkey]".yellow()
            );
            println!(
                "  {:<26} Cloudflare Tunnel & DNS status / API token setup",
                "cf [status|token <KEY>]".yellow()
            );
            println!(
                "  {:<26} Run active health probes right now",
                "probe".yellow()
            );
            println!("  {:<26} Show Nftyfile configuration", "show".yellow());
            println!(
                "  {:<26} Show allow-lists & resolved hosts",
                "show allow".yellow()
            );
            println!(
                "  {:<26} Show compiled nftables ruleset",
                "show nft".yellow()
            );
            println!(
                "  {:<26} Drain backend from load balancer",
                "drain <ip:port>".yellow()
            );
            println!(
                "  {:<26} Re-enable drained backend",
                "enable <ip:port>".yellow()
            );
            println!("  {:<26} Change nfty login password", "password".yellow());
            println!("  {:<26} Exit nfty", "exit".yellow());
        }
        ShellLevel::Debug => {
            println!(
                "{}",
                "Debug & Troubleshooting Mode Commands (nfty(debug)#):"
                    .bold()
                    .cyan()
            );
            println!(
                "  {:<32} Send 5 ICMP echo pings (capped at -c 5)",
                "ping <host> [-I <ip|iface>]".yellow()
            );
            println!(
                "  {:<32} Trace route hops to destination host",
                "traceroute <host> [-i <iface>]".yellow()
            );
            println!(
                "  {:<32} Test TCP connectivity & handshake latency",
                "tcp <host:port>".yellow()
            );
            println!(
                "  {:<32} Resolve hostname via system or specific DNS server",
                "dns <host> [server]".yellow()
            );
            println!(
                "  {:<32} Send 3 ARP requests on local LAN interface",
                "arping <ip> [-I <iface>]".yellow()
            );
            println!(
                "  {:<32} Show live kernel network interfaces & IPs",
                "interfaces".yellow()
            );
            println!(
                "  {:<32} Show main, policy rules & WireGuard routing tables",
                "routes".yellow()
            );
            println!(
                "  {:<32} Show kernel ARP / L2 neighbor cache",
                "arp".yellow()
            );
            println!(
                "  {:<32} Show active listening TCP/UDP sockets",
                "sockets".yellow()
            );
            println!(
                "  {:<32} Show live WireGuard tunnel handshakes & transfer",
                "wg [wg0]".yellow()
            );
            println!(
                "  {:<32} Show live kernel nftables ruleset & counters",
                "nft".yellow()
            );
            println!(
                "  {:<32} Show active conntrack flows & NAT translations",
                "flows".yellow()
            );
            println!(
                "  {:<32} Show recent kernel ring buffer messages",
                "dmesg [lines]".yellow()
            );
            println!(
                "  {:<32} Run active health probes across all backends",
                "probe".yellow()
            );
            println!(
                "  {:<32} Exit back to operational mode",
                "exit / ..".yellow()
            );
        }
        ShellLevel::ConfigRoot => {
            println!("{}", "Config Root Commands (nfty(config)#):".bold().cyan());
            println!(
                "  {:<32} Create/enter a static or DHCP VIP container (e.g. 'vip 192.168.1.4' or 'vip sonarr')",
                "vip <ipv4[/cidr]|name>".yellow()
            );
            println!(
                "  {:<32} Create/enter a Virtual Gateway (static IP or DHCP, e.g. 'gateway 192.168.1.10' or 'gateway mullvad')",
                "gateway <ipv4[/cidr]|name>".yellow()
            );
            println!(
                "  {:<32} Configure authoritative DNS, split-horizon, & nftset routing",
                "dns".yellow()
            );
            println!(
                "  {:<32} Bootstrap VIP + base SSH service config",
                "bootstrap <ip[/24]>...".yellow()
            );
            println!(
                "  {:<32} Enter global allow-list block (supports wildcards e.g. '*.office.lan', '192.168.1.*')",
                "allow [pattern...]".yellow()
            );
            println!(
                "  {:<32} Register/update hostname -> IP mapping for wildcard rules",
                "host <hostname> <ipv4>".yellow()
            );
            println!(
                "  {:<32} Delete a VIP, gateway, service, or allow entry",
                "no <vip|gateway|service|allow> <target>".yellow()
            );
            println!("  {:<32} Show candidate configuration", "show".yellow());
            println!(
                "  {:<32} Show live active conntrack flows",
                "flows".yellow()
            );
            println!(
                "  {:<32} List saved WireGuard configs (/data/wg)",
                "wg".yellow()
            );
            println!(
                "  {:<32} Paste a WireGuard .conf (terminal only)",
                "wg add <name>".yellow()
            );
            println!(
                "  {:<32} List saved SSH authorized keys (/data/ssh)",
                "ssh".yellow()
            );
            println!(
                "  {:<32} Add an SSH public key (inline, or paste on a terminal)",
                "ssh add <name> [pubkey]".yellow()
            );
            println!(
                "  {:<32} Cloudflare Tunnel & DNS setup (e.g. 'cf token <API_TOKEN>')",
                "cf [status|token|sync|logs]".yellow()
            );
            println!(
                "  {:<32} Show allow-lists & resolved hosts",
                "show allow".yellow()
            );
            println!(
                "  {:<32} Show generated nftables ruleset",
                "show nft".yellow()
            );
            println!(
                "  {:<32} Compare candidate vs running config",
                "diff".yellow()
            );
            println!(
                "  {:<32} Validate config & nftables dry-run",
                "test".yellow()
            );
            println!(
                "  {:<32} Apply candidate config to kernel",
                "apply".yellow()
            );
            println!(
                "  {:<32} Apply with auto-rollback timer (e.g. 60s)",
                "apply confirm <secs>".yellow()
            );
            println!("  {:<32} Confirm a pending timed apply", "confirm".yellow());
            println!(
                "  {:<32} Rollback to previous committed config",
                "rollback [N]".yellow()
            );
            println!("  {:<32} Save config to Nftyfile", "save [path]".yellow());
            println!(
                "  {:<32} Exit back to operational mode",
                "exit / ..".yellow()
            );
        }
        ShellLevel::Vip(k) => {
            println!(
                "{}",
                format!("VIP '{}' Commands (nfty(config-vip:{})#):", k, k)
                    .bold()
                    .cyan()
            );
            println!(
                "  {:<32} Map listen port to backend (e.g. '80 to sonarr:8989')",
                "<port> to <host:port>".yellow()
            );
            println!(
                "  {:<32} Add/enter backend service on matching port (e.g. 'app-backend:9090')",
                "<host_or_ip:port>".yellow()
            );
            println!(
                "  {:<32} Enable local nfty SSH shell on this VIP",
                "ssh:22 (or 'ssh')".yellow()
            );
            println!(
                "  {:<32} Enable dnsmasq DNS endpoint on this VIP (UDP+TCP 53)",
                "dns:53 (or 'dns')".yellow()
            );
            println!(
                "  {:<32} Enable HTTP Control API on this VIP & configure keys",
                "api:9090 (or 'api')".yellow()
            );
            println!(
                "  {:<32} Enable Web UI Console on this VIP (supports allow-lists & keys)",
                "web:8000 (or 'web')".yellow()
            );
            println!(
                "  {:<32} Lease VIP via DHCP + register hostname with UDM DNS",
                "dhcp [eth0|off]".yellow()
            );
            println!(
                "  {:<32} Set 802.1Q VLAN tag (e.g. 'vlan 20')",
                "vlan <1-4094>".yellow()
            );
            println!(
                "  {:<32} Set NIC interface / subnet CIDR (e.g. 'interface eth1/24')",
                "interface <iface[/prefix]>".yellow()
            );
            println!(
                "  {:<32} Expose via Cloudflare Tunnel & DNS (e.g. 'cloudflare-dns app.domain.com')",
                "cloudflare-dns <fqdn>".yellow()
            );
            println!(
                "  {:<32} Remove VLAN, DHCP, Cloudflare, SSH, or a forwarded service",
                "no <vlan|dhcp|cloudflare-dns|ssh:22|<target>>".yellow()
            );
            println!("  {:<32} Show this VIP block", "show".yellow());
            println!(
                "  {:<32} Return to config root",
                ".. / up / exit / top".yellow()
            );
        }
        ShellLevel::VipService(k) => {
            println!(
                "{}",
                format!(
                    "VIP '{}' Forwarded Services Mode (nfty(config-vip:{}-service)#):",
                    k, k
                )
                .bold()
                .cyan()
            );
            println!(
                "  {:<32} Create/enter backend service (e.g. 'plex:32400' or 'app-backend:9090')",
                "<host_or_ip:port>".yellow()
            );
            println!(
                "  {:<32} Create/enter service by listen port (e.g. '80' or '53/udp')",
                "<port[/proto]>".yellow()
            );
            println!(
                "  {:<32} Remove a service from this VIP",
                "no <target>".yellow()
            );
            println!(
                "  {:<32} Return to VIP {} prompt",
                ".. / up / exit".yellow(),
                k
            );
        }
        ShellLevel::GlobalAllow => {
            println!(
                "{}",
                "Global Allow-List Mode (nfty(config-allow)#):"
                    .bold()
                    .cyan()
            );
            println!(
                "  {:<32} Allow wildcard domain (e.g. '*.office.lan')",
                "<*.domain.tld>".yellow()
            );
            println!(
                "  {:<32} Allow IP wildcard (e.g. '192.168.1.*')",
                "<a.b.c.*>".yellow()
            );
            println!(
                "  {:<32} Allow hostname or CIDR (e.g. 'admin.lan' or '10.0.0.0/8')",
                "<host|cidr>".yellow()
            );
            println!("  {:<32} Remove allow entry", "no <pattern>".yellow());
            println!("  {:<32} Return to config root", ".. / up / exit".yellow());
        }
        ShellLevel::Dns => {
            println!(
                "{}",
                "Programmable DNS Endpoint Mode (nfty(config-dns)#):"
                    .bold()
                    .cyan()
            );
            println!(
                "  {:<36} Set authoritative search domain (default: 'lan')",
                "domain <lan|home.arpa>".yellow()
            );
            println!(
                "  {:<36} Add upstream resolver (e.g. 'upstream 1.1.1.1 9.9.9.9')",
                "upstream <ip[:port]>...".yellow()
            );
            println!(
                "  {:<36} Forward specific domain zone to custom DNS server",
                "forward <domain> <ip[:port]>".yellow()
            );
            println!(
                "  {:<36} Auto-synthesize A/PTR records from VIPs & gateways",
                "auto-vips <on|off>".yellow()
            );
            println!(
                "  {:<36} Auto-synthesize A/PTR records from resolved backend hosts",
                "auto-hosts <on|off>".yellow()
            );
            println!(
                "  {:<36} Auto-remove unhealthy backends from DNS responses",
                "health-aware <on|off>".yellow()
            );
            println!(
                "  {:<36} Add authoritative A record (with automatic PTR)",
                "a <fqdn> <ipv4>".yellow()
            );
            println!(
                "  {:<36} Add authoritative AAAA record",
                "aaaa <fqdn> <ipv6>".yellow()
            );
            println!(
                "  {:<36} Wildcard domain override (e.g. 'address *.dev.lan 10.0.0.5')",
                "address <*.domain> <ip>".yellow()
            );
            println!(
                "  {:<36} Add CNAME alias record",
                "cname <alias> <target>".yellow()
            );
            println!(
                "  {:<36} Add TXT record (SPF, ACME, verification)",
                "txt <fqdn> \"<text>\"".yellow()
            );
            println!(
                "  {:<36} Add SRV record (_service._proto.domain target:port)",
                "srv <_svc._proto.dom> <host:port> [prio N] [weight N]".yellow()
            );
            println!(
                "  {:<36} Add MX record",
                "mx <domain> <mailhost> [prio N]".yellow()
            );
            println!(
                "  {:<36} Add explicit PTR reverse record",
                "ptr <ipv4> <fqdn>".yellow()
            );
            println!(
                "  {:<36} Route resolved domain IPs through a gateway via nftset",
                "route <domain...> via <gw>".yellow()
            );
            println!(
                "  {:<36} Bypass VPN gateway for resolved domain IPs via nftset",
                "bypass <domain...> from <gw>".yellow()
            );
            println!(
                "  {:<36} Sinkhole domain/wildcard to 0.0.0.0 + ::",
                "block <*.domain...>".yellow()
            );
            println!(
                "  {:<36} Remove a record, upstream, forward, or routing rule",
                "no <a|aaaa|address|cname|txt|srv|mx|ptr|upstream|forward|route|bypass|block> <target>".yellow()
            );
            println!("  {:<36} Show this DNS block", "show".yellow());
            println!("  {:<36} Return to config root", ".. / up / exit / top".yellow());
        }
        ShellLevel::Service(k) => {
            println!(
                "{}",
                format!("Service '{}' Settings (nfty(config-service:{})#):", k, k)
                    .bold()
                    .cyan()
            );
            println!(
                "  {:<32} Override external VIP listen port (e.g. 'port 80')",
                "port <1-65535>".yellow()
            );
            println!(
                "  {:<32} Set protocol ('tcp', 'udp', or 'both')",
                "proto <tcp|udp|both>".yellow()
            );
            println!(
                "  {:<32} Enter backend targets prompt ('to' sub-level)",
                "to".yellow()
            );
            println!(
                "  {:<32} Add backend directly in one line",
                "to <ip|host[:port]> [weight N] [backup]".yellow()
            );
            println!(
                "  {:<32} Announce mDNS (*.local) + route HTTP Host / TLS SNI",
                "hostname <name.local>".yellow()
            );
            println!(
                "  {:<32} Expose via Cloudflare Tunnel & DNS (e.g. 'cloudflare-dns app.domain.com')",
                "cloudflare-dns <fqdn>".yellow()
            );
            println!(
                "  {:<32} Require Cloudflare Access (you@example.com or *@example.com)",
                "cloudflare-auth <rule...>".yellow()
            );
            println!(
                "  {:<32} Generate or add scoped API key ('ro' or 'rw') for api:<port>",
                "key <new | token> [ro|rw]".yellow()
            );
            println!(
                "  {:<32} Load balance strategy",
                "balance <round-robin|sticky>".yellow()
            );
            println!(
                "  {:<32} Bind Virtual IP to NIC (e.g. 'vip eth0/21')",
                "vip <interface[/prefix]>".yellow()
            );
            println!(
                "  {:<32} Active health check",
                "check <tcp|http /path|ping> [5s]".yellow()
            );
            println!(
                "  {:<32} Per-IP DDoS/rate limit guard",
                "limit <100/sec|600/min> [burst N] [per-ip]".yellow()
            );
            println!(
                "  {:<32} Client IP mode (nat masquerade vs transparent)",
                "mode <nat|transparent>".yellow()
            );
            println!(
                "  {:<32} Enter source host/wildcard allowlist prompt",
                "allow [pattern...]".yellow()
            );
            println!(
                "  {:<32} Remove a directive or backend",
                "no <vip|hostname|key|check|limit|allow|to <ip>>".yellow()
            );
            println!("  {:<32} Show this service block", "show".yellow());
            println!(
                "  {:<32} Go up one level / jump to config root",
                ".. / exit / top".yellow()
            );
        }
        ShellLevel::ServiceTo(k) => {
            println!(
                "{}",
                format!(
                    "Service '{}' Backend Target Mode (nfty(config-service:{}-to)#):",
                    k, k
                )
                .bold()
                .cyan()
            );
            println!(
                "  {:<32} Add backend (e.g. 'plex:32400' or '192.168.1.60:9000')",
                "<ip|host[:port]>".yellow()
            );
            println!(
                "  {:<32} Add weighted backend",
                "<ip|host[:port]> weight <1-100>".yellow()
            );
            println!(
                "  {:<32} Add failover standby backend",
                "<ip|host[:port]> backup".yellow()
            );
            println!("  {:<32} Remove a backend", "no <ip|host[:port]>".yellow());
            println!(
                "  {:<32} Go back to service {} prompt",
                ".. / up / exit".yellow(),
                k
            );
            println!("  {:<32} Jump back to config root", "top".yellow());
        }
        ShellLevel::ServiceAllow(k) => {
            println!(
                "{}",
                format!(
                    "Service '{}' Source Allowlist Mode (nfty(config-service:{}-allow)#):",
                    k, k
                )
                .bold()
                .cyan()
            );
            println!(
                "  {:<32} Allow wildcard domain, IP wildcard, host, or CIDR (e.g. '*.office.lan', '192.168.1.*')",
                "<pattern>".yellow()
            );
            println!("  {:<32} Remove source pattern", "no <pattern>".yellow());
            println!(
                "  {:<32} Go back to service {} prompt",
                ".. / up / exit".yellow(),
                k
            );
        }
        ShellLevel::Gateway(k) => {
            println!(
                "{}",
                format!(
                    "Virtual Gateway '{}' Commands (nfty(config-gateway:{})#):",
                    k, k
                )
                .bold()
                .cyan()
            );
            println!(
                "  {:<32} Enable local nfty SSH shell on this gateway",
                "ssh:22 (or 'ssh')".yellow()
            );
            println!(
                "  {:<32} Enable dnsmasq DNS endpoint on this gateway (UDP+TCP 53)",
                "dns:53 (or 'dns')".yellow()
            );
            println!(
                "  {:<32} Enable HTTP Control API on this gateway & configure keys",
                "api:9090 (or 'api')".yellow()
            );
            println!(
                "  {:<32} Enable inbound WireGuard VPN server endpoint & manage peers",
                "wg-in:51820 (or 'wg-in')".yellow()
            );
            println!(
                "  {:<32} Forward inbound tunnel port (TCP+UDP) to LAN host",
                "forward <port> to <host:port>".yellow()
            );
            println!(
                "  {:<32} Enter optional WireGuard tunnels sub-level",
                "tunnels".yellow()
            );
            println!(
                "  {:<32} Add an optional WireGuard tunnel config directly",
                "tunnel <mullvad-us-sea-001.conf> [weight N]".yellow()
            );
            println!(
                "  {:<32} Bind Virtual Gateway IP to NIC (e.g. 'vip eth0/21')",
                "vip <interface[/prefix]>".yellow()
            );
            println!(
                "  {:<32} Announce mDNS name (e.g. 'hostname vpn.local')",
                "hostname <name.local>".yellow()
            );
            println!(
                "  {:<32} Per-flow load balance strategy across tunnels",
                "balance <round-robin|sticky>".yellow()
            );
            println!(
                "  {:<32} Toggle WAN leak kill-switch when tunnels are used",
                "killswitch <on|off>".yellow()
            );
            println!(
                "  {:<32} Remove a tunnel, service, or directive",
                "no <ssh|dns|api|web|tunnel <name>|vip|killswitch>".yellow()
            );
            println!("  {:<32} Show this gateway block", "show".yellow());
            println!(
                "  {:<32} Go up one level / jump to config root",
                ".. / top".yellow()
            );
        }
        ShellLevel::GatewayService(k) => {
            println!(
                "{}",
                format!(
                    "Gateway '{}' Services Mode (nfty(config-gateway:{}-service)#):",
                    k, k
                )
                .bold()
                .cyan()
            );
            println!(
                "  {:<32} Enable nfty SSH shell on this gateway IP",
                "ssh:22 (or 'ssh')".yellow()
            );
            println!(
                "  {:<32} Enable HTTP Control API on this gateway IP",
                "api:9090 (or 'api')".yellow()
            );
            println!(
                "  {:<32} Disable a gateway service",
                "no <ssh|dns|api|web>".yellow()
            );
            println!(
                "  {:<32} Return to gateway {} prompt",
                ".. / up / exit".yellow(),
                k
            );
        }
        ShellLevel::GatewayApi(k, p) => {
            println!(
                "{}",
                format!(
                    "Gateway '{}' API Service Mode (nfty(config-gateway:{}-api:{})#):",
                    k, k, p
                )
                .bold()
                .cyan()
            );
            println!(
                "  {:<32} Generate new read-only API key",
                "key new ro".yellow()
            );
            println!(
                "  {:<32} Generate new read-write API key",
                "key new rw".yellow()
            );
            println!(
                "  {:<32} Add explicit API key with scope ('ro' or 'rw')",
                "key <token> [ro|rw]".yellow()
            );
            println!(
                "  {:<32} Remove an API key (or all keys)",
                "no key [<token>]".yellow()
            );
            println!("  {:<32} Show this gateway block", "show".yellow());
            println!(
                "  {:<32} Return to gateway {} prompt",
                ".. / up / exit".yellow(),
                k
            );
        }
        ShellLevel::GatewayTunnels(k) => {
            println!(
                "{}",
                format!(
                    "Gateway '{}' WireGuard Tunnels Mode (nfty(config-gateway:{}-tunnels)#):",
                    k, k
                )
                .bold()
                .cyan()
            );
            println!(
                "  {:<32} Paste a new WireGuard config & attach it",
                "add <name>".yellow()
            );
            println!(
                "  {:<32} Attach an existing /data/wg/<file> tunnel",
                "<mullvad-us-sea-001.conf> [weight N]".yellow()
            );
            println!(
                "  {:<32} Add inline tunnel",
                "<wg0> address <ip/32> privkey <k> peer <pub> endpoint <ip:port>".yellow()
            );
            println!("  {:<32} Remove a tunnel", "no <name>".yellow());
            println!(
                "  {:<32} Return to gateway {} prompt",
                ".. / up / exit".yellow(),
                k
            );
        }
        ShellLevel::GatewayWgIngress(k, p) => {
            println!(
                "{}",
                format!(
                    "Gateway '{}' WireGuard Ingress Endpoint Mode (nfty(config-gateway:{}-wg:{})#):",
                    k, k, p
                )
                .bold()
                .cyan()
            );
            println!(
                "  {:<36} Add client peer (auto-generates keys, .conf & QR code)",
                "peer add <name> [ip <ip>]".yellow()
            );
            println!(
                "  {:<36} Add client peer with external public key",
                "peer add <name> pubkey <base64>".yellow()
            );
            println!(
                "  {:<36} Print copy/paste client .conf for peer",
                "peer show <name>".yellow()
            );
            println!(
                "  {:<36} Render terminal UTF-8 QR code for mobile WireGuard app",
                "peer qr <name>".yellow()
            );
            println!(
                "  {:<36} List configured peers & server public key",
                "peer list".yellow()
            );
            println!(
                "  {:<36} Remove a client peer",
                "peer rm <name> (or 'no peer <name>')".yellow()
            );
            println!(
                "  {:<36} Set tunnel interface IP/subnet (default: 10.99.0.1/24)",
                "subnet <ip/prefix>".yellow()
            );
            println!(
                "  {:<36} Set public endpoint host:port for client configs",
                "endpoint <host:port>".yellow()
            );
            println!(
                "  {:<36} Set DNS server IP for client configs",
                "dns <ipv4>".yellow()
            );
            println!(
                "  {:<36} Set client routing ('full' 0.0.0.0/0, 'lan', or CIDRs)",
                "split-tunnel <full|lan|cidr...>".yellow()
            );
            println!("  {:<36} Show this gateway block", "show".yellow());
            println!(
                "  {:<36} Return to gateway {} prompt",
                ".. / up / exit".yellow(),
                k
            );
        }
    }
}
