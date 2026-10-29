# Interactive CLI Guide

`nfty` includes a hierarchical command-line interface (CLI). Access it locally, through the embedded SSH server on an appliance, or through one-shot commands. Secondary sessions talk to the long-running controller over a root-only Unix socket (`/run/nfty/ctl.sock`).

---

## Table of Contents

1. [Zero-Flag CLI & One-Shot Execution](#1-zero-flag-cli--one-shot-execution)
2. [Operational Mode vs. Configuration Mode](#2-operational-mode-vs-configuration-mode)
3. [Hierarchy Navigation & Input Shortcuts](#3-hierarchy-navigation--input-shortcuts)
4. [Configuration Context Drill-Down](#4-configuration-context-drill-down)
5. [Candidate vs. Running Configuration Workflow](#5-candidate-vs-running-configuration-workflow)
6. [Operational Mode Commands](#6-operational-mode-commands)

---

## 1. Zero-Flag CLI & One-Shot Execution

When running `nfty` directly on a Linux host or inside an appliance container, each CLI invocation maintains its own local state. Secondary sessions notify the controller over its Unix socket (falling back to `SIGHUP`) after persisting changes; if notification fails, they report an error even though the local apply and save may already have completed:

| Command | Description |
| :--- | :--- |
| `nfty` | Starts a local interactive CLI (`nfty>`). |
| `nfty status` | Prints the current VIP, service, backend health, WireGuard gateway, and DNS status table and exits. |
| `nfty diff` | Compares the candidate configuration with the active running configuration and prints a colorized unified diff. |
| `nfty apply` | Applies the configured file and attempts to notify the controller. |
| `nfty daemon` | Runs the background supervisor, health prober, and REST API server in the foreground (used by `systemd`). Appliance mode also starts the embedded SSH server. |
| `nfty -c "<cli command>"` | Executes a one-shot CLI command sequence, including `;` command chaining. |

### One-Shot Scripting Examples

```bash
# Check overall appliance status
nfty status

# Inspect active NAT conntrack flows matching port 443
nfty -c "flows 443"

# Drain a backend server before maintenance
nfty -c "drain 192.168.1.21:443"

# Add a new backend to an existing service and apply it
nfty -c "configure; vip 192.168.1.4; service https:443; to 192.168.1.23:443 weight 2; apply; save"

# Execute a remote one-shot command over SSH
ssh admin@192.168.1.4 "show nft"
```

---

## 2. Operational Mode, Debug Mode, and Configuration Mode

The interactive shell separates **Operational Mode** (`nfty>`), **Debug & Troubleshooting Mode** (`nfty(debug)#`), and **Configuration Mode** (`nfty(config)#`).

```mermaid
stateDiagram-v2
    [*] --> Operational: Login / nfty
    Operational --> DebugMode: debug
    DebugMode --> Operational: exit / .. / top / Ctrl-C
    DebugMode --> ConfigRoot: configure
    Operational --> ConfigRoot: configure
    ConfigRoot --> Operational: exit / Ctrl-C
    
    state "Operational Mode (nfty>)" as Operational
    state "Debug Mode (nfty(debug)#)" as DebugMode
    state "Configuration Mode" as ConfigMode {
        ConfigRoot: nfty(config)#
        AllowCtx: nfty(config-allow)#
        DnsCtx: nfty(config-dns)#
        VipCtx: nfty(config-vip:192.168.1.4)#
        VipSvcCtx: nfty(config-vip:192.168.1.4-service:https:443)#
        VipSvcToCtx: nfty(config-vip:192.168.1.4-service:https:443-to)#
        GwCtx: nfty(config-gateway:192.168.1.10)#
        GwTunCtx: nfty(config-gateway:192.168.1.10-tunnels)#
        GwApiCtx: nfty(config-gateway:192.168.1.10-api:9090)#

        ConfigRoot --> AllowCtx: allow
        ConfigRoot --> DnsCtx: dns
        ConfigRoot --> VipCtx: vip 192.168.1.4
        VipCtx --> VipSvcCtx: service https:443
        VipSvcCtx --> VipSvcToCtx: to
        ConfigRoot --> GwCtx: gateway 192.168.1.10
        GwCtx --> GwTunCtx: tunnels
        GwCtx --> GwApiCtx: api:9090
    }
```

### Prompt Indicators Reference

The shell prompt dynamically reflects your exact location in the configuration hierarchy:

| Prompt | Context Level | Description |
| :--- | :--- | :--- |
| `nfty>` | Operational Mode | Default starting mode for status, flows, `ping`, `traceroute`, and runtime operations. |
| `nfty(debug)#` | Debug & Troubleshooting | Dedicated troubleshooting mode (`ping`, `traceroute`, `tcp`, `dns`, `arping`, `interfaces`, `routes`, `arp`, `sockets`, `wg`, `nft`, `flows`, `dmesg`). |
| `nfty(config)#` | Root Configuration | Top-level candidate configuration context. |
| `nfty(config-allow)#` | Global Allowlist | Editing global `allow` subnets, hosts, and VLANs. |
| `nfty(config-dns)#` | Programmable DNS | Editing DNS listeners, zones, records, `nftset` routes, and blocklists. |
| `nfty(config-vip:<ip>)#` | Virtual IP Block | Editing a specific VIP (`192.168.1.4`, `192.168.1.4/24@eth0.20`, etc.). |
| `nfty(config-vip:<ip>-service)#` | VIP Services List | Intermediate context listing or selecting services inside a VIP. |
| `nfty(config-vip:<ip>-api:<port>)#` | VIP API Server | Managing scoped `rw` / `ro` API keys for a VIP-bound HTTP control plane. |
| `nfty(config-vip:<ip>-service:<key>)#` | VIP Service | Editing a specific service (`https:443`, `dns:53/udp`) inside a VIP. |
| `nfty(config-vip:<ip>-service:<key>-to)#` | Service Backends | Adding/removing backend targets (`ip:port [weight W] [backup]`). |
| `nfty(config-vip:<ip>-service:<key>-allow)#` | Service ACL | Editing per-service source IP/CIDR/hostname allowlists. |
| `nfty(config-service:<key>)#` | Standalone Service | Editing a top-level service block (not nested inside a VIP). |
| `nfty(config-gateway:<ip>)#` | WireGuard Gateway | Editing a virtual gateway router (`gateway 169.254.1.10`). |
| `nfty(config-gateway:<ip>-tunnels)#` | Gateway Tunnels | Adding/removing WireGuard `.conf` profile references or inline tunnels. |
| `nfty(config-gateway:<ip>-wg:<port>)#` | Gateway WireGuard Ingress | Configuring a WireGuard ingress server (`wg-in:51820`), `subnet`, `endpoint`, `split-tunnel`, and `peer add/show/qr/rm`. |
| `nfty(config-gateway:<ip>-service)#` | Gateway Services | Managing services nested under a WireGuard gateway. |
| `nfty(config-gateway:<ip>-api:<port>)#` | Gateway API Server | Managing scoped `rw` / `ro` API keys bound to the gateway IP. |

---

## 3. Hierarchy Navigation & Input Shortcuts

`nfty` supports fast navigation across hierarchy levels as well as multi-command chaining and raw block pasting:

| Command / Shortcut | Action |
| :--- | :--- |
| `configure` | Enter `nfty(config)#` from `nfty>`. |
| `..` or `up` | Move up one level in the configuration hierarchy (e.g., from `service` back to `vip`). |
| `top` | Jump directly from any nested sub-context back to `nfty(config)#`. |
| `exit` | From a nested sub-context, step up one level; from `nfty(config)#`, return to `nfty>`; from `nfty>`, close the session. |
| `Ctrl-C` | Abort the current input line and immediately return to `nfty>` (or exit if already at `nfty>`). |
| `;` (Semicolon) | Chain multiple commands on a single line (e.g., `vip 192.168.1.4; service web:80; to 192.168.1.20:8080; top`). |
| `?` or `help` | Display context-sensitive help for the current hierarchy level. |
| `Tab` | Auto-complete commands, sub-contexts, service names, and parameters. |

### Pasting Multi-Line `Nftyfile` Blocks

When at `nfty(config)#`, you can paste raw `Nftyfile` blocks containing `{` and `}` braces directly into the terminal. The REPL automatically detects brace depth (`paste_buf`) and parses the entire block into the candidate configuration once the closing `}` is reached:

```text
nfty(config)# vip 192.168.1.4/24 {
  service app:8443 {
    balance round-robin
    check tcp 2s
    to {
      192.168.1.31:8443 weight 2
      192.168.1.32:8443 weight 1
    }
  }
}
Parsed and merged into candidate configuration.
```

---

## 4. Configuration Context Drill-Down

Instead of writing braces, you can interactively drill down into any configuration object or issue full inline paths from `nfty(config)#`.

### Drilling into VIPs, Services, Backends, and Allowlists

```text
nfty> configure
Entering configuration mode. Type 'apply' to commit, 'exit' to leave.
nfty(config)# allow
nfty(config-allow)# 192.168.1.0/24
Added '192.168.1.0/24' to global allow list.
nfty(config-allow)# 10.100.0.0/16
Added '10.100.0.0/16' to global allow list.
nfty(config-allow)# ..
nfty(config)# vip 192.168.1.4/24@eth0
nfty(config-vip:192.168.1.4)# api:9090
nfty(config-vip:192.168.1.4-api:9090)# key new rw
Generated new rw API key on vip 192.168.1.4 api:9090:
  nfty_rw_84f9a2d1c3e5b7091a2b3c4d5e6f7a8b
nfty(config-vip:192.168.1.4-api:9090)# key new ro
Generated new ro API key on vip 192.168.1.4 api:9090:
  nfty_ro_19c4e8b2a0f6d3157e8a9b0c1d2e3f4a
nfty(config-vip:192.168.1.4-api:9090)# ..
nfty(config-vip:192.168.1.4)# service https:443
nfty(config-vip:192.168.1.4-service:https:443)# balance sticky
Set balance to sticky.
nfty(config-vip:192.168.1.4-service:https:443)# mode nat
Set forwarding mode to nat.
nfty(config-vip:192.168.1.4-service:https:443)# check http /healthz 5s
Set health check to http /healthz every 5s.
nfty(config-vip:192.168.1.4-service:https:443)# to
nfty(config-vip:192.168.1.4-service:https:443-to)# 192.168.1.21:443 weight 3
Added backend 192.168.1.21:443.
nfty(config-vip:192.168.1.4-service:https:443-to)# 192.168.1.22:443 weight 1
Added backend 192.168.1.22:443.
nfty(config-vip:192.168.1.4-service:https:443-to)# 192.168.1.99:443 backup
Added backup backend 192.168.1.99:443.
nfty(config-vip:192.168.1.4-service:https:443-to)# top
nfty(config)#
```

### Drilling into WireGuard Gateways and DNS

```text
nfty(config)# gateway 192.168.1.10/24@eth0
nfty(config-gateway:192.168.1.10)# balance round-robin
nfty(config-gateway:192.168.1.10)# killswitch on
nfty(config-gateway:192.168.1.10)# forward 51413 to 192.168.20.15:51413
nfty(config-gateway:192.168.1.10)# tunnels
nfty(config-gateway:192.168.1.10-tunnels)# wg-mullvad-us1.conf weight 2
nfty(config-gateway:192.168.1.10-tunnels)# wg-mullvad-us2.conf weight 1
nfty(config-gateway:192.168.1.10-tunnels)# top
nfty(config)# dns
nfty(config-dns)# listen 192.168.1.4
nfty(config-dns)# domain lan.internal
nfty(config-dns)# upstream 1.1.1.1 9.9.9.9
nfty(config-dns)# route ipinfo.io via 192.168.1.10
nfty(config-dns)# bypass bank.com from 192.168.1.10
nfty(config-dns)# top
```

### Removing Items with `no ...`

Every context supports negating directives using the `no` prefix (see the [Nftyfile Configuration Reference](./nftyfile-reference.md#9-removing-configuration-with-no-) for the complete matrix):

```text
nfty(config)# vip 192.168.1.4
nfty(config-vip:192.168.1.4)# service https:443
nfty(config-vip:192.168.1.4-service:https:443)# no to 192.168.1.22:443
Removed backend 192.168.1.22:443.
nfty(config-vip:192.168.1.4-service:https:443)# no check
Reverted health check to default (tcp 3s).
```

---

## 5. Candidate vs. Running Configuration Workflow

`nfty` uses a two-stage configuration model:
1. **Running Configuration**: The active configuration currently compiled into the Linux kernel's `table ip nfty` / `table netdev nfty_ingress` ruleset and actively monitored by health probers.
2. **Candidate Configuration**: Your staging buffer in `nfty(config)#`. Modifications made in `configure` mode only affect the candidate configuration until you explicitly `apply` them.

```mermaid
flowchart LR
    Edit["Edit Candidate<br/>(nfty(config)#)"] --> Diff["diff<br/>(Inspect changes)"]
    Diff --> Test["test<br/>(nft -c -f dry-run)"]
    Test --> Apply["apply<br/>(Multi-subsystem apply)"]
    Test --> ApplyConfirm["apply confirm 60<br/>(Process-local timer)"]
    ApplyConfirm -->|"confirm within 60s"| Saved["Save configured Nftyfile"]
    ApplyConfirm -->|"timeout"| AutoRollback["Attempt rollback"]
    Apply --> Saved
```

### Configuration Lifecycle Commands

| Command | Description |
| :--- | :--- |
| `show [section]` | Displays the configuration for the current context (or specific section: `all`, `running`, `candidate`, `nft`, `allow`, `vips`, `dns`). |
| `diff` | Shows a colorized line-by-line diff (`-` removed in red, `+` added in green) between the running config and candidate config. |
| `test` | Compiles the candidate config into `nftables` batch commands and runs `nft -c -f -` (kernel dry-run validation) without applying changes. |
| `apply` | Applies the candidate config, snapshots the previous running config, and saves the configured file. External operations are not one atomic transaction. |
| `apply confirm [sec]` | On a long-running controller, tentatively applies the candidate and starts a process-local rollback timer (default `60` seconds). |
| `confirm` | Cancels an active `apply confirm` rollback countdown and persists the configured file. |
| `load` | Discards all uncommitted edits in the candidate configuration and reloads it from the active running configuration. |
| `rollback [N]` | Reverts the running configuration to snapshot `N` (default `1`, up to the last 10 applied configurations in the rollback ring). |
| `save [path]` | Writes the configuration to `/data/Nftyfile` (or a custom file path). |

> [!WARNING]
> Confirmed apply is unavailable in secondary SSH and one-shot sessions. Its timer is process-local, not durable: a controller crash can leave trial kernel state active until restart. Do not rely on it as the sole recovery mechanism for remote changes.
> Secondary shells do not start their own API or health supervisors; their local state is not a live copy of the controller's health or drain state. Secondary drain/enable commands are sent to the controller socket and fail if it cannot be reached. A command matching multiple endpoints can partially succeed.

---

## 6. Operational Mode Commands

The following commands are available at `nfty>` (and from `nfty(config)#` when not shadowed by a sub-context):

### Health, Backends & Probing

| Command | Description |
| :--- | :--- |
| `status` | Displays a comprehensive dashboard of all VIPs, services, backend health states (`UP`, `DOWN`, `DRAINING`, `STANDBY`), RTT latencies, active failover state, WireGuard tunnels, and DNS status. |
| `probe` | Triggers an immediate out-of-band health probe across all services and backends and prints the refreshed status table. |
| `drain <ip:port>` | Marks a backend as `DRAINING` across all services referencing `<ip:port>` and immediately rebuilds the kernel `nftables` numgen verdict map to stop new connections while existing `conntrack` sessions finish gracefully. |
| `enable <ip:port>` | Clears the `DRAINING` state on `<ip:port>`, returning it to active rotation (if healthy) and immediately updating the kernel verdict map. |

### Flow Inspection & Host Mappings

| Command | Description |
| :--- | :--- |
| `flows [filter]` | Reads `/proc/net/nf_conntrack` and displays active NAT sessions (`proto`, `state`, `src -> dst`, `backend`, `packets`, `bytes`), optionally filtered by substring (IP, port, or protocol). |
| `host <hostname> <ip...>` | Adds or updates a mapping in `/data/hosts.json`, refreshes the active dataplane, and notifies the controller from a secondary session. |

### WireGuard Profile Management (`wg`)

| Command | Description |
| :--- | :--- |
| `wg` | Lists all WireGuard `.conf` profiles stored in `/data/wg/`, active `wg0..wgN` interfaces, endpoints, latest handshakes, and transfer counters. |
| `wg add <name>` | Enters interactive paste mode to upload a WireGuard `.conf` profile into `/data/wg/<name>.conf` (finish with `EOF` or `.`). Newly written profiles use owner-only permissions. Use `POST /api/v1/wg` for non-interactive uploads. |
| `wg show <name>` | Displays the contents of `/data/wg/<name>.conf` (with private keys visible to authenticated CLI administrators). |
| `wg rm <name>` | Deletes `/data/wg/<name>.conf` from disk. |
| `peer list` | Lists all configured WireGuard ingress (`wg-in`) client peers across all gateways. |
| `peer show <name>` | Renders the copy/paste client `.conf` AND terminal UTF-8 QR code for `<name>`. |
| `peer qr <name>` | Renders the scannable terminal UTF-8 QR code for `<name>`. |

### Global SSH Authorized Key Management (`ssh`)

| Command | Description |
| :--- | :--- |
| `ssh` / `ssh list` | Lists all authorized OpenSSH public keys stored in `/data/ssh/*.pub` with their algorithm (`ssh-ed25519`, `ecdsa-sha2-*`, `ssh-rsa`), `SHA256:...` fingerprint, and comment. |
| `ssh add <name> <pubkey>` | Validates and saves an inline OpenSSH public key directly to `/data/ssh/<name>.pub` (e.g. `ssh add workstation ssh-ed25519 AAAA... user@host`). |
| `ssh add <name>` | Enters interactive paste mode and saves `/data/ssh/<name>.pub` once a valid OpenSSH public key line is pasted. |
| `ssh show <name>` | Displays the algorithm, `SHA256:...` fingerprint, and raw OpenSSH public key line in `/data/ssh/<name>.pub`. |
| `ssh rm <name>` | Deletes `/data/ssh/<name>.pub` from `/data/ssh/`. |

### Programmable DNS Operations (`dns`)

| Command | Description |
| :--- | :--- |
| `dns` / `dns status` | Shows the running `dnsmasq` daemon status, listening interfaces, auto-discovered VIP/service host count, active blocklists, and `nftset` policy routes. |
| `dns test <domain>` | Resolves `<domain>` against the local DNS server and displays the returned records and latency. |
| `dns config` | Displays the generated `/run/nfty-dnsmasq.conf` and `/run/nfty-dnsmasq.hosts` files. |
| `dns reload` | Regenerates the `dnsmasq` configuration and sends `SIGHUP` to reload records and blocklists with zero downtime. |

### Cloudflare Zero-Trust Operations (`cf`)

| Command | Description |
| :--- | :--- |
| `cf` / `cf status` | Displays Cloudflare API token state, `cloudflared` tunnel daemon status, and configured `cloudflare-dns` / `cloudflare-auth` services. |
| `cf token <API_TOKEN> [ACCOUNT_ID]` | Stores a Cloudflare API token (and optional Account ID for automatic Zero-Trust tunnel provisioning) in `/data/cloudflare.json` (`0600`). |
| `cf tunnel-token <TUNNEL_TOKEN>` | Stores a pre-generated `cloudflared` tunnel connector token (`eyJ...`) in `/data/cloudflare.json`. |
| `cf sync` | Resumes the connector and synchronizes `cloudflare-dns` records and `cloudflare-auth` Zero-Trust ingress rules with the Cloudflare API. `cf stop` pauses automatic restart until sync, a Cloudflare settings update, or reboot. |
| `cf logs` | Displays the recent output ring buffer from the supervised `cloudflared` daemon. |
| `cf stop` | Stops the supervised `cloudflared` tunnel process. |
| `cf clear` | Removes stored Cloudflare credentials from `/data/cloudflare.json`. |

### Troubleshooting & Diagnostics (`ping`, `traceroute`, and `debug` Mode)

`ping`, `traceroute`, and `arping` can be run directly from `nfty>` (or any mode), and typing `debug` enters the dedicated **`nfty(debug)#`** troubleshooting prompt (or runs a single debug command via `debug <cmd>`):

| Command | Mode | Description |
| :--- | :--- | :--- |
| `ping <host> [-I <ip\|iface>]` | Global (`nfty>`, `nfty(debug)#`) | Sends 5 ICMP echo requests (hard-capped at `-c 5` so the CLI never hangs indefinitely). Supports `-I <source-ip-or-iface>` to test routing from a specific VIP or WireGuard tunnel. |
| `traceroute <host> [-i <iface>]` | Global (`nfty>`, `nfty(debug)#`) | Traces hop-by-hop UDP/ICMP route to `<host>` (max 20 hops, 2s wait per hop). |
| `arping <ip> [-I <iface>]` | Global (`nfty>`, `nfty(debug)#`) | Sends 3 ARP requests on the LAN interface (`eth0` by default) to verify L2 neighbor reachability. |
| `debug` (or `debug <cmd>`) | Global (`nfty>`) | Enters `nfty(debug)#` mode, or executes `<cmd>` directly as a one-shot diagnostic command. |
| `tcp <host:port>` | `nfty(debug)#` | Tests TCP 3-way handshake connectivity to `<host:port>`, measures connection RTT in milliseconds, and reads any initial protocol banner. |
| `dns <host> [server]` | `nfty(debug)#` | Resolves `<host>` via `dnsmasq` / system DNS or a specific upstream DNS server. |
| `interfaces` | `nfty(debug)#` | Displays live kernel network interfaces, link states, MAC addresses, and assigned IPv4/IPv6 addresses (`ip -br link` & `ip -br addr`). |
| `routes` | `nfty(debug)#` | Displays the main routing table (`ip route`), policy routing rules (`ip rule`), and per-tunnel WireGuard routing tables (`table 100..`). |
| `arp` | `nfty(debug)#` | Displays the kernel ARP / L2 neighbor table (`ip neigh`). |
| `sockets` | `nfty(debug)#` | Displays active listening TCP and UDP sockets (`netstat -tulnp`). |
| `wg [iface]` | `nfty(debug)#` | Displays live kernel WireGuard interface status, peer endpoints, latest handshakes, and transfer counters (`wg show`). |
| `nft` | `nfty(debug)#` | Displays the live kernel `nftables` ruleset and packet/byte counters (`nft list ruleset`). |
| `flows` | `nfty(debug)#` | Displays active NAT conntrack sessions from `/proc/net/nf_conntrack`. |
| `dmesg` | `nfty(debug)#` | Displays the last 40 lines of the kernel ring buffer (`dmesg`). |

### Appliance Administration

| Command | Description |
| :--- | :--- |
| `password` | Interactively changes the SSH `nfty` login password (persisted as a salted hash in `/data/auth.json`). |
| `bootstrap` | Bootstraps a static VIP and SSH service in `/data/Nftyfile`. |

