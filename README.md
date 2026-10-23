# nfty

`nfty` is a Linux L4/L7 load balancer, virtual IP (VIP) appliance, and WireGuard policy-routing gateway written in Rust. It compiles a declarative configuration file (`Nftyfile`) or interactive router-style CLI session into atomic kernel `nftables` rulesets (`table ip nfty`), manages static and DHCP `macvlan` virtual IPs (including 802.1Q VLAN sub-interfaces), runs active backend health checks, and boots directly as PID 1 inside a minimal LXD container or UEFI unikernel VM.

## Architecture and Capabilities

- **Declarative `Nftyfile` and Router CLI**: Configure services via `/data/Nftyfile`, a hierarchical CLI (`configure`, `diff`, `test`, `commit`, `apply confirm <secs>`, `rollback`), or the HTTP/JSON control API.
- **Kernel `nftables` Dataplane + Userspace L7 Proxy**:
  - Compiles L4 TCP/UDP port forwarding and weighted `numgen inc mod` (`round-robin`) or `ip saddr` (`sticky`) load balancing into atomic `nft -f` transactions.
  - Provides a userspace L7 reverse proxy for HTTP `Host` and TLS `SNI` routing (`hostname <name>.local`) paired with a multicast mDNS responder (`224.0.0.251:5353`).
- **Static, VLAN, and DHCP Virtual IPs**:
  - Binds static VIPs (`vip 169.254.10.10/24`) to host interfaces or 802.1Q VLAN sub-interfaces (`vlan 20`).
  - Provisions dedicated `macvlan` interfaces with deterministic MAC addresses and `udhcpc` leases for hostname-based DHCP VIPs (`vip web-frontend { dhcp eth0 }`), registering the hostname directly with upstream router DNS.
- **WireGuard Egress Gateways**:
  - Aggregates one or more WireGuard `.conf` tunnels under a single LAN gateway IP (`gateway 169.254.10.20`) using kernel `fwmark` policy routing (`ip rule` + per-tunnel routing tables) and `ct mark` connection pinning.
  - Supports `killswitch on` to drop non-tunnel egress if all WireGuard peers go down.
  - Exposes gateway-bound `privoxy:<port>` (HTTP/HTTPS `CONNECT`) and `socks5:<port>` listeners pinned to active WireGuard interfaces via `SO_BINDTODEVICE` and `SO_MARK`.
- **Cloudflare Tunnel and Authentication**:
  - `cloudflare-dns <fqdn>` provisions a remotely-managed Cloudflare Tunnel, ingress rule, and proxied CNAME record via the Cloudflare API and supervises `cloudflared`.
  - `cloudflare-auth <email...>` configures Cloudflare Zero Trust Access self-hosted applications and email/domain allow policies (`user@example.com`, `*@example.com`).
  - `auth <user:pass | nfty>` enforces HTTP Basic Authentication directly in `nfty` across both Cloudflare Tunnel traffic and local VIP requests.
- **PID-1 Appliance Runtime**:
  - Runs as `/sbin/init` (PID 1): mounts `/proc`, `/sys`, `/dev`, and `/data`, brings up networking, starts an embedded SSH2 server (`russh`) on port 22, and persists configuration atomically to `/data`.

---

## Bootstrapping a New Appliance

On a fresh LXD container or unikernel VM with an empty `/data/Nftyfile`, the `bootstrap` command assigns your primary virtual IP to the network interface, creates the initial `vip` block with local SSH (`ssh:22`) enabled, applies the kernel `nftables` ruleset, and writes `/data/Nftyfile`.

### 1. Run `bootstrap` from the Host or Console

From an LXD host (without entering an interactive shell):

```bash
lxc exec nfty -- /sbin/init -c "bootstrap 169.254.10.10/24 on eth0"
```

Or from the appliance console (`lxc console nfty` / `lxc exec nfty -- /bin/nfty`):

```text
nfty# bootstrap 169.254.10.10/24 on eth0
  ✔ Bootstrapped VIP 169.254.10.10/24 on eth0 (created base config 'service 169.254.10.10:22' with SSH enabled)
  → VIP applied: ip addr replace 169.254.10.10/24 dev eth0
```

This generates and commits the base configuration:

```hcl
vip 169.254.10.10/24 {
    ssh:22
}
```

### 2. Connect Over SSH and Set the Appliance Password

Once bootstrapped, connect directly to the VIP over SSH:

```bash
ssh nfty@169.254.10.10
```

- **Default initial credentials**: username `nfty`, password `nfty`.
- On first login, `nfty` enforces an interactive password change and stores the salted SHA-256 hash in `/data/auth.json`. You can rotate the password at any time from the operational prompt with `password`.

---

## Common Configuration Examples

### 1. Static VIP with Port Forwarding and L7 Hostname Routing

Multiple backend services can share a single static VIP. Each service can expose its native port on the VIP and optionally register a `.local` hostname for mDNS and L7 HTTP `Host` / TLS `SNI` routing on ports `80` and `443`:

```hcl
vip 169.254.10.10/24 {
    ssh:22
    app-server:3000 {
        hostname grafana.local
        check tcp 5s
    }
    metrics-node:9090 {
        hostname prometheus.local
        check http /-/healthy 10s
    }
}
```

Equivalent interactive CLI commands:

```text
nfty# conf
nfty(config)# vip 169.254.10.10/24
nfty(config-vip:169.254.10.10)# ssh:22
nfty(config-vip:169.254.10.10)# service app-server:3000
nfty(config-service:169.254.10.10:3000)# hostname grafana.local
nfty(config-service:169.254.10.10:3000)# check tcp 5s
nfty(config-service:169.254.10.10:3000)# commit
```

### 2. Dedicated DHCP `macvlan` VIPs and 802.1Q VLANs

Instead of managing static IPs, a VIP can be named after a service (`vip web-app`). `nfty` creates a `macvlan` interface (optionally on an 802.1Q VLAN tag), requests a DHCP lease via `udhcpc -x hostname:web-app` so your router registers `web-app` in local DNS, and maps port `80` on that leased IP to the backend container's port:

```hcl
vip web-app {
    dhcp eth0
    vlan 20
    80 to backend-container:8080 {
        check tcp 5s
    }
}
```

Equivalent interactive CLI commands:

```text
nfty(config)# vip web-app dhcp eth0 vlan 20
nfty(config-vip:web-app)# 80 to backend-container:8080
nfty(config-vip:web-app)# commit
```

### 3. Multi-Backend Load Balancing, Weights, and Failover

Services with multiple backends in a `to { ... }` block are load-balanced in kernel `nftables` (`round-robin` or `sticky` by source IP). Backends marked `backup` are only programmed into the active `nftables` set when all primary backends fail their health checks:

```hcl
vip 169.254.10.15/24 {
    443 {
        balance round-robin
        check tcp 3s
        limit 200/sec burst 100 per-ip
        allow {
            169.254.0.0/16
            *.corp.local
        }
        to {
            169.254.20.11:8443 weight 3
            169.254.20.12:8443 weight 1
            169.254.20.13:8443 backup
        }
    }
}
```

### 4. WireGuard Multi-Tunnel Egress Gateway

A `gateway` block binds a virtual gateway IP (`169.254.10.20`) and distributes outbound traffic across one or more WireGuard configurations stored in `/data/wg/`. Other machines or containers on the LAN can either set `169.254.10.20` as their default IPv4 gateway or use the built-in `privoxy` (HTTP/CONNECT) and `socks5` proxies bound to the gateway IP. Inbound ports on the WireGuard tunnel interfaces can also be forwarded to LAN hosts with `forward <port> to <host:port>` (with per-tunnel `ct mark` return-path pinning):

```hcl
gateway 169.254.10.20 {
    balance round-robin
    killswitch on
    check ping 5s
    privoxy:8118
    socks5:1080
    forward 51413 to 169.254.20.15:51413
    tunnels {
        wg-exit-01.conf weight 2
        wg-exit-02.conf weight 1
    }
}
```

Adding WireGuard tunnel configs and port forwards from the CLI:

```text
nfty# wg paste wg-exit-01
nfty# conf
nfty(config)# gateway 169.254.10.20
nfty(config-gw:169.254.10.20)# killswitch on
nfty(config-gw:169.254.10.20)# privoxy:8118
nfty(config-gw:169.254.10.20)# socks5:1080
nfty(config-gw:169.254.10.20)# forward 51413 to 169.254.20.15:51413
nfty(config-gw:169.254.10.20)# tunnels
nfty(config-gw-tunnels:169.254.10.20)# wg-exit-01.conf
nfty(config-gw-tunnels:169.254.10.20)# commit
```

### 5. Cloudflare Tunnel, Zero Trust Email Auth, and HTTP Basic Auth

Once a Cloudflare API token is registered (`cf token <API_TOKEN> [ACCOUNT_ID]`), any service with `cloudflare-dns <fqdn>` is automatically published through a remotely-managed Cloudflare Tunnel and DNS CNAME record. You can layer Cloudflare Zero Trust email OTP/IdP policies (`cloudflare-auth`) and/or `nfty`'s built-in HTTP Basic Auth (`auth`):

```hcl
vip 169.254.10.10/24 {
    internal-app:8080 {
        hostname app.local
        cloudflare-dns app.example.com
        cloudflare-auth ops@example.com *@example.com
        auth admin:s3cr3t nfty
        check tcp 5s
    }
}
```

Checking tunnel and auth status:

```text
nfty# cf status
```

### 6. Service Discovery (`scan` / `adopt`) and Safe Rollbacks

Scan the local subnet/ARP table for running containers and adopt a discovered service directly into a VIP:

```text
nfty# scan
nfty# adopt 1 vip 169.254.10.10
nfty(config-vip:169.254.10.10)# apply confirm 60
  ✔ Applied ruleset to kernel nftables
  Safety rollback timer active for 60s! Type 'confirm' to keep changes.
nfty(config-vip:169.254.10.10)# confirm
```

---

## Building and Launching

### Prerequisites

- Linux host (`x86_64`) with Rust 1.75+ and the `x86_64-unknown-linux-musl` target installed:
  ```bash
  rustup target add x86_64-unknown-linux-musl
  ```
- Runtime tools required on the target host (or bundled into the appliance rootfs by `packaging/unikernel/build-unikernel.sh`):
  - `nft` (`nftables`)
  - `wg` (`wireguard-tools`, optional unless using `gateway` tunnels)
  - Static `busybox` at `packaging/unikernel/busybox` (for `ip`, `ping`, `udhcpc`, `mount`, `vi` inside the appliance image)
  - Optional `cloudflared` binary at `packaging/unikernel/cloudflared` (only required if using `cloudflare-dns`)

### 1. Build and Launch on LXD (Container Appliance)

`packaging/unikernel/build-unikernel.sh` compiles a static `musl` binary and packages a minimal rootfs where `/sbin/init` is `nfty`.

```bash
# Build LXD container and VM images into dist/
./packaging/unikernel/build-unikernel.sh

# Import and launch on a local LXD daemon
lxc image import dist/lxd-container/lxd.tar.gz dist/lxd-container/rootfs.tar.gz --alias nfty-ct
lxc storage volume create default nfty-data
lxc init nfty-ct nfty
lxc config device add nfty data disk pool=default source=nfty-data path=/data
lxc start nfty
```

To build and roll out an update to a remote LXD host while preserving `/data` (`Nftyfile`, `auth.json`, `cloudflare.json`, `hosts.json`, and `/data/wg/*.conf`):

```bash
./packaging/deploy-lxd.sh <lxd-host-ip> [instance-name]
# Example:
./packaging/deploy-lxd.sh 169.254.1.10 nfty
```

For fast binary-only updates during development without rebuilding the full LXD image:

```bash
cargo build --release --target x86_64-unknown-linux-musl
scp target/x86_64-unknown-linux-musl/release/nfty 169.254.1.10:/tmp/nfty-bin
ssh 169.254.1.10 "lxc stop -f nfty && lxc file push --mode=0755 /tmp/nfty-bin nfty/bin/nfty && lxc start nfty"
```

### 2. Build and Launch as a Bootable Unikernel VM (LXD VM or QEMU)

`packaging/unikernel/build-unikernel.sh` also assembles a 196 MiB GPT disk image (`dist/lxd-vm/disk.qcow2`) containing a 64 MiB UEFI ESP (`systemd-boot` + kernel + `nfty` initramfs with `rdinit=/init`) and a 128 MiB `ext4` partition labeled `nfty-data` mounted at `/data`.

**Launch as an LXD Virtual Machine:**

```bash
./packaging/unikernel/build-unikernel.sh
lxc image import dist/lxd-vm/lxd.tar.gz dist/lxd-vm/disk.qcow2 --alias nfty-unikernel
lxc launch nfty-unikernel nfty-vm --vm -c security.secureboot=false
lxc console nfty-vm
```

**Launch directly with QEMU/KVM (initramfs + kernel):**

```bash
qemu-system-x86_64 \
  -enable-kvm -m 256M -smp 2 \
  -kernel /boot/vmlinuz-linux \
  -initrd dist/nfty-unikernel-initramfs.cpio.gz \
  -append "console=ttyS0 quiet rdinit=/init -- --unikernel --file /data/Nftyfile" \
  -nographic
```

### 3. Build and Run as a Standalone Linux Daemon

To run `nfty` on an existing Linux server or router without the PID-1 unikernel init flow:

```bash
./packaging/standalone/build-standalone.sh

# Run interactive REPL + background health prober + HTTP control API
sudo ./dist/standalone/nfty --file /etc/nfty/Nftyfile --api-bind 127.0.0.1:9090

# Or run headless under systemd (see packaging/standalone/nfty.service)
sudo ./dist/standalone/nfty --file /etc/nfty/Nftyfile --apply --daemon
```

---

## Codebase Layout

```text
src/
├── main.rs                  # CLI entrypoint, PID-1 detection, unit/integration tests
├── ast.rs                   # Nftyfile AST (Config, VipConfig, Service, Gateway, WgTunnel)
├── state.rs                 # Shared runtime state, candidate/running configs, allow-lists
├── parser.rs                # Nftyfile and interactive directive parser
├── compiler.rs              # nftables ruleset generator, DHCP macvlan & VLAN setup
├── unikernel.rs             # PID-1 mount/network init, atomic /data persistence, L4 fallback
├── health.rs                # TCP/HTTP/ICMP/WireGuard health prober and DNS refresher
├── api.rs                   # HTTP/JSON control API and embedded status UI
├── ssh.rs                   # Built-in SSH2 server (russh) and credential store
├── tui.rs                   # Terminal dashboard (ratatui)
├── features/
│   ├── mod.rs               # Background daemon supervisor and module re-exports
│   ├── wireguard.rs         # WireGuard config parser, kernel wg/ip-rule sync, wg CLI
│   ├── vhost_mdns.rs        # Multicast mDNS responder and L7 Host/SNI reverse proxy
│   ├── gateway_proxy.rs     # Gateway-bound Privoxy (HTTP/CONNECT) and SOCKS5 proxies
│   ├── cloudflare.rs        # cloudflared supervisor, Cloudflare API sync, Basic Auth gate
│   ├── scanner.rs           # LAN/LXD service discovery and banner probing
│   └── flows.rs             # Kernel conntrack (/proc/net/nf_conntrack) flow viewer
└── repl/
    ├── mod.rs               # Interactive shell loop, drill-down contexts, command handlers
    ├── completer.rs         # Context-aware tab completion (rustyline)
    ├── status.rs            # status, show, and diff formatters
    └── help.rs              # Context-sensitive CLI help
```

---

## Contributing

1. **Keep modules focused**:
   - Parser changes belong in `src/parser.rs` and AST serialization in `src/ast.rs` (ensure `parse_nftyfile(&cfg.format_nftyfile())` round-trips cleanly).
   - Feature daemons belong in their respective `src/features/<feature>.rs` submodule rather than growing `mod.rs` or `repl/mod.rs`.
2. **Preserve `/data` compatibility**:
   - Any new fields added to serialized structs in `src/ast.rs`, `src/ssh.rs`, or `src/features/cloudflare.rs` must use `#[serde(default)]` so existing `/data/*.json` and `/data/Nftyfile` files upgrade without data loss.
   - Never write to `/data` non-atomically; use write-to-temp + `fs::rename`.
3. **Verify before opening a pull request**:
   - Run the test suite:
     ```bash
     cargo test
     ```
   - Verify the static `musl` target compiles cleanly with zero warnings:
     ```bash
     cargo check --release --target x86_64-unknown-linux-musl
     ```
4. **Commit messages**:
   - Use clear, imperative commit subjects describing the subsystem and behavior change (e.g., `cloudflare: strip Basic Authorization header before upstream proxy`).

## License

See [LICENSE](LICENSE).
