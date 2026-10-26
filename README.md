# nfty

`nfty` is a Linux L4/L7 load balancer, virtual IP (VIP) appliance, and policy-routing egress gateway (direct Internet NAT or multi-tunnel WireGuard) written in Rust. It compiles a declarative configuration file (`Nftyfile`) or interactive router-style CLI session into atomic kernel `nftables` rulesets (`table ip nfty`), manages static and DHCP `macvlan` virtual IPs (including 802.1Q VLAN sub-interfaces), runs active backend health checks, and boots directly as PID 1 inside a minimal LXD container, UEFI unikernel VM, or bare-metal ARM64 SBC.

## Architecture and Capabilities

- **Declarative `Nftyfile` and Router CLI**: Configure services via `/data/Nftyfile`, a hierarchical CLI (`configure`, `diff`, `test`, `commit`, `apply confirm <secs>`, `rollback`), or the HTTP/JSON control API.
- **Kernel `nftables` Dataplane + Userspace L7 Proxy**:
  - Compiles L4 TCP/UDP port forwarding and weighted `numgen inc mod` (`round-robin`) or `ip saddr` (`sticky`) load balancing into atomic `nft -f` transactions.
  - Provides a userspace L7 reverse proxy for HTTP `Host` and TLS `SNI` routing (`hostname <name>.local`) paired with a multicast mDNS responder (`224.0.0.251:5353`).
- **Static, VLAN, and DHCP Virtual IPs**:
  - Binds static VIPs (`vip 169.254.10.10/24`) to host interfaces or 802.1Q VLAN sub-interfaces (`vlan 20`).
  - Provisions dedicated `macvlan` interfaces with deterministic MAC addresses and `udhcpc` leases for hostname-based DHCP VIPs (`vip web-frontend { dhcp eth0 }`), registering the hostname directly with upstream router DNS.
- **Internet NAT and WireGuard Egress Gateways**:
  - Binds static or DHCP virtual gateway IPs (`gateway 169.254.10.20` or `gateway lan-exit dhcp eth0`) that LAN machines or containers can use as their default IPv4 gateway (`ip route replace default via ...`).
  - **Direct Internet Gateway Mode**: When configured without WireGuard tunnels, `nfty` masquerades forwarded LAN traffic directly out the primary WAN/LAN interface (`eth0`), enforces optional source `allow` ACLs, and exposes built-in `privoxy:<port>` (HTTP/HTTPS `CONNECT`) and `socks5:<port>` proxies.
  - **WireGuard Multi-Tunnel Mode**: Aggregates one or more WireGuard `.conf` tunnels under the gateway IP using kernel `fwmark` policy routing (`ip rule` + per-tunnel routing tables), `ct mark` connection pinning, `killswitch on`, and inbound tunnel port forwarding (`forward <port> to <host:port>`).
- **Programmable DNS Endpoint (`dnsmasq` + `nftset`)**:
  - Supervises a native `dnsmasq` endpoint (`dns:53` on VIPs/gateways or global `dns { ... }`) that automatically synthesizes forward (`A`) and reverse (`PTR`) records from configured VIPs, gateways, `/etc/hosts`, and discovered LAN services, and dynamically removes unhealthy backends from DNS responses (`health-aware on`).
  - Supports authoritative `a`, `aaaa`, wildcard `address`, `cname`, `txt`, `srv`, `mx`, and `ptr` records, split-horizon conditional zone forwarding (`forward <domain> <server> [via <gateway>]`), and domain sinkholing (`block` / `blocklist`).
  - Integrates `dnsmasq`'s native `nftset=` engine with `table ip nfty` dynamic timeout sets (`@dns_route_<gw>` and `@dns_bypass_<gw>`) for zero-latency domain-based policy routing (`route <domain...> via <gateway>` and `bypass <domain...> from <gateway>`).
- **Cloudflare Tunnel and Authentication**:
  - `cloudflare-dns <fqdn>` provisions a remotely-managed Cloudflare Tunnel, ingress rule, and proxied CNAME record via the Cloudflare API and supervises `cloudflared`.
  - `cloudflare-auth <email...>` configures Cloudflare Zero Trust Access self-hosted applications and email/domain allow policies (`user@example.com`, `*@example.com`).
  - `auth <user:pass | nfty>` enforces HTTP Basic Authentication directly in `nfty` across both Cloudflare Tunnel traffic and local VIP requests.
- **PID-1 Appliance Runtime & 100% Config-Driven IP Assignment**:
  - Runs as `/sbin/init` (PID 1): mounts `/proc`, `/sys`, `/dev`, and `/data`, brings up link layer on `eth0` without grabbing an unconfigured base OS IP, starts an embedded post-quantum SSH2 server (`russh` with `mlkem768x25519-sha256`) on port 22, and persists configuration atomically to `/data`. Every IP address on the appliance (static or DHCP) is strictly declared in `/data/Nftyfile`.
  - No default `:9090` Control API listener is bound unless explicitly configured via `api:<port>` / `web:<port>` on a VIP/Gateway (or `--api-bind`).
  - Includes a dedicated **`debug` mode (`nfty(debug)#`)** and top-level `ping` (capped at `-c 5`) and `traceroute` commands for live network diagnostics (`ping`, `traceroute`, `tcp`, `dns`, `arping`, `interfaces`, `routes`, `arp`, `sockets`, `wg`, `nft`, `flows`, `dmesg`).

---

## Default DHCP Gateway & Bootstrapping a New Appliance

Fresh LXD container and unikernel VM appliances ship with a pre-seeded `/data/Nftyfile` defining a DHCP gateway named `default` with SSH (`ssh:22`) enabled:

```hcl
gateway default {
    dhcp eth0
    ssh:22
}
```

On first boot, `nfty` automatically acquires a DHCP lease on `eth0` (because `gateway default` is named `default`), applies the kernel `nftables` ruleset, and exposes the embedded SSH server on port 22 so you can connect immediately (`ssh nfty@default` or `ssh nfty@<leased-ip>`, inspectable via `status` or `debug interfaces`). Once you replace `gateway default` with your own static VIPs or gateways, `nfty` automatically stops `udhcpc` on `eth0` and removes the unconfigured DHCP lease so only your configured IPs remain on `eth0`.

If you prefer a static Virtual IP instead, run `bootstrap` to assign a static VIP to `eth0` and replace the starter config.

### 1. Optional: Run `bootstrap` for a Static VIP


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

### 2. Connect Over SSH and Set the Appliance Password (or Add SSH Public Keys)

Once bootstrapped, connect directly to the VIP over SSH:

```bash
ssh nfty@169.254.10.10
```

- **Default initial credentials**: username `nfty`, password `nfty`.
- On first password login, `nfty` enforces an interactive password change and stores the salted SHA-256 hash in `/data/auth.json`. You can rotate the password at any time from the operational prompt with `password`.
- **Global SSH Authorized Keys (`/data/ssh/*.pub`)**: Add OpenSSH public keys (`ssh-ed25519`, `ecdsa-sha2-*`, `ssh-rsa`) for passwordless SSH login across all `ssh:22` listeners using the same workflow as `wg`:
  ```text
  nfty> ssh add workstation ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... admin@workstation
  nfty> ssh paste laptop
  nfty> ssh add yubikey          # opens nano on /data/ssh/yubikey.pub
  nfty> ssh list                 # lists all saved keys and SHA256 fingerprints
  nfty> ssh rm laptop
  ```

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

### 4. Internet NAT and WireGuard Egress Gateways

A `gateway` block binds a virtual gateway IP (`169.254.10.20` or a DHCP `macvlan` hostname) that other machines, VMs, or containers on the LAN can set as their default IPv4 gateway or reach via the built-in `privoxy` (HTTP/CONNECT) and `socks5` proxies.

**Direct Internet / LAN NAT Gateway (no VPN tunnels):**

When no `tunnels` block is configured, `nfty` enables IPv4 forwarding and kernel `nftables` masquerading (`oifname "eth0" masquerade`) so isolated containers, VLANs, or lab hosts can route outbound Internet traffic or proxy connections through `nfty`:

```hcl
gateway 169.254.10.19 {
    check ping 5s
    privoxy:8118
    socks5:1080
    allow {
        169.254.0.0/16
    }
}
```

**WireGuard Multi-Tunnel Egress Gateway:**

When one or more WireGuard configurations stored in `/data/wg/` are attached, `nfty` policy-routes traffic from the gateway across the tunnels (`round-robin` or `sticky`), optionally drops non-tunnel leaks with `killswitch on`, and forwards inbound ports from the WireGuard interfaces to LAN hosts with `forward <port> to <host:port>` (using per-tunnel `ct mark` return-path pinning):

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

Configuring a gateway from the CLI:

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

### 6. Programmable DNS Endpoint (`dnsmasq` + `nftset` Domain Routing)

`nfty` can act as a full authoritative and caching DNS server on any VIP or gateway (`dns:53`) or via a global `dns { ... }` block. Under the hood, `nfty` compiles your `Nftyfile` and live health-check state into `/run/nfty-dnsmasq.conf` and `/run/nfty-dnsmasq.hosts`, signals `dnsmasq` via `SIGHUP` on host/health changes for zero-downtime cache preservation, and wires `dnsmasq`'s `nftset=` directive into kernel `table ip nfty` sets:

```hcl
vip 169.254.10.10/24 {
    dns:53
    80 to 169.254.20.10:8989 {
        hostname sonarr.local
    }
}

gateway 169.254.10.20/24 {
    dns:53
    killswitch on
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
    forward corp.internal 169.254.99.1 via 169.254.10.20

    a nas.lan 169.254.1.50
    aaaa nas.lan fd00::50
    address *.k8s.lan 169.254.1.100
    cname media.lan sonarr.lan
    txt _acme-challenge.example.com "token-xyz"
    srv _minecraft._tcp.lan mc.lan:25565 priority 0 weight 5
    mx lan mail.lan priority 10

    # Populate kernel nftables sets on DNS resolution to route or bypass gateways by domain:
    route linuxisos.org tracker.example.org via 169.254.10.20
    bypass plex.tv netflix.com from 169.254.10.20

    block doubleclick.net *.ads.example.com
}
```

Interactive CLI configuration and operational diagnostics:

```text
nfty# conf
nfty(config)# dns
nfty(config-dns)# domain lan
nfty(config-dns)# a nas.lan 169.254.1.50
nfty(config-dns)# address *.k8s.lan 169.254.1.100
nfty(config-dns)# route linuxisos.org via 169.254.10.20
nfty(config-dns)# bypass plex.tv from 169.254.10.20
nfty(config-dns)# commit
nfty# dns status
nfty# dns test sonarr.lan
```

### 7. Service Discovery (`scan` / `adopt`), Troubleshooting (`debug`), and Safe Rollbacks

Scan the local subnet/ARP table for running containers and adopt a discovered service directly into a VIP:

```text
nfty> scan
nfty> adopt 1 vip 169.254.10.10
nfty(config-vip:169.254.10.10)# apply confirm 60
  ✔ Applied ruleset to kernel nftables
  Safety rollback timer active for 60s! Type 'confirm' to keep changes.
nfty(config-vip:169.254.10.10)# confirm
```

Run `ping` (automatically capped at 5 packets) and `traceroute` directly from `nfty>`, or enter `debug` mode (`nfty(debug)#`) for interactive network troubleshooting:

```text
nfty> ping 1.1.1.1
nfty> traceroute 1.1.1.1
nfty> debug
nfty(debug)# interfaces
nfty(debug)# routes
nfty(debug)# tcp 169.254.20.10:8080
nfty(debug)# wg
nfty(debug)# nft
nfty(debug)# dmesg
nfty(debug)# exit
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
  - `dnsmasq` (compiled with `nftset` support, optional unless using `dns`)
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

`packaging/unikernel/build-unikernel.sh` builds a hybrid BIOS + UEFI Secure Boot ISO (`dist/nfty-unikernel-x86_64.iso`) and a 264 MiB GPT disk image (`dist/nfty-unikernel-x86_64.img.gz` / `dist/lxd-vm/disk.qcow2`) containing a 128 MiB UEFI Secure Boot ESP (`shim-signed` + `grub-efi-amd64-signed` + signed Debian 6.12 LTS kernel + `nfty` initramfs with `rdinit=/init`) and a 128 MiB `ext4` partition labeled `nfty-data` mounted at `/data`.

**Launch as an LXD Virtual Machine:**

```bash
./packaging/unikernel/build-unikernel.sh
lxc image import dist/lxd-vm/lxd.tar.gz dist/lxd-vm/disk.qcow2 --alias nfty-unikernel
lxc launch nfty-unikernel nfty-vm --vm
lxc console nfty-vm
```

**Launch directly with QEMU/KVM from the ISO:**

```bash
qemu-system-x86_64 \
  -enable-kvm -m 512M -smp 2 \
  -cdrom dist/nfty-unikernel-x86_64.iso \
  -nographic
```

### 3. Build and Run as a Standalone Linux Daemon

To run `nfty` on an existing Linux server or router without the PID-1 unikernel init flow:

```bash
./packaging/standalone/build-standalone.sh

# Run interactive REPL + background health prober
sudo ./dist/standalone/nfty --file /etc/nfty/Nftyfile

# Or run headless under systemd (see packaging/standalone/nfty.service)
sudo ./dist/standalone/nfty --file /etc/nfty/Nftyfile daemon
```

### 4. Build and Flash a Bare-Metal RK3588S / ARM64 Unikernel Image

`packaging/rk3588s/build-rk3588s.sh` cross-compiles `nfty` to `aarch64-unknown-linux-musl` and builds a bootable GPT disk image (`dist/rk3588s/nfty-rk3588s.img.gz`) containing Rockchip U-Boot (`idbloader` + `u-boot.itb` at sector 64), a hybrid U-Boot (`extlinux.conf`) + UEFI (`BOOTAA64.EFI`) boot partition with Linux 6.18 LTS and all mainline `rk3588s-*.dtb` / `rk3588-*.dtb` device trees, the ARM64 `nfty` PID-1 initramfs, and a 128 MiB `ext4` `/data` partition.

```bash
# Build universal RK3588S / RK3588 disk image and ARM64 LXD container image
./packaging/rk3588s/build-rk3588s.sh

# Or build with board-specific edk2-rk3588 UEFI firmware embedded at sector 64:
./packaging/rk3588s/build-rk3588s.sh orangepi-5   # or rock-5a, nanopi-r6s, nanopi-r6c, edge2

# Flash directly to MicroSD, eMMC, or NVMe:
zcat dist/rk3588s/nfty-rk3588s.img.gz | sudo dd of=/dev/sdX bs=4M status=progress conv=fsync
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
│   ├── dns.rs               # dnsmasq config/hosts compiler, supervisor, nftset & DNS CLI
│   ├── wireguard.rs         # WireGuard config parser, kernel wg/ip-rule sync, wg CLI
│   ├── vhost_mdns.rs        # Multicast mDNS responder and L7 Host/SNI reverse proxy
│   ├── gateway_proxy.rs     # Gateway-bound Privoxy (HTTP/CONNECT) and SOCKS5 proxies
│   ├── cloudflare.rs        # cloudflared supervisor, Cloudflare API sync, Basic Auth gate
│   ├── scanner.rs           # LAN/LXD service discovery and banner probing
│   └── flows.rs             # Kernel conntrack (/proc/net/nf_conntrack) flow viewer
└── repl/
    ├── mod.rs               # Interactive shell loop, drill-down contexts, command handlers
    ├── debug.rs             # Troubleshooting & diagnostics mode (nfty(debug)#, ping, traceroute)
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
