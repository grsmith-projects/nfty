# nfty

`nfty` is a Linux L4/L7 load balancer, virtual IP (VIP) appliance, and WireGuard policy-routing gateway written in Rust. It compiles a declarative configuration file (`Nftyfile`) or interactive router-style CLI session into atomic kernel `nftables` rulesets (`table ip nfty`), manages static and DHCP `macvlan` virtual IPs (including 802.1Q VLAN sub-interfaces), runs active backend health checks, and can boot directly as PID 1 inside a minimal LXD container or UEFI unikernel VM.

## Architecture and Capabilities

- **Declarative `Nftyfile` and Router CLI**: Configure services via `/data/Nftyfile`, a hierarchical CLI (`configure`, `diff`, `test`, `commit`, `apply confirm <secs>`, `rollback`), or the HTTP/JSON control API.
- **Kernel `nftables` Dataplane + Userspace L7 Proxy**:
  - Compiles L4 TCP/UDP port forwarding and weighted `numgen inc mod` (`round-robin`) or `ip saddr` (`sticky`) load balancing into atomic `nft -f` transactions.
  - Provides a userspace L7 reverse proxy for HTTP `Host` and TLS `SNI` routing (`hostname <name>.local`) paired with a multicast mDNS responder (`224.0.0.251:5353`).
- **Static, VLAN, and DHCP Virtual IPs**:
  - Binds static VIPs (`vip 192.168.1.4`) to host interfaces or 802.1Q VLAN sub-interfaces (`vlan 20`).
  - Provisions dedicated `macvlan` interfaces with deterministic MAC addresses and `udhcpc` leases for hostname-based DHCP VIPs (`vip sonarr { dhcp eth0 }`), registering the hostname directly with upstream router DNS (e.g., UniFi Dream Machine, dnsmasq).
- **WireGuard Egress Gateways**:
  - Aggregates one or more WireGuard `.conf` tunnels under a single LAN gateway IP (`gateway 192.168.1.10`) using kernel `fwmark` policy routing (`ip rule` + per-tunnel routing tables) and `ct mark` connection pinning.
  - Supports `killswitch on` to drop non-tunnel egress if all WireGuard peers go down.
  - Exposes gateway-bound `privoxy:<port>` (HTTP/HTTPS `CONNECT`) and `socks5:<port>` listeners pinned to active WireGuard interfaces via `SO_BINDTODEVICE` and `SO_MARK`.
- **Cloudflare Tunnel and Authentication**:
  - `cloudflare-dns <fqdn>` provisions a remotely-managed Cloudflare Tunnel, ingress rule, and proxied CNAME record via the Cloudflare API and supervises `cloudflared`.
  - `cloudflare-auth <email...>` configures Cloudflare Zero Trust Access self-hosted applications and email/domain allow policies (`user@domain.com`, `*@domain.com`).
  - `auth <user:pass | nfty>` enforces HTTP Basic Authentication directly in `nfty` across both Cloudflare Tunnel traffic and local VIP requests.
- **PID-1 Appliance Runtime**:
  - Runs as `/sbin/init` (PID 1): mounts `/proc`, `/sys`, `/dev`, and `/data`, brings up networking, starts an embedded SSH2 server (`russh`) on port 22, and persists configuration atomically to `/data`.

---

## Example Configuration (`Nftyfile`)

```hcl
vip 192.168.1.4 {
    ssh:22
    media-util:7878 {
        hostname radarr.local
        cloudflare-dns radarr.example.com
        check tcp 5s
    }
    media-util:8989 {
        hostname sonarr.local
        check tcp 5s
    }
    gamble:9090 {
        hostname gamble.local
        cloudflare-dns gamble.example.com
        cloudflare-auth admin@example.com *@example.com
        auth admin:secret nfty
        check tcp 5s
    }
}

vip sonarr {
    dhcp eth0
    vlan 20
    80 to media-util:8989 {
        check tcp 5s
    }
}

gateway 192.168.1.10 {
    balance round-robin
    killswitch on
    check ping 5s
    privoxy:8118
    socks5:1080
    tunnels {
        wg-van-01.conf
        wg-van-02.conf
    }
}
```

### Interactive CLI Usage

Connect to a running appliance over SSH (`ssh nfty@<vip>`, default initial credentials `nfty` / `nfty` with forced password change on first login) or attach via `lxc exec nfty -- /bin/nfty`:

```text
nfty# status
nfty# scan
nfty# conf
nfty(config)# vip 192.168.1.4
nfty(config-vip:192.168.1.4)# service media-util:7878
nfty(config-service:192.168.1.4:7878)# cloudflare-dns radarr.example.com
nfty(config-service:192.168.1.4:7878)# auth admin:hunter2
nfty(config-service:192.168.1.4:7878)# diff
nfty(config-service:192.168.1.4:7878)# commit
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
./packaging/deploy-lxd.sh 192.168.1.3 nfty
```

For fast binary-only updates during development without rebuilding the full LXD image:

```bash
cargo build --release --target x86_64-unknown-linux-musl
scp target/x86_64-unknown-linux-musl/release/nfty 192.168.1.3:/tmp/nfty-bin
ssh 192.168.1.3 "lxc stop -f nfty && lxc file push --mode=0755 /tmp/nfty-bin nfty/bin/nfty && lxc start nfty"
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
