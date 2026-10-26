# Programmable DNS, WireGuard Gateways & Zero-Trust Tunnels

Beyond Layer 4 load balancing, `nfty` unifies **authoritative & split-horizon DNS (`dnsmasq`)**, **multi-tunnel WireGuard Virtual Gateways**, **DNS-driven kernel `nftset` policy routing**, **gateway-bound HTTP/SOCKS5 proxies**, and **Cloudflare Zero-Trust tunnels (`cloudflared`)** inside a single declarative `Nftyfile`.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Programmable DNS (`dns` Block)](#2-programmable-dns-dns-block)
3. [Automatic VIP & Health-Aware Service DNS Discovery](#3-automatic-vip--health-aware-service-dns-discovery)
4. [Split-Horizon DNS & Tunnel-Bound Upstream Forwarding](#4-split-horizon-dns--tunnel-bound-upstream-forwarding)
5. [DNS-Driven Kernel `nftset` Policy Routing (`route` & `bypass`)](#5-dns-driven-kernel-nftset-policy-routing-route--bypass)
6. [Ad, Tracker & Malware Sinkholing (`block` & `blocklist`)](#6-ad-tracker--malware-sinkholing-block--blocklist)
7. [WireGuard Virtual Gateways (`gateway` Block)](#7-wireguard-virtual-gateways-gateway-block)
8. [Gateway Proxies (`privoxy` & `socks5`) & Port Forwarding](#8-gateway-proxies-privoxy--socks5--port-forwarding)
9. [Cloudflare DNS & Zero-Trust Tunnels (`cloudflare-dns` & `cloudflare-auth`)](#9-cloudflare-dns--zero-trust-tunnels-cloudflare-dns--cloudflare-auth)

---

## 1. Architecture Overview

The following diagram illustrates how `nfty` coordinates `dnsmasq`, kernel `nftables` sets (`@dns_route_<gw>` and `@dns_bypass_<gw>`), Linux policy routing tables (`101..100+N`), and `wg0..wgN` interfaces:

```mermaid
flowchart TD
    Client["LAN Client<br/>(Default GW: 169.254.1.10, DNS: 169.254.1.4)"]
    Dnsmasq["Embedded dnsmasq<br/>(/run/nfty-dnsmasq.conf)"]
    NftSetRoute["Kernel nftables Set<br/>@dns_route_169_254_1_10"]
    NftSetBypass["Kernel nftables Set<br/>@dns_bypass_169_254_1_10"]
    Mangle["chain mangle_prerouting<br/>(Assigns meta mark 0x101 / 0x102)"]
    IpRule["Linux Policy Routing<br/>(fwmark 0x101 -> table 101)"]
    Wg0["wg0 Tunnel<br/>(FwMark 0x51820)"]
    Wg1["wg1 Tunnel<br/>(FwMark 0x51820)"]
    Wan["Local WAN / ISP Gateway"]

    Client -->|"1. DNS Query (e.g. ipinfo.io)"| Dnsmasq
    Dnsmasq -->|"2a. Populates resolved IPv4"| NftSetRoute
    Dnsmasq -->|"2b. Populates bypass IPv4"| NftSetBypass
    Client -->|"3. Packet to Resolved IP"| Mangle
    NftSetRoute -.->|"Match destination"| Mangle
    NftSetBypass -.->|"Clear mark (0x0)"| Mangle
    Mangle -->|"Marked 0x101 / 0x102"| IpRule
    Mangle -->|"Unmarked / Bypassed"| Wan
    IpRule -->|"Table 101"| Wg0
    IpRule -->|"Table 102"| Wg1
```

---

## 2. Programmable DNS (`dns` Block)

When a `dns { ... }` block is declared in `/data/Nftyfile`, `nfty` generates `/run/nfty-dnsmasq.conf` and `/run/nfty-dnsmasq.hosts` and supervises the system `dnsmasq` process. Whenever the configuration or backend health state changes, `nfty` rewrites the hosts file and sends `SIGHUP` to `dnsmasq` for zero-downtime reloads.

### Complete `dns` Block Example

```hcl
dns {
  # Bind addresses and interfaces
  listen 169.254.1.4:53
  listen 10.20.0.1:53
  interface eth0

  # Local authoritative search domain & cache tuning
  domain lan.internal
  cache-size 10000
  ttl 60

  # Default upstream recursive resolvers
  upstream 1.1.1.1 1.0.0.1
  upstream 9.9.9.9

  # Automatic synthesis from nfty VIPs & services
  auto-vips on
  auto-hosts on
  health-aware on

  # Static authoritative DNS records
  a nas.lan.internal 169.254.1.50
  aaaa nas.lan.internal fd00:169:254::50
  cname files.lan.internal nas.lan.internal
  ptr 169.254.1.50 nas.lan.internal
  mx lan.internal mail.lan.internal 10
  txt lan.internal "v=spf1 mx -all"
  srv _ldap._tcp.lan.internal dc1.lan.internal 389 10 100

  # Split-horizon conditional forwarding
  forward corp.internal to 10.100.0.53
  forward vault.partner.net to 10.64.0.1 via 169.254.1.10

  # Dynamic nftset policy routing
  route ipinfo.io via 169.254.1.10
  route *.streaming.example.com via 169.254.1.10
  bypass *.local-bank.example.com from 169.254.1.10

  # Ad/tracker sinkholing (0.0.0.0 & ::)
  block telemetry.example.com
  block ads.example.net
  blocklist /data/dns/lists/stevenblack-hosts.txt
}
```

### Authoritative Record Types

| Directive | Syntax | Description |
| :--- | :--- | :--- |
| `a` / `host` | `a <fqdn> <ipv4>` | Maps `<fqdn>` (and its short hostname if under `domain`) to `<ipv4>`. |
| `aaaa` | `aaaa <fqdn> <ipv6>` | Maps `<fqdn>` to `<ipv6>`. |
| `cname` | `cname <alias> <target>` | Creates a canonical name alias pointing `<alias>` to `<target>`. |
| `ptr` | `ptr <ip> <fqdn>` | Creates a reverse DNS `PTR` record for `<ip>`. |
| `mx` | `mx <domain> <mailhost> [prio]` | Creates an `MX` mail exchange record (default priority `10`). |
| `txt` | `txt <fqdn> "<text>"` | Publishes an arbitrary `TXT` record. |
| `srv` | `srv <_service._proto.domain> <target> <port> [prio] [weight]` | Publishes an RFC 2782 `SRV` record for service discovery. |

---

## 3. Automatic VIP & Health-Aware Service DNS Discovery

`nfty` eliminates manual DNS bookkeeping by automatically synthesizing DNS records from your configured `vip`, `service`, and `gateway` blocks:

1. **`auto-vips on`** (default: `on`):
   - Automatically registers `vip-<octets>.<domain>` (e.g., `vip-169-254-1-4.lan.internal`) and `gw-<octets>.<domain>` for every configured VIP and Gateway IP.
2. **`auto-hosts on`** (default: `on`):
   - For every named service (e.g., `service grafana:3000` inside `vip 169.254.1.4`), `nfty` automatically publishes `grafana.lan.internal -> 169.254.1.4`.
   - If a service also declares `host grafana.corp.internal`, that FQDN is automatically registered as an `A` record pointing to the parent VIP.
3. **`health-aware on`** (default: `on`):
   - Ties DNS resolution directly to `nfty`'s real-time L4/L7 health prober.
   - If **all** primary and backup backends for `service grafana:3000` are `DOWN` (or `DRAINING`), `nfty` dynamically withdraws `grafana.lan.internal` from `/run/nfty-dnsmasq.hosts` and reloads `dnsmasq` so clients immediately fail over or receive `NXDOMAIN` instead of blackholing traffic. As soon as at least one backend passes health checks, the `A` record is restored.

---

## 4. Split-Horizon DNS & Tunnel-Bound Upstream Forwarding

With `forward <domain> to <nameserver> [via <gateway>]`, you can route DNS queries for specific internal or partner zones to dedicated upstream DNS servers:

```hcl
dns {
  # Standard split-horizon forwarding to an internal Active Directory / CoreDNS server
  forward k8s.internal to 10.96.0.10:53

  # Route DNS queries for a remote private zone through a WireGuard Gateway!
  forward internal.partner.org to 10.64.0.1 via 169.254.1.10
}
```

### How `via <gateway>` Works Under the Hood

When `via 169.254.1.10` is appended to a `forward` rule:
1. `nfty` looks up the primary tunnel interface IP (e.g., `10.64.0.2` on `wg0`) associated with `gateway 169.254.1.10`.
2. `nfty` emits `server=/internal.partner.org/10.64.0.1@10.64.0.2` in `/run/nfty-dnsmasq.conf` to bind outbound DNS queries to the WireGuard tunnel source IP.
3. In `table ip nfty -> chain mangle_output`, `nfty` adds a kernel rule matching `ip daddr 10.64.0.1 udp dport 53` and `tcp dport 53` that stamps `meta mark set 0x101`, ensuring the DNS query itself is policy-routed inside the encrypted WireGuard tunnel and never leaks onto the local WAN.

---

## 5. DNS-Driven Kernel `nftset` Policy Routing (`route` & `bypass`)

Traditional policy-based routing struggles with modern CDN-backed services whose IPv4 addresses change on every DNS lookup. `nfty` solves this by combining `dnsmasq`'s native `nftset=` directive with dynamic kernel `nftables` sets in `table ip nfty`:

```hcl
dns {
  # Force specific domains through WireGuard gateway 169.254.1.10
  route ipinfo.io via 169.254.1.10
  route github.com via 169.254.1.10

  # Exempt specific domains from a full-tunnel WireGuard gateway
  bypass local-stream.example.com from 169.254.1.10
}
```

### Step-by-Step Packet Flow

1. **Kernel Set Creation**: When `nfty` compiles `table ip nfty`, it creates two dynamic IPv4 sets with a 1-hour entry timeout (`timeout 1h`) for each gateway:
   ```nft
   set dns_route_169_254_1_10 {
       type ipv4_addr
       flags dynamic, timeout
       timeout 1h
   }
   set dns_bypass_169_254_1_10 {
       type ipv4_addr
       flags dynamic, timeout
       timeout 1h
   }
   ```
2. **Real-Time DNS Population**: When a client queries `ipinfo.io`, `dnsmasq` resolves the `A` records and immediately inserts the returned IPv4 addresses into `@dns_route_169_254_1_10` via netlink (`nftset=/ipinfo.io/4#ip#nfty#dns_route_169_254_1_10`) **before** returning the DNS reply to the client.
3. **Zero-Latency Kernel Forwarding**:
   - When the client sends its first TCP `SYN` or UDP packet to the resolved IP, `chain mangle_prerouting` matches `ip daddr @dns_route_169_254_1_10` and applies the gateway's WireGuard tunnel mark (`meta mark set 0x101` or ECMP `numgen inc mod N`).
   - Conversely, if a LAN client uses `169.254.1.10` as its full-tunnel default gateway, matching `ip daddr @dns_bypass_169_254_1_10` clears the packet mark (`meta mark set 0x0`) and skips the gateway's killswitch so traffic exits directly via the local WAN router.

---

## 6. Ad, Tracker & Malware Sinkholing (`block` & `blocklist`)

`nfty` can act as a network-wide DNS sinkhole (similar to Pi-hole or AdGuard Home) with zero additional software:

- **Inline Domain Blocking (`block <domain>`)**:
  Emits `address=/<domain>/0.0.0.0` and `address=/<domain>/::`, immediately returning `0.0.0.0` / `::` for `<domain>` and all of its subdomains.
- **External Blocklist Files (`blocklist <path>`)**:
  Place standard `/etc/hosts`-formatted lists, domain-per-line lists, or `dnsmasq` config fragments inside `/data/dns/lists/` and reference them in `dns`:
  ```hcl
  dns {
    block doubleclick.net
    blocklist /data/dns/lists/ads-hosts.txt
    blocklist /data/dns/lists/malware-domains.conf
  }
  ```
  - Files ending in `.conf` are loaded via `conf-file=<path>`.
  - Standard hosts files (`0.0.0.0 domain.com` or `127.0.0.1 domain.com`) are loaded via `addn-hosts=<path>`.

---

## 7. WireGuard Virtual Gateways (`gateway` Block)

A `gateway` block turns `nfty` into a high-performance policy-routed WireGuard router and load balancer. Any machine on your LAN can set its default gateway (or route specific subnets/domains) to the `gateway` IP (e.g., `169.254.1.10`) to have its traffic transparently encrypted and load-balanced across one or more WireGuard tunnels.

### Managing WireGuard Profiles (`/data/wg/`)

You can supply WireGuard tunnel configurations in two ways:
1. **Saved `.conf` Files in `/data/wg/`**:
   Upload standard WireGuard client configurations (`[Interface]` + `[Peer]`) using the CLI (`wg add <name>`, `wg paste <name>`, `wg vi <name>`) or REST API (`POST /api/v1/wg`), and reference them inside `tunnels { ... }`:
   ```hcl
   gateway 169.254.1.10/24@eth0 {
     balance round-robin
     killswitch on
     tunnels {
       wg-mullvad-us1.conf weight 2
       wg-mullvad-us2.conf weight 1
     }
   }
   ```
2. **Inline Tunnel Declarations**:
   Define tunnels directly inside `Nftyfile`:
   ```hcl
   gateway 169.254.1.10/24@eth0 {
     balance sticky
     killswitch on
     tunnel wg-nyc weight 2 {
       private-key "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE="
       address 10.64.0.2/32
       peer "YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI="
       endpoint 198.51.100.10:51820
       allowed-ips 0.0.0.0/0
       keepalive 25
     }
   }
   ```

### Multi-Tunnel Kernel Routing & Loop Prevention (`FwMark`)

When `nfty` brings up `N` WireGuard tunnels (`wg0`, `wg1`, ...):
1. **Outer UDP Loop Prevention (`FwMark = 0x51820`)**:
   Every WireGuard interface is configured with `FwMark = 0x51820`. In `chain mangle_prerouting`, packets carrying `meta mark 0x51820` are immediately `accept`ed so encrypted outer WireGuard UDP packets always egress via the physical WAN interface and never loop back into a tunnel.
2. **Per-Tunnel Routing Tables (`101 + i`)**:
   Each tunnel `wg<i>` gets a dedicated Linux routing table (`101`, `102`, ...) with `ip route replace default dev wg<i> table <101+i>` and `ip rule add fwmark <0x101+i> table <101+i> pref <101+i>`.
3. **Kernel ECMP Load Balancing (`round-robin` vs `sticky`)**:
   - `balance round-robin` (default): Uses `meta mark set numgen inc mod <total_weight> map { 0 : 0x101, 1 : 0x101, 2 : 0x102 }` combined with `ct mark set meta mark` so each new connection is distributed across active tunnels according to weight, while all packets within an established flow stay pinned to the same tunnel.
   - `balance sticky`: Uses `meta mark set ip saddr map @gw_sticky_<gw>` (with a 30-minute dynamic timeout) so all connections from a given LAN client IP stick to the same WireGuard exit node.
4. **Fail-Closed Killswitch (`killswitch on|off`)**:
   When `killswitch on` (the default) is active, `chain forward` drops any packet from a LAN client routed through the gateway whose `meta mark` is `0` or whose egress interface (`oifname`) is not one of the active `wg*` interfaces (`oifname != { "wg0", "wg1" } drop`). Even if a tunnel interface goes down, traffic is blocked at the kernel level rather than leaking out the unencrypted WAN.

---

## 8. Gateway Proxies (`privoxy` & `socks5`) & Port Forwarding

Often you do not want to change a client machine's system-wide default gateway, or you only want specific applications (web browsers, CLI tools, Docker containers, torrent clients) to egress through a WireGuard tunnel.

`nfty` includes a built-in userspace proxy engine (`src/features/gateway_proxy.rs`) that binds directly to the gateway VIP and routes all proxied connections through the gateway's WireGuard tunnels using kernel socket marks (`SO_MARK`) and device binding (`SO_BINDTODEVICE`):

```hcl
gateway 169.254.1.10/24@eth0 {
  balance round-robin
  killswitch on

  # Expose an HTTP/HTTPS proxy (HTTP CONNECT + Privoxy-compatible forwarding)
  privoxy:8118

  # Expose an RFC 1928 SOCKS5 proxy (supports IPv4, IPv6, and remote DNS domain resolution)
  socks5:1080

  # Inbound port forwarding from the remote WireGuard VPN exit into a LAN host
  forward 51413 to 169.254.20.15:51413
  forward 6881/udp to 169.254.20.15:6881

  tunnels {
    wg-mullvad-us1.conf
  }
}
```

### Testing Gateway Proxies from any LAN Host

```bash
# Verify egress IP via the Gateway HTTP/HTTPS Proxy (privoxy:8118)
curl -x http://169.254.1.10:8118 https://ipinfo.io/json

# Verify egress IP and remote DNS resolution via the Gateway SOCKS5 Proxy (socks5:1080)
curl --socks5-hostname 169.254.1.10:1080 https://ipinfo.io/json
```

### Symmetric Inbound Port Forwarding (`forward <port> to <ip:port>`)

When `forward 51413 to 169.254.20.15:51413` is configured on a gateway:
1. **Inbound DNAT**: Packets arriving from `iifname "wg0"` on port `51413` are marked in `chain mangle_prerouting` (`ct mark set 0x101`) and DNATed in `chain prerouting` to `169.254.20.15:51413`.
2. **Masquerade**: `chain postrouting` masquerades the forwarded packet to the `nfty` appliance's LAN address so `169.254.20.15` always sends replies back to `nfty` regardless of its own default gateway.
3. **Symmetric Tunnel Return**: When `169.254.20.15` replies, `chain mangle_prerouting` restores `meta mark set ct mark` (`0x101`), ensuring return packets are routed back out the exact same WireGuard tunnel (`wg0`) they entered on.

---

## 9. Cloudflare DNS & Zero-Trust Tunnels (`cloudflare-dns` & `cloudflare-auth`)

`nfty` integrates directly with the Cloudflare v4 API and supervises `cloudflared` to expose internal services externally with optional edge authentication:

```hcl
vip 169.254.1.4/24@eth0 {
  service grafana:3000 {
    host grafana.example.com

    # Automatically provision/update a proxied Cloudflare DNS record
    cloudflare-dns on

    # Expose through a supervised Cloudflare Zero-Trust Tunnel (cloudflared)
    cloudflare-auth on

    # Require HTTP Basic Auth at the nfty edge before reaching backends
    auth admin:$2b$12$eImiTXuWVxfM37uY4JANjQ==

    to 169.254.1.21:3000
  }
}
```

### Setting Up Cloudflare Credentials

Configure your Cloudflare API Token and Account ID (or pre-generated Tunnel Token) via the CLI or REST API:

```text
nfty> cf token cf_api_token_here 0123456789abcdef0123456789abcdef
Saved Cloudflare API token and Account ID to /data/cloudflare.env.
nfty> cf sync
Reconciled Cloudflare Zero-Trust tunnel and DNS records.
nfty> cf status
```

### Edge Authentication Gate (`auth <user>:<pass>`)

When a service has `cloudflare-auth on` and one or more `auth <user>:<password>` directives:
1. `cloudflared` routes incoming public HTTPS requests for `grafana.example.com` to `nfty`'s internal authentication reverse proxy listening on `127.0.0.1:18443`.
2. The authentication gate verifies the `Authorization: Basic ...` header against the configured credentials for that `Host` header ( returning `401 Unauthorized` with `WWW-Authenticate: Basic realm="nfty Zero-Trust Gate"` if missing or invalid).
3. Upon successful authentication, `nfty` strips the `Authorization` header (preventing credential leakage to downstream backends), injects `X-Forwarded-User: <username>` and `X-Nfty-Authenticated: true`, and proxies the request to a healthy backend in the service pool.
