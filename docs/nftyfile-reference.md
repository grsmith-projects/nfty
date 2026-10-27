# `Nftyfile` Configuration Reference

`nfty` uses a declarative, block-structured configuration file stored at `/data/Nftyfile` (or `/etc/nfty/Nftyfile` on standalone Linux installations).

Every directive in `Nftyfile` has a 1:1 equivalent in the interactive router CLI (`configure`) and the HTTP/JSON Control API (`POST /api/v1/cli`). Moreover, `nfty` guarantees clean round-trip formatting: any changes made via the interactive CLI or REST API are serialized back into canonical `Nftyfile` syntax when committed.

---

## 1. File Structure & Syntax Rules

- **Comments**: Everything after `#` on a line is ignored.
- **Statement Separators**: Newlines or semicolons (`;`) separate statements.
- **Blocks**: Curly braces `{ ... }` group nested contexts (`allow`, `vip`, `service`, `to`, `gateway`, `tunnels`, `api:<port>`, `dns`).

### Top-Level Blocks Overview

```hcl
# 1. Global Source Allow-List (optional)
allow {
    192.168.1.*
    10.0.0.0/8
    *.office.lan
}

# 2. Programmable DNS Endpoint (optional)
dns {
    domain lan
    auto-vips on
    auto-hosts on
    health-aware on
    upstream 1.1.1.1 9.9.9.9
}

# 3. Virtual IP (VIP) Containers (Static IPv4 or DHCP macvlan hostname)
vip 192.168.10.10/24 {
    ssh:22
    dns:53
    api:9090 {
        key nfty_rw_0123456789abcdef0123456789abcdef rw
        key nfty_ro_fedcba9876543210fedcba9876543210 ro
    }
    80 to 192.168.20.10:8080 {
        hostname web.local
        check tcp 5s
    }
}

# 4. Top-Level Standalone Services (optional)
service 9000 {
    balance round-robin
    check tcp 5s
    to {
        192.168.20.11:9000 weight 2
        192.168.20.12:9000 weight 1
        192.168.20.13:9000 backup
    }
}

# 5. Virtual Egress Gateways (Direct NAT or Multi-Tunnel WireGuard)
gateway 192.168.10.20 {
    balance round-robin
    killswitch on
    check ping 5s
    privoxy:8118
    socks5:1080
    forward 51413 to 192.168.20.15:51413
    tunnels {
        wg-exit-01.conf weight 2
        wg-exit-02.conf weight 1
    }
}
```

---

## 2. Global `allow { ... }` Block

The top-level `allow` block defines a global source IPv4 access-control list (ACL). When `global_allow` is non-empty, `nfty` compiles an interval `nftables` set (`@allow_<service>` and `@allow_gw_<gateway>`) for every service and gateway, unioning the global `allow` entries with any per-service or per-gateway `allow` entries.

### Supported Entry Formats

| Format | Example | Compilation Behavior |
| :--- | :--- | :--- |
| **Exact IPv4** | `192.168.1.50` | Inserted directly into the kernel `nftables` set (`type ipv4_addr; flags interval`). |
| **IPv4 CIDR** | `10.10.0.0/16`, `172.16.0.0/12` | Inserted as a CIDR interval into the `nftables` set. |
| **IPv4 Octet Wildcard** | `192.168.1.*`, `10.0.*.*`, `*` | Automatically expanded to CIDR (`192.168.1.0/24`, `10.0.0.0/16`, `0.0.0.0/0`). |
| **Exact Hostname** | `admin.office.lan`, `workstation.local` | Resolved via `/data/hosts.json`, `/etc/hosts`, and DNS; refreshed automatically in the background. |
| **Wildcard Hostname** | `*.office.lan`, `dev-*.corp.lan` | Matched dynamically against known hostnames in `/data/hosts.json` and `/etc/hosts`. Register mappings explicitly with `host` or `POST /api/v1/allow/hosts`; scans do not modify the allow-list host cache. |

### Syntax Example

```hcl
allow {
    192.168.1.*
    10.20.0.0/16
    172.16.5.10
    admin-laptop.office.lan
    *.trusted.lan
}
```

Single-line shorthand is also accepted:

```hcl
allow 192.168.1.* 10.20.0.0/16 *.trusted.lan
```

---

## 3. `vip <ip[/cidr] | hostname> { ... }` Blocks

A `vip` block provisions a Virtual IP address on the appliance and groups all local management endpoints (`ssh`, `dns`, `api`) and L4/L7 forwarded backend services bound to that IP.

### 3.1 Static IPv4 VIPs

When the `vip` identifier is an IPv4 address (with an optional `/prefix`), `nfty` binds that static IP directly to the target network interface using `ip addr replace <ip>/<prefix> dev <iface>`. All IP addresses on the appliance are strictly driven by `/data/Nftyfile` (the base OS does not hold an unconfigured DHCP lease on `eth0`), and non-`/24` prefixes (such as `/21`) are explicitly preserved via `interface eth0/<prefix>` when `Nftyfile` is formatted.

```hcl
vip 192.168.10.10/24 {
    interface eth0/24
    ssh:22
    80 to 192.168.20.10:8080
}
```

### 3.2 Named DHCP `macvlan` VIPs (`dhcp <iface>`)

When the `vip` identifier is a **hostname** (e.g., `vip sonarr` or `vip media-front`) or includes `dhcp <iface>`, `nfty` creates a dedicated kernel `macvlan` interface (named `mv-<name>`) with a deterministic locally-administered MAC address derived from the VIP name, tunes `arp_ignore=1` and `arp_announce=2` to prevent ARP flux, and spawns `udhcpc -x hostname:<name>` to request a dedicated DHCP lease from your router (e.g., UniFi UDM, OPNsense, pfSense).

`nfty` removes only macvlans with its runtime ownership marker and refuses
conflicting interfaces or generated names. After an upgrade, an existing
unmarked interface is adopted only when its MAC, lease file, and managed DHCP
process can be verified; otherwise an operator must inspect it before removing
or recreating it. These markers are not a complete isolation mechanism.
The configured parent interface must already exist; apply does not rename a
different interface to satisfy it. The special DHCP name `default` uses
`eth0` and currently cannot be assigned a different parent or VLAN.

> [!WARNING]
> DHCP deconfiguration and renewal do not reliably remove stale lease files or
> old addresses. Inspect and recover affected interfaces manually after lease
> loss or an address change. Existing VLAN interfaces are not fully verified
> for ownership before reuse.

```hcl
vip sonarr {
    dhcp eth0
    80 to 192.168.20.10:8989 {
        check tcp 5s
    }
}
```

Header shorthand is also supported:

```hcl
vip sonarr dhcp eth0 vlan 20 {
    80 to 192.168.20.10:8989
}
```

### 3.3 802.1Q VLAN Tagging (`vlan <1-4094>`)

Both static and DHCP VIPs can be placed on an 802.1Q VLAN tag (`1`–`4094`). `nfty` automatically creates the kernel VLAN sub-interface (`eth0.<vlan>`) and attaches either the static IP or the DHCP `macvlan` child interface on top of that VLAN interface:

```hcl
vip 10.20.0.10/24 {
    interface eth0/24
    vlan 20
    ssh:22
    443 to 10.20.1.50:8443
}
```

### 3.4 VIP-Level Directives

| Directive | Arguments | Description |
| :--- | :--- | :--- |
| `interface` (or `vip` / `dev`) | `<iface>[/<prefix>]` | Binds the VIP to a specific network interface and CIDR prefix length (e.g., `interface eth1/24` or `interface eth0.30/24`). |
| `dhcp` | `[<iface> \| on \| off]` | Enables or disables `macvlan` + `udhcpc` dynamic IP leasing on `<iface>` (defaults to `eth0`). |
| `vlan` | `<1-4094>` | Configures an 802.1Q VLAN ID on the parent interface (`<iface>.<vlan>`). |
| `ssh` / `ssh:<port>` | Optional port (default `22`) | Enables the embedded `nfty` SSH2 management shell on this VIP. Without this directive, port 22 is dropped on the VIP. |
| `dns` / `dns:<port>` | Optional port (default `53`) | Binds the supervised `dnsmasq` DNS server (UDP + TCP) to this VIP. |
| `web` / `web:<port>` | Optional port (default `8000`) | Exposes the interactive JavaScript Web Console (`GET /`) and backing REST API on this VIP. Supports `allow { ... }` CIDR/hostname ACLs so allowed LAN clients get immediate access in the browser. |
| `api` / `api:<port>` | Optional port (default `9090`) | Exposes the headless HTTP/JSON Control API on this VIP (`GET /` is disabled). Can be opened as a block (`api:8080 { ... }`) to configure scoped `ro` / `rw` API keys. |
| `<port[/proto]> to <host:port>` | Listen port & target backend | Maps external `<port>` (e.g., `80`, `443`, `53/udp`) on this VIP to `<host_or_ip>:<port>`. Can be followed by `{ ... }` for service options. |
| `<host_or_ip>:<port>` | Target backend endpoint | Forwards the matching port on this VIP directly to `<host_or_ip>:<port>` (e.g., `plex:32400` or `192.168.20.15:32400`). |

### 3.5 `web:<port>` (Web Console) and `api:<port>` (Headless JSON API) Inside a VIP

No Control API or Web Console port is bound by default unless declared via `web:<port>` or `api:<port>` in `Nftyfile` (or `--api-bind`). `nfty` enforces strict separation between `web:<port>` and `api:<port>`:
- **`web:<port>`** serves the interactive 8-tab HTML/JS Web Console (`GET /`) and requires an IP `allow` list (e.g., `allow { 192.168.0.0/16 }`).
- **`api:<port>`** serves only the headless JSON Control API (`/api/v1/*`), requires an IP `allow` list, and is further secured with scoped `ro` or `rw` API keys.

Every `web:` and `api:` listener must be covered by at least one IP, CIDR, or IPv4-wildcard allow entry (its own, its gateway's, or the global `allow`). Otherwise `validate`/`apply` fail. Hostname entries (e.g. `*.office.lan`) are rejected on these listeners and ignored when they come from the global allow-list:

```hcl
vip 192.168.1.4/21 {
    interface eth0/21
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
        key new rw
        key new ro
    }
}
```

> **Note:** When `key new rw` or `key new ro` is parsed or entered in the CLI, `nfty` immediately generates a cryptographically random 128-bit token prefixed with its scope (`nfty_rw_<32-hex>` or `nfty_ro_<32-hex>`) and persists the generated token in `/data/Nftyfile`.

---

## 4. `service <spec> { ... }` Blocks & Service Directives

Services can be defined either nested inside a `vip { ... }` block or at the top level of `Nftyfile` via `service <spec> { ... }`.

### Service Specification (`<spec>`) Formats

- **Port only (all interfaces, TCP)**: `service 9000 { ... }` or `9000 { ... }`
- **Port + Protocol (`tcp`, `udp`, `both`)**: `service 53/udp { ... }`, `service 51413/both { ... }`
- **Explicit VIP IP + Port [+ Protocol]**: `service 192.168.1.240:443 { ... }`, `service 10.0.1.10:53/both { ... }`
- **Inside a `vip` block**:
  - `80 to 192.168.20.10:8080 { ... }`
  - `plex:32400 { ... }`
  - `443 { ... }`

### Complete Service Directive Reference

| Directive | Syntax | Default | Description |
| :--- | :--- | :--- | :--- |
| `port` | `port <1-65535>` | Inferred from header | Overrides the external listen port on the VIP. |
| `proto` | `proto <tcp\|udp\|both>` | `tcp` | Sets L4 transport protocol (`tcp`, `udp`, or `both` for TCP+UDP). |
| `balance` | `balance <round-robin\|sticky>` | `round-robin` | Kernel `nftables` load-balancing algorithm. `round-robin` uses `numgen inc mod N`; `sticky` uses `ip saddr mod N` source-IP hashing. |
| `mode` | `mode <nat\|transparent>` | `nat` | `nat` applies `masquerade` in `postrouting` so return traffic routes back through `nfty`. `transparent` preserves the original client source IP (requires backends to use `nfty` as their default gateway). |
| `check` | `check <tcp \| http [/path] \| ping \| off> [<secs>s]` | None (or `tcp 5s` on `adopt`) | Configures active health probing. Unhealthy backends are dynamically removed from the kernel verdict map. |
| `limit` | `limit <rate>/<sec\|min> [burst <N>] [per-ip\|global]` | None | Limits first-packet matches in the kernel NAT chain; established flows are not packet-rate limited. Defaults to `per-ip` dynamic meter sets (`size 65535; timeout 1m`). |
| `hostname` | `hostname <fqdn.local>` | None | Announces `<fqdn.local>` via multicast mDNS (`224.0.0.251:5353`), registers it in `dnsmasq` (`auto-vips on`), and enables L7 HTTP `Host` / TLS `SNI` virtual-host routing when multiple services share port `80` or `443`. |
| `cloudflare-dns` | `cloudflare-dns <fqdn>` | None | Publishes the service publicly via a remotely-managed Cloudflare Tunnel and creates a proxied DNS `CNAME` record for `<fqdn>`. |
| `cloudflare-auth` | `cloudflare-auth <email \| *@domain>...` | None | Configures a Cloudflare Zero-Trust Access self-hosted application and email/domain allow policy (e.g., `ops@example.com *@example.com`). |
| `auth` | `auth <user:pass \| nfty>...` | None | Enforces HTTP Basic Auth across both Cloudflare Tunnel and local TCP VIP requests (`redirect to :80` / `:18443`). Rejected on UDP or encrypted TLS passthrough port `443`. |
| `key` | `key <new \| token> [ro\|rw]` | None | Attaches a scoped (`ro` or `rw`) API key when the service is `api:<port>`. |
| `vip` / `interface` | `interface <iface[/prefix]>` | Inherited from `vip` block | Binds a standalone `service <ip:port>` to a specific NIC and subnet prefix. |
| `vlan` | `vlan <1-4094>` | Inherited from `vip` block | Attaches an 802.1Q VLAN tag to the service's VIP. |
| `allow` | `allow { <entry>... }` or `allow <entry>...` | None (inherits global `allow`) | Restricts source IPs allowed to reach this service (IPs, CIDRs, IP wildcards `192.168.1.*`, hostnames, or wildcard hostnames `*.office.lan`). |
| `to` | `to { <backend>... }` or `to <backend>...` | None | Defines one or more backend targets (`<ip_or_host>[:<port>] [weight <1-100>] [backup]`). |

Apply rejects overlapping services on the same address, port, and protocol.
Distinct hostnames may share TCP port `80` or `443`; UDP cannot be multiplexed
by hostname, including the UDP half of `proto both`. Per-service `limit` is
rejected on shared HTTP/TLS virtual-host bindings because it cannot be enforced
per hostname before routing. Avoid overlapping a wildcard binding with a
specific VIP as well; that case is not fully validated.

> [!WARNING]
> Avoid using the same L7 hostname on different VIPs sharing a port: the
> listener may fall back to another VIP's service when the redirected socket
> does not identify the original destination. TLS ClientHello messages split
> across multiple TLS records are not supported.

### Health Check (`check`) Variations

```hcl
check tcp 5s                    # TCP 3-way handshake probe every 5 seconds
check http /healthz 10s         # HTTP GET /healthz expecting 2xx/3xx every 10 seconds
check http 5s                   # HTTP GET / every 5 seconds
check ping 3s                   # ICMP Echo Request every 3 seconds
check off                       # Disable active health probing
```

### Rate Limit (`limit`) Variations

```hcl
limit 100/sec per-ip            # Up to 100 first-packet matches/sec per source IP
limit 250/sec burst 100 per-ip  # Per-source limit with a 100-packet burst bucket
limit 60/min burst 15 per-ip    # Up to 60 first-packet matches/minute per source IP
limit 5000/sec burst 1000 global # Global service-wide rate limit across all clients
```

### Multi-Backend `to { ... }` Block with Weights and Backup Failover

```hcl
vip 10.0.10.50/24 {
    443 {
        proto tcp
        balance sticky
        mode nat
        check http /api/health 5s
        limit 300/sec burst 150 per-ip
        allow {
            10.0.0.0/8
            192.168.1.*
            *.corp.lan
        }
        to {
            10.0.20.11:8443 weight 3
            10.0.20.12:8443 weight 2
            10.0.20.13:8443 weight 1
            10.0.20.99:8443 backup
        }
    }
}
```

- **Weights (`weight 1`–`100`)**: A backend with `weight 3` receives 3 slots in the kernel `nftables` `vmap` for every 1 slot of a `weight 1` backend.
- **Standby Failover (`backup`)**: Backends marked `backup` (or `standby`) are excluded from the kernel `nftables` verdict map while at least one primary backend is healthy (`UP`). If all primary backends fail health checks or are manually drained, `nfty` automatically activates the `backup` backends.

---

## 5. `gateway <ip[/cidr] | name> { ... }` Blocks

A `gateway` block provisions a Virtual Gateway IP (either a static IPv4 like `gateway 192.168.10.20/24` or a named DHCP `macvlan` host like `gateway vpn-exit { dhcp eth0 }`) that LAN hosts, VMs, or containers can use as:
1. Their **default IPv4 gateway** (`ip route replace default via 192.168.10.20`),
2. An **HTTP/HTTPS `CONNECT` proxy** (`privoxy:8118`),
3. A **SOCKS5 proxy** (`socks5:1080`), or
4. A **DNS resolver** (`dns:53`).

### 5.1 Direct Internet NAT Mode vs. WireGuard Tunnel Mode

- **Direct Internet NAT Gateway** (no `tunnels` block): `nfty` enables IPv4 forwarding and masquerades traffic out `eth0` (`oifname "eth0" masquerade`).
- **WireGuard Multi-Tunnel Egress Gateway** (with `tunnels { ... }`): `nfty` creates managed `wgN` interfaces, per-tunnel policy routing tables and `fwmark` rules, pins connections with `ct mark`, and load-balances outbound traffic across eligible tunnels.

### 5.2 Gateway Directive Reference

| Directive | Syntax | Default | Description |
| :--- | :--- | :--- | :--- |
| `interface` / `vip` | `interface <iface[/prefix]>` | `eth0/24` | Binds the gateway VIP to the specified interface and subnet prefix. |
| `dhcp` | `dhcp [<iface>]` | `false` | Acquires the gateway IP dynamically via a dedicated `macvlan` interface and `udhcpc`. |
| `vlan` | `vlan <1-4094>` | None | Places the gateway VIP on an 802.1Q VLAN sub-interface. |
| `hostname` | `hostname <name.local>` | None | Announces the gateway IP via multicast mDNS and registers it in `dnsmasq`. |
| `balance` | `balance <round-robin\|sticky>` | `round-robin` | Selects how new flows are distributed across active WireGuard tunnels (`numgen inc mod N` vs `jhash ip saddr . ip daddr mod N`). |
| `killswitch` | `killswitch <on\|off>` | `on` | Drops new gateway traffic when no tunnel is eligible and drops marked external traffic leaving a non-WireGuard interface. |
| `check` | `check <ping\|tcp\|http> [<secs>s]` | `ping 5s` | Probes each WireGuard tunnel interface (`ping -I wgN 1.1.1.1`) and removes dead tunnels from the ECMP verdict map. |
| `privoxy:<port>` | `privoxy:8118` (or `privoxy`) | Disabled | Starts a privacy-sanitizing HTTP + HTTPS `CONNECT` proxy bound to the gateway IP and socket-marked (`SO_MARK` + `SO_BINDTODEVICE`) to egress through the gateway's healthy WireGuard tunnels. |
| `socks5:<port>` | `socks5:1080` (or `socks5`) | Disabled | Starts an RFC 1928 SOCKS5 proxy bound to the gateway IP and pinned to the gateway's WireGuard tunnels. |
| `ssh:<port>` | `ssh:22` (or `ssh`) | Disabled | Enables the `nfty` SSH shell on the gateway IP. |
| `dns:<port>` | `dns:53` (or `dns`) | Disabled | Binds `dnsmasq` to the gateway IP and routes upstream DNS queries through the gateway's healthy WireGuard tunnel (`server=<ip>@wgN`). |
| `api:<port>` | `api:9090 { key ... }` | Disabled | Enables the HTTP/JSON Control API on the gateway IP with optional scoped `ro`/`rw` keys. |
| `forward` | `forward <port[/proto]> to <ip_or_host:port>` | None | Forwards inbound traffic arriving on the gateway's `wg*` interfaces on `<port>` (`tcp`, `udp`, or `both`) to a LAN backend, pinning the connection's `ct mark` so reply traffic returns out the exact same WireGuard tunnel. |
| `allow` | `allow { <entry>... }` | None | Restricts which LAN client IPs/hosts are permitted to route or proxy through this gateway. |
| `tunnels` | `tunnels { <tunnel>... }` | None | Attaches one or more file-based (`/data/wg/*.conf`) or inline WireGuard tunnels. |

### 5.3 `tunnels { ... }` Syntax (File-Based & Inline)

Inside `tunnels { ... }`, you can reference standard WireGuard `.conf` files saved in `/data/wg/` or define tunnels inline in `Nftyfile`:

File-based tunnel interface names are derived from the gateway and profile
names, so they remain stable when other tunnels are added or removed. Existing
installations that referred to automatically assigned `wg0`, `wg1`, etc. must
update those references after upgrading. Explicit inline `wgN` names are
preserved. Collisions are rejected instead of sharing an interface.

```hcl
gateway 192.168.10.20/24 {
    hostname vpn-gw.local
    balance sticky
    killswitch on
    check ping 5s
    privoxy:8118
    socks5:1080
    dns:53
    api:9091 {
        key nfty_ro_99887766554433221100aabbccddeeff ro
    }
    allow {
        192.168.0.0/16
        10.10.0.0/16
    }
    forward 51413/both to 192.168.20.15:51413
    forward 6881/tcp to torrent-box:6881
    tunnels {
        # 1. File-based WireGuard configs stored in /data/wg/
        wg-us-west.conf weight 3
        wg-us-east.conf weight 1

        # 2. Inline WireGuard tunnel definition
        wg2 address 10.64.0.42/32 privkey YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE= peer YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI= endpoint 172.16.200.1:51820 weight 1
    }
}
```

---

## 6. `dns { ... }` Block

The top-level `dns { ... }` block configures `nfty`'s supervised `dnsmasq` instance. `nfty` compiles this block into `/run/nfty-dnsmasq.conf` and `/run/nfty-dnsmasq.hosts` and reloads host records on the fly via `SIGHUP` without dropping cached entries.

DNS listen addresses and gateway DNS listeners currently use port 53. Configuring
more than one WireGuard gateway DNS listener is rejected because one dnsmasq
instance cannot isolate its upstream routing by receiving gateway.

### Complete `dns` Directive Reference

| Directive | Syntax | Default | Description |
| :--- | :--- | :--- | :--- |
| `listen` | `listen <ip[:port]>...` | Auto-bound to VIPs/Gateways with `dns:53` | Explicitly binds `dnsmasq` to additional IPv4 addresses (or `0.0.0.0` for all interfaces). |
| `domain` | `domain <suffix \| off>` | `lan` | Sets the authoritative local search domain (e.g., `lan`, `home.arpa`, `corp.internal`) and enables `expand-hosts` and `local=/<domain>/`. |
| `cache-size` | `cache-size <0-65535>` | `10000` | Sets the number of cached DNS records in `dnsmasq`. |
| `auto-vips` | `auto-vips <on\|off>` | `on` | Automatically synthesizes forward `A` and reverse `PTR` records for all configured VIPs, service `hostname`s, `cloudflare-dns` names, and gateways. |
| `auto-hosts` | `auto-hosts <on\|off>` | `on` | Automatically synthesizes `A` and `PTR` records for registered/resolved hosts in the host cache. Scans do not register host mappings. |
| `health-aware` | `health-aware <on\|off>` | `on` | Dynamically removes a service's hostname from DNS responses when all of its backends fail health checks or are drained. |
| `all-servers` | `all-servers <on\|off>` | `on` | Queries all configured upstream resolvers in parallel and returns the fastest response. |
| `bogus-priv` | `bogus-priv <on\|off>` | `on` | Prevents reverse DNS lookups for private RFC1918/RFC3927 IP ranges from being leaked to upstream public resolvers. |
| `domain-needed` | `domain-needed <on\|off>` | `on` | Prevents plain single-label hostnames (without dots) from being forwarded to upstream public resolvers. |
| `upstream` | `upstream <ip[:port][@gw_or_iface]>...` | `1.1.1.1 9.9.9.9` | Configures upstream recursive DNS servers. Supports `@<gateway>` or `@<iface>` to pin upstream queries through a WireGuard gateway. |
| `no upstream` | `no upstream` | — | Clears all upstream DNS resolvers (authoritative-only mode). |
| `forward` | `forward <domain> [to] <srv...> [via <gw>]` | None | Conditional split-horizon zone forwarding: sends queries for `*.<domain>` to `<srv...>` and optionally routes them through a WireGuard `<gateway>`. |
| `a` | `a <hostname> <ipv4> [ipv4...]` | None | Defines an authoritative IPv4 `A` record (and automatic `PTR` record). Single-label names automatically expand with `domain`. |
| `aaaa` | `aaaa <hostname> <ipv6>` | None | Defines an authoritative IPv6 `AAAA` record. |
| `address` | `address <domain_or_wildcard> <ipv4>` | None | Wildcard DNS override returning `<ipv4>` for `<domain>` and all its subdomains (e.g., `address *.k8s.lan 192.168.10.80`). |
| `cname` | `cname <alias> <target>` | None | Creates a `CNAME` alias pointing to `<target>`. |
| `txt` | `txt <name> "<text>"` | None | Creates a `TXT` record (for ACME DNS-01 challenges, SPF, DKIM, or service verification). |
| `srv` | `srv <_svc._proto.dom> <target:port> [priority <P>] [weight <W>]` | None | Creates an `SRV` service record (e.g., `_minecraft._tcp.lan`, `_ldap._tcp.corp.lan`). |
| `mx` | `mx <domain> <mailhost> [preference]` | None | Creates an `MX` mail exchange record (default preference `10`). |
| `ptr` | `ptr <ipv4> <hostname>` | None | Creates an explicit `in-addr.arpa` reverse DNS `PTR` record. |
| `route` | `route <domain...> via <gateway>` | None | Compiles a `dnsmasq` `nftset=/<domains>/4#ip#nfty#dns_route_<gw>` rule that dynamically populates the kernel `@dns_route_<gw>` set on DNS resolution, routing matching traffic through `<gateway>`. |
| `bypass` | `bypass <domain...> from <gateway>` | None | Compiles a `dnsmasq` `nftset=/<domains>/4#ip#nfty#dns_bypass_<gw>` rule that dynamically populates `@dns_bypass_<gw>`, bypassing the VPN tunnel on `<gateway>` and routing matching traffic directly out `eth0`. |
| `block` | `block <domain_or_wildcard...>` | None | Sinkholes the specified domains and all subdomains to `0.0.0.0`. |
| `blocklist` | `blocklist <name> <url_or_path>` | None | Normalizes a hosts/domain list into `/data/dns/lists/<name>.hosts` and loads it into `dnsmasq`. Remote lists refresh every 24h; an existing cache is retained with a warning if refresh fails. Missing or empty lists fail reconciliation. Names use letters, digits, `.`, `_`, and `-`. |
| `raw` | `raw <dnsmasq-option>` | None | Appends a safe native `dnsmasq` directive (e.g., `raw expand-hosts` or `raw log-queries`). Restricted file/exec options (`dhcp-script`, `conf-file`, etc.) are blocked for security. |

### Comprehensive `dns { ... }` Example

```hcl
dns {
    listen 192.168.10.10 192.168.10.20
    domain lan
    cache-size 20000
    auto-vips on
    auto-hosts on
    health-aware on
    all-servers on
    bogus-priv on
    domain-needed on

    upstream 1.1.1.1 9.9.9.9
    forward corp.internal to 10.100.0.2 10.100.0.3 via 192.168.10.20

    a nas.lan 192.168.1.50
    a k8s-ingress.lan 192.168.1.80 192.168.1.81
    aaaa nas.lan fd00:10::50
    address *.apps.lan 192.168.10.10
    cname files.lan nas.lan
    txt _acme-challenge.example.com "R29vZ2xlQUNNRVRva2VuMjAyNg"
    srv _ldap._tcp.lan dc01.lan:389 priority 10 weight 100
    mx lan mail.lan 10
    ptr 192.168.1.50 nas.lan

    route linuxisos.org tracker.example.org via 192.168.10.20
    bypass plex.tv netflix.com from 192.168.10.20

    block doubleclick.net *.telemetry.example.com
    blocklist stevenblack https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
    raw localise-queries
}
```

---

## 7. Negation Directives (`no ...`) Across All Contexts

In both `Nftyfile` and the interactive CLI, any setting, block, backend, tunnel, key, or DNS record can be removed using `no <directive>` (or `delete` / `remove`):

| Context | Negation Syntax | Effect |
| :--- | :--- | :--- |
| **Root (`config`)** | `no vip <ip_or_name>` | Deletes the VIP container and all services attached to it. |
| **Root (`config`)** | `no gateway <ip_or_name>` | Deletes the Virtual Gateway and cleans up its WireGuard interfaces. |
| **Root (`config`)** | `no service <spec>` | Deletes a standalone or VIP-bound service. |
| **Root (`config`)** | `no allow [<entry>]` | Removes `<entry>` from the global allow-list (or clears the entire global allow-list if `<entry>` is omitted). |
| **Root (`config`)** | `no dns [<sub-directive>]` | Removes the entire `dns` block (or executes `no <sub-directive>` inside `dns`). |
| **VIP (`config-vip`)** | `no vlan` / `no dhcp` | Removes the 802.1Q VLAN tag or disables DHCP on the VIP. |
| **VIP (`config-vip`)** | `no ssh:22` / `no dns:53` / `no api:9090` | Disables local SSH, DNS, or HTTP Control API on the VIP. |
| **VIP (`config-vip`)** | `no <service_target>` | Removes a forwarded service (e.g., `no plex:32400` or `no 80`) from the VIP. |
| **Service (`config-service`)** | `no check` / `no limit` / `no hostname` | Removes health checking, rate limiting, or the mDNS/L7 hostname from the service. |
| **Service (`config-service`)** | `no cloudflare-dns` / `no cloudflare-auth [<rule>]` / `no auth [<rule>]` | Removes Cloudflare Tunnel publishing, Zero-Trust Access rules, or HTTP Basic Auth rules. |
| **Service / Gateway API** | `no key [<token_or_scope>]` | Removes a specific API key token, all keys of a scope (`no key ro`), or all API keys (`no key`). |
| **Service (`config-service`)** | `no allow [<entry>]` | Removes `<entry>` from the service allow-list (or clears all service allow entries). |
| **Service (`config-service`)** | `no to [<ip_or_host:port>]` | Removes a specific backend (or clears all backends if omitted). |
| **Gateway (`config-gateway`)** | `no killswitch` / `no check` / `no hostname` / `no vlan` | Disables the kill-switch, tunnel health check, mDNS hostname, or VLAN tag on the gateway. |
| **Gateway (`config-gateway`)** | `no privoxy` / `no socks5` / `no ssh` / `no dns` / `no api` | Removes the specified local service from the gateway. |
| **Gateway (`config-gateway`)** | `no forward [<port>]` | Removes an inbound WireGuard port forward rule (or all forwards). |
| **Gateway (`config-gateway`)** | `no tunnel [<name>]` | Detaches a specific WireGuard tunnel (or all tunnels) from the gateway. |
| **DNS (`config-dns`)** | `no upstream [<ip>]` | Removes a specific upstream DNS server (or clears all upstreams so `no upstream` is set). |
| **DNS (`config-dns`)** | `no forward [<domain>]` | Removes a split-horizon forward zone (or all forward zones). |
| **DNS (`config-dns`)** | `no <a\|aaaa\|address\|cname\|txt\|srv\|mx\|ptr> [<name>]` | Removes a specific DNS record by name/domain (or clears all records). |
| **DNS (`config-dns`)** | `no route [<domain_or_gw>]` / `no bypass [<domain_or_gw>]` | Removes a domain or gateway from `nftset` policy routing rules. |
| **DNS (`config-dns`)** | `no block [<domain>]` / `no blocklist [<name>]` | Removes a sinkholed domain or remote blocklist. |
