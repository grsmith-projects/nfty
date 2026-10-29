# REST API & Web Dashboard Reference

`nfty` embeds a zero-dependency asynchronous HTTP/1.1 REST API and single-page web dashboard directly in the appliance binary. Every CLI operation, health metric, NAT flow table, WireGuard tunnel profile, and `Nftyfile` configuration transaction can be inspected or automated via JSON over HTTP.

---

## Table of Contents

1. [Enabling & Scoping `api:<port>`](#1-enabling--scoping-apiport)
2. [Authentication & API Key Scopes (`rw` vs `ro`)](#2-authentication--api-key-scopes-rw-vs-ro)
3. [Embedded Web Dashboard (`GET /`)](#3-embedded-web-dashboard-get-)
4. [Endpoint Summary Table](#4-endpoint-summary-table)
5. [Status, Config, NFT & Flows Endpoints](#5-status-config-nft--flows-endpoints)
6. [Allowlist & Dynamic Host Registration Endpoints](#6-allowlist--dynamic-host-registration-endpoints)
7. [Backend Drain, Undrain & Health Probe Endpoints](#7-backend-drain-undrain--health-probe-endpoints)
8. [WireGuard & Cloudflare Endpoints](#8-wireguard--cloudflare-endpoints)
9. [1:1 CLI Execution & Service CRUD Endpoints](#9-11-cli-execution--service-crud-endpoints)

---

## 1. Enabling `web:<port>` vs. `api:<port>`

By default, **`nfty` does not bind any Control API or Web Console port** unless you explicitly declare `web:<port>` or `api:<port>` inside a `vip` or `gateway` block in `/data/Nftyfile`.

`nfty` enforces a strict separation between the interactive Web Console (`web:<port>`) and the headless JSON Control API (`api:<port>`):

- **`web:<port>`** (default `:8000`): Serves the interactive 7-tab JavaScript Web Console (`GET /`, `/ui`, `/dashboard`, `/index.html`) plus the `/api/v1/*` endpoints it calls. Requires an IP/CIDR `allow` list (e.g. `allow { 192.168.0.0/16 }`) so allowed operators can use the web frontend directly in their browser.
- **`api:<port>`** (default `:9090`): Serves **only** the headless JSON Control API (`/api/v1/*`; `GET /` returns `404 Not Found` JSON). Requires an IP/CIDR `allow` list, plus a scoped `rw` or `ro` API key if any keys are configured.

Both listener types **must** have at least one IP, CIDR, or IPv4-wildcard allow entry (their own, their gateway's, or the global `allow`). Configs without one fail `test`/`apply` and are rejected by `PUT /api/v1/config`. Hostname entries are not accepted for these listeners. Remote clients outside the allow-list, or connecting to a port with no `web:`/`api:` listener, get `403`. Loopback clients get no special treatment.

### `Nftyfile` Configuration

```hcl
vip 192.168.1.4/21 {
  ssh:22

  # Interactive Web Console on port 8000 secured by IP allow-list
  web:8000 {
    allow {
      192.168.0.0/16
    }
  }

  # Headless JSON Control API on port 8080 secured by IP allow-list + scoped API keys
  api:8080 {
    allow {
      192.168.0.0/16
    }

    # Full read-write automation key
    key nfty_rw_84f9a2d1c3e5b7091a2b3c4d5e6f7a8b rw

    # Read-only monitoring key
    key nfty_ro_5a2d949e15250c395c4b9683833c5bc3 ro
  }

  app-backend:5055 {
    hostname app.local
    check tcp 5s
  }
}
```

### Generating Keys via the Interactive CLI

You can generate cryptographically random `rw` or `ro` keys directly inside `configure` mode using `key new [rw|ro]`:

```text
nfty> configure
nfty(config)# vip 192.168.1.4
nfty(config-vip:192.168.1.4)# api:9090
nfty(config-vip:192.168.1.4-api:9090)# key new rw
Generated new rw API key on vip 192.168.1.4 api:9090:
  nfty_rw_84f9a2d1c3e5b7091a2b3c4d5e6f7a8b
nfty(config-vip:192.168.1.4-api:9090)# key new ro
Generated new ro API key on vip 192.168.1.4-api:9090:
  nfty_ro_19c4e8b2a0f6d3157e8a9b0c1d2e3f4a
nfty(config-vip:192.168.1.4-api:9090)# apply
```

### Kernel `nftables` Input Chain Protection

When one or more `api:<port>` blocks are configured on VIPs or Gateways, the `nfty` compiler automatically emits strict kernel `nftables` rules in `table ip nfty -> chain input`:
- Traffic to `tcp dport <port>` is **accepted** only when the destination IP (`ip daddr`) matches the specific VIP or Gateway IP where `api:<port>` is declared (and passes the global `allow` set if configured).
- Traffic to `tcp dport <port>` destined for any other IP on the host is **dropped** at the kernel firewall layer (`ip daddr != { 192.168.1.4 } tcp dport 9090 drop`).

---

## 2. Authentication & API Key Scopes (`rw` vs `ro`)

### Supported Authentication Headers & Parameters

Clients can present their API key using one of three mechanisms:

1. **Bearer Token Authorization Header** (Recommended):
   ```http
   Authorization: Bearer nfty_rw_84f9a2d1c3e5b7091a2b3c4d5e6f7a8b
   ```
2. **Custom API Key Header**:
   ```http
   X-API-Key: nfty_rw_84f9a2d1c3e5b7091a2b3c4d5e6f7a8b
   ```
3. **URL Query Parameter** (Convenient for Prometheus/Grafana scrapers; prefer a header where possible because URLs can end up in logs):
   ```text
   http://192.168.1.4:9090/api/v1/status?key=nfty_ro_19c4e8b2a0f6d3157e8a9b0c1d2e3f4a
   ```

There is no username/password login for the web console or API. Access is controlled by the listener's IP allow-list plus optional API keys.

> [!NOTE]
> **Loopback & Unconfigured Key Behavior**
> - Every client, including loopback, must pass the receiving listener's IP allow-list. A listener with no configured keys grants allow-listed clients read-write access; a keyed listener requires a matching key.
> - On a shared port, a key must be accepted by every keyed listener on that port and receives the least privilege granted by them.
> - Local CLI and SSH sessions do not use HTTP. They reach the controller over a Unix socket (`/run/nfty/ctl.sock`, mode `0600`) that accepts only root or the controller's own user.
### Permission Scopes & Secret Redaction (`rw` vs `ro`)

Every API key is assigned either `rw` (**Read-Write**) or `ro` (**Read-Only**) scope:

| Capability | `rw` (Read-Write Key) | `ro` (Read-Only Key) | Logged-in SSH/Local CLI User |
| :--- | :---: | :---: | :---: |
| `GET /api/v1/status`, `/config`, `/nft`, `/flows`, `/allow` | Allowed | Allowed | Full CLI access |
| `POST` / `PUT` / `DELETE` configuration & drain mutations | Allowed | `403 Forbidden` | Allowed |
| Visibility of `ro` API keys in config output | Full plaintext | Full plaintext | Full plaintext |
| Visibility of `rw` API keys in config output | Full plaintext | Redacted as `<redacted-rw-key>` | Full plaintext |
| Visibility of WireGuard `PrivateKey` / `PresharedKey` | Full plaintext | Redacted as `<redacted>` | Full plaintext |

> [!IMPORTANT]
> **Why `ro` Redacts `rw` Keys and WireGuard Private Keys**
> Because `GET /api/v1/status` and `GET /api/v1/config` return the full `Nftyfile` AST and formatted configuration text, an `ro` key holder would be able to escalate privileges to `rw` if `rw` keys were returned in cleartext. `nfty` automatically sanitizes all `rw` keys to `<redacted-rw-key>` and all WireGuard private/preshared keys to `<redacted>` whenever a request is authenticated with an `ro` token.

If an `ro` token attempts a write operation, `nfty` returns `403 Forbidden`:

```json
{
  "ok": false,
  "error": "Forbidden: API key has read-only ('ro') scope; write operations require a read-write ('rw') key"
}
```

---

## 3. Interactive Web Console (`web:<port>`)

Navigating to `http://192.168.1.4:8000/` (or `/dashboard`, `/ui`, `/index.html`) on any port configured with `web:<port>` serves the built-in dark-mode **7-Tab Interactive Web Console**:

- **Strict Port Separation**: `GET /` is only served on `web:<port>` listeners (e.g., `web:8000`). Hitting `GET /` on an `api:<port>` listener (e.g., `api:8080`) returns `404 Not Found` (`application/json`).
- **IP Allow-List Authentication**: `web:8000` requires an allow-list such as `allow { 192.168.0.0/16 }`; any browser client on `192.168.0.0/16` is automatically authenticated with `rw` access without needing to paste an API key. Clients outside it receive `403`.
- **7 Interactive Views + Web CLI Drawer**:
  1. **Overview & Topology** (KPI cards, live VIP/Service/Gateway topology cards, health matrix, 1-click Probe Now)
  2. **VIPs & Services** (1-click Backend Drain/Enable, Add/Delete Service, API Key generator)
  3. **WireGuard Gateways** (Upload `.conf` profiles, ECMP tunnel health/latency/traffic, port forwards)
  4. **Programmable DNS** (`dnsmasq` settings, authoritative records, `nftset` policy routes, adblock domains)
  5. **Allow-List & Cloudflare** (Global & per-service allow-lists, dynamic host->IP registration, Refresh DNS Now)
  6. **Conntrack Flows** (Real-time `/proc/net/nf_conntrack` table with search/filter and pause/resume)
  7. **Nftyfile & `nftables`** (Editable `Nftyfile` with Save & Apply + compiled `table ip nfty` viewer)
  - **Slide-Up Web CLI (`)**: Press `` ` `` to run any `nfty` CLI command directly in the browser.

---

## 4. Endpoint Summary Table

| Method | Endpoint | Min Scope | Description |
| :--- | :--- | :---: | :--- |
| `GET` | `/`, `/dashboard`, `/ui` | `web:<port>` only | Serves the embedded 7-tab interactive HTML/JS Web Console (`404` on `api:<port>`). |
| `GET` | `/api/v1/auth/whoami` | `ro` / Allow-List | Returns active authentication scope (`rw` or `ro`), mode (`allowlist` or `token`), client IP, and listener port. |
| `GET` | `/api/v1/status` | `ro` | Full appliance snapshot: config, backend health/RTT, active backends, flows, WireGuard profiles, and compiled `nftables` ruleset. |
| `GET` | `/api/v1/config` | `ro` | Returns structured JSON and formatted `Nftyfile` text for both `running` and `candidate` configs. |
| `PUT` | `/api/v1/config` | `rw` | Parses and applies an `Nftyfile` with checked operations and best-effort restoration; the overall apply is not atomic. |
| `GET` | `/api/v1/nft` | `ro` | Returns the compiled kernel `nftables` script (`table ip nfty` and `table netdev nfty_ingress`). |
| `GET` | `/api/v1/flows` | `ro` | Returns active NAT connections parsed from `/proc/net/nf_conntrack`. |
| `GET` | `/api/v1/wg` | `ro` | Lists saved WireGuard `.conf` profiles in `/data/wg/` (`PrivateKey` redacted for `ro`). |
| `POST` | `/api/v1/wg` | `rw` | Uploads and validates a WireGuard `.conf` profile into `/data/wg/<name>.conf`. |
| `GET` | `/api/v1/cloudflare` | `ro` | Returns `cloudflared` daemon status, tunnel metadata, and active `cloudflare-dns` / `cloudflare-auth` routes. |
| `POST` | `/api/v1/cloudflare` | `rw` | Updates Cloudflare API/tunnel credentials in `/data/cloudflare.json` and reconciles the tunnel. |
| `GET` | `/api/v1/allow` | `ro` | Returns global allowlists, per-service allowlists, resolved DNS host mappings, and expanded `nftables` IP sets. |
| `POST`, `PUT` | `/api/v1/allow` | `rw` | Appends (`POST`) or replaces (`PUT`) global or per-service allowlist entries and optionally applies to the kernel. |
| `DELETE` | `/api/v1/allow` | `rw` | Removes specified entries from the global or per-service allowlist. |
| `POST`, `PUT` | `/api/v1/allow/hosts` | `rw` | Registers or updates a dynamic hostname-to-IPv4 mapping and immediately refreshes kernel allow sets. |
| `POST` | `/api/v1/allow/refresh` | `rw` | Forces immediate DNS re-resolution of all hostname and wildcard allowlist entries. |
| `POST` | `/api/v1/drain` | `rw` | Marks a backend `ip:port` as `DRAINING` and removes it from the kernel `nftables` verdict map. |
| `POST` | `/api/v1/enable` | `rw` | Clears `DRAINING` on a backend `ip:port` and restores it to active kernel rotation. |
| `POST` | `/api/v1/probe` | `rw` | Triggers an immediate health check cycle across all services and returns probe outcomes. |
| `POST` | `/api/v1/cli` | `rw` | Executes any semicolon-separated or multi-line CLI command string (1:1 parity with interactive shell). |
| `POST` | `/api/v1/apply` | `rw` | Validates and commits the current `candidate` configuration to `running` and reloads the kernel. |
| `GET` | `/api/v1/services` | `ro` | Returns a map of all configured services. |
| `GET`, `PUT`, `DELETE` | `/api/v1/services/<key>` | `ro` / `rw` | Retrieves (`GET`), creates/updates (`PUT`/`POST`), or deletes (`DELETE`) an individual service by key. |

---

## 5. Status, Config, NFT & Flows Endpoints

### `GET /api/v1/status`

Returns the complete operational state of the appliance.

**Request:**
```bash
curl -s -H "Authorization: Bearer nfty_ro_19c4e8b2a0f6d3157e8a9b0c1d2e3f4a" \
  http://192.168.1.4:9090/api/v1/status
```

**Response (`200 OK`):**
```json
{
  "running": {
    "global_allow": ["192.168.1.0/24"],
    "vips": {
      "192.168.1.4": {
        "ip": "192.168.1.4",
        "prefix": 24,
        "interface": "eth0",
        "vlan": null,
        "dhcp": false,
        "dhcp_hostname": null,
        "api": {
          "port": 9090,
          "keys": [
            { "key": "<redacted-rw-key>", "scope": "rw" },
            { "key": "nfty_ro_19c4e8b2a0f6d3157e8a9b0c1d2e3f4a", "scope": "ro" }
          ]
        }
      }
    },
    "services": {
      "192.168.1.4:443": {
        "key": "192.168.1.4:443",
        "name": "https",
        "vip": "192.168.1.4",
        "listen_port": 443,
        "proto": "tcp",
        "mode": "nat",
        "balance": "sticky",
        "backends": [
          { "ip": "192.168.1.21", "port": 443, "weight": 2, "backup": false },
          { "ip": "192.168.1.22", "port": 443, "weight": 1, "backup": false }
        ]
      }
    }
  },
  "runtime": {
    "192.168.1.21:443": {
      "healthy": true,
      "drained": false,
      "last_rtt_ms": 0.84,
      "last_error": null,
      "consecutive_successes": 142,
      "consecutive_failures": 0
    },
    "192.168.1.22:443": {
      "healthy": true,
      "drained": false,
      "last_rtt_ms": 1.12,
      "last_error": null,
      "consecutive_successes": 142,
      "consecutive_failures": 0
    }
  },
  "active_backends": {
    "192.168.1.4:443": ["192.168.1.21:443", "192.168.1.22:443"]
  },
  "resolved_hosts": {},
  "flows": [
    {
      "proto": "tcp",
      "state": "ESTABLISHED",
      "src": "192.168.1.105:54322",
      "dst": "192.168.1.4:443",
      "backend": "192.168.1.21:443",
      "packets": 48,
      "bytes": 19420
    }
  ],
  "wg_configs": {},
  "kernel_applied": true,
  "nft_ruleset": "table ip nfty {\n  ...\n}\n"
}
```

---

### `GET /api/v1/config` & `PUT /api/v1/config`

- **`GET /api/v1/config`** (`ro` or `rw`): Retrieves both `running` and `candidate` configurations as structured JSON and canonical `Nftyfile` text.
- **`PUT /api/v1/config`** (`rw` only): Applies a raw `Nftyfile`, snapshots the prior running configuration, and persists the configured file. VIPs, tunnels, DNS, Cloudflare and storage are not a single transaction; on failure, restoration is best-effort. A persistence error may be reported after the dataplane changed.

**Example — Replacing the Configuration via `PUT /api/v1/config`:**
```bash
curl -s -X PUT \
  -H "Authorization: Bearer nfty_rw_84f9a2d1c3e5b7091a2b3c4d5e6f7a8b" \
  --data-binary @/data/Nftyfile \
  http://192.168.1.4:9090/api/v1/config
```

**Response (`200 OK`):**
```json
{
  "ok": true,
  "running": { "...": "..." }
}
```

---

### `GET /api/v1/nft`

Returns the exact `nftables` ruleset compiled from the active configuration and current backend health states.

```bash
curl -s -H "X-API-Key: nfty_ro_19c4e8b2a0f6d3157e8a9b0c1d2e3f4a" \
  http://192.168.1.4:9090/api/v1/nft
```

**Response (`200 OK`):**
```json
{
  "nft": "#!/usr/sbin/nft -f\nflush table ip nfty\ntable ip nfty {\n  ...\n}\n"
}
```

---

### `GET /api/v1/flows`

Reads `/proc/net/nf_conntrack` and returns all active NAT connections tracked by the kernel for configured VIPs and services.

```bash
curl -s -H "X-API-Key: nfty_ro_19c4e8b2a0f6d3157e8a9b0c1d2e3f4a" \
  http://192.168.1.4:9090/api/v1/flows
```

**Response (`200 OK`):**
```json
{
  "ok": true,
  "flows": [
    {
      "proto": "tcp",
      "state": "ESTABLISHED",
      "src": "192.168.1.105:54322",
      "dst": "192.168.1.4:443",
      "backend": "192.168.1.21:443",
      "packets": 48,
      "bytes": 19420
    }
  ]
}
```

---

## 6. Allowlist & Dynamic Host Registration Endpoints

### `GET /api/v1/allow`

Returns the global allowlist, per-service allowlists, dynamically resolved DNS host mappings, and expanded `nftables` IP/CIDR sets.

```bash
curl -s -H "X-API-Key: nfty_ro_19c4e8b2a0f6d3157e8a9b0c1d2e3f4a" \
  http://192.168.1.4:9090/api/v1/allow
```

**Response (`200 OK`):**
```json
{
  "global_allow": ["192.168.1.0/24", "*.office.lan"],
  "service_allow": {
    "192.168.1.4:443": ["10.20.0.0/16"]
  },
  "resolved_hosts": {
    "laptop.office.lan": ["192.168.1.150"]
  },
  "expanded_service_sets": {
    "192.168.1.4:443": ["192.168.1.0/24", "192.168.1.150", "10.20.0.0/16"]
  }
}
```

---

### `POST /api/v1/allow`, `PUT /api/v1/allow` & `DELETE /api/v1/allow`

Modifies the global allowlist (when `service` is omitted or `null`) or a specific service's allowlist (when `service` is set to e.g. `"192.168.1.4:443"`):
- `POST /api/v1/allow`: Appends new entries without removing existing entries.
- `PUT /api/v1/allow`: Replaces the target allowlist with the provided `hosts` array.
- `DELETE /api/v1/allow`: Removes matching entries from the target allowlist.

**Request Schema:**
```json
{
  "service": null,
  "hosts": ["10.50.0.0/16", "172.16.10.*", "*.corp.internal"],
  "apply": true
}
```

**Example (`POST /api/v1/allow`):**
```bash
curl -s -X POST \
  -H "Authorization: Bearer nfty_rw_84f9a2d1c3e5b7091a2b3c4d5e6f7a8b" \
  -d '{"hosts": ["10.50.0.0/16", "admin-ws.office.lan"], "apply": true}' \
  http://192.168.1.4:9090/api/v1/allow
```

---

### `POST /api/v1/allow/hosts` & `POST /api/v1/allow/refresh`

- **`POST /api/v1/allow/hosts`** (or `PUT`): Registers or updates a concrete hostname-to-IPv4 mapping, persists it in `/data/hosts.json`, and reloads the active dataplane. Passing an empty `ips: []` removes the registered mapping. A hostname independently discovered from DNS or `/etc/hosts` may later reappear; persistence errors are reported.
- **`POST /api/v1/allow/refresh`**: Triggers an immediate DNS resolution pass for all hostnames and wildcard patterns in global and service allowlists.

Registered mappings take precedence over automatically discovered addresses.
Automatic discoveries are runtime cache entries, not persistent registrations.
Updating a mapping requires `/data`; it may already be active if persistence
or controller notification fails.

**Example (`POST /api/v1/allow/hosts`):**
```bash
curl -s -X POST \
  -H "Authorization: Bearer nfty_rw_84f9a2d1c3e5b7091a2b3c4d5e6f7a8b" \
  -d '{"host": "dev-laptop.office.lan", "ips": ["192.168.1.188"]}' \
  http://192.168.1.4:9090/api/v1/allow/hosts
```

---

## 7. Backend Drain, Enable & Health Probe Endpoints

### `POST /api/v1/drain` & `POST /api/v1/enable`

Gracefully drains or re-enables a backend `<ip:port>` across all services.

- When drained, the backend is immediately removed from the kernel `nftables` `numgen` / sticky verdict map so new connections are routed only to remaining healthy backends, while existing `conntrack` sessions continue undisturbed.

**Drain Request:**
```bash
curl -s -X POST \
  -H "Authorization: Bearer nfty_rw_84f9a2d1c3e5b7091a2b3c4d5e6f7a8b" \
  -d '{"backend": "192.168.1.21:443"}' \
  http://192.168.1.4:9090/api/v1/drain
```

**Drain Response (`200 OK`):**
```json
{
  "ok": true,
  "backend": "192.168.1.21:443",
  "drained": true
}
```

**Enable Request:**
```bash
curl -s -X POST \
  -H "Authorization: Bearer nfty_rw_84f9a2d1c3e5b7091a2b3c4d5e6f7a8b" \
  -d '{"backend": "192.168.1.21:443"}' \
  http://192.168.1.4:9090/api/v1/enable
```

**Enable Response (`200 OK`):**
```json
{
  "ok": true,
  "backend": "192.168.1.21:443",
  "drained": false
}
```

---

### `POST /api/v1/probe`

Forces an immediate out-of-band health check cycle across all configured backends and updates the kernel `nftables` verdict maps if any backend transitioned state.

```bash
curl -s -X POST \
  -H "Authorization: Bearer nfty_rw_84f9a2d1c3e5b7091a2b3c4d5e6f7a8b" \
  http://192.168.1.4:9090/api/v1/probe
```

**Response (`200 OK`):**
```json
{
  "ok": true,
  "outcomes": [
    {
      "service": "192.168.1.4:443",
      "backend": "192.168.1.21:443",
      "healthy": true,
      "rtt_ms": 0.79,
      "error": null
    }
  ]
}
```

---

## 8. WireGuard & Cloudflare Endpoints

### `GET /api/v1/wg` & `POST /api/v1/wg`

- **`GET /api/v1/wg`**: Lists all saved WireGuard `.conf` profiles in `/data/wg/`. When called with an `ro` API key, `private_key` and `preshared_key` fields are automatically redacted to `"<redacted>"`.
- **`POST /api/v1/wg`** (`rw` only): Uploads and validates a standard WireGuard `.conf` file into `/data/wg/<name>.conf`.

**Example (`POST /api/v1/wg`):**
```bash
curl -s -X POST \
  -H "Authorization: Bearer nfty_rw_84f9a2d1c3e5b7091a2b3c4d5e6f7a8b" \
  -d '{
    "name": "wg-mullvad-us1.conf",
    "config": "[Interface]\nPrivateKey = YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=\nAddress = 10.64.0.2/32\n\n[Peer]\nPublicKey = YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=\nEndpoint = 198.51.100.10:51820\nAllowedIPs = 0.0.0.0/0\n"
  }' \
  http://192.168.1.4:9090/api/v1/wg
```

---

### `GET /api/v1/ssh`, `POST /api/v1/ssh` & `DELETE /api/v1/ssh`

- **`GET /api/v1/ssh`** (`ro` or `rw`): Lists all saved global OpenSSH authorized public keys in `/data/ssh/*.pub` along with their algorithm, `SHA256:...` fingerprint, and comment.
- **`POST /api/v1/ssh`** (`rw` only): Validates and saves an OpenSSH public key (`ssh-ed25519`, `ecdsa-sha2-*`, or `ssh-rsa`) to `/data/ssh/<name>.pub`.
- **`DELETE /api/v1/ssh`** (`rw` only): Removes `/data/ssh/<name>.pub`.

**Example (`POST /api/v1/ssh`):**
```bash
curl -s -X POST \
  -H "Authorization: Bearer nfty_rw_84f9a2d1c3e5b7091a2b3c4d5e6f7a8b" \
  -d '{
    "name": "workstation",
    "key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ admin@workstation.example.com"
  }' \
  http://192.168.1.4:9090/api/v1/ssh
```

---

### `GET /api/v1/cloudflare` & `POST /api/v1/cloudflare`

Manages the integrated Cloudflare DNS and Zero-Trust `cloudflared` tunnel supervisor.

**Example (`POST /api/v1/cloudflare`):**
```bash
curl -s -X POST \
  -H "Authorization: Bearer nfty_rw_84f9a2d1c3e5b7091a2b3c4d5e6f7a8b" \
  -d '{
    "api_token": "cf_api_token_here",
    "account_id": "0123456789abcdef0123456789abcdef",
    "tunnel_name": "nfty-edge-tunnel"
  }' \
  http://192.168.1.4:9090/api/v1/cloudflare
```

---

## 9. 1:1 CLI Execution & Service CRUD Endpoints

### `POST /api/v1/cli`

Executes any interactive CLI command sequence (separated by `;` or newlines) starting from `nfty(config)#` and returns the resulting `candidate` and `running` configurations.

```bash
curl -s -X POST \
  -H "Authorization: Bearer nfty_rw_84f9a2d1c3e5b7091a2b3c4d5e6f7a8b" \
  -d '{
    "command": "vip 192.168.1.4; service redis:6379; balance sticky; to 192.168.1.41:6379 weight 2; to 192.168.1.42:6379 backup; apply; save"
  }' \
  http://192.168.1.4:9090/api/v1/cli
```

**Response (`200 OK`):**
```json
{
  "ok": true,
  "candidate": { "...": "..." },
  "running": { "...": "..." },
  "nftyfile": "allow {\n  192.168.1.0/24\n}\n..."
}
```

### `POST /api/v1/apply`

Validates the current `candidate` configuration via `nft -c -f -` dry-run and commits it to `running` and the Linux kernel.

```bash
curl -s -X POST \
  -H "Authorization: Bearer nfty_rw_84f9a2d1c3e5b7091a2b3c4d5e6f7a8b" \
  http://192.168.1.4:9090/api/v1/apply
```

### `GET /api/v1/services` & `/api/v1/services/<key>`

Provides direct RESTful CRUD operations on individual service objects:
- `GET /api/v1/services`: Lists all services in the configuration.
- `GET /api/v1/services/192.168.1.4:443`: Returns the JSON representation of service `192.168.1.4:443`.
- `PUT /api/v1/services/192.168.1.4:443`: Creates or replaces a service object and reloads the kernel ruleset.
- `DELETE /api/v1/services/192.168.1.4:443`: Deletes the service and reloads the kernel ruleset.
