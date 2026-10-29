# nfty — Full-Repository Security & Functionality Review (Opus)

- **Date:** 2026-10-29
- **Status:** ✅ **ALL FINDINGS REMEDIATED IN `v0.8.0`** (verified by `test_security_review_hardening_regressions` and 46/46 unit tests)
- **Reviewer:** GitHub Copilot CLI (Claude Opus 5.5)
- **Revision reviewed:** `main` @ `4ee3249` (after rebase onto `origin/main`, includes wg-in / v0.7.0, RustSec dependency fixes, CI pinning)
- **Scope:** Entire Rust codebase (`src/**`), generated nftables/dnsmasq output, packaging scripts. This supersedes the diff-only scope of `2026-10-29-security-functionality-review.md`, which only looked at four file-mode changes.
- **Validation performed:** `cargo test` (45/45 pass); `cargo build`; `nfty -f <file> validate|compile` against purpose-built Nftyfiles to confirm firewall-generation findings.
- **Design constraint (from owner):** The web interface / API must be protected **only by IP allow-lists**. No login/auth layer is to be added in front of it. Every remediation below is allow-list-compatible; none of them add authentication to the web UI.

---

## Summary table

| # | Severity | File | Lines | Vulnerability | Confidence |
|---|----------|------|-------|---------------|------------|
| 1 | 🔴 CRITICAL | src/api.rs, src/features/gateway_proxy.rs, src/features/cloudflare.rs, src/parser.rs | api.rs 186-197, 341-378, 571-580; gateway_proxy.rs 173-249, 351-425; cloudflare.rs 544-561, 1185-1201; parser.rs 1576-1627 | Control-plane allow-list **and** API-key bypass: loopback is implicitly trusted and `X-Nfty-Internal-IPC: 1` is client-settable; nfty's own relays (gateway HTTP/SOCKS proxy, Cloudflare tunnel) deliver remote traffic to the API from 127.0.0.1 | 8/10 |
| 2 | 🔴 CRITICAL | src/api.rs | 564-569, 1357 | Cross-origin control of the allow-list-only API (CSRF + DNS rebinding): wildcard CORS, no Origin/Host/Content-Type checks; allow-listed browser = root RW for any web page | 9/10 |
| 3 | 🟠 HIGH | src/compiler.rs, src/ssh.rs | compiler.rs 462-481, 595-611; ssh.rs 784 | Gateway `allow` is not enforced for gateway `ssh:22` (and SSH generally): no policy-drop after the redirect, input chain accepts, sshd has no source check | 9/10 |
| 4 | 🟠 HIGH | src/repl/mod.rs, src/api.rs | mod.rs 2978-2998; api.rs 1191-1215 | Arbitrary file write as root via `save <path>` over `POST /api/v1/cli` | 9/10 |
| 5 | 🟡 MEDIUM | src/repl/mod.rs | 3000-3020 | Arbitrary file read / existence oracle via `load <path>` (errors echoed in HTTP 400) | 8/10 |
| 6 | 🟡 MEDIUM | src/ssh.rs, src/api.rs | ssh.rs 399-520, ~580-720; api.rs 1207 | Interactive editor (`nano`/`vi`) and stdin-paste paths reachable from the HTTP CLI → daemon worker hang, console editor shell escape | 8/10 |
| 7 | 🟡 MEDIUM | src/ssh.rs, src/api.rs | ssh.rs 38, 43-48, 94-97, 195-207; api.rs 83-103 | Weak credential handling: fixed-salt single SHA-256, static never-expiring session token, default `nfty/nfty` usable over HTTP before forced change — bypasses API-key requirement on keyed listeners | 8/10 |
| 8 | 🟡 MEDIUM | src/main.rs (default config), src/ssh.rs | main.rs 1526-1529 (default gateway), ssh.rs 38 | First-boot SSH takeover race: default gateway exposes `ssh:22` with `nfty/nfty`, no allow-list | 7/10 |
| 9 | 🟡 MEDIUM | packaging/unikernel/build-unikernel.sh, packaging/rk3588s/build-rk3588s.sh | unikernel 28-36, 105; rk3588s 31-40 | Supply chain: downloads (APKs, debs, kernel, `cloudflared` from `releases/latest`) have no checksum/signature verification | 8/10 |
| 10 | 🟡 MEDIUM (functional) | packaging/*.sh | file mode | Packaging scripts lost the executable bit (100755 → 100644); `deploy-lxd.sh:18` invokes `build-unikernel.sh` directly | 9/10 |
| 11 | ⚪ LOW | src/parser.rs, src/features/dns.rs | parser.rs 3270-3305; dns.rs 76-77, 296-298 | `dns raw` deny-list is incomplete (`log-facility`, `dhcp-leasefile`, `dhcp-hostsfile`, `dhcp-optsfile`, `tftp-root`/`enable-tftp`, …) and dnsmasq runs as `user=root` | 7/10 |
| 12 | ⚪ LOW | src/ssh.rs | 801-824 | SSH public-key auth ignores the username | 8/10 |
| 13 | ⚪ LOW | src/features/cloudflare.rs | 642-656 | Cloudflare tunnel token passed on argv (visible in `/proc/<pid>/cmdline`) | 9/10 |
| 14 | ⚪ LOW | src/features/wireguard.rs, src/compiler.rs | — | wg-in: `preshared_key` not validated like `public_key`; VPN peers get unrestricted LAN/Internet forwarding (no per-peer ACL, gateway `allow` not applied to `ig*`) | 6/10 |
| 15 | ⚪ LOW (functional) | src/repl/mod.rs | 2985, 2989 | `save` pending-confirm guard uses textual path equality (`/data/./Nftyfile` bypasses it) | 8/10 |
| 16 | ⚪ LOW | src/api.rs, src/compiler.rs | api.rs 153; compiler.rs 563-611 | Control listeners bind `0.0.0.0:<port>` and match by port only — a `web:` declared on one VIP is served on every non-VIP appliance address (eth0, `wg*`, `ig*`) | 7/10 |

> No findings recommend authentication in front of the web UI. Items 1–3 are allow-list *bypasses*, so fixing them is what makes "allow-list only" a sound model.

---

## 🔴 1. Allow-list and API-key bypass through loopback trust + nfty's own relays

### Root cause

`src/api.rs`:

- `186-197`: any request header `X-Nfty-Internal-IPC: 1` sets `is_internal_ipc = true`. The header is plain text and any client can set it.
- `341-343`: `if peer_is_loopback && is_internal_ipc { return Ok(ReadWrite) }`.
- `346-354`: loopback peers **skip `control_access()` entirely** (no allow-list).
- `375-378`: loopback without a key gets `ReadWrite` whenever no API keys are configured (`None if !cfg.has_any_api_keys()`).
- `571-580`: the pre-routing allow-list gate is also skipped for loopback.

On its own that is meant for the local CLI (`unikernel.rs:706`). It becomes critical because nfty itself relays remote traffic to 127.0.0.1.

### Path A: Gateway HTTP/SOCKS proxy (`privoxy:` / `socks5:`)

- `gateway_proxy.rs:268-290`: the only gate is the **gateway** allow-list (`st.is_ip_allowed(peer, &gw.allow, &global_allow)`). Per `state.rs:292-295`, an **empty list means allow-all**.
- `gateway_proxy.rs:173-249`: `connect_via_gateway_tunnel` has **no destination filtering**. In `DirectHost` mode, it connects straight to any IPv4, including `127.0.0.1`. That mode applies to gateways without tunnels, and to tunnels that are down with killswitch off.
- `gateway_proxy.rs:395-425`: plain-HTTP proxy mode forwards every client header except `connection`, `proxy-*`, `x-forwarded-for`, and `via`. So `X-Nfty-Internal-IPC` passes through.

Exploit, from any host allowed to use the proxy but **not** in the web/API allow-list:

```
curl -x http://<gateway-ip>:8118 -H 'X-Nfty-Internal-IPC: 1' \
     -X POST http://127.0.0.1:<web-port>/api/v1/cli \
     -d '{"command":"save /data/auth.json"}'
```

That returns RW on the control plane. It works the same with `CONNECT 127.0.0.1:<port>` or SOCKS5. Clients can also reach `127.0.0.1:22`, dnsmasq, and the local CF auth port.

### Path B: Cloudflare-published `web:` / `api:`

- `parser.rs:1576-1627`: `api:`/`web:` services are created with backend `127.0.0.1:<port>`.
- `cloudflare.rs:544-561` and `1185-1201`: the tunnel upstream is `backends.first()`, which is `http://127.0.0.1:<port>`.
- `docs/web-interface-spec.md:16` documents `cloudflare-dns` on `web:`. I verified that this Nftyfile passes `nfty validate`:
  ```
  vip 10.9.9.7 { web:8000 { allow 192.168.50.0/24; cloudflare-dns nfty.example.com } }
  ```
- `cloudflared` connects from loopback, so **any Internet user** who reaches the hostname gets RW. If no API keys are configured, no header is needed. If keys are configured, they add `X-Nfty-Internal-IPC: 1`. The nft `allow` set never applies, because locally generated traffic does not traverse `prerouting`.

### Impact

Full root control of the appliance:

- run any CLI command, including `save` → arbitrary file write (#4);
- `PUT /api/v1/config`;
- `POST /api/v1/ssh` (persistent SSH keys);
- read WireGuard private keys and PSKs (`GET /api/v1/status` and `/api/v1/wg`; redaction only applies to `ReadOnly` scope, `api.rs:791-797`, `857-866`);
- read API keys (`GET /api/v1/config`).

### Remediation (allow-list compatible)

1. **Stop trusting a TCP header for IPC.** Move local CLI ↔ daemon IPC to a Unix domain socket (`/run/nfty/ctl.sock`, mode 0600, optionally checking `SO_PEERCRED` uid 0). Alternatively, use a random per-boot token stored 0600 in `/run`. Ignore `X-Nfty-Internal-IPC` on TCP entirely.
2. **Do not exempt loopback from `control_access()`.** Treat 127.0.0.0/8 as just another source that must appear in the listener's allow-list. The local CLI uses the Unix socket from step 1 instead.
3. **Gateway proxies must refuse internal destinations.** After resolution, reject 127.0.0.0/8, 0.0.0.0/8, 169.254.0.0/16, and every appliance-owned address (VIPs, gateway IPs, leased DHCP IPs, eth0, `wg*`/`ig*` addresses). Also strip `X-Nfty-*` headers in `handle_privoxy_client` as defense in depth.
4. **Reject `cloudflare-dns` on `web:`/`api:` listeners** in `control_allow_list_errors()`. A tunnel's source IP is always the appliance itself, so IP allow-lists cannot be applied to tunnelled control traffic. Update `docs/web-interface-spec.md:16` accordingly.

---

## 🔴 2. Cross-origin control of the allow-list-only API (CSRF / DNS rebinding)

### Evidence

- `api.rs:564-569`: `OPTIONS` returns `Access-Control-Allow-Origin: *` and allows `GET, POST, PUT, DELETE` with `Authorization, X-API-Key, X-Nfty-Key, Content-Type`.
- `api.rs:1357`: `send_json` adds `Access-Control-Allow-Origin: *` to **every** JSON response.
- There is no `Origin`, `Host`, or `Content-Type` validation. Bodies go through `serde_json::from_str` regardless of content type, so a `text/plain` "simple request" POST works without a preflight.
- Allow-listed clients without keys get `ReadWrite` (`api.rs:375-376`).

### Impact

Any website opened in a browser on an allow-listed IP can:

- drive `POST /api/v1/cli` (arbitrary CLI, including #4 file write), `PUT /api/v1/config`, `POST /api/v1/ssh`, and `POST /api/v1/cloudflare`;
- **read** secrets, because the wildcard ACAO lets the attacker's JavaScript read responses: WireGuard private keys from `/api/v1/status` and `/api/v1/wg`, and API keys from `/api/v1/config`.

DNS rebinding gives the same result even if CORS is tightened, unless `Host` is validated.

### Remediation: per-listener Origin/Host allow-list derived from VIPs and gateways (no auth)

For each control listener (`ControlListener`, `ast.rs` ~1199 / `control_listeners()` ~1328), compute a trusted authority set:

- `<listen_ip>:<port>` for the owning VIP or gateway (including the `leased_ip` for DHCP VIPs and gateways, taken from runtime state);
- `<hostname>.local:<port>` when `hostname` is set (mDNS);
- the `cloudflare-dns` FQDN, if #1 step 4 is not adopted;
- optionally an explicit `origin <url>` sub-directive for names nfty can't know, such as router DNS, NAT, or reverse proxies.

Then enforce:

1. **Host check (anti-rebinding):** reject requests whose `Host` header is not in the listener's set.
2. **Origin check:** if `Origin` is present and not `http://<authority in set>`, reject with 403. On success, reflect the exact origin with `Vary: Origin`. Never send `*`.
3. **Unsafe methods (POST/PUT/DELETE):** require a matching `Origin`, or no `Origin` and no `Sec-Fetch-Site: cross-site`. Also require `Content-Type: application/json`, which forces a preflight that step 2 will refuse.
4. Requests with no Origin (curl, CLI, automation) remain governed solely by the IP allow-list, so the allow-list-only model is preserved.

---

## 🟠 3. Gateway `allow` not enforced for `ssh:22`; sshd has no source filtering

### Evidence

I compiled this with `nfty -f … compile`:

```
gateway 10.9.9.9 {
    allow 192.168.50.0/24
    ssh:22
    web:8000
}
```

It produced:

```
ip daddr 10.9.9.9 tcp dport 22   ip saddr @allow_gw_10_9_9_9 counter redirect to :22   comment "nfty:gw-ssh=10.9.9.9"
ip daddr 10.9.9.9 tcp dport 8000 ip saddr @allow_gw_10_9_9_9 counter redirect to :8000 comment "nfty:gw-api=10.9.9.9"
```

The ruleset has **no `drop` for non-matching sources and no `chain input`**. `compiler.rs:462-481` never emits a policy-drop for gateway services, unlike VIP services (`compiler.rs:891-896`). Since the redirect is `:22 → :22`, a non-allowed source falls through to INPUT (`policy accept`) and reaches sshd on `0.0.0.0:22` anyway. For comparison, `vip 10.9.9.8 { ssh:22 { allow … } }` *does* get `nfty:svc-policy-drop`.

`ssh.rs:784`: `new_client(_peer_addr)` ignores the peer, so the SSH server has no application-level allow-list. sshd is also always reachable on non-VIP appliance addresses (eth0 primary, `wg*`, `ig*`), because the input chain (`compiler.rs:595-611`) only drops port 22 on VIP addresses.

`web:`/`api:` on gateways are saved by the app-level `control_access()` check. SSH, which is root-equivalent, is not.

### Remediation

- After each gateway service redirect with an allow-list, emit `ip daddr <gw> tcp dport <port> counter drop comment "nfty:gw-policy-drop=…"`. This mirrors `svc-policy-drop`.
- Enforce SSH source filtering in-process in `new_client`/`auth_*`. Reject peers not in the union of `ssh:` allow-lists (and the global allow), so non-VIP addresses are covered too.
- Optionally add an input-chain rule that drops `tcp dport 22` on all local addresses except those explicitly enabled.

---

## 🟠 4. Arbitrary file write as root via `save <path>`

### Evidence

`repl/mod.rs:2978-2998` (`handle_save`) calls `write_atomic(&path, formatted_nftyfile)` on any user-supplied path. `POST /api/v1/cli` (`api.rs:1191-1215`) only blocks `password`, `passwd`, `watch`, and interactive `wg`.

### Impact

An attacker can overwrite `/data/auth.json`. It is then parsed as corrupt, which locks out password login. They can also overwrite `/sbin/init`, `/bin/nfty`, `/etc/*`, cron/profile files where present, and so on. Combined with #1 or #2, this is reachable without being on the allow-list.

### Remediation

Over the API, `save` should accept no argument (save to `config_path`) or a bare filename confined to `/data/backups/` (canonicalize, then verify the prefix). Better still, introduce an **allow-list of CLI verbs** permitted via `/api/v1/cli` instead of the current deny-list.

---

## 🟡 5. Arbitrary file read via `load <path>`

`repl/mod.rs:3000-3020` reads any path. Parse failures are formatted with `{:#}` and returned in the HTTP 400 body. Parser errors quote offending tokens (`Unexpected token '…'`), so fragments of arbitrary files leak, and success or failure works as a file-existence oracle. When the parse succeeds, the target file replaces the candidate config.

**Fix:** same confinement as #4, and return generic errors to the API.

---

## 🟡 6. Interactive REPL paths reachable from the HTTP CLI

The following run on the daemon's stdio from inside an async request handler:

- `ssh add <name>` (no key), `ssh edit|nano|vi <name>`, and the unknown-subcommand fallback in `handle_ssh_cli_command` call `edit_ssh_key_interactive` (`ssh.rs:399`), which spawns `nano`/`vi` with blocking `Command::status()`;
- `ssh paste <name>` (`ssh.rs:480`), which blocks reading stdin;
- the same commands under the `ssh-key …` alias.

### Impact

- Each request pins a tokio worker thread. A handful of requests stalls health checks, proxies, and the API: a DoS from any allow-listed client, or from the CSRF in #2.
- In PID 1 / console mode, the editor attaches to the physical console. `vi :!sh` and nano without `-R` give a root shell to whoever is at the console.

### Remediation

Use the CLI verb allow-list from #4. Additionally, make the interactive helpers refuse to run when `!isatty(0)`, or when called from the API context.

---

## 🟡 7. Weak credential handling (affects keyed listeners)

- `ssh.rs:43-48`: `hash_password` is a single SHA-256 with a global constant salt `"nfty-salt-v1:"`. It is fast to brute-force, and identical passwords hash identically across appliances.
- `ssh.rs:94-97`: `verify_login` compares with `==`, which is not constant-time.
- `api.rs:83-87`: the session token is `nfty_session_` plus the first 32 hex characters of the password hash. It is deterministic and never expires. For the default password `nfty`, it is a publicly computable constant.
- `api.rs:89-103`: `verify_appliance_credential` accepts the password or session token **in place of any API key**.
- `ssh.rs:38` / `195-207`: `must_change_password` is only enforced for SSH shells. `/api/v1/auth/login` and Basic auth accept `nfty/nfty` before the forced change.

### Impact

On listeners where an operator added `key`s as a second layer, an allow-listed client bypasses them with `nfty/nfty` or the constant token.

### Remediation (no new web auth)

- Use argon2id or scrypt with a per-user random salt, and constant-time comparison.
- Use random, expiring session tokens kept in memory.
- Refuse appliance credentials over HTTP while `must_change_password` is set.
- Consider not accepting appliance credentials as API-key substitutes at all.

---

## 🟡 8. First-boot SSH takeover race

The default config, `gateway default { dhcp eth0; ssh:22 }` (see `main.rs:1526-1529` test fixture and the first-boot generator), exposes SSH with `nfty/nfty` to the whole LAN with no allow-list. The first person to log in chooses the password.

**Fix:**

- Generate a random first-boot password and print it on the console or serial port only. Alternatively, ship with SSH limited to the console until a password is set.
- Seed the default gateway with an RFC1918 `allow` (and fix #3 so it is enforced).

---

## 🟡 9. Unverified downloads in image builds

`packaging/unikernel/build-unikernel.sh:28-36` and `packaging/rk3588s/build-rk3588s.sh:31-40` (`fetch_cached`) download Alpine APKs, Debian debs, kernels, and bootloaders over HTTPS without checksum or signature verification. `cloudflared` is fetched from `releases/latest/download/…` (`build-unikernel.sh:105`), so builds are unpinned and non-reproducible. These binaries run as root on the appliance.

**Fix:** pin versions and verify SHA-256 values committed in the repo, or verify Alpine/Debian signatures. Pin cloudflared to a version and verify its checksum.

---

## 🟡 10. (Functional) Packaging scripts no longer executable

This was carried over from the earlier review and is still present in the working tree. `deploy-lxd.sh`, `build-rk3588s.sh`, `build-standalone.sh`, and `build-unikernel.sh` changed from 100755 to 100644. `deploy-lxd.sh:18` calls `./packaging/unikernel/build-unikernel.sh` directly, so the deploy will fail with `Permission denied`.

**Fix:** `git update-index --chmod=+x packaging/**/*.sh` (or `git checkout -- packaging/`).

---

## ⚪ 11. `dns raw` deny-list is incomplete; dnsmasq runs as root

`parser.rs:3270-3305` blocks `dhcp-script`, `dhcp-luascript`, `conf-file`, `conf-dir`, `servers-file`, `addn-hosts`, `hostsdir`, `user`, `group`, and `pid-file`. It still allows several file-touching options:

- `log-facility=/path` creates or appends to any path as root;
- `dhcp-leasefile=/path` overwrites any path;
- `dhcp-hostsfile`, `dhcp-optsfile`, `dhcp-hostsdir`, and `dhcp-optsdir` read any file;
- `enable-tftp` with `tftp-root=/` serves world-readable files to the network. When dnsmasq runs as root, only world-readable files are served, which limits impact because nfty writes secrets 0600.

`dns.rs:76-77` forces `user=root` / `group=root`.

Config write is already admin-level, so this is hardening. However, the deny-list implies a boundary that doesn't hold.

**Fix:** switch `raw` to an allow-list of benign options, and run dnsmasq as `nobody`/`dnsmasq` where it is not doing DHCP on privileged sockets.

## ⚪ 12. SSH public-key auth ignores the username

`ssh.rs:801-824` (`auth_publickey_offered` / `auth_publickey`) accepts any authorized key for any username. Single-user appliance, so the impact is low, but the result is surprising, and audit logs record a misleading user.

## ⚪ 13. Cloudflare tunnel token on argv

`cloudflare.rs:642-656` runs `cloudflared … run --token <token>`, so the token is readable from `/proc/<pid>/cmdline` by any local process. Use `TUNNEL_TOKEN` in the environment, or `--token-file`, instead.

## ⚪ 14. wg-in (new in v0.7.0)

- `preshared_key` is not validated with `validate_wg_key_base64` (only `public_key` is, in `configuration_safety_errors`). It is interpolated into the `wg setconf` file and the generated client `.conf`. The tokenizer probably prevents newline injection, but validating it costs one line.
- The forward chain `iifname "ig*" counter accept` plus masquerade to `eth0`/`mv-*` gives VPN peers unrestricted LAN and Internet access. The gateway `allow` is not applied to `ig*` traffic. This is likely by design; document it, or add per-peer `allow`.
- `wg_storage_base_dir` falls back to `/tmp/nfty-wg-<uid>` when not root (predictable path; dev-only).
- Positive: runtime wg configs are written 0600 (`wireguard.rs:419-435`).

## ⚪ 15. (Functional) `save` pending-confirm guard bypassable

`repl/mod.rs:2985` and `2989` compare `path == st.config_path` textually. `save /data/./Nftyfile` (or a symlink) skips the "pending confirm" protection and the post-save bookkeeping. Canonicalize both sides first.

## ⚪ 16. Control listeners bound on 0.0.0.0 and matched by port

`api.rs:153` binds `0.0.0.0:<port>`, and `Config::control_access` (`ast.rs:1623-1659`) matches listeners by **port** only. The input chain drops the port only on *other VIPs* (`compiler.rs:563-611`), not on eth0, `wg*`, or `ig*` addresses. The allow-list still applies, but the web UI appears on addresses the operator didn't declare.

**Fix:** match on `(local_ip, port)`, or bind to the declared `listen_ip`s.

### Informational

- The web UI and API are plain HTTP. API keys, Basic credentials, and session tokens cross the LAN in cleartext. This is not an auth recommendation; optional TLS on `web:` would protect the existing keys.
- Cloudflare **auth proxy** (`cloudflare.rs:364-500`) has an `is_direct_cf_loopback` guard. It was not found to be bypassable in this review.

---

## Positive observations

- `control_allow_list_errors()` (`ast.rs:1554-1573`) refuses to apply a config whose `web:`/`api:` listener lacks an IP/CIDR allow-list, and rejects hostnames there.
- VIP services with `allow` correctly emit `svc-policy-drop` (verified by compile).
- `repl/debug.rs:12-27` validates ping/traceroute/arping targets (no leading `-`, restricted charset), so there is no argument injection.
- `unikernel::write_atomic` uses `create_new` temp files, mode 0600, `fsync`, and rename. WireGuard runtime configs are 0600.
- `dns raw` rejects newlines, which prevents dnsmasq directive injection.
- Gateway proxies do enforce the gateway allow-list (but see #1 for the empty-list and destination issues).
- The new `cargo-audit` workflow and RustSec dependency remediations are good additions.

## Recommended fix order

1. **#1:** Unix-socket IPC, no loopback exemption, proxy destination filtering, and rejecting `cloudflare-dns` on control listeners. These close remote, unauthenticated root.
2. **#2:** Origin/Host/Content-Type enforcement derived from VIPs and gateways.
3. **#3:** gateway policy-drop and SSH source filtering.
4. **#4, #5, #6:** replace the `/api/v1/cli` deny-list with a verb allow-list.
5. **#7, #8:** credential hardening and the first-boot password.
6. The rest.

## Limitations

- This was a direct, time-boxed manual review. Automated sub-agent passes were unavailable in this session (model-not-supported errors), so the compiler/parser and TUI code received lighter coverage than the API, proxy, SSH, and firewall paths.
- No live root-privileged deployment was exercised. Firewall findings were confirmed against generated rulesets (`nfty compile`); runtime proxy and Cloudflare paths were confirmed by code reading.
- `SECURITY-REVIEW.md` (committed in `4ee3249`) is currently deleted in the working tree. It was left untouched.
