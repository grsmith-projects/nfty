# Architectural and code review - 2026-10-25

## Evidence, scope, and interpretation

This review is against the **current working tree**, including its 23 pre-existing modified files, not merely `HEAD`. All 34 tracked files were read in full. References use the physical, one-based line numbers of that working tree. Suggested files, APIs, dependencies, and code below are proposals, not changes made to the application.

Only this report was created. No application, test, image builder, deployment script, network reconfiguration, dependency installation, or migration was executed. In particular, the current tests are not a safe read-only validation mechanism: they reach the same configuration/application paths that can manipulate interfaces, processes, nftables, and persistent storage. Source-level defects are distinguished from platform assumptions that require isolated execution. The proposed Rust implementations have not been compiled as an integrated replacement and must pass the acceptance gates in section 5 before deployment; "complete body" below is not a claim of executed production certification.

**Priority notation:** B = build-blocking; P1 = correctness, configuration integrity, unintended activation, or operational recovery failure; P2 = substantial maintainability, diagnostic, or contract failure; P3 = bounded cleanup that should follow the architectural fixes. IDs are stable work-item references used by the execution plan.

### Read coverage

| Files read completely | Physical lines |
|---|---:|
| `.cargo\config.toml`, `.gitignore`, `Cargo.toml`, `Cargo.lock`, `LICENSE`, `README.md` | 7, 8, 24, 2954, 201, 457 |
| `packaging\deploy-lxd.sh` | 66 |
| `packaging\standalone\build-standalone.sh`, `packaging\standalone\nfty.service` | 22, 15 |
| `packaging\unikernel\build-unikernel.sh`, `packaging\unikernel\ops_config.json` | 227, 21 |
| `packaging\rk3588s\build-rk3588s.sh` | 388 |
| `src\main.rs`, `src\ast.rs`, `src\state.rs`, `src\parser.rs`, `src\compiler.rs` | 800, 1353, 325, 2847, 1413 |
| `src\api.rs`, `src\health.rs`, `src\ssh.rs`, `src\tui.rs`, `src\unikernel.rs` | 1291, 505, 502, 360, 602 |
| `src\features\mod.rs`, `cloudflare.rs`, `dns.rs`, `flows.rs` | 97, 1192, 901, 252 |
| `src\features\gateway_proxy.rs`, `scanner.rs`, `vhost_mdns.rs`, `wireguard.rs` | 451, 472, 437, 595 |
| `src\repl\mod.rs`, `completer.rs`, `help.rs`, `status.rs` | 2615, 825, 651, 425 |

There is no `src\lib.rs`, separate integration-test tree, checked-in Nftyfile/example fixture, toolchain pin, or CI workflow in this inventory. Absence of an example is relevant because a packaging manifest explicitly requires one; absence of a library matters because tests are coupled to the executable's side-effecting implementation. Neither absence is, by itself, a request for a multi-crate rewrite.

## 1. Cross-File Continuity & Coherence Audit

### 1.1 Build continuity must be restored before architectural changes

**B01 - Missing API-scope method (B).** `ApiKeyScope` defines `Display`, but not `as_str`, in `src\ast.rs:249-264`. Calls exist at `src\parser.rs:1771,2125,2248` and `src\repl\mod.rs:1822,2065,2150`. These are ordinary source paths, not feature-gated examples. Add the canonical scope-name method and have `Display` delegate to it; do not add divergent string conversions at each call site.

**B02 - Invalid hash-map key bound (B).** `Proto` does not derive `Hash` (`src\ast.rs:6-12`), but the listener map uses `(String, Option<Ipv4Addr>, u16, Proto)` as its key and calls hash-map operations (`src\unikernel.rs:399-443`). Derive `Hash` for the protocol enum or use a deliberately ordered listener key; the eventual listener key must also stop conflating service identity with the socket address.

**B03 - Overlapping mutable borrows in gateway editing (B).** `handle_gateway_level_command` borrows a gateway from `st.candidate`, calls `st.sync_runtime_entries()`, and then reads the borrowed gateway again (`src\repl\mod.rs:2044-2065`). This is not fixed by adding a lock or cloning all state. End the gateway borrow by extracting the small command result before synchronizing runtime state. Longer term, candidate editing must not synchronize active runtime state at all.

**B04 - JSON response tested as a string (B, test build).** `route_api_request_scoped` returns `(u16, serde_json::Value)` (`src\api.rs:368-375`), while the scoped-key test calls `body_ro_get.contains(...)` and `body_rw_get.contains(...)` (`src\main.rs:774-775,797-798`). Assert the actual DTO fields. Serializing everything and searching substrings would repair the type error but still fail to verify the intended secret-projection contract.

**B05 - Unsupported documented minimum toolchain (P2).** README requires Rust 1.75+ (`README.md:303-313`); the lockfile uses format version 4 (`Cargo.lock:1-3`), which the Cargo shipped with Rust 1.75 cannot consume. `Cargo.toml:1-24` has no `rust-version`; the resolved dependencies also need a measured MSRV. The lockfile was reviewed completely, but dependency package manifests outside this repository were not inspected. Do not infer the final minimum Rust version solely from a package name or pin a guessed version. Select and test a minimum toolchain, declare it, and test the checked-in lockfile with it.

### 1.2 Documented and serialized intent does not consistently survive execution

| ID / priority | Exact discrepancy and evidence | Required correction |
|---|---|---|
| C01 / P1 | Atomic nft transactions are accurately described at `README.md:3,9`, but this is easily read as atomic application. Apply also changes VIPs, DHCP, WireGuard, DNS, Cloudflare, memory, and disk independently: `src\compiler.rs:828-1123,1333-1413`; `src\repl\mod.rs:2391-2468`. | Distinguish nft atomicity from configuration commit. Introduce prepare/activate/compensate plus a durable transaction journal; report partial failure explicitly. |
| C02 / P1 | "Safe rollbacks" (`README.md:286-299`) do not survive the initiating process or reboot. Trial config is persisted immediately; the timer is process-local; timeout/manual rollback does not persist the restored config: `src\repl\mod.rs:2391-2513`; `src\health.rs:458-505`; `src\unikernel.rs:317-394`. | Daemon-owned confirmed commits, durable baseline/trial record, independent deadline, and durable rollback. |
| C03 / P1 | Canonical round-trip requirement (`README.md:437-442`) is violated by rate scope. `RateLimit::fmt` omits `global` for `per_ip == false` (`src\ast.rs:195-204`), whereas parsing defaults to per-IP (`src\parser.rs:415-477`). | Emit the scope explicitly; compare semantic values after parsing, not merely expected text. |
| C04 / P1 | Static VIP/gateway prefixes on `eth0` disappear: formatters emit neither header CIDR nor interface/prefix for that default interface (`src\ast.rs:792-814,1265-1311`). Reparse infers a host-dependent prefix via `default_eth0_prefix_len` (`src\ast.rs:56-79`). | Persist explicit static address/prefix/interface; keep interface observation out of domain defaults. |
| C05 / P1 | VIP formatting abbreviates local SSH/DNS to a single service line, discarding attached service policy (`src\ast.rs:1289-1304`). Bootstrap attaches SSH check/rate settings (`src\repl\mod.rs:578-688`) that this path cannot preserve. | Local endpoints must have an explicit kind and the same lossless policy-block rules as other services. |
| C06 / P1 | `no domain` and an empty upstream list cannot round-trip. Formatter omits both; parser starts from defaults `lan`, `1.1.1.1`, `9.9.9.9`; compiler independently reinstates resolver defaults (`src\ast.rs:1047-1125`; `src\parser.rs:2380-2415,2739-2847`; `src\features\dns.rs:146-159`). Explicit upstreams append to defaults. | Represent default/inherit/disabled/explicit choices separately; serialize clearing explicitly and replace, rather than accidentally extend, defaults. |
| C07 / P1 | Gateway `check = None` and missing VIP are omitted on write, but `Gateway::new` reconstructs a ping/5s check and default VIP (`src\ast.rs:754-847`). | Define disabled/unmanaged states explicitly; do not encode them as omitted defaults. |
| C08 / P1 | Partial inline WireGuard configuration is accepted by the model but discarded by `WgTunnel::fmt`; `iface` is never persisted (`src\ast.rs:593-645`). Reparse reallocates interface identity (`src\parser.rs:1813-1888`). | Use an exclusive file-reference versus complete-inline enum; validate all required fields together; persist allocated resource identity separately. |
| C09 / P1 | `Service.vip`, `Service.vip_id`, `listen_ip`, map key, `key`, and name redundantly represent identity. Parent-first VIP collection/serialization can ignore a service-specific edit; key rebuilding loses disambiguation (`src\ast.rs:287-322,349-407,1265-1353`; `src\parser.rs:1289-1530`; `src\compiler.rs:1125-1205`). | One VIP definition, stable service ID, explicit listener/parent reference, and separate display label. Reject duplicate listener/protocol ownership during validation. |
| C10 / P1 | Disambiguated keys omit protocol and append `@suffix`, which the root service-spec parser cannot parse; subsequent rebuild can overwrite another map entry (`src\parser.rs:10-65,1289-1308`; `src\ast.rs:394-407`). | Do not use a human display/address string as the primary key. Add explicit collision checks and an ID migration. |
| C11 / P1 | DNS `listen IP:PORT` parses but the compiler removes the port (`src\parser.rs:2310-2380`; `src\features\dns.rs:106-134`). A gateway `dns:<port>` is skipped by the gateway redirect path (`src\compiler.rs:392-394`); custom VIP DNS instead redirects to 53. | Group DNS listeners by port and policy, or reject non-53 ports until supported. Make endpoint-port mapping one shared plan. |
| C12 / P1 | `--api-bind` / `--ssh-bind` do not define all resulting listeners or redirects. Dynamic API listeners bind wildcard ports from candidate and running; VIP API targets 9090; compiler guards use 9090/22 (`src\api.rs:73-127`; `src\parser.rs:1470-1529`; `src\compiler.rs:350-460`; `src\main.rs:35-86`). | Separate management binds from explicit exposure endpoints; resolve internal target ports in one place; never activate candidate listeners. |
| C13 / P1 | Native L4 traffic does not enforce `Service.auth`. Basic Auth is only checked on selected userspace paths, only against an initial request; TLS passthrough cannot inspect it (`README.md:202-222`; `src\compiler.rs:631-743`; `src\features\vhost_mdns.rs:290-437`; `src\unikernel.rs:449-576`). | Validate capabilities: authentication requires an HTTP termination path; reject unsupported TLS-passthrough/L4 policy combinations rather than claim they are enforced. |
| C14 / P1 | HTTP hostname routing and mDNS described at `README.md:10,74-102` do not start in standalone mode; advanced daemons start only under `is_unikernel` (`src\main.rs:153-174`). Native service port, listener 80/443, and backend transport are separate but implicit concepts. | Make enabled features a validated runtime plan independent of PID1; model HTTP versus TLS termination/passthrough and origin transport explicitly. |
| C15 / P1 | Gateway sticky balance is parsed and formatted (`src\ast.rs:738-741`; `src\parser.rs:1890-2066`), but userspace gateway selection always uses a global round-robin cursor (`src\features\gateway_proxy.rs:84-171`). DNS routing chooses a single tunnel; kernel selection has another implementation. | A common eligible-target/weight/stickiness policy with transport-specific execution; document DNS resolver routing separately from connection balance. |
| C16 / P1 | `check` has incompatible semantics across entity types. TCP services default to `tcp 5s`, which was previously applied to UDP services; gateway kind/path are ignored and WireGuard always pings 1.1.1.1; direct gateways are not checked (`src\health.rs:21-150,160-261`; `src\features\wireguard.rs:564-595`; `src\repl\status.rs:166-421`). | Preserve ergonomic `tcp 5s` default for TCP services unless `no check` / `check off` is explicitly configured; skip TCP default on UDP-only services; honor gateway probe kind/target and report `Unknown`/`NotMonitored` for unprobed direct gateways. |
| C17 / P1 | Drain/failover promises (`README.md:126-147,286-299`) differ by transport. If all choices are unavailable, `active_backends_for_service` returns DOWN primaries or ultimately all backends, including drained ones (`src\state.rs:261-303`). | Never undo an operator drain implicitly. Default to no eligible target; an explicit, separate emergency health-fail-open policy must still respect drain. |
| C18 / P2 | "Full authoritative and caching DNS", health-filtered answers, and cache-preserving SIGHUP overstate implementation (`README.md:18-21,224-284`). Compiler produces local records rather than a complete authoritative-zone model; health filtering affects only selected synthesized service aliases (`src\features\dns.rs:71-378`). dnsmasq SIGHUP reloads hosts but clears its DNS cache. | State supported local-record/cache semantics precisely; test the packaged dnsmasq behavior; distinguish alias visibility from per-backend DNS balancing. |
| C19 / P1 | Domain nftsets are advertised as continuous native integration (`README.md:21,226`), but every compiled reload recreates `table ip nfty` (`src\compiler.rs:50-621`). Dynamic set contents disappear while dnsmasq may still cache answers. | Retain sets and named stateful objects in the same nft table; atomically replace policy chains/maps without deleting the table. |
| C20 / P2 | `auto-hosts off` does not stop dnsmasq's own `/etc/hosts` loading; IPv4-only sinkhole output contradicts help promising both address families (`src\features\dns.rs:160-219,277-378`; `src\repl\help.rs:4-651`). | Emit `no-hosts` when required, define synthesis and daemon-native sources separately, and explicitly support or reject each address family. |
| C21 / P1 | Cloudflare "same service" semantics differ: first backend only, scheme guessed from port, no local health/drain/weight/rate/allow equivalence; the fallback auth gate uses plaintext TCP (`src\features\cloudflare.rs:321-452,814-839`). | Feed Cloudflare from the same validated origin plan, or declare a distinct external-origin product with rejected unsupported service policies. |
| C22 / P1 | Access email authentication can silently become appliance-password Basic Auth after an API error (`src\features\cloudflare.rs:641-791`). These are not equivalent authentication mechanisms. | Retain the requested policy and surface a failed/degraded deployment; require an explicit operator decision to change authentication mode. |
| C23 / P2 | "Supervises cloudflared" (`README.md:23,423`) is not sustained crash supervision. Reconcile can spawn it, but child ownership/readiness and periodic restart are absent; token changes can retain the old process (`src\features\cloudflare.rs:455-593,595-1017`). | Retain the child, expose readiness/exit status, restart on configuration generation changes, and bound retry backoff. |
| C24 / P1 | README's non-atomic `/data` prohibition (`README.md:442`) contradicts direct writes to auth, host keys, WG files, Cloudflare JSON, host maps, and REPL save (`src\ssh.rs:55-77,462-481`; `src\features\wireguard.rs:327-417`; `src\features\cloudflare.rs:64-81`; `src\unikernel.rs:317-394`; `src\repl\mod.rs:2515-2563`). | One checked atomic-file store with explicit permissions, file/directory sync, and separate intent versus observation persistence. |
| C25 / P2 | Password storage is called "salted SHA-256" (`README.md:68`), but the prefix is a fixed constant for every installation (`src\ssh.rs:40-45`). Read/parse failure resets the credential file to defaults (`src\ssh.rs:55-65`). | Versioned password KDF with random salt; only initialize on confirmed absence; never turn corruption/permission failure into initial credentials. |
| C26 / P2 | README uses `nfty#` and `config-gw` examples; operational prompt is `nfty>` and gateway contexts are `config-gateway...` (`README.md:44-56,149-200`; `src\repl\mod.rs:18-68`). | Generate command examples/help from one command vocabulary; distinguish cosmetic prompt rendering from actual command syntax. |
| C27 / P2 | README standalone example uses nonexistent `--apply --daemon` flags (`README.md:383`); actual clap uses `apply` and `daemon` subcommands (`src\main.rs:35-86`). | Fix the example and add executable help/example contract tests. |
| C28 / P2 | Hostname DHCP examples guarantee upstream router DNS registration (`README.md:13,106`). Sending the DHCP hostname option is not a guarantee that the upstream server publishes it. | Describe requested hostname registration and show lease/DNS verification status independently. |
| C29 / P1 | "Running", "active", "applied", and "saved" are not synonyms. `active_config` uses candidate when running is empty; disk changes replace running without applying; `save` writes candidate that another process treats as running (`src\state.rs:144-201`; `src\repl\mod.rs:2515-2563`). | Define candidate, committed, observed, durable, and pending-confirmed revisions; readers must never choose candidate implicitly. |
| C30 / P2 | `privoxy` means a custom HTTP/CONNECT relay here, not Privoxy's filtering/privacy feature set (`src\ast.rs:648-666`; `src\features\gateway_proxy.rs:304-396`). "Unikernel" includes Linux PID1/container and host-daemon behaviors, not one runtime capability set. | Name the implementation `http-proxy` with a deprecated syntax alias; identify deployment mode separately from transport capabilities. |
| C31 / P1 | Internal API models are also persistence/domain models. Read-only redaction hides RW API keys only, not service Basic Auth or inline WG secrets; status/WG output includes `ParsedWgConf` secrets (`src\ast.rs:1240-1259`; `src\api.rs:389-450,464-467`; `src\features\wireguard.rs:13-20`). | Preserve scoped `api:<port>` key visibility (`rw` / logged-in sessions can view `ro` and `rw` API keys in `show` / `Nftyfile` / `/api/v1/config` / `/api/v1/status`; `ro` keys see `ro` keys with `rw` keys redacted), while redacting WireGuard private/preshared keys and service Basic Auth passwords from unprivileged read DTOs. |
| C32 / P1 | Kernel names are not unique IDs: punctuation maps to `_` in service/gateway `nft_id` (`src\ast.rs:584-590,852-856`). Distinct accepted names can generate identical sets/chains. | Allocate validated, stable, collision-checked resource IDs, not lossy sanitized labels. |

### 1.3 Terminology that must become explicit types

| Present term | Conflicting meanings | Replacement contract |
|---|---|---|
| `key` | Service map key, API secret, gateway address/name, nft identifier | `ServiceId`, `GatewayId`, `CredentialId`, `SecretToken`, `NftObjectName` |
| `vip` | Parent configuration, copied service binding, DHCP identity, currently leased address | `VipId`, `VipSpec`, `LeaseObservation`, `ResolvedListener` |
| `host` | Desired DNS name, cached resolution, discovered name, local record, ACL pattern, service directive alias | `BackendTarget`, `DnsName`, `ResolvedAddressSet`, `DiscoveryObservation`, `AclEntry` |
| `active` | Candidate fallback, committed config, selected backend, process exists, kernel applied | Explicit revision plus `SelectionState` / `Readiness` / `ObservedApplyState` |
| `check` / `health` | Implicit TCP check, configured HTTP/Ping, tunnel ping, unconditional direct-gateway UP | `ProbePolicy`, `ProbeTarget`, `ProbeObservation`, `AdministrativeState` |
| `allow` | Union of global and local sources, NAT match guard, application admission, control API credential authorization | `SourceAcl` with explicit inheritance; separate `PrincipalPermissions` |
| `port` | Public listener, internal local daemon, origin, proxy protocol endpoint | `ListenEndpoint`, `LocalTarget`, `OriginEndpoint` |
| `auth` | Local HTTP Basic credentials, Cloudflare Access identities, SSH credential store, API key scope | Distinct tagged policy types; no fallback between authentication systems |
| `save` / `apply` / `confirm` | Disk export, shared candidate commit, OS changes, ephemeral timer | Explicit export, validate, prepare, activate, commit, confirm, revert operations |
| `packets` / `bytes` | Kernel rule counters, conntrack estimates, completed userspace relay bytes | Typed measurement source and lifetime; no fabricated packet counts |

### 1.4 Complete configuration-to-execution inventory

The tables include the stored fields, not just advertised directives. "Wired" does not mean correctly validated or consistently implemented across transports. Defaults must be applied once during semantic lowering, not independently by constructors, serde, compilers, and runtime helpers.

#### Root configuration, VIPs, and services

| Fields / declaration | Parse or edit path | Execution and persistence assessment |
|---|---|---|
| `Config.global_allow` (`src\ast.rs:1128-1140`) | `src\parser.rs:697-1262`; API allow routes `src\api.rs:574-688` | Unioned with local allow, not local override: `src\state.rs:228-259`. Feeds nft sets and selected userspace admission checks. Empty source list means unrestricted, but a configured unresolved list can mean no matches; preserve that distinction. |
| `Config.dns` | `src\parser.rs:2310-2847` | Feeds DNS compilation and nft rules. `None` is not equivalent to no DNS listener because VIP/gateway DNS services also enable DNS (`src\ast.rs:1162-1170`). |
| `Config.vips` | `src\parser.rs:697-1020` | Parent VIPs feed OS provisioning and formatting; empty VIPs remain meaningful. Do not infer parent identity from the presence of services. |
| `Config.services`, `Config.gateways` | Root parser and REPL; direct JSON service upload | Used by every layer. Map keys are not validated against embedded keys at the JSON boundary (`src\api.rs:811-845`). Introduce constructors and collection-level uniqueness checks. |
| `VipConfig.interface` (`src\ast.rs:83-119`) | `parse_vip`, `parse_vip_header`, interface/dev/dhcp directives (`src\parser.rs:222-343`) | Used by address, VLAN/macvlan, WG scope, and mDNS helpers. Some consumers hardcode `eth0` or recognize only `eth0.*`/`mv-*`; arbitrary declared interfaces do not have consistent support. |
| `VipConfig.prefix_len` | CIDR header/interface parsing | Used in address commands, but lost by default-interface formatting (C04). Runtime environment inference is not an acceptable deserialization default. |
| `VipConfig.dhcp` | Named VIP/defaults and DHCP directives | Starts udhcpc/macvlan provisioning (`src\compiler.rs:828-1123`). Service/gateway `dhcp off` can become interface name `off`, unlike VIP-context handling. DHCP state belongs in a tagged address mode, not a boolean plus static fields. |
| `VipConfig.vlan` | `parse_vlan_id` and interface suffixes (`src\parser.rs:200-220`) | Used in VLAN creation; copied parent/service values can disagree. A VLAN is a property of one binding, not independently mutable on every child. |
| `VipConfig.leased_ip` | Imported from runtime lease files by parsing/reconciliation | Observed state embedded in persistent intent. Service VIP changes are detected in health refresh, but gateway-only lease changes are not equivalently detected (`src\health.rs:231-261`). Remove from user configuration and carry lease generation/expiry separately. |
| `Service.key`, `vip_id`, `name` (`src\ast.rs:287-322`) | Service factory, disambiguation, REPL rename/rekey paths | Used for lookup, grouping, display, local API detection, and nft naming. These are distinct concerns; `name` can affect behavior, not just display. C09/C10/C32 apply. |
| `Service.listen_ip`, `port`, `proto` | `parse_service_spec`, VIP factory (`src\parser.rs:10-65,1318-1530`) | nft supports TCP/UDP/both; fallback is TCP-only and skips local/port-22 paths (`src\unikernel.rs:397-576`). L7 listeners 80/443 are separate. JSON can bypass nonzero-port checks. |
| `Service.vip` | Service-level interface/dhcp/vlan mutations | Duplicate of root VIP intent; ignored or overwritten by parent-first reconciliation in some paths. Remove after migration to `VipId`. |
| `Service.hostname` | Service directive (`src\parser.rs:1532-1734`) | Used for mDNS, HTTP Host/TLS SNI, and DNS synthesis. No explicit listener scope, transport/TLS mode, or ownership uniqueness. DNS-safe hostname validation must not be an incidental parser string check. |
| `Service.cloudflare` | `cloudflare-dns`/related shortcuts | Used to provision external hostname/ingress/CNAME. Does not inherit all local service behavior (C21). VIP shortcut can select an inappropriate service by a display-name heuristic (`src\repl\mod.rs:1085-1491`). |
| `Service.cloudflare_auth` | Cloudflare auth directive | Email identity list becomes Cloudflare Access policy, or silently changes to local Basic Auth on errors. Must be a distinct, non-downgradable policy. |
| `Service.auth` | Auth directive | Basic credential strings consumed by initial-buffer userspace checks; ignored by ordinary kernel DNAT. Never return these through read DTOs; never allow a policy on a path incapable of enforcing it. |
| `Service.api_keys` | `parse_api_key_directive` and API service contexts (`src\parser.rs:479-580,2083-2137`) | Authentication must validate against committed `running` keys rather than candidate keys (`src\ast.rs:1207-1238`; `src\api.rs:237-259`). Logged-in REPL/SSH sessions and `rw` API keys can view `ro` and `rw` `api:<port>` keys inside the config, whereas `ro` API keys have `rw` keys redacted. |
| `ApiKey.key`, `scope` (`src\ast.rs:249-284`) | Token generation/import and scope aliases (`key new [ro\|rw]`, `key <token> [ro\|rw]`) | Scope is consumed by API authorization; implement `ApiKeyScope::as_str` (`"ro"` / `"rw"`). Preserve full `key <token> <scope>` round-tripping in `Nftyfile` and `show` for logged-in sessions while enforcing `ro` redaction of `rw` tokens on `/api/v1/config` and `/api/v1/status`. |
| `Service.balance` | `balance round-robin/sticky` | Expanded weighted slots in several paths, with different cursor/hash algorithms. No shared stability contract on membership changes. |
| `Service.mode` | NAT/transparent directive | Affects nft masquerade decisions, not the source address of a normal userspace TCP relay. Reject transparent userspace mode until a real transparent-proxy transport exists. |
| `Service.check` | `parse_health_check` (`src\parser.rs:357-413`) | Probe type/path/interval partly used. `None` means implicit TCP, not disabled. Identical endpoints in different services share health even when checks differ. |
| `HealthCheckConfig.kind`, `interval_secs` (`src\ast.rs:139-160`) | TCP/Ping/HTTP with HTTP path and interval | Service checks use kind; gateway checks only interval. TUI forced probing disregards ordinary scheduling. Timeout, expected HTTP response, Host header, and tunnel probe target are hardcoded. |
| `Service.limit` / `RateLimit.rate`, `unit`, `burst`, `per_ip` (`src\ast.rs:163-204`) | `parse_rate_limit` (`src\parser.rs:415-477`) | Kernel rate rule versus userspace fixed-window arithmetic differ; L7/gateway/Cloudflare paths do not consistently enforce it. Global scope is lost on write. Validate nonzero rate, bounded burst, and overflow at every input boundary. |
| `Service.allow` | Allow blocks/directives and API routes | Union with global ACL; DNS wildcard resolution uses shared cache. Kernel guards do not by themselves deny all unmatched local-listener traffic. Protocol acceptance must share one admission policy. |
| `Service.backends` / `Backend.host`, `ip` (`src\ast.rs:208-246`) | `parse_backend` performs DNS and uses `0.0.0.0` on unresolved names (`src\parser.rs:67-180`) | Desired name and current address are stored together and mutated by refresh. A missing answer is not an IPv4 endpoint. Resolve outside parsing and publish an explicit unavailable observation. |
| `Backend.port`, `weight`, `backup` | Backend parser and raw Service JSON | Used for dial/DNAT/selection; zero backend port and bypassed/unbounded weights are not uniformly rejected. Eligible primary/backup selection is overridden by fail-open fallback (C17). |

#### Gateways and WireGuard

| Fields / declaration | Parse/edit and runtime trace | Required invariant |
|---|---|---|
| `Gateway.key`, `listen_ip`, `vip`, `hostname` (`src\ast.rs:732-789`) | VIP-header parser, DHCP reconcile, nft, proxies, DNS/mDNS | Desired gateway identity is not the current lease; an unleased gateway must not become a wildcard proxy or DNS listener. |
| `Gateway.balance` | Gateway parser -> nft weighted marks and userspace route selector | Same declared selection policy must mean the same eligible tunnel set and stickiness semantics. DNS routing needs its own explicitly documented selection rule. |
| `Gateway.killswitch` | Gateway parser -> global nft forwarding decisions | Currently globalized, interface-specific, and dependent on packet marks; direct gateways carry a mostly irrelevant flag. Model it on the tunnel uplink policy and test established-flow behavior. |
| `Gateway.check` | Parser -> health scheduler -> hardcoded WireGuard ping | Direct gateways have no actual probe; check kind is not honored. No claimed UP state without an observation. |
| `Gateway.allow` | Parser -> nft guards and proxy admission | Does not establish a general deny policy for direct forwarding. Source admission and return traffic must be planned explicitly. |
| `Gateway.services` | `parse_gateway_service`, upsert (`src\parser.rs:2068-2137,2185-2225`) | Upsert is by kind, so a second endpoint of the same kind replaces the first port. Either expose this restriction in validation or represent multiple endpoints by stable ID. |
| `GatewayService.kind`, `port`, `api_keys` (`src\ast.rs:648-708`) | Redirect/local-listener generation; key handling | SSH, API, DNS, HTTP proxy, and SOCKS have different implicit target rules. Key fields accepted outside an API endpoint can be ignored on serialization/execution. Use kind-specific payloads. |
| `Gateway.forwards`, `GatewayPortForward.listen_port`, `proto`, `backend` (`src\ast.rs:710-729`) | `parse_gateway_forward` (`src\parser.rs:2139-2183`) -> `src\compiler.rs:399-432,536-548`; hostname refresh `src\health.rs:330-334,398-408` | Forward target weight/backup have no balancing effect; forwards are not included in service health probing (`src\health.rs:160-200`). Without gateway tunnels, ingress matches `wg*`, not an explicit direct-uplink interface. Use a dedicated single-target forwarding type and explicit ingress ownership. |
| `Gateway.tunnels` / `WgTunnel.name` (`src\ast.rs:593-645`) | Parser -> saved-config path lookup or inline tunnel | Name is a logical ID, file name, and sometimes path. Define one safe reference syntax and distinguish imported config from allocated interface identity. |
| `WgTunnel.iface` | Parser assigns per-gateway `wgN`; compiler/executor otherwise allocate globally | Cross-gateway interface collision. One allocator must supply every consumer with the same interface/mark/table tuple. |
| `WgTunnel.address`, `private_key`, `peer_pubkey`, `endpoint` | Partially optional inline model -> loader | Either all required inline data is valid, or it is a file reference. Never silently ignore partial fields. Public DTOs may expose public peer identity, not private key. |
| `WgTunnel.weight` | Unbounded parse -> expanded slots; proxy selection | Bound the value and sum; use cumulative weights, not proportional memory allocation. |
| `ParsedWgConf.address`, `private_key`, `peer_pubkey`, `preshared_key`, `endpoint`, `keepalive` (`src\features\wireguard.rs:13-76`) | Loose `.conf` parser -> `wg setconf` and `ip` | Parser collapses peers/sections, discards standard fields, selects first IPv4 address, and forces default-route AllowedIPs/MTU behavior. Reject unsupported fields/peers or support them faithfully; never imply general wg-quick compatibility. |

#### DNS: all stored fields and record variants

Source declarations: `src\ast.rs:862-1125`; directive implementation: `src\parser.rs:2310-2847`; main consumer: `src\features\dns.rs:71-378`.

| Field | Current behavior / gap | Required contract |
|---|---|---|
| `listen` | Strings, optional port discarded; implicit wildcard when no usable address | Typed endpoints; explicit wildcard opt-in; wait for required DHCP bindings |
| `domain` | Defaults to `lan`; omitted disabled state reparses as default | Explicit optional suffix with lossless clearing |
| `cache_size` | Emitted as dnsmasq cache size | Validate against a documented resource budget; report whether cache is enabled |
| `auto_vips` | Synthesizes selected VIP/service/gateway names | Separate named VIP records from health-controlled service aliases; reject unspecified addresses |
| `auto_hosts` | Governs synthesized cache records but not dnsmasq native hosts loading | Define each source, emit `no-hosts` as needed, track provenance |
| `health_aware` | Only filters selected generated service aliases | Either document that exact scope or apply a declared visibility policy to each generated record |
| `all_servers` | Emitted to dnsmasq | Define interaction with tunnel-bound upstream policy rather than silently using one selected tunnel |
| `bogus_priv`, `domain_needed` | Emitted as dnsmasq flags | Use the same defaults in DSL and JSON; test explicit false round-trip |
| `upstreams` | Built-in defaults retained/appended/reintroduced | Typed IPv4/IPv6 resolver endpoint; explicit empty means no upstream, not automatic fallback |
| `forward_zones` | Domain/server list; optional `via_gateway` silently ignored if unresolved | Unknown gateway is a validation error; route DNS lookup traffic through the chosen uplink too |
| `DnsForwardZone.domain`, `servers`, `via_gateway` | Stringly typed; colon replacement corrupts IPv6 endpoint syntax (`src\features\dns.rs:161-189`) | Domain suffix and resolver endpoint types; validate gateway references before process start |
| `records: A { name, ips }` | Multiple IPv4 addresses; not filtered by backend health | Explicit records are static unless an explicit dynamic-record policy says otherwise |
| `Aaaa { name, ip }` | Address is an unchecked string | `Ipv6Addr`; validate family support throughout DNS output |
| `Address { domain, ip }` | IPv4 suffix-wide override | Explicit suffix-match semantics and address family |
| `Cname { alias, target }` | Stored/rendered as strings | Validate names and conflicts; retain terminal-dot semantics deliberately |
| `Txt { name, text }` | Formatter does not escape quotes; lexer destroys `#`/`;` in quoted data | Quote-aware tokenizer and escaped canonical output |
| `Srv { service, target, port, priority, weight }` | Some invalid/missing numbers silently become defaults | Validate every supplied number; distinguish omission from parse failure |
| `Mx { domain, target, preference }` | Similar silent numeric fallback | Strict positional grammar and explicit default only for omitted preference |
| `Ptr { ip, name }` | Record compiles; `no ptr <ip>` does not match deletion consistently | Type-specific record key and deletion command |
| `blocks` | IPv4 sinkhole, not complete IPv6 behavior | Explicit NXDOMAIN/refused/address sinkhole policy, with tested AAAA behavior |
| `blocklists` / `name`, `url` | Filename from name; weak validation; unbounded downloads; errors swallowed (`src\features\dns.rs:438-511`) | Safe file component, accepted URL schemes, download size/deadline, content validation, and atomic replacement retaining last good data |
| `nft_rules` / `action`, `domains`, `gateway` | Shared DNS/compiler naming, but missing reference silently skipped and table replacement erases contents | Resolved stable gateway/set IDs; retain named sets in `table ip nfty`; validate route/bypass conflicts and precedence |
| `raw_options` | Bypass typed model and can conflict with generated options | Explicit advanced escape hatch with origin diagnostics and deny/conflict checks for owned listener/pid/config directives |

**C33 / P1 - DNS deletion is not type-safe.** `apply_dns_no_directive` clears all records for some incomplete type-specific commands and does not consistently match by record kind (`src\parser.rs:2739-2847`). Parse deletion into `DeleteRecord { kind, key }`; reserve `clear records` for an explicit collection-wide operation. Validate before mutating.

#### Auxiliary persisted configuration and observations

| Storage / fields | Trace and assessment |
|---|---|
| `CloudflareConfig.api_token`, `account_id`, `tunnel_id`, `tunnel_name`, `tunnel_token` (`src\features\cloudflare.rs:21-81`) | Stored separately from Nftyfile; token/account discovery can claim verification after ignored errors (`150-190`). Token/account changes do not invalidate dependent IDs/process identity coherently. Treat as a credential-backed provider configuration with generation. |
| `managed_dns_records`, `managed_access_apps` | Ownership ledger, but reconcile can adopt matching external resources and discard local ownership before remote deletion succeeds (`src\features\cloudflare.rs:595-1017`). Keep pending-deletion records until acknowledged; never mutate unowned records without explicit adoption. |
| `access_api_enabled`, `last_status` | Cached capability/error state mixed into desired configuration; one boolean collapses per-resource/transient failures | Move to provider observations with timestamp, error category, and requested-versus-observed policy. |
| `AuthConfig.username`, stored password hash, `must_change_password` (`src\ssh.rs:24-77`) | Whole-file JSON, fixed-salt hash, missing/corrupt/read-error conflation | Versioned credential storage and atomic migration; successful first-login update must durably clear the flag. |
| `/data/hosts.json` and `resolved_hosts` (`src\state.rs:103-107`; `src\health.rs:268-418`) | Manual registrations, discovery, `/etc/hosts`, and DNS answers share an indefinitely growing map; persistence merges old entries back | Separate authoritative registrations from expiring resolver/discovery observations; deletion must remain deleted. |
| `BackendRuntime` health/drain/error/latency/timestamps/counters (`src\state.rs:28-55`) | One entry per mutable endpoint string; different services/probes collide; entries are not pruned | Key by stable backend/probe identity and observation generation; persist administrative drain only if that is the declared contract. |
| `PendingConfirm.revert_to`, `deadline` (`src\state.rs:58-62`) | Only process memory and monotonic time | Durable baseline/trial journal; revert an unconfirmed boot recovery before admitting ordinary writes. |
| `AppState.history`, `last_applied_nft`, `last_disk_nftyfile`, `kernel_applied` (`src\state.rs:95-117`) | Unbounded snapshots, string equality as change detection, premature persistence marker, one boolean for partial system state | Bounded revision history; canonical semantic digest; actual per-controller generation/readiness. |

### 1.5 Every clap argument, subcommand, and environment input

Actual clap definitions are `src\main.rs:35-86`; lifecycle is `src\main.rs:89-266`.

| Surface | Declared/default behavior | Actual execution / defect |
|---|---|---|
| `-f`, `--file` | `Nftyfile` | Implicit fallback to `/data/Nftyfile`, then `/etc/nfty/Nftyfile`; nonexistent explicit file also becomes empty configuration (`111-138`). Distinguish omitted path from explicit path. |
| `--api-bind` | `0.0.0.0:9090`, string | Not parsed as `SocketAddr` by clap; bind failures disappear; dynamic custom ports ignore this address restriction. |
| `--ssh-bind` | `0.0.0.0:22`, string | Only starts SSH in appliance mode; custom internal port not propagated into local redirects. |
| `--unikernel` | Appliance boot and native fallback | Also triggers privileged initialization outside PID1 where applicable; fallback starts only if initial nft activation appears inactive, not as a sustained mode controller. |
| `--ssh-session` | Hidden internal password-enforcement flag | Full application startup, background work, and API attempts occur before enforcement. Child does not inherit the parent configuration/bind contract. |
| `-c`, `--command` | Semicolon/newline-separated commands | Wins over a supplied subcommand; lexical splitting is not quote-aware; command errors generally do not affect process exit status (`178-192`; `src\repl\mod.rs:153-530`). |
| `shell` / omitted subcommand | Interactive shell | Starts its own API/probers; separate processes become independent state writers. PID1 respawns console shell forever even after repeated errors. |
| `daemon` | Headless daemon | Applies after background startup; ignores several failures and prints running; does not start standalone advanced features or enable forwarding (`201-221`). |
| `watch` | Dashboard | Runs another probe/counter owner in addition to background tasks; can apply drains directly. |
| `status` | Read status | Resolves hosts and forces probes, with potential reload side effects; not a read-only daemon query (`225-229`). |
| `validate` | Validate and nft dry-run | Starts background mutators first; missing/permission-denied nft can be reported as simulated success. Separate pure semantic validation from an explicit platform check. |
| `compile` | Print nft | Starts background mutators first; parsing/resolution can do host I/O. Compilation must accept resolved inputs explicitly and never initialize controllers. |
| `apply` | Apply file/VIPs | One-shot process owns transient state, then exits; confirmed-apply semantics belong to a persistent daemon. |
| `-h`/`--help`, `-V`/`--version` | clap built-ins | No need to invent flags. Version is duplicated elsewhere but currently matches; replace explicit clap version with Cargo metadata to prevent future divergence. |
| DHCP `interface`, `ip`, `mask`, `router`, `dns` | Hook environment (`src\unikernel.rs:40-106`) | Inputs from udhcpc; weak validation and silent command errors. Not general application configuration variables. |
| `TERM`, `TERMINFO` | Editor/SSH environment (`src\features\wireguard.rs:369-373`; `src\ssh.rs:335-340`) | Terminal runtime settings; packaged editor/terminfo availability is not consistently verified. |
| Target `CC_*`, `AR_*`, linker configuration | `.cargo\config.toml:1-7` | Build-only environment/toolchain contract, not runtime knobs. The x86-musl C compiler is host `gcc`; validate the resulting target rather than assume any host GCC is musl-compatible. |

No application `NFTY_*` environment configuration was found. There is no implemented gRPC or Unix-domain control API. A local control socket proposed later is a new architecture choice, not an undocumented existing feature.

### 1.6 Complete current HTTP route contract

The transport is handwritten HTTP/1 framing (`src\api.rs:262-366,851-887`). Except for the public HTML routes, authentication is applied before dispatch; RO allows GET except scan and rejects every write method (`src\api.rs:130-261,375-387`). Keys are accepted from several header/query forms, and loopback plus a caller-supplied internal header grants RW. Candidate and running keys are both trusted. These are separate defects from route shape.

| Method / path | Request / response as implemented | Contract failure and required replacement |
|---|---|---|
| GET `/`, `/ui`, `/dashboard`, `/index.html` | Public embedded HTML | Public shell is fine only if its API failures are explicit and rendering escapes data. Do not imply authenticated live status merely because HTML loaded. |
| GET `/api/v1/status`, `/status` (`389-436`) | Large object: running/candidate/active config, formatted text, runtime, active backends, resolutions, flows, WG configs, kernel flag, nft text | Heavy recomputation and secret-bearing domain serialization; replace with versioned status DTO and separate diagnostic endpoints. |
| GET `/api/v1/flows` (`437-440`) | `{ok, flows}` | Missing measurement source, availability, truncation, and collection error metadata. |
| GET/POST `/api/v1/scan` (`441-445`) | Raw body used as optional filter; `{ok, discovered}` | GET starts side effects; synchronous scan blocks the request; RO special-case reveals method semantics are wrong. POST should create a bounded scan job; GET should read it. |
| GET `/api/v1/wg` (`446-449`) | `{ok, wg_configs}` | Includes private/preshared key data through parsed config serialization. Return import names, public peer metadata, validation and observed readiness only. |
| POST `/api/v1/wg` (`496-512`) | JSON `{name, config}` | Raw configuration upload needs safe logical name, strict supported-schema validation, atomic secret-file write, explicit import result. |
| GET `/api/v1/cloudflare`, `/api/v1/cf` (`450-470`) | Token-configured boolean, account/tunnel IDs, process flags, hostnames, routes | Process existence is not readiness; route collection itself reads external stored configuration. |
| POST same (`471-495`) | Optional token/account/name/connector-token fields | Omitted versus explicit clearing conflated; reconcile failures can still return 200. Use typed patch operations and an asynchronous operation result. |
| GET `/api/v1/config` (`513-534`) | JSON containing internal configurations and formatted Nftyfile | Not just the inverse of raw-text PUT; RO projection incomplete. Explicit representation/media type and secret-free export required. |
| PUT `/api/v1/config` (`535-563`) | Raw Nftyfile body | Publishes candidate/running without the full validation/apply contract; errors can be ignored. Replace candidate by revision, then commit through one path. |
| GET `/api/v1/nft` (`564-573`) | Generated nft text in JSON | Does not prove installed state. Label desired generation separately from observed kernel generation. |
| GET `/api/v1/allow` (`574-594`) | Global/local lists, resolved hosts, expanded sets | Return semantic ACL entries plus resolution status; avoid making cache contents the authority. |
| POST/PUT `/api/v1/allow` (`595-654`) | JSON `{service?, hosts, apply=true}` | Ambiguous append/replace semantics and immediate-apply default; `apply=false` does not prevent candidate-driven listener/auth effects. Make resource mutation and commit separate. |
| DELETE `/api/v1/allow` (`655-689`) | Same request type | Invalid entries can fall back to raw lowercase; missing targets may succeed. Use validated identifiers and a precise deletion result. |
| POST/PUT `/api/v1/allow/hosts` (`690-716`) | JSON `{host, ips}` | Registration and resolver cache conflated; no coherent deletion/expiry authority. |
| POST `/api/v1/allow/refresh` (`717-728`) | Refresh/resolution operation | Long-running external I/O and uncertain effect; expose job/outcome and retain last-good observations. |
| POST `/api/v1/cli` (`729-752`) | JSON `{command}` | Starts in a different context from the shell, returns configs instead of command results, ignores quit semantics, and can reach interactive commands. Only typed noninteractive commands belong here. |
| POST `/api/v1/apply` (`753-777`) | Applies candidate, returns validation/application-oriented object | Validation path differs from PUT; application errors can be discarded; no revision/confirm ownership contract. |
| POST `/api/v1/probe` (`778-781`) | Probe results | Forced probes are not a configuration mutation; success wrapper still triggers persistence. |
| POST `/api/v1/drain`, `/api/v1/enable` (`782-801`) | JSON `{backend}` | String endpoint lookup differs from CLI matching; unknown targets can look successful; drain can be bypassed by selection fallback. |
| GET `/api/v1/services` (`802-810`) | Internal service collection, scope-dependent projection | Exposes storage shape and shares secret-projection deficiencies. |
| GET/PUT/POST/DELETE `/api/v1/services/<key>` (`811-845`) | Internal `Service` JSON for writes | URI key and body key need not agree; no complete domain/VIP/history validation; unknown fields ignored; delimiter-containing keys are poor path IDs. |
| Unmatched route/method (`846-849`) | Usually 404-style error | Distinguish unknown resource, known route/wrong method (405 + Allow), malformed body, unsupported media type, semantic validation, revision conflict, and platform failure. |

**U01 / P1 - Incomplete HTTP messages can reach mutation handlers.** `read_full_http_request` returns accumulated input after timeout/EOF/read failure, defaults malformed Content-Length to zero, does not implement chunked decoding, has unchecked length arithmetic, and lacks a header-specific limit and absolute request deadline (`src\api.rs:262-308`). A 4 MiB aggregate buffer is not a framing implementation. Use a maintained HTTP server and body-limits middleware; do not patch individual string splits.

**U02 / P1 - Successful write-method dispatch causes unrelated persistence and self-IPC.** The wrapper persists every successful POST/PUT/DELETE (`src\api.rs:352-354`), including scan/probe/provider operations. Persistence then sends another PUT to fixed localhost:9090 for every non-PID1 process (`src\unikernel.rs:364-392`). A standalone daemon on that port can recursively send configuration writes to itself. Remove the persistence-to-IPC edge entirely.

**U03 / P1 - Authentication is not revision- or endpoint-consistent.** Candidate credentials grant access before commit; dynamic candidate endpoints become live; authentication runs before disk refresh inside the route handler (`src\api.rs:99-106,237-259,383-387`). Use one committed snapshot for listener identity, credential lookup, permission checks, and operation revision.

**U04 / P2 - Error and success shapes are inconsistent.** Raw objects, `{ok}`, validation reports, arrays, and string errors vary per endpoint; application failures are commonly returned as 200. Establish one error envelope with operation ID, stable code, field/source context, and retryability. A generated plan is not an apply success.

## 2. Module Topology & Architectural Critique

### 2.1 Present dependency direction is inverted

`src\ast.rs:56-79` invokes a host command to construct a default. `src\parser.rs:67-111,697-1262` resolves names, reads persistent hosts/lease files, and depends on compiler naming. `src\state.rs:1-3,228-259` imports parser helpers to implement runtime ACL behavior. `src\compiler.rs:1367-1413` both compiles and operates unrelated feature controllers. Persistence in `src\unikernel.rs:317-394` calls the control API. The API calls REPL command handling and serializes domain/storage structs (`src\api.rs:729-752,811-845`). Presentation code performs probing, mutation, and kernel application.

These are **conceptual dependency cycles**, not an assertion of an illegal Rust module import cycle. Reading a type or parser cannot explain its behavior without reading process execution, platform state, and serialization. Moving existing functions into smaller files without removing these edges will preserve the underlying cognitive load.

#### Current ownership map

| Resource | Current owners | Failure mode |
|---|---|---|
| Candidate/running configuration | Every `SharedState` holder; every independent nfty process | Uncommitted activation; last-writer wins; lost updates; no session/revision boundary |
| nft policy | Main, REPL, API, health, TUI, disk refresh-triggered work | Competing rebuilds; desired state advertised despite failed application |
| VIP/VLAN/macvlan | Parser lease imports, compiler reconciliation, PID1 hook | Intent and observation mixed; cleanup may remove resources without ownership evidence |
| WG interfaces/marks/routes | Parser, compiler, WireGuard executor, DNS, gateway proxy | Inconsistent allocation and destructive churn |
| DNS process/files/cache | Reload path, DNS supervisor, DNS CLI | Concurrent writes/restarts/signals; existence confused with readiness |
| Cloudflare resources/process | Detached thread per reload, CLI/API reconcile | Stale concurrent desired states and ownership-ledger races |
| Probes/counters | Background health loop, explicit status/probe, TUI | Duplicate probes, stale observations, invalid rate denominators |
| Child processes/listeners | Detached Tokio/OS tasks, pidfiles, `/proc` scans | Lost exit state, no backpressure, no coordinated shutdown |
| Durable config | REPL save, persistence helper, HTTP success wrapper, self-IPC | Recursive writes; custom paths ignored; partial data writes |
| Confirm deadline | Initiating process's health loop | Lost on disconnect/exit; delayed by unrelated I/O; rollback not durable |

### 2.2 State, transactions, and concurrency findings

**R01 / P1 - Candidate fallback is an activation path.** `active_config()` returns candidate whenever running is empty (`src\state.rs:144-150`). The API also unions candidate listeners/keys explicitly. Empty committed configuration is legitimate; it must not mean "use someone else's uncommitted changes." In addition, `AppState::new` calls loaded configuration running before any application (`src\state.rs:122-141`). Use separate desired/committed/observed revisions and never infer state from `Config::is_empty`.

**R02 / P1 - SSH sessions and one-shot commands are competing daemons.** `shell_request` starts the executable again with `--ssh-session` (`src\ssh.rs:325-413`), which starts background API/health work (`src\main.rs:153-176`). Disk polling and localhost PUT are improvised synchronization between independent writers. Replace each session with a client of one daemon; session state should contain only authentication context, candidate revision, prompt level, and command output.

**R03 / P1 - Persistence lies about completion and cannot persist all valid states.** `persist_to_storage` sets its last-written marker before successful I/O, generally persists only `/data` paths, refuses to overwrite nonempty config with empty config, merges deleted hosts back from disk, uses per-PID temporary names, and ignores errors (`src\unikernel.rs:317-394`). A custom `--file` path and intentional empty configuration must be first-class. Keep persistence free of IPC, reject failures, and update the marker only after durable completion.

**R04 / P1 - Applying an unavailable platform is reported as success-shaped simulation.** `run_nft_command` treats spawn/permission/wait failures as a simulation-like successful outcome and ignores stdin-write errors (`src\compiler.rs:1279-1331`). `apply_vip_commands` converts errors to "staged" text (`1333-1365`). Callers often publish running state regardless. Introduce explicit `PlanOnly`, `Verified`, `Applied`, `Unavailable`, and `Failed` outcomes; only the first is a user-requested offline operation.

**R05 / P1 - Disk refresh changes the control plane outside transactions.** Read/parse errors disappear; successfully changed text replaces running without preparing/applying; candidate preservation depends on lossy formatting (`src\state.rs:153-201`). Treat an external file modification as an import candidate with source revision, never as proof of active configuration. A reload command must return an actual operation result.

**R06 / P1 - Global lock scope includes slow external work.** `reload_kernel_from_state`, WireGuard/file operations, provider work, DNS reconciliation, and several route/CLI helpers execute while holding state locks (`src\compiler.rs:1367-1413`; `src\features\gateway_proxy.rs:84-171`; `src\features\dns.rs:572-603`; `src\repl\mod.rs:2391-2468`). DNS downloads can take seconds while readers/writers wait. Completion also recursively acquires read locks (`src\repl\completer.rs:483-491,775-776`); a queued writer can turn recursive read acquisition into a deadlock on a writer-preferring implementation. Clone one immutable snapshot, release the guard, then perform I/O.

**R07 / P1 - Observations have neither stable identity nor generation.** `Backend::endpoint` includes the current resolved address; runtime records are only inserted, not pruned (`src\ast.rs:218-232`; `src\state.rs:203-223`). Shared endpoints with different service checks collide. Probe tasks capture old configuration and apply their results after changes (`src\health.rs:160-261`). Every observation must include stable subject ID, configuration generation, and observation sequence/time. Reject stale generations and remove orphaned records deliberately.

**R08 / P1 - Confirmation is coupled to unrelated scheduling.** The same loop performs disk sync, deadline handling, counters, probes, and DNS work (`src\health.rs:458-505`). Confirmation expiry cannot depend on a DNS timeout or provider call completing. The transaction owner must own a deadline independently; kernel/platform operations need bounded deadlines and cancellation/recovery semantics.

**R09 / P1 - Task registries retain failed listeners and lose accepted connections.** Gateway/fallback listeners keep a task entry after bind failure or exit; removing a listener aborts the accept task but not its spawned clients (`src\features\gateway_proxy.rs:17-66`; `src\unikernel.rs:397-576`). API ports are never removed (`src\api.rs:97-127`). Retain listener and connection task sets, report readiness, retry under policy, and distinguish stop-admission from force-close.

**R10 / P1 - WireGuard reconciliation does not respect resource identity or ownership.** Every reload flushes/reconfigures interfaces and routing rules; multiple gateways can use the same `wg0`; cleanup removes any unconfigured `wg*` interface and leaves some source rules behind (`src\parser.rs:1813-1888`; `src\features\wireguard.rs:126-289`). Do not operate on an interface merely because its name has a prefix. Use persisted ownership and stable mark/table/interface assignments, diff actual managed state, and mutate only changed resources.

**R11 / P1 - DHCP lease lifecycle is incomplete.** PID1 uses udhcpc `-b -q`, not a retained lease-renewal child; hook deconfiguration leaves stale addresses/lease files and renewal need not remove the old IP (`src\unikernel.rs:40-106,190-313`). Secondary lease handling imposes `/32` without a full subnet/router model. Compiler cleanup can remove any `mv-*` not in the current config (`src\compiler.rs:828-1123`). Model lease acquisition, renewal, expiry, removal, and owner explicitly.

**R12 / P1 - DNS readiness is not process existence.** Reconcile writes active files before validation, can kill/restart the current daemon, waits a fixed 80 ms, and can stage successfully when dnsmasq is unavailable (`src\features\dns.rs:513-570`). PID lookup uses pidfiles or process scans (`380-436`); two reconciliation owners can race. Validate candidate files with the packaged daemon, retain `Child`, apply one generation, verify DNS responsiveness, then expose readiness.

**R13 / P1 - Cloudflare reconciles stale snapshots concurrently.** Every root reload can start an independent OS thread (`src\compiler.rs:1367-1413`). Provider reconcile reads/writes shared JSON, mutates remote resources, and drops ownership records before deletion acknowledgement (`src\features\cloudflare.rs:595-1017`). Introduce one provider controller with coalesced desired generations, idempotent resource operations, explicit ownership/adoption, bounded retries, and durable pending deletions.

**R14 / P1 - PID1 shutdown and child reaping are not a lifecycle.** Signal handler calls `process::exit(0)` (`src\unikernel.rs:110-112,190-198`); there is no general orphan reaper. PID1 must stop admission, terminate/reap owned and adopted children, flush durable state, unmount/sync as appropriate, and perform the selected shutdown action. A signal callback must not run arbitrary Rust shutdown logic.

**R15 / P1 - PTY ownership is unsafe and session cancellation incomplete.** Raw descriptors, unchecked `dup`/`pre_exec` results, possible spawn-path leaks, inherited master descriptors, and no retained child shutdown contract appear in `src\ssh.rs:189-214,325-450`. A map lock is held during async writes. Use `OwnedFd`, close-on-exec, verified session setup, one child owner, bounded terminal I/O tasks, and explicit cancellation/reaping. Validate dimensions before narrowing to `u16`.

**R16 / P1 - Persistent credential corruption becomes initialization.** Auth and SSH host-key read/parse errors silently trigger defaults/replacement (`src\ssh.rs:55-77,462-481`). Missing, malformed, unreadable, and unsupported-version are different outcomes. Replacing a corrupt host key changes server identity; require explicit recovery instead.

**R17 / P2 - TUI does not own terminal restoration reliably.** Early `?` in draw/poll/read can bypass raw-mode/alternate-screen cleanup (`src\tui.rs:34-266`). Move terminal acquisition/restoration into RAII and make event handling submit commands rather than apply network state.

**R18 / P1 - Scanner blocks the runtime it needs.** `scan_network_services` is synchronous, starts async work through a scoped thread/current-runtime handle, and waits on that thread (`src\features\scanner.rs:257-408`). This can deadlock under a current-thread Tokio runtime. It also spawns target-by-port probes without a concurrency budget, does synchronous DNS/reverse lookup, clamps CIDR scope silently, and misenumerates `/32`. Make it a bounded async job with a validated explicit scope.

**R19 / P2 - Counter meaning is not stable across layers.** nft forward counters occur after established-flow acceptance, repeated endpoint rules overwrite rather than aggregate in the text poller, resets produce bad rates, and TUI/background samplers use different intervals (`src\compiler.rs:480-566`; `src\health.rs:420-456`; `src\tui.rs:34-266`). Userspace reports finished-connection bytes and a synthetic two packets, not live packet counters (`src\unikernel.rs:449-576`; `src\features\vhost_mdns.rs:290-437`). Assign stable named counters, use nft JSON, compute rates from actual monotonic sample times, and expose source/unit/lifetime.

**R20 / P2 - Flow and status fallbacks hide unavailable observability.** `/proc` conntrack absence is converted into local socket rows, legacy formats share offsets incorrectly, sockets can include unrelated traffic, and `mark` text is displayed as hex by adding `0x` to decimal (`src\features\flows.rs:22-252`; `src\api.rs:889-1291`). Distinguish unavailable/empty/truncated sources; parse each format independently; use numeric marks with actual hexadecimal formatting.

### 2.3 L4/L7 policy and protocol continuity

| ID / priority | Defect and exact location | Engineering correction |
|---|---|---|
| N01 / P1 | Gateway mark chain returns, then later matching gateways can overwrite the mark. Validation says first unscoped gateway wins (`src\compiler.rs:150-350,1207-1277`). | Explicit disjoint ingress selectors and terminal selection; reject ambiguous gateways. Do not identify multiple L2 gateway IPs solely by one shared ingress interface. |
| N02 / P1 | Private bypass/NAT/killswitch exclusions omit `192.168.0.0/16`; killswitch behavior is global and tied to `eth0`/marks, with established acceptance earlier (`src\compiler.rs:150-350,480-621`). | Shared validated local-network policy and per-gateway uplink/fail-closed rules; test pre-existing connections and each private range. |
| N03 / P1 | Direct-gateway allow lists do not establish general forwarding denial; service ACL/rate NAT guards do not deny every alternate local path (`src\compiler.rs:350-621,631-743`). | Separate admission/filter policy from NAT translation; enforce it on every supported path and test bypass paths explicitly. |
| N04 / P1 | Masquerade matching by backend destination can affect a transparent service sharing that backend (`src\compiler.rs:550-621`). | Preserve service identity through conntrack/marks and apply source translation by connection policy, not backend address alone. |
| N05 / P1 | All-down WireGuard tunnels are reintroduced by nft selection; userspace route selection has different fallback behavior (`src\compiler.rs:224-230`; `src\features\gateway_proxy.rs:84-171`). | One eligibility policy; unavailable tunnel sets remain unavailable unless an explicit direct-fallback mode is configured. |
| N06 / P1 | Socket marking, device binding, and local binding errors are ignored; route lookup/name resolution can use the ordinary host path (`src\features\gateway_proxy.rs:192-246`). | A tunnel-bound dial must fail if its required binding cannot be established. Resolve using the selected egress policy; never silently dial direct. |
| N07 / P1 | HTTP proxy reads once, reconstructs headers, and loses a body already in that buffer; CONNECT can lose coalesced tunnel bytes (`src\features\gateway_proxy.rs:304-396`). | Incremental bounded header parsing, preserve prefetched bytes, typed authority parsing, explicit error responses, and one-request-per-message HTTP handling. |
| N08 / P1 | SOCKS5 assumes arbitrary reads align with greeting/request, ignores method negotiation, and loses coalesced/fragmented data (`src\features\gateway_proxy.rs:398-451`). | Read exact protocol lengths; validate version/reserved/method/command/address type; send protocol failure replies and preserve subsequent payload. |
| N09 / P1 | HTTP Host/TLS SNI are extracted from one 2048-byte read and a single-record ClientHello assumption (`src\features\vhost_mdns.rs:215-287,290-437`). Routing can fall back to another VIP. | Bounded incremental sniffing with destination/listener scope fixed first; reassemble TLS records or use a maintained parser. Keep all prefetched bytes for relay. |
| N10 / P1 | Basic Auth inspects only the first request, skips TLS passthrough, and treats websocket as a substring; Cloudflare auth parsing requires the whole received buffer to be UTF-8 (`src\features\cloudflare.rs:214-407`; `src\features\vhost_mdns.rs:290-437`). | Use a message-aware HTTP server/proxy, parse headers independently of binary body, authorize each request, and handle Upgrade as an explicit transition. |
| N11 / P1 | TCP fallback silently omits UDP, cannot implement transparent source forwarding, collides with L7/public listeners, and lacks connect/relay deadlines (`src\unikernel.rs:397-602`). | Explicit `Kernel`/`UserspaceTcp` capability choice; reject unsupported config before activation; one listener registry and shared relay policy. |
| N12 / P2 | mDNS interface refresh waits for packets, membership removal is absent, source sockets/TTL/interface handling are incomplete, and `/24` octet comparison substitutes for network topology (`src\features\vhost_mdns.rs:137-213`; `src\features\mod.rs:75-97`). `eth0@ifN`/custom NICs are not correctly generalized. | Netlink/interface-index observations, timed membership reconcile, per-interface socket behavior, loop prevention, and a declared limited responder versus repeater contract. |
| N13 / P2 | DNS diagnostic client uses fixed transaction ID, insufficient peer/rcode/TC/class checks, and apparent success on malformed/partial data (`src\features\dns.rs:755-843`). | Validated DNS response decoder and bounded query transport; an inspected config is not a successful live DNS answer. |
| N14 / P2 | HTTP health probe reads one short buffer, uses IP Host, accepts coarse status prefixes, and hardcodes timeouts; UDP service defaults to TCP probing (`src\health.rs:21-150`). | Typed protocol-specific probes with configured host/path/timeout/expected status and bounded response-header parsing. |
| N15 / P1 | `.conf` parsing silently drops WireGuard section/peer fields, AllowedIPs, MTU, DNS, routing/hooks; forces its own policy (`src\features\wireguard.rs:23-76,126-289`). | Implement a strict supported subset with actionable unsupported-field errors, or use an explicit nfty tunnel format. Do not partially emulate wg-quick. |
| N16 / P2 | DNS blocklist/forward generation performs filesystem/provider work while "compiling", silently ignores failed resources, and can route an unknown `via` gateway direct (`src\features\dns.rs:17-50,71-378,438-603`). | Pure render from a fully resolved DNS plan; all fetch/resolve/capability failures become explicit controller observations. |

### 2.4 Operator and code-organization failures beyond the route matrix

**U05 / P2 - Three independent command grammars.** `handle_line`, parser/feature handlers, `print_context_help`, and `Completer::complete` independently encode syntax (`src\repl\mod.rs:153-530`; `src\repl\help.rs:4-651`; `src\repl\completer.rs:96-817`). Completion suggests `wg status`, which the WG handler treats as an editable filename. Cloudflare and DNS global-command guards disagree with their feature handlers. Use one typed command registry for dispatch metadata/help/completion; leave resource-specific parsing in focused parsers.

**U06 / P1 - Erroring commands can partially mutate configuration.** In-place directive parsing and remove/edit/reinsert patterns retain earlier mutations after a later error (`src\parser.rs:1532-1734,1890-2066,2310-2737`; `src\repl\mod.rs:690-1491,1841-1926`). Parse a complete command first, apply to a cloned candidate entity, validate, then replace exactly once.

**U07 / P2 - Context and identity behavior is unpredictable.** Global `host` dispatch shadows a service alias; service-to contexts treat missing parent directives as backend strings; root one-line mutations can change `svc.key` without rekeying the map (`src\repl\mod.rs:153-530,690-1021,1841-1926`). Completion produces display strings containing weights/backup or resolved-address decorations that parsers cannot accept (`src\repl\completer.rs:96-817`). Complete with canonical identifiers, not rendered labels.

**U08 / P2 - Help omits effective policy and unsupported behavior.** Service Basic Auth, DNS listen/cache/blocklist/raw options, operational aliases, and common context actions are not consistently exposed (`src\repl\help.rs:4-651`). A generic success message for deletion/drain is not evidence a target existed. Expose command result type, policy scope, capability requirements, and precise target-not-found errors.

**U09 / P2 - Web/TUI/terminal independently reimplement truth.** Direct gateways appear UP without probes, WG drain is not consistently reflected, configured DNS can appear ready without a daemon, and desired nft text is labeled active (`src\repl\status.rs:166-421`; `src\tui.rs:268-360`; `src\api.rs:889-1291`). HTML treats non-2xx JSON as ordinary empty live data and interpolates unescaped fields. Publish one secret-free `StatusSnapshot`; renderers must not select backends, inspect the kernel, or infer readiness.

**U10 / P2 - Error architecture loses cause and category.** Broad `anyhow::Result` at inner boundaries, `let _ =` around platform calls, lock `unwrap`, and `unwrap_or` defaults erase whether an operation failed because of input, capability, privilege, unavailable binary, timeout, or persistence. Significant clusters: `src\compiler.rs:778-1123,1279-1413`; `src\unikernel.rs:40-106,190-394`; `src\features\wireguard.rs:126-417`; `src\features\cloudflare.rs:150-190,595-1017`; `src\features\dns.rs:438-603`; `src\api.rs:535-845`. Use typed errors internally and add context at the boundary that knows resource/operation identity. Retain `anyhow` only at executable/interactive edges.

**U11 / P2 - Panic handling is not a recovery policy.** Runtime lock `unwrap`s are widespread in API/REPL/TUI/background paths. Cloudflare token display slices unvalidated UTF-8 by byte offsets (`src\features\cloudflare.rs:1019-1192`). In contrast, test assertions and literal parsing whose invariants are established locally should not be mechanically rewritten. Eliminate recoverable runtime panics; let truly violated internal invariants stop a supervised component with an explicit diagnostic.

**U12 / P3 - Uncalled wrappers imply APIs that do not exist.** Whole-source reference search found definitions only for `spawn_mdns_and_sni_router` (`src\features\mod.rs:70`), `format_vip_block` (`src\ast.rs:1261`), `create_or_find_vip_service` (`src\parser.rs:1310`), and `print_status` (`src\repl\status.rs:423`). Remove after restoring the build and establishing actual library exports. Do not retain accidental compatibility wrappers in a private binary solely because they are `pub`.

### 2.5 Target dependency and ownership contract

The useful separation is:

```text
bytes / HTTP DTO / CLI arguments
        -> syntax with source spans
        -> validated desired configuration
        -> resolved immutable execution plan
        -> platform/protocol controllers
        -> typed observations
        -> immutable status snapshot
```

Only the daemon coordinator commits configuration and durable state. Readers use `tokio::sync::watch<Arc<Snapshot>>` or an equivalent immutable snapshot handle; no external I/O occurs while a shared-state guard is held. Bounded `mpsc` carries commands/results, not arbitrary mutable `AppState` access. Protocol tasks receive immutable route/admission/dial policy for a revision and report observations; they do not read config files or apply nftables.

Suggested destinations are responsibility boundaries, not a demand to create all files in one patch:

```text
src\main.rs                       composition and exit-code mapping only
src\lib.rs                        testable public application boundary
src\domain\{types,config,error}.rs validated intent; no filesystem/process calls
src\syntax\{lexer,lower,format}.rs grammar, spans, lossless semantic round-trip
src\control\{commands,coordinator,api,credentials}.rs
src\planning\{routing,nft,dns}.rs  pure compilation from explicit inputs
src\runtime\{listeners,health,discovery,status}.rs
src\transport\{http,socks,tls_sniff,relay,mdns}.rs
src\adapters\{command,store,linux,wireguard,dnsmasq,cloudflare,pid1,pty}.rs
src\presentation\{repl,tui,web}.rs render/parse presentation, no platform mutation
```

Do not add a trait for every function. Introduce a port only where there is a real effect to substitute in tests: platform execution, durable storage, time, name resolution, provider HTTP, and process/listener ownership. Pure formatting/selection/parsing should be ordinary functions and enums.

**Required state invariants:**

1. A committed empty configuration remains empty; candidate configuration never drives listeners, credentials, probes, DNS, or routing.
2. Each command has an expected base revision and an initiating principal/session. A stale edit cannot overwrite a newer commit.
3. Each listener, interface, routing rule, nft object, child process, and provider resource has one owner and a stable identity.
4. A policy requiring a capability absent from its transport fails validation; it is never silently approximated.
5. A published applied revision means required controllers acknowledged activation. Partial failure is a distinct observable state.
6. A confirmed trial has a durable baseline and daemon-owned deadline; rollback completion is persisted.
7. External observations are generation-scoped and expiring; they never rewrite desired configuration.
8. Compilation and formatting are pure. Runtime discovery is an explicit input to resolution, not a hidden parser action.
9. Error paths retain the operation, resource, cause, and recovery state without exposing credentials.
10. Admission, eligibility, and selection are shared semantics; kernel, HTTP, SOCKS, fallback, DNS, and Cloudflare cannot independently invent fallback policy.

## 3. File-by-File Readability & Refactoring Blueprints

### 3.1 Extraction inventory and scope

Line count is evidence of scope, not the reason for a refactor. The reason is the number of independently changing policies and effects a reader must hold in mind. Short unsafe boundary functions are included alongside long functions.

The replacement units below have complete function bodies, including failure paths. They are a **staged design kit**, not mutually independent snippets to paste blindly into the present binary. Generic ports are explicit test/adapter boundaries, not omitted function implementations. Existing unchanged leaf routines can remain during extraction, but must pass the field matrix and acceptance tests; a new orchestration function does not by itself repair an old parser/compiler leaf. Proposed dependency additions are listed in section 4. No code fence uses an elided body.

| Current file / complex symbols | Why the scope is wrong | Concrete decomposition / replacement units |
|---|---|---|
| `src\main.rs:89-266` `main` | Argument dispatch occurs after privileged/controller startup; client and daemon lifecycles mixed | Parse execution intent first; pure file loading/validation/compiler client paths; one daemon composition root. Units A, C, M. |
| `src\main.rs:268-799` tests, especially `698-799` | Large interaction scripts assert formatted strings and invoke effectful paths | Move parser/format/reducer tests into library modules; use fake ports for commit tests; isolated Linux tests for real adapters. Section 5 test matrix. |
| `src\ast.rs:83-119,287-590,593-858,862-1125,1128-1353` | Desired state, observed state, naming, platform defaults, secret serialization, and grammar formatting mixed | Validated types and discriminated service/tunnel kinds; pure canonical writer; public DTOs separate. Units A, B, L. |
| `src\parser.rs:255-343,479-580` header/key parsing | Partial parsing, silent tails/defaults, credential generation mixed with syntax | Token spans, exact arity, typed argument constructors; token generation is a command effect. Units A, B, I. |
| `src\parser.rs:697-1262` `parse_nftyfile` | 566-line state machine owns partially built entities and performs runtime reads | Lex -> block tree -> context-specific lowering -> whole-config validation. Complete lexer/tree in B; context lowering obligations explicitly enumerated below. |
| `src\parser.rs:1318-1530` VIP service factory | Infers service kind, backend, identity, and policy from strings | Parse `EndpointKind`, resolve local target from runtime plan, allocate stable service ID once. Units A, I, M. |
| `src\parser.rs:1532-1734,1890-2066,2310-2737,2739-2847` directive reducers | Parse and mutate incrementally; unrelated directive families share one match | Parse typed edits, type-specific DNS record/delete parsers, validate clone, replace once. Units B, C, I. |
| `src\state.rs:95-303` `AppState` and helpers | God object and endpoint-string identity; hidden candidate activation | Revisioned immutable snapshots, separate candidate sessions/observations, pure eligibility. Units A, C, G, L. |
| `src\compiler.rs:50-621` `compile_nft_ruleset` | ACL, routing, balancing, counters, DNS set lifecycle, local endpoint exposure, and NAT concatenated | Resolved plan -> typed nft delta -> pure renderer; persistent object schema versus replaceable chains. Units E, F. |
| `src\compiler.rs:631-743` `emit_service_prerouting` | Endpoint selection, availability, ACL/rate, and translation entangled | Plan admission first, eligible targets second, translation last; reject unsupported capabilities before rendering. Units A, F. |
| `src\compiler.rs:828-1123` DHCP/VLAN reconcile; `1125-1205` VIP commands | Duplicate VIP/gateway loops, shell-like command strings, non-owned cleanup | One desired binding collection and owned-resource delta; typed program/arguments; lease events outside intent. Units D, E, F. |
| `src\compiler.rs:1207-1413` validation/nft/apply | Validation does effects; false success and feature reconciliation in compiler | Pure validation report, explicit platform verification, transaction coordinator. Units C, E, M. |
| `src\health.rs:21-150,160-261,268-418,420-505` | Probe codec, scheduling, DNS cache, metrics, persistence and rollback share ownership | Separate bounded probe worker, resolver cache, counter sampler, generation reducer; coordinator owns deadlines. Units C, G, L. |
| `src\api.rs:73-127,130-366,368-849` | Custom HTTP transport, credential lookup, filesystem, command and platform mutation | Maintained HTTP framework, one principal/snapshot, typed commands/DTOs, explicit errors. Units C, H, L, M. |
| `src\api.rs:889-1291` HTML/JS | Embedded UI reimplements domain truth and ignores HTTP failure | Extract assets; render shared status DTO; use text nodes and explicit stale/error display. Unit L and section 4. |
| `src\repl\mod.rs:70-530` REPL/dispatch | Terminal, navigation, global commands, feature operations, mutations and prints mixed | Parse -> authorize -> execute typed command -> render result; navigation is local. Units C, I, L. |
| `src\repl\mod.rs:578-688,690-1021,1085-1592` bootstrap/root/VIP handlers | Context-specific duplicate mutation and config/runtime cross-calls | Entity edit commands plus common transactional reducer; bootstrap returns a candidate edit, not an ad hoc apply path. Units C, I. |
| `src\repl\mod.rs:1594-1760,1841-1926,1980-2368` adopt/backend/gateway handlers | Index-based identity, rekeying, nested parsing, duplicated gateway API/tunnel grammar | Adopt by stable discovery ID; typed backend/gateway/credential edits; clone/validate/publish. Units A, C, I. |
| `src\repl\mod.rs:2391-2563` apply/confirm/rollback/save | A shell command owns durable system state and timers | Client methods into C; export is distinct from commit; store D is daemon-owned. |
| `src\repl\help.rs:4-651`, `completer.rs:96-817` | 648/722-line independent command grammars; nested locks | Shared registry and context-aware completion over a captured snapshot. Unit I. |
| `src\repl\status.rs:8-141,166-421` | Rendering does lookups/selection/probes and holds global guard | Project once into public status model; pure text renderer. Unit L. |
| `src\features\mod.rs:38-97` | Supervisor starts unrelated infinite tasks without retained ownership; interface policy hardcoded | Runtime supervisor handle with explicit feature list and shutdown; interface observer feeds MDNS/listener plans. Units F, J, M. |
| `src\features\gateway_proxy.rs:17-66,84-171,192-246,304-451` | Lifecycle, config lookup, route selection, unsafe socket setup, HTTP and SOCKS codecs | Registry -> admission -> immutable egress decision -> checked dial -> protocol handler -> measured relay. Units A, F, H. |
| `src\features\vhost_mdns.rs:137-437` | mDNS and HTTP/TLS routing share a file but not a lifecycle/protocol | Separate mDNS controller and bounded preface parser; scope route by listener before hostname. Units H, J. |
| `src\features\dns.rs:71-378,513-698,755-901` | Compiler does runtime discovery; process control/CLI/query codec mixed | Resolved DNS plan, pure render, retained daemon, public status, validated diagnostic transport. Units F, J, L. |
| `src\features\wireguard.rs:23-76,126-289,338-417,467-595` | Config import, live kernel reconcile, editor, CLI, probes all coupled | Strict import schema; owned resource diff; editor works on validated temporary candidate; probe policy owned by health. Units D, E, F, G, I. |
| `src\features\cloudflare.rs:150-190,214-452,595-1017,1019-1192` | Token verification, HTTP auth, origin selection, provider reconcile, child and CLI intertwined | Provider adapter, owned-resource controller, maintained HTTP auth proxy, common origin plan, typed commands. Units H, K, I. |
| `src\features\scanner.rs:174-408,410-472` | Blocking orchestration, unbounded fanout, guessing and persistence in scan | Explicit CIDR iterator, async bounded jobs, typed observations, separate adoption command. Unit G. |
| `src\features\flows.rs:22-252` | Different data sources parsed as equivalent observations | One parser per source; explicit source/result metadata; numeric marks; no fake packets. Unit L. |
| `src\ssh.rs:24-214,325-502` | Credential persistence, terminal password input, raw PTY and SSH service mixed | Credential adapter, terminal guard, owned PTY child session, daemon client. Units D, J, M. |
| `src\tui.rs:34-360` | Event/render/probe/apply all in one 233-line loop | RAII terminal + event-to-command + snapshot-to-view; no network operations in render. Units J, L. |
| `src\unikernel.rs:40-112,190-394,397-602` | PID1, DHCP, disk discovery, persistence/self-IPC and fallback transport | Linux bootstrap adapter, owned DHCP child, store, lifecycle supervisor, explicit transport capability. Units D, F, H, J, M. |

### 3.2 Unit A - validated types and one backend-eligibility policy

**Replaces:** primitive routing identities and duplicated selection in `src\ast.rs`, `src\state.rs:261-303`, `src\unikernel.rs:578-602`, `src\features\gateway_proxy.rs:84-171`, and L7/Cloudflare selection. IDs must be assigned once during migration/import and persisted; they are not recomputed from a currently resolved address.

```rust
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::num::{NonZeroU16, NonZeroU32};
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidValue {
    pub field: &'static str,
    pub reason: String,
}

impl fmt::Display for InvalidValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.reason)
    }
}

impl std::error::Error for InvalidValue {}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct EntityId(String);

impl TryFrom<String> for EntityId {
    type Error = InvalidValue;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let valid = !value.is_empty()
            && value.len() <= 63
            && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !valid {
            return Err(InvalidValue {
                field: "id",
                reason: "expected 1..=63 ASCII letters, digits, '-' or '_'".into(),
            });
        }
        Ok(Self(value))
    }
}

impl From<EntityId> for String {
    fn from(value: EntityId) -> Self {
        value.0
    }
}

impl fmt::Display for EntityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct Port(NonZeroU16);

impl TryFrom<u16> for Port {
    type Error = InvalidValue;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        NonZeroU16::new(value).map(Self).ok_or_else(|| InvalidValue {
            field: "port",
            reason: "must be in 1..=65535".into(),
        })
    }
}

impl From<Port> for u16 {
    fn from(value: Port) -> Self {
        value.0.get()
    }
}

impl FromStr for Port {
    type Err = InvalidValue;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let parsed = value.parse::<u16>().map_err(|_| InvalidValue {
            field: "port",
            reason: "expected an integer in 1..=65535".into(),
        })?;
        Self::try_from(parsed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct Weight(NonZeroU16);

impl TryFrom<u16> for Weight {
    type Error = InvalidValue;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        if !(1..=100).contains(&value) {
            return Err(InvalidValue {
                field: "weight",
                reason: "must be in 1..=100".into(),
            });
        }
        NonZeroU16::new(value).map(Self).ok_or_else(|| InvalidValue {
            field: "weight",
            reason: "must not be zero".into(),
        })
    }
}

impl From<Weight> for u16 {
    fn from(value: Weight) -> Self {
        value.0.get()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Transport {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum BackendTarget {
    Address { address: IpAddr, port: Port },
    Name { name: String, port: Port },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    Unknown,
    Healthy,
    Unhealthy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdministrativeState {
    Enabled,
    Drained,
}

#[derive(Debug, Clone)]
pub struct BackendChoice {
    pub id: EntityId,
    pub address: SocketAddr,
    pub weight: Weight,
    pub backup: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct BackendObservation {
    pub revision: u64,
    pub sequence: u64,
    pub health: Health,
}

#[derive(Debug, Clone, Copy)]
pub enum UnknownHealthPolicy {
    Eligible,
    Ineligible,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectionError {
    NoEligibleBackend,
    WeightOverflow,
}

impl fmt::Display for SelectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoEligibleBackend => f.write_str("no eligible backend"),
            Self::WeightOverflow => f.write_str("total backend weight exceeds supported range"),
        }
    }
}

impl std::error::Error for SelectionError {}

pub fn eligible_backends<'a>(
    backends: &'a [BackendChoice],
    observations: &BTreeMap<EntityId, BackendObservation>,
    administrative: &BTreeMap<EntityId, AdministrativeState>,
    revision: u64,
    unknown: UnknownHealthPolicy,
) -> Vec<&'a BackendChoice> {
    let eligible = |backend: &&BackendChoice| {
        if administrative.get(&backend.id) == Some(&AdministrativeState::Drained) {
            return false;
        }
        let observation = observations.get(&backend.id);
        let health = observation
            .filter(|o| o.revision == revision)
            .map(|o| o.health)
            .unwrap_or(Health::Unknown);
        match health {
            Health::Healthy => true,
            Health::Unhealthy => false,
            Health::Unknown => matches!(unknown, UnknownHealthPolicy::Eligible),
        }
    };
    let primary: Vec<_> = backends.iter().filter(eligible).filter(|b| !b.backup).collect();
    if !primary.is_empty() {
        return primary;
    }
    backends.iter().filter(eligible).filter(|b| b.backup).collect()
}

pub fn select_weighted<'a>(
    choices: &[&'a BackendChoice],
    ticket: u64,
) -> Result<&'a BackendChoice, SelectionError> {
    let total = choices.iter().try_fold(0_u32, |sum, choice| {
        sum.checked_add(u32::from(u16::from(choice.weight)))
            .ok_or(SelectionError::WeightOverflow)
    })?;
    let total = NonZeroU32::new(total).ok_or(SelectionError::NoEligibleBackend)?;
    let mut offset = ticket % u64::from(total.get());
    for choice in choices {
        let weight = u64::from(u16::from(choice.weight));
        if offset < weight {
            return Ok(choice);
        }
        offset -= weight;
    }
    Err(SelectionError::NoEligibleBackend)
}

pub fn apply_observation(
    current_revision: u64,
    observations: &mut BTreeMap<EntityId, BackendObservation>,
    id: EntityId,
    observation: BackendObservation,
) -> bool {
    if observation.revision != current_revision {
        return false;
    }
    if observations.get(&id).is_some_and(|old| {
        old.revision == observation.revision && old.sequence >= observation.sequence
    }) {
        return false;
    }
    observations.insert(id, observation);
    true
}
```

The `Name` string above is the boundary before DNS-name validation, not permission for downstream raw strings: lower it through the DNS-name constructor in the syntax/domain validation pass. Administrative drain is deliberately stored separately from probe results so a health worker cannot overwrite it.

`ticket` deliberately separates eligibility/weighted selection from the mechanism that generates a per-service round-robin cursor or stable client hash. Define the stickiness guarantee explicitly: within a given executor and route generation, not accidental equality between Rust's unspecified default hasher and nft jhash. If identical cross-executor mapping is required, select and implement one supported hash contract rather than pretending the current implementations match.

Use the same constructor pattern for `PrefixLen(0..=32)`, `VlanId(1..=4094)`, `InterfaceName` (Linux byte-length and character constraints), DNS names, credential IDs, and nft object names. Add distinct `ServiceId`, `GatewayId`, and `BackendId` newtypes around `EntityId` at the collection boundaries; one generic string ID alone does not prevent passing a gateway ID where a service ID is required.

### 3.3 Unit B - quote-aware syntax, balanced blocks, and lossless output

**Replaces:** line/comment/semicolon splitting and the ownership-heavy block state in `src\parser.rs:697-1262`. This lexer/tree parser is complete and bounded. It parses syntax only; it does not resolve names, read leases, allocate interfaces, create keys, or modify state.

```rust
use std::fmt;

const MAX_INPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_TOKENS: usize = 65_536;
const MAX_DEPTH: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Position {
    pub line: usize,
    pub column: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntaxError {
    pub at: Position,
    pub message: String,
}

impl fmt::Display for SyntaxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.at.line, self.at.column, self.message)
    }
}

impl std::error::Error for SyntaxError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenKind {
    Word(String),
    Open,
    Close,
    End,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub kind: TokenKind,
    pub at: Position,
}

fn push_token(tokens: &mut Vec<Token>, token: Token) -> Result<(), SyntaxError> {
    if tokens.len() == MAX_TOKENS {
        return Err(SyntaxError {
            at: token.at,
            message: "too many configuration tokens".into(),
        });
    }
    tokens.push(token);
    Ok(())
}

pub fn lex(input: &str) -> Result<Vec<Token>, SyntaxError> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(SyntaxError {
            at: Position { line: 1, column: 1 },
            message: "configuration exceeds 4 MiB".into(),
        });
    }
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();
    let mut at = Position { line: 1, column: 1 };
    while let Some(ch) = chars.next() {
        let start = at;
        at.column += 1;
        match ch {
            '\n' => {
                push_token(&mut tokens, Token { kind: TokenKind::End, at: start })?;
                at.line += 1;
                at.column = 1;
            }
            ' ' | '\t' | '\r' => {}
            '#' => {
                while chars.peek().is_some_and(|c| *c != '\n') {
                    chars.next();
                    at.column += 1;
                }
            }
            '{' => push_token(&mut tokens, Token { kind: TokenKind::Open, at: start })?,
            '}' => push_token(&mut tokens, Token { kind: TokenKind::Close, at: start })?,
            ';' => push_token(&mut tokens, Token { kind: TokenKind::End, at: start })?,
            '"' => {
                let mut word = String::new();
                let mut closed = false;
                while let Some(c) = chars.next() {
                    at.column += 1;
                    match c {
                        '"' => {
                            closed = true;
                            break;
                        }
                        '\\' => {
                            let escaped = chars.next().ok_or_else(|| SyntaxError {
                                at,
                                message: "unfinished quoted escape".into(),
                            })?;
                            at.column += 1;
                            match escaped {
                                '"' => word.push('"'),
                                '\\' => word.push('\\'),
                                'n' => word.push('\n'),
                                'r' => word.push('\r'),
                                't' => word.push('\t'),
                                _ => {
                                    return Err(SyntaxError {
                                        at,
                                        message: "supported escapes are quote, backslash, n, r and t".into(),
                                    });
                                }
                            }
                        }
                        '\n' => {
                            return Err(SyntaxError {
                                at: start,
                                message: "quoted values cannot cross a physical line".into(),
                            });
                        }
                        c => word.push(c),
                    }
                }
                if !closed {
                    return Err(SyntaxError {
                        at: start,
                        message: "unterminated quoted value".into(),
                    });
                }
                if chars.peek().is_some_and(|c| {
                    !c.is_whitespace() && !matches!(*c, ';' | '{' | '}' | '#')
                }) {
                    return Err(SyntaxError {
                        at,
                        message: "expected a separator after quoted value".into(),
                    });
                }
                push_token(&mut tokens, Token { kind: TokenKind::Word(word), at: start })?;
            }
            first => {
                let mut word = String::from(first);
                while let Some(&next) = chars.peek() {
                    if next.is_whitespace() || matches!(next, ';' | '{' | '}' | '#') {
                        break;
                    }
                    if next == '"' {
                        return Err(SyntaxError {
                            at,
                            message: "quote must begin a separate value".into(),
                        });
                    }
                    word.push(next);
                    chars.next();
                    at.column += 1;
                }
                push_token(&mut tokens, Token { kind: TokenKind::Word(word), at: start })?;
            }
        }
    }
    Ok(tokens)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    pub at: Position,
    pub words: Vec<String>,
    pub children: Option<Vec<Statement>>,
}

struct Cursor {
    tokens: Vec<Token>,
    index: usize,
}

impl Cursor {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.index)
    }

    fn advance(&mut self) {
        self.index += 1;
    }

    fn statements(
        &mut self,
        opened_at: Option<Position>,
        depth: usize,
    ) -> Result<Vec<Statement>, SyntaxError> {
        let mut result = Vec::new();
        loop {
            while self.peek().is_some_and(|t| matches!(t.kind, TokenKind::End)) {
                self.advance();
            }
            let Some(first) = self.peek().cloned() else {
                return match opened_at {
                    Some(at) => Err(SyntaxError { at, message: "unclosed block".into() }),
                    None => Ok(result),
                };
            };
            if matches!(first.kind, TokenKind::Close) {
                if opened_at.is_none() {
                    return Err(SyntaxError {
                        at: first.at,
                        message: "unexpected closing brace".into(),
                    });
                }
                self.advance();
                return Ok(result);
            }
            let mut words = Vec::new();
            while let Some(Token { kind: TokenKind::Word(word), .. }) = self.peek() {
                words.push(word.clone());
                self.advance();
            }
            if words.is_empty() {
                return Err(SyntaxError {
                    at: first.at,
                    message: "expected a directive or block header".into(),
                });
            }
            let children = if self.peek().is_some_and(|t| matches!(t.kind, TokenKind::Open)) {
                if depth == MAX_DEPTH {
                    return Err(SyntaxError {
                        at: first.at,
                        message: "configuration nesting exceeds 32 blocks".into(),
                    });
                }
                self.advance();
                Some(self.statements(Some(first.at), depth + 1)?)
            } else {
                None
            };
            result.push(Statement { at: first.at, words, children });
        }
    }
}

pub fn parse_document(input: &str) -> Result<Vec<Statement>, SyntaxError> {
    Cursor { tokens: lex(input)?, index: 0 }.statements(None, 0)
}

pub fn quote_atom(value: &str) -> String {
    let safe = !value.is_empty()
        && value.chars().all(|c| !c.is_whitespace() && !matches!(c, '#' | ';' | '{' | '}' | '"' | '\\'));
    if safe {
        return value.to_owned();
    }
    let mut result = String::from("\"");
    for ch in value.chars() {
        match ch {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            ch => result.push(ch),
        }
    }
    result.push('"');
    result
}

pub fn write_document(statements: &[Statement]) -> String {
    fn emit(statements: &[Statement], depth: usize, out: &mut String) {
        for statement in statements {
            out.push_str(&"    ".repeat(depth));
            out.push_str(&statement.words.iter().map(|w| quote_atom(w)).collect::<Vec<_>>().join(" "));
            if let Some(children) = &statement.children {
                out.push_str(" {\n");
                emit(children, depth + 1, out);
                out.push_str(&"    ".repeat(depth));
                out.push_str("}\n");
            } else {
                out.push('\n');
            }
        }
    }
    let mut result = String::new();
    emit(statements, 0, &mut result);
    result
}
```

**Semantic lowering is a separate, mandatory migration, not a call back into the old side-effecting parser.** Use one lowering function per context: root accepts allow/VIP/service/gateway/DNS; VIP accepts binding changes and endpoint blocks; service accepts backend/admission/probe/origin directives; gateway accepts uplink/endpoints/forwards/admission; DNS accepts typed resolver/record/routing statements. Each receives token slices and a source span, requires exact argument count, rejects unexpected child blocks, and builds an entity before inserting it into the configuration. The `to`, `allow`, `tunnels`, and `services` wrapper blocks flatten into those typed collections rather than moving entire entities between parser-state variants. Reject duplicate IDs/listener ownership and unknown trailing tokens.

This tightens rejection of unclosed blocks while keeping brace-less single-line REPL commands, inline `{ ... }` forms, and natural `ip:port` / `vip` service and gateway keys first-class alongside block syntax. Existing quoted TXT values must be preserved directly without passing through `join(" ")` and a lossy whitespace splitter.

Two complete immediate replacement functions repair concrete serialization/deletion losses while the larger syntax extraction proceeds:

```rust
use crate::ast::{DnsRecord, RateLimit};
use std::fmt;
use std::net::Ipv4Addr;

impl fmt::Display for RateLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.rate, self.unit)?;
        if let Some(burst) = self.burst {
            write!(f, " burst {burst}")?;
        }
        f.write_str(if self.per_ip { " per-ip" } else { " global" })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordKey {
    A(String),
    Aaaa(String),
    Address(String),
    Cname(String),
    Txt(String),
    Srv(String),
    Mx(String),
    Ptr(Ipv4Addr),
}

fn record_matches(record: &DnsRecord, key: &RecordKey) -> bool {
    match (record, key) {
        (DnsRecord::A { name, .. }, RecordKey::A(key)) => name.eq_ignore_ascii_case(key),
        (DnsRecord::Aaaa { name, .. }, RecordKey::Aaaa(key)) => name.eq_ignore_ascii_case(key),
        (DnsRecord::Address { domain, .. }, RecordKey::Address(key)) => domain.eq_ignore_ascii_case(key),
        (DnsRecord::Cname { alias, .. }, RecordKey::Cname(key)) => alias.eq_ignore_ascii_case(key),
        (DnsRecord::Txt { name, .. }, RecordKey::Txt(key)) => name.eq_ignore_ascii_case(key),
        (DnsRecord::Srv { service, .. }, RecordKey::Srv(key)) => service.eq_ignore_ascii_case(key),
        (DnsRecord::Mx { domain, .. }, RecordKey::Mx(key)) => domain.eq_ignore_ascii_case(key),
        (DnsRecord::Ptr { ip, .. }, RecordKey::Ptr(key)) => ip == key,
        _ => false,
    }
}

pub fn delete_record(records: &mut Vec<DnsRecord>, key: &RecordKey) -> Result<usize, String> {
    let matches = records.iter().filter(|record| record_matches(record, key)).count();
    if matches == 0 {
        return Err(format!("DNS record not found: {key:?}"));
    }
    records.retain(|record| !record_matches(record, key));
    Ok(matches)
}
```

Other canonical-output requirements are non-negotiable: always emit static prefix/interface; serialize disabled checks and cleared DNS defaults; render local service blocks whenever they contain policy; never persist leases; preserve full inline/file tunnel alternatives; derive IDs independently of display spelling. Test `lower(parse(format(validated))) == validated`, excluding observations and source spans by construction.

### 3.4 Unit C - transactional editing and durable commit/recovery core

**Replaces:** in-place REPL/API mutation, `active_config` fallback, `handle_apply`, rollback, persistence-triggered application, and application ownership in status/probe paths.

The small edit primitive is complete and immediately usable for service/gateway/DNS reducers. Mutation closures operate only on a private clone; validation failure cannot leave half an edit in the candidate.

```rust
pub fn edit_validated<T, E>(
    current: &mut T,
    edit: impl FnOnce(&mut T) -> Result<(), E>,
    validate: impl FnOnce(&T) -> Result<(), E>,
) -> Result<(), E>
where
    T: Clone,
{
    let mut proposed = current.clone();
    edit(&mut proposed)?;
    validate(&proposed)?;
    *current = proposed;
    Ok(())
}
```

The following core provides serialized commit, durable pre-activation intent, trial confirmation, startup recovery, compensation, and monotonic rollback revisions. It does not claim a distributed transaction across Cloudflare and the kernel. `Platform::activate` must apply one already-prepared local plan with bounded steps and return failure rather than simulation; asynchronous provider reconciliation is separately observable. The store must implement Unit D and must never call the API.

```rust
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::error::Error;

pub type EffectError = Box<dyn Error + Send + Sync>;
pub type EffectResult<T> = Result<T, EffectError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Versioned<C> {
    pub revision: u64,
    pub config: C,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum PendingKind {
    Commit { confirm_by_ms: Option<u64> },
    Recovery,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pending<C> {
    pub target: Versioned<C>,
    pub kind: PendingKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Journal<C> {
    pub format_version: u32,
    pub high_watermark: u64,
    pub stable: Versioned<C>,
    pub pending: Option<Pending<C>>,
}

#[derive(Debug, thiserror::Error)]
pub enum CommitError {
    #[error("revision conflict: expected {expected}, current {actual}")]
    Conflict { expected: u64, actual: u64 },
    #[error("a commit or recovery is already pending")]
    Busy,
    #[error("no confirmable trial exists")]
    NoTrial,
    #[error("trial confirmation deadline expired")]
    Expired,
    #[error("revision space exhausted")]
    RevisionExhausted,
    #[error("unsupported journal format {0}")]
    JournalVersion(u32),
    #[error("invalid commit journal: {0}")]
    InvalidJournal(&'static str),
    #[error("{operation} failed: {source}")]
    Effect {
        operation: &'static str,
        #[source]
        source: EffectError,
    },
    #[error("activation failed: {activation}; recovery also failed: {recovery}")]
    Recovery {
        activation: EffectError,
        #[source]
        recovery: Box<CommitError>,
    },
}

#[async_trait]
pub trait Store<C>: Send
where
    C: Send + Sync,
{
    async fn load(&mut self) -> EffectResult<Journal<C>>;
    async fn save(&mut self, journal: &Journal<C>) -> EffectResult<()>;
}

#[async_trait]
pub trait Platform<C>: Send
where
    C: Send + Sync,
{
    type Plan: Send + Sync;
    async fn prepare(&mut self, target: &Versioned<C>) -> EffectResult<Self::Plan>;
    async fn activate(&mut self, plan: &Self::Plan) -> EffectResult<()>;
}

pub struct Coordinator<C, S, P>
where
    C: Clone + Send + Sync,
    S: Store<C>,
    P: Platform<C>,
{
    journal: Journal<C>,
    store: S,
    platform: P,
    active: Versioned<C>,
}

impl<C, S, P> Coordinator<C, S, P>
where
    C: Clone + Send + Sync,
    S: Store<C>,
    P: Platform<C>,
{
    pub async fn open(mut store: S, platform: P) -> Result<Self, CommitError> {
        let journal = store.load().await.map_err(|source| CommitError::Effect {
            operation: "load commit journal",
            source,
        })?;
        if journal.format_version != 1 {
            return Err(CommitError::JournalVersion(journal.format_version));
        }
        if journal.stable.revision > journal.high_watermark {
            return Err(CommitError::InvalidJournal("stable revision exceeds high watermark"));
        }
        match &journal.pending {
            Some(pending) if pending.target.revision != journal.high_watermark
                || pending.target.revision <= journal.stable.revision => {
                return Err(CommitError::InvalidJournal("pending revision is inconsistent"));
            }
            None if journal.stable.revision != journal.high_watermark => {
                return Err(CommitError::InvalidJournal("unexplained reserved revision"));
            }
            _ => {}
        }
        let mut this = Self {
            active: journal.stable.clone(),
            journal,
            store,
            platform,
        };
        if this.journal.pending.is_some() {
            this.restore().await?;
        } else {
            let plan = this.platform.prepare(&this.active).await.map_err(|source| {
                CommitError::Effect { operation: "prepare startup configuration", source }
            })?;
            this.platform.activate(&plan).await.map_err(|source| {
                CommitError::Effect { operation: "activate startup configuration", source }
            })?;
        }
        Ok(this)
    }

    pub fn active(&self) -> &Versioned<C> {
        &self.active
    }

    pub fn confirmation_deadline_ms(&self) -> Option<u64> {
        match self.journal.pending.as_ref().map(|pending| pending.kind) {
            Some(PendingKind::Commit { confirm_by_ms }) => confirm_by_ms,
            _ => None,
        }
    }

    fn next_target(&self, config: C) -> Result<Versioned<C>, CommitError> {
        let revision = self.journal.high_watermark.checked_add(1)
            .ok_or(CommitError::RevisionExhausted)?;
        Ok(Versioned { revision, config })
    }

    async fn persist_pending(
        &mut self,
        target: Versioned<C>,
        kind: PendingKind,
    ) -> Result<(), CommitError> {
        let mut next = self.journal.clone();
        next.high_watermark = target.revision;
        next.pending = Some(Pending { target, kind });
        self.store.save(&next).await.map_err(|source| CommitError::Effect {
            operation: "persist activation intent",
            source,
        })?;
        self.journal = next;
        Ok(())
    }

    async fn persist_stable(&mut self, target: Versioned<C>) -> Result<(), CommitError> {
        let mut next = self.journal.clone();
        next.stable = target.clone();
        next.pending = None;
        self.store.save(&next).await.map_err(|source| CommitError::Effect {
            operation: "persist committed configuration",
            source,
        })?;
        self.journal = next;
        self.active = target;
        Ok(())
    }

    async fn restore(&mut self) -> Result<(), CommitError> {
        let target = self.next_target(self.journal.stable.config.clone())?;
        let plan = self.platform.prepare(&target).await.map_err(|source| {
            CommitError::Effect { operation: "prepare baseline recovery", source }
        })?;
        self.persist_pending(target.clone(), PendingKind::Recovery).await?;
        self.platform.activate(&plan).await.map_err(|source| CommitError::Effect {
            operation: "restore baseline configuration",
            source,
        })?;
        self.active = target.clone();
        self.persist_stable(target).await
    }

    async fn compensate(&mut self, activation: EffectError) -> CommitError {
        match self.restore().await {
            Ok(()) => CommitError::Effect { operation: "activate configuration", source: activation },
            Err(recovery) => CommitError::Recovery { activation, recovery: Box::new(recovery) },
        }
    }

    pub async fn commit(
        &mut self,
        expected: u64,
        config: C,
        confirm_by_ms: Option<u64>,
        now_ms: u64,
    ) -> Result<Versioned<C>, CommitError> {
        if self.journal.pending.is_some() {
            return Err(CommitError::Busy);
        }
        if expected != self.active.revision {
            return Err(CommitError::Conflict { expected, actual: self.active.revision });
        }
        if confirm_by_ms.is_some_and(|deadline| deadline <= now_ms) {
            return Err(CommitError::Expired);
        }
        let target = self.next_target(config)?;
        let plan = self.platform.prepare(&target).await.map_err(|source| {
            CommitError::Effect { operation: "prepare configuration", source }
        })?;
        self.persist_pending(
            target.clone(),
            PendingKind::Commit { confirm_by_ms },
        ).await?;
        if let Err(error) = self.platform.activate(&plan).await {
            return Err(self.compensate(error).await);
        }
        self.active = target.clone();
        if confirm_by_ms.is_none() {
            if let Err(error) = self.persist_stable(target.clone()).await {
                return Err(self.compensate(Box::new(error)).await);
            }
        }
        Ok(target)
    }

    pub async fn confirm(&mut self, revision: u64, now_ms: u64) -> Result<(), CommitError> {
        let pending = self.journal.pending.as_ref().ok_or(CommitError::NoTrial)?;
        let Some(deadline) = self.confirmation_deadline_ms() else {
            return Err(CommitError::NoTrial);
        };
        if revision != pending.target.revision {
            return Err(CommitError::Conflict { expected: revision, actual: pending.target.revision });
        }
        if now_ms >= deadline {
            self.restore().await?;
            return Err(CommitError::Expired);
        }
        self.persist_stable(self.active.clone()).await
    }

    pub async fn expire(&mut self, now_ms: u64) -> Result<bool, CommitError> {
        let Some(deadline) = self.confirmation_deadline_ms() else {
            return Ok(false);
        };
        if now_ms < deadline {
            return Ok(false);
        }
        self.restore().await?;
        Ok(true)
    }

    pub async fn revert_trial(&mut self, revision: u64) -> Result<(), CommitError> {
        let pending = self.journal.pending.as_ref().ok_or(CommitError::NoTrial)?;
        if pending.target.revision != revision {
            return Err(CommitError::Conflict {
                expected: revision,
                actual: pending.target.revision,
            });
        }
        self.restore().await
    }
}
```

**Integration requirements, not optional refinements:** retain a single daemon lock; use a bounded command channel with priority expiry handling; publish a distinct recovering/degraded status after failed compensation; stop ordinary writes while recovery is pending; sample the clock again after activation before acknowledging a trial; use monotonic deadlines during one boot and always revert unconfirmed state on restart. A failed confirmation write leaves the trial pending, which is safer than falsely confirming it. The driver must continue deadline handling after that error.

Per-session candidates are `Candidate { base_revision, edit_revision, config }` outside the active snapshot. The edit revision prevents two requests within one session from overwriting each other; the base revision prevents committing over someone else's committed change. Both are checked on commit. A historical rollback is a new commit of historical config, not assignment to an old revision. Coalesce health-driven plan updates through the same local platform owner, but do not route provider downloads or ordinary status reads through the transaction critical path.

```rust
#[derive(Debug, Clone)]
pub struct Candidate<T> {
    pub base_revision: u64,
    pub edit_revision: u64,
    pub config: T,
}

#[derive(Debug)]
pub enum CandidateEditError<E> {
    Conflict { expected: u64, actual: u64 },
    RevisionExhausted,
    Rejected(E),
}

impl<T: Clone> Candidate<T> {
    pub fn edit<E>(
        &mut self,
        expected_edit_revision: u64,
        edit: impl FnOnce(&mut T) -> Result<(), E>,
        validate: impl FnOnce(&T) -> Result<(), E>,
    ) -> Result<u64, CandidateEditError<E>> {
        if expected_edit_revision != self.edit_revision {
            return Err(CandidateEditError::Conflict {
                expected: expected_edit_revision,
                actual: self.edit_revision,
            });
        }
        let next = self.edit_revision.checked_add(1)
            .ok_or(CandidateEditError::RevisionExhausted)?;
        edit_validated(&mut self.config, edit, validate).map_err(CandidateEditError::Rejected)?;
        self.edit_revision = next;
        Ok(next)
    }
}
```

### 3.5 Unit D - atomic persistence without hidden IPC

**Replaces:** configuration, credential, host-registration, WireGuard-import, and provider-ledger writes. This is a Linux file adapter; callers select secret/public permissions deliberately and create the configured parent directory during explicit initialization. It never invents `/data`, merges old data, suppresses empty content, or sends HTTP.

```rust
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("invalid destination path: {0}")]
    InvalidPath(PathBuf),
    #[error("{operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("published {path}, but directory durability could not be confirmed: {source}")]
    PublishedNotSynced {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> StoreError {
    StoreError::Io { operation, path: path.to_owned(), source }
}

struct TemporaryPath(Option<PathBuf>);

impl Drop for TemporaryPath {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            if let Err(error) = fs::remove_file(&path) {
                if error.kind() != io::ErrorKind::NotFound {
                    eprintln!("temporary-file cleanup failed for {}: {error}", path.display());
                }
            }
        }
    }
}

pub fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<(), StoreError> {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path.file_name().ok_or_else(|| StoreError::InvalidPath(path.to_owned()))?;
    let directory = File::open(parent).map_err(|e| io_error("open parent directory", parent, e))?;
    let mut opened = None;
    for _attempt in 0..32 {
        let mut temporary_name = OsString::from(".");
        temporary_name.push(name);
        temporary_name.push(format!(".{:032x}.tmp", rand::random::<u128>()));
        let temporary_path = parent.join(temporary_name);
        match OpenOptions::new().write(true).create_new(true).mode(mode).open(&temporary_path) {
            Ok(file) => {
                opened = Some((file, temporary_path));
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(io_error("create temporary file", &temporary_path, error)),
        }
    }
    let (mut file, temporary_path) = opened.ok_or_else(|| {
        io_error(
            "allocate unique temporary file",
            path,
            io::Error::new(io::ErrorKind::AlreadyExists, "temporary-name attempts exhausted"),
        )
    })?;
    let mut cleanup = TemporaryPath(Some(temporary_path.clone()));
    file.write_all(bytes).map_err(|e| io_error("write temporary file", &temporary_path, e))?;
    file.sync_all().map_err(|e| io_error("sync temporary file", &temporary_path, e))?;
    drop(file);
    fs::rename(&temporary_path, path).map_err(|e| io_error("publish temporary file", path, e))?;
    cleanup.0 = None;
    directory.sync_all().map_err(|source| StoreError::PublishedNotSynced {
        path: path.to_owned(),
        source,
    })?;
    Ok(())
}

pub fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, StoreError> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(io_error("read", path, error)),
    }
}
```

`PublishedNotSynced` is intentionally not equivalent to "nothing happened": the new file is visible, but durability is uncertain. The coordinator must retain/reload recovery intent rather than retry as though no write occurred. Secret files should be created with `0600`; directory ownership/mode and symlink policy belong to initialization. JSON parse/version errors after `read_optional` are propagated, not converted into `None`. Run blocking file/fsync work on a bounded blocking adapter, never under a global state guard.

### 3.6 Unit E - explicit, bounded platform execution

**Replaces:** `run_nft_command`, whitespace-split VIP commands, unchecked WG/ip calls, and success-shaped missing-tool handling. Commands are executable plus arguments, never shell source. Expected idempotent absence is handled by the resource planner, not by swallowing every process error.

```rust
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};

#[derive(Debug, Clone, Copy)]
pub enum OutputPrivacy {
    Public,
    Sensitive,
}

pub struct CommandSpec {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub input: Vec<u8>,
    pub deadline: Duration,
    pub output_privacy: OutputPrivacy,
}

pub struct CommandOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    #[error("cannot start {program}: {source}")]
    Spawn { program: PathBuf, #[source] source: io::Error },
    #[error("{program} exceeded its execution deadline")]
    Timeout { program: PathBuf },
    #[error("{program} I/O failed: {source}")]
    Io { program: PathBuf, #[source] source: io::Error },
    #[error("{program} exited with {status}: {diagnostic}")]
    Exit { program: PathBuf, status: ExitStatus, diagnostic: String },
    #[error("{program} failed and could not be reaped: {source}")]
    Reap { program: PathBuf, #[source] source: io::Error },
    #[error("{program} did not expose its configured {pipe} pipe")]
    MissingPipe { program: PathBuf, pipe: &'static str },
}

async fn read_output(reader: impl AsyncRead + Unpin, label: &'static str) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(65_537).read_to_end(&mut bytes).await?;
    if bytes.len() > 65_536 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{label} exceeds 64 KiB")));
    }
    Ok(bytes)
}

async fn stop_and_reap(child: &mut Child) -> io::Result<()> {
    if child.try_wait()?.is_none() {
        child.kill().await?;
    }
    Ok(())
}

pub async fn execute(spec: CommandSpec) -> Result<CommandOutput, CommandError> {
    let mut command = Command::new(&spec.program);
    command.args(&spec.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().map_err(|source| CommandError::Spawn {
        program: spec.program.clone(),
        source,
    })?;
    let Some(mut stdin) = child.stdin.take() else {
        stop_and_reap(&mut child).await.map_err(|source| CommandError::Reap {
            program: spec.program.clone(),
            source,
        })?;
        return Err(CommandError::MissingPipe { program: spec.program, pipe: "stdin" });
    };
    let Some(stdout) = child.stdout.take() else {
        stop_and_reap(&mut child).await.map_err(|source| CommandError::Reap {
            program: spec.program.clone(),
            source,
        })?;
        return Err(CommandError::MissingPipe { program: spec.program, pipe: "stdout" });
    };
    let Some(stderr) = child.stderr.take() else {
        stop_and_reap(&mut child).await.map_err(|source| CommandError::Reap {
            program: spec.program.clone(),
            source,
        })?;
        return Err(CommandError::MissingPipe { program: spec.program, pipe: "stderr" });
    };
    let result = tokio::time::timeout(spec.deadline, async {
        let write = async {
            stdin.write_all(&spec.input).await?;
            stdin.shutdown().await?;
            drop(stdin);
            Ok::<(), io::Error>(())
        };
        tokio::try_join!(write, read_output(stdout, "stdout"), read_output(stderr, "stderr"), child.wait())
    }).await;
    let (status, stdout, stderr) = match result {
        Ok(Ok(((), stdout, stderr, status))) => (status, stdout, stderr),
        failure => {
            stop_and_reap(&mut child).await.map_err(|source| CommandError::Reap {
                program: spec.program.clone(),
                source,
            })?;
            return match failure {
                Err(_) => Err(CommandError::Timeout { program: spec.program }),
                Ok(Err(source)) => Err(CommandError::Io { program: spec.program, source }),
                Ok(Ok(_)) => unreachable!("successful command result was handled above"),
            };
        }
    };
    if !status.success() {
        let diagnostic = match spec.output_privacy {
            OutputPrivacy::Public => String::from_utf8_lossy(&stderr).trim().to_owned(),
            OutputPrivacy::Sensitive => "command output redacted because it may contain credentials".into(),
        };
        return Err(CommandError::Exit { program: spec.program, status, diagnostic });
    }
    Ok(CommandOutput { stdout, stderr })
}

#[derive(Debug, Clone, Copy)]
pub enum NftAction {
    Verify,
    Apply,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NftOutcome {
    Verified,
    Applied,
}

pub async fn execute_nft(
    executable: PathBuf,
    ruleset: String,
    action: NftAction,
    deadline: Duration,
) -> Result<NftOutcome, CommandError> {
    let mut args = Vec::new();
    if matches!(action, NftAction::Verify) {
        args.push(OsString::from("--check"));
    }
    args.extend([OsString::from("-f"), OsString::from("-")]);
    execute(CommandSpec {
        program: executable,
        args,
        input: ruleset.into_bytes(),
        deadline,
        output_privacy: OutputPrivacy::Public,
    }).await?;
    Ok(match action {
        NftAction::Verify => NftOutcome::Verified,
        NftAction::Apply => NftOutcome::Applied,
    })
}
```

The one `unreachable!` is a local exhaustive-match invariant, not an unchecked runtime input. It can also be eliminated by splitting the timeout and I/O matches if that reads better to the team. More importantly, command arguments/stdin are never dumped into diagnostics; WG/credential-related tool output must use `Sensitive`. A command killed by timeout is not an applied operation. Retain operation IDs and step results in the coordinator so compensation knows which resources may have changed.

### 3.7 Unit F - owned-resource deltas, stable nft state, and listener lifetime

**Replaces:** duplicated DHCP/VIP/gateway loops, prefix-based interface deletion, order-derived tunnel resource allocation, and table-wide policy replacement. Build one resolved binding set from static bindings plus lease observations; no platform controller reads `Config` directly.

The complete generic delta below refuses implicit adoption and never removes a foreign resource:

```rust
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owned<V> {
    pub owner: String,
    pub value: V,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change<K, V> {
    Create { key: K, value: V },
    Update { key: K, before: V, after: V },
    Delete { key: K, before: V },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError<K> {
    ForeignOwner(K),
    MissingDependency(K),
    DependencyCycle(Vec<K>),
}

pub fn owned_delta<K, V>(
    owner: &str,
    desired: &BTreeMap<K, V>,
    observed: &BTreeMap<K, Owned<V>>,
) -> Result<Vec<Change<K, V>>, PlanError<K>>
where
    K: Clone + Ord,
    V: Clone + Eq,
{
    let mut result = Vec::new();
    for (key, value) in desired {
        match observed.get(key) {
            None => result.push(Change::Create { key: key.clone(), value: value.clone() }),
            Some(existing) if existing.owner != owner => {
                return Err(PlanError::ForeignOwner(key.clone()));
            }
            Some(existing) if existing.value != *value => result.push(Change::Update {
                key: key.clone(),
                before: existing.value.clone(),
                after: value.clone(),
            }),
            Some(_) => {}
        }
    }
    for (key, existing) in observed {
        if existing.owner == owner && !desired.contains_key(key) {
            result.push(Change::Delete { key: key.clone(), before: existing.value.clone() });
        }
    }
    Ok(result)
}

pub fn dependency_order<K>(
    keys: &BTreeSet<K>,
    dependencies: &BTreeMap<K, BTreeSet<K>>,
) -> Result<Vec<K>, PlanError<K>>
where
    K: Clone + Ord,
{
    for required in dependencies.values().flatten() {
        if !keys.contains(required) {
            return Err(PlanError::MissingDependency(required.clone()));
        }
    }
    let mut pending = keys.clone();
    let mut complete = BTreeSet::new();
    let mut order = Vec::with_capacity(keys.len());
    while !pending.is_empty() {
        let ready: Vec<K> = pending.iter().filter(|key| {
            dependencies.get(*key).is_none_or(|required| required.is_subset(&complete))
        }).cloned().collect();
        if ready.is_empty() {
            return Err(PlanError::DependencyCycle(pending.into_iter().collect()));
        }
        for key in ready {
            pending.remove(&key);
            complete.insert(key.clone());
            order.push(key);
        }
    }
    Ok(order)
}
```

Execute creates/updates in dependency order and deletions in reverse dependency order. The graph includes explicitly observed external prerequisites, but those nodes have no mutation operation. Persist ownership only after acknowledgement; retain pending-deletion state on failure. For WireGuard, stable allocated interface/mark/table/priority IDs are part of the desired resource value, not recomputed from gateway iteration order. Do not flush/recreate unchanged interfaces, addresses, or rules on a backend health change.

For nft, **sets cannot be referenced across arbitrary nft tables**. Keep the stable DNS sets and the chains that reference them in `table ip nfty`; split their lifecycle, not their table namespace. The replacement compiler should consume a validated typed delta rather than emit `delete table` every time:

```rust
use std::fmt::Write;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NftName(String);

impl NftName {
    pub fn parse(value: &str) -> Result<Self, String> {
        if value.is_empty() || value.len() > 63
            || !value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || value.as_bytes()[0].is_ascii_digit()
        {
            return Err("invalid allocated nft object name".into());
        }
        Ok(Self(value.into()))
    }
}

#[derive(Debug, Clone, Copy)]
pub enum IpProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone)]
pub enum MatchExpr {
    Destination(Ipv4Addr),
    SourceSet(NftName),
    DestinationSet(NftName),
    Port(IpProtocol, std::num::NonZeroU16),
    Mark(u32),
    EstablishedRelated,
}

#[derive(Debug, Clone)]
pub enum ActionExpr {
    Counter(NftName),
    Jump(NftName),
    SetMark(u32),
    SaveConnectionMark,
    RestoreConnectionMark,
    Dnat(Ipv4Addr, std::num::NonZeroU16),
    Masquerade,
    Accept,
    Drop,
    Return,
}

#[derive(Debug, Clone)]
pub struct NftRule {
    pub matches: Vec<MatchExpr>,
    pub actions: Vec<ActionExpr>,
}

#[derive(Debug, Clone)]
pub struct ChainReplacement {
    pub name: NftName,
    pub rules: Vec<NftRule>,
}

#[derive(Debug, Clone)]
pub struct NftPolicyDelta {
    pub replace: Vec<ChainReplacement>,
}

fn render_match(value: &MatchExpr, out: &mut String) -> std::fmt::Result {
    match value {
        MatchExpr::Destination(ip) => write!(out, "ip daddr {ip} "),
        MatchExpr::SourceSet(name) => write!(out, "ip saddr @{} ", name.0),
        MatchExpr::DestinationSet(name) => write!(out, "ip daddr @{} ", name.0),
        MatchExpr::Port(proto, port) => {
            let proto = match proto { IpProtocol::Tcp => "tcp", IpProtocol::Udp => "udp" };
            write!(out, "{proto} dport {port} ")
        }
        MatchExpr::Mark(mark) => write!(out, "meta mark {mark:#x} "),
        MatchExpr::EstablishedRelated => out.write_str("ct state established,related "),
    }
}

fn render_action(value: &ActionExpr, out: &mut String) -> std::fmt::Result {
    match value {
        ActionExpr::Counter(name) => write!(out, "counter name {} ", name.0),
        ActionExpr::Jump(name) => write!(out, "jump {} ", name.0),
        ActionExpr::SetMark(mark) => write!(out, "meta mark set {mark:#x} "),
        ActionExpr::SaveConnectionMark => out.write_str("ct mark set meta mark "),
        ActionExpr::RestoreConnectionMark => out.write_str("meta mark set ct mark "),
        ActionExpr::Dnat(ip, port) => write!(out, "dnat to {ip}:{port} "),
        ActionExpr::Masquerade => out.write_str("masquerade "),
        ActionExpr::Accept => out.write_str("accept "),
        ActionExpr::Drop => out.write_str("drop "),
        ActionExpr::Return => out.write_str("return "),
    }
}

pub fn compile_policy_delta(plan: &NftPolicyDelta) -> Result<String, std::fmt::Error> {
    let mut out = String::from("table ip nfty\n");
    for chain in &plan.replace {
        writeln!(out, "add chain ip nfty {}", chain.name.0)?;
        writeln!(out, "flush chain ip nfty {}", chain.name.0)?;
        for rule in &chain.rules {
            write!(out, "add rule ip nfty {} ", chain.name.0)?;
            for expression in &rule.matches {
                render_match(expression, &mut out)?;
            }
            for action in &rule.actions {
                render_action(action, &mut out)?;
            }
            out.push('\n');
        }
    }
    Ok(out)
}
```

This unit replaces the **policy-chain update renderer**, not the entire schema/bootstrap compiler. Its precondition is that the owned base chains, stable sets/maps/counters, and hook priorities have already been prepared and verified. Extend the IR with weighted maps, rate meters, interface selectors, and interval ACL elements as those existing compiler sections are extracted; do not pass raw config strings around the IR. The extraction is complete only when every row in section 1.4 lowers to a tested plan or an explicit capability error. Validate chain type/action compatibility and terminal-verdict order before rendering.

The stable schema requires explicit lifecycle operations: create missing owned objects on first activation; preserve DNS timeout-set contents and counters on policy refresh; update maps atomically; remove an object only after references and retained connection-mark ownership are gone. An nft check is mandatory before activation, and its failure aborts the commit.

Listener reconciliation must use the same owned-delta idea. A listener key contains address, port, transport, and listener role; one listener can route several virtual services. Retain an accept-loop handle and a connection task set, expose bind failure, remove finished handles, and stop admission before deciding whether to drain or cancel accepted connections. Unit H supplies the connection relay; Unit J supplies cancellation-aware ownership.

### 3.8 Unit G - bounded async work, exact scan scope, and typed probes

**Replaces:** `run_probes_internal`, synchronous scanner orchestration, and their unbounded spawn loops. The worker primitive does not create all tasks and merely limit them with a semaphore afterward; it maintains at most the requested number of tasks.

```rust
use std::collections::VecDeque;
use std::future::Future;
use std::net::Ipv4Addr;
use std::num::NonZeroUsize;
use tokio::task::{JoinError, JoinSet};

pub async fn bounded_map<I, O, F, Fut>(
    inputs: impl IntoIterator<Item = I>,
    concurrency: NonZeroUsize,
    work: F,
) -> Result<Vec<O>, JoinError>
where
    I: Send + 'static,
    O: Send + 'static,
    F: Fn(I) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = O> + Send + 'static,
{
    let mut queue: VecDeque<I> = inputs.into_iter().collect();
    let mut tasks = JoinSet::new();
    let mut completed = Vec::new();
    loop {
        while tasks.len() < concurrency.get() {
            let Some(input) = queue.pop_front() else { break };
            let work = work.clone();
            tasks.spawn(async move { work(input).await });
        }
        let Some(result) = tasks.join_next().await else {
            return Ok(completed);
        };
        completed.push(result?);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScanScopeError {
    #[error("IPv4 prefix must be in 0..=32")]
    Prefix,
    #[error("scope contains {requested} addresses; configured maximum is {maximum}")]
    Budget { requested: u64, maximum: usize },
}

pub fn scan_addresses(
    address: Ipv4Addr,
    prefix: u8,
    maximum: NonZeroUsize,
) -> Result<Vec<Ipv4Addr>, ScanScopeError> {
    if prefix > 32 {
        return Err(ScanScopeError::Prefix);
    }
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    let network = u32::from(address) & mask;
    let broadcast = network | !mask;
    let (first, last) = if prefix < 31 {
        (network + 1, broadcast - 1)
    } else {
        (network, broadcast)
    };
    let requested = u64::from(last) - u64::from(first) + 1;
    if requested > maximum.get() as u64 {
        return Err(ScanScopeError::Budget { requested, maximum: maximum.get() });
    }
    Ok((first..=last).map(Ipv4Addr::from).collect())
}
```

Validate the product of address count and port count before allocating probe jobs. `/31` contains both addresses and `/32` contains exactly the requested address. Never clamp a user's scope silently. Default discovery from known hosts is a separate mode from explicit CIDR scanning and must not claim an LXD API integration or subnet sweep.

A complete network-probe worker can remain small when protocol execution and orchestration are separated:

```rust
use std::net::SocketAddr;
use std::ops::RangeInclusive;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

#[derive(Debug, Clone)]
pub enum ProbeSpec {
    Tcp { target: SocketAddr },
    Http {
        target: SocketAddr,
        host: String,
        path: String,
        accepted: RangeInclusive<u16>,
    },
}

#[derive(Debug, Clone)]
pub struct ProbeJob {
    pub backend_id: String,
    pub revision: u64,
    pub sequence: u64,
    pub timeout: Duration,
    pub spec: ProbeSpec,
}

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("probe deadline expired")]
    Timeout,
    #[error("TCP connect failed: {0}")]
    Connect(#[source] std::io::Error),
    #[error("HTTP probe failed: {0}")]
    Http(#[source] reqwest::Error),
    #[error("HTTP status {0} is outside the configured accepted range")]
    Status(u16),
    #[error("HTTP probe path must start with '/'")]
    InvalidPath,
}

#[derive(Debug)]
pub struct ProbeResult {
    pub backend_id: String,
    pub revision: u64,
    pub sequence: u64,
    pub elapsed: Duration,
    pub result: Result<(), ProbeError>,
}

pub fn probe_http_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .pool_max_idle_per_host(0)
        .build()
}

async fn execute_probe(client: &reqwest::Client, job: &ProbeJob) -> Result<(), ProbeError> {
    match &job.spec {
        ProbeSpec::Tcp { target } => {
            TcpStream::connect(target).await.map_err(ProbeError::Connect)?;
            Ok(())
        }
        ProbeSpec::Http { target, host, path, accepted } => {
            if !path.starts_with('/') {
                return Err(ProbeError::InvalidPath);
            }
            let response = client.get(format!("http://{target}{path}"))
                .header(reqwest::header::HOST, host)
                .timeout(job.timeout)
                .send().await.map_err(ProbeError::Http)?;
            let status = response.status().as_u16();
            if accepted.contains(&status) {
                Ok(())
            } else {
                Err(ProbeError::Status(status))
            }
        }
    }
}

pub async fn run_probe(client: &reqwest::Client, job: ProbeJob) -> ProbeResult {
    let started = Instant::now();
    let result = match tokio::time::timeout(job.timeout, execute_probe(client, &job)).await {
        Ok(result) => result,
        Err(_) => Err(ProbeError::Timeout),
    };
    ProbeResult {
        backend_id: job.backend_id,
        revision: job.revision,
        sequence: job.sequence,
        elapsed: started.elapsed(),
        result,
    }
}
```

This worker covers the existing TCP/plain-HTTP probe behavior without the single-read status parser. Add Ping as a separate adapter around Unit E with a typed target/interface and deadline; it must not silently replace other gateway check kinds. `Disabled` creates no job. HTTPS, UDP-specific health, expected response-body predicates, and tunnel-bound HTTP require explicit probe variants and capability validation rather than guessing from the service port.

Scheduling is one owner per probe ID: compute due jobs from configured interval and monotonic last-start time; deduplicate shared probes only when target **and complete probe policy** are identical; run a bounded batch; reduce only current-generation results through Unit A. TUI/API request a probe job from that owner instead of starting a second scheduler. Resolution work uses its own bounded queue and expiring/provenance-aware cache, not the configuration store.

### 3.9 Unit H - stream-correct protocol boundaries and checked relay

**Replaces:** one-read parsing in `handle_privoxy_client`, `handle_socks5_client`, L7 sniffing, and Cloudflare's auth gate. HTTP proxying/authentication should use maintained HTTP message handling (Hyper/Axum), not a raw relay after checking the first header.

#### H1. Header collection that preserves prefetched bytes

This is suitable for **unauthenticated HTTP routing preface inspection**, not a replacement HTTP server. It uses httparse for syntax and retains every byte already read, including body bytes. Header/body framing for the API or authenticated proxy belongs to the HTTP framework.

```rust
use std::io;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug)]
pub struct HttpPreface {
    pub method: String,
    pub target: String,
    pub host: Option<String>,
    pub header_len: usize,
    pub wire: Vec<u8>,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub async fn read_http_preface<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_header_bytes: usize,
    deadline: Duration,
) -> io::Result<HttpPreface> {
    tokio::time::timeout(deadline, async {
        let mut wire = Vec::new();
        loop {
            let mut headers = [httparse::EMPTY_HEADER; 64];
            let mut request = httparse::Request::new(&mut headers);
            let parsed = request.parse(&wire).map_err(|e| invalid(&e.to_string()))?;
            if let httparse::Status::Complete(header_len) = parsed {
                let method = request.method.ok_or_else(|| invalid("missing HTTP method"))?.to_owned();
                let target = request.path.ok_or_else(|| invalid("missing HTTP request target"))?.to_owned();
                let hosts: Vec<_> = request.headers.iter()
                    .filter(|h| h.name.eq_ignore_ascii_case("host"))
                    .collect();
                if hosts.len() > 1 {
                    return Err(invalid("duplicate Host header"));
                }
                let host = hosts.first().map(|header| {
                    std::str::from_utf8(header.value)
                        .map(str::trim)
                        .map(str::to_owned)
                        .map_err(|_| invalid("Host header is not valid ASCII/UTF-8"))
                }).transpose()?;
                return Ok(HttpPreface { method, target, host, header_len, wire });
            }
            if wire.len() >= max_header_bytes {
                return Err(invalid("HTTP header limit exceeded"));
            }
            let capacity = (max_header_bytes - wire.len()).min(4096);
            let mut chunk = [0_u8; 4096];
            let count = reader.read(&mut chunk[..capacity]).await?;
            if count == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete HTTP header"));
            }
            wire.extend_from_slice(&chunk[..count]);
        }
    }).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP header deadline expired"))?
}
```

Normalize/validate Host with an authority/domain parser after collection. Fix listener/VIP scope before hostname lookup; never search other VIPs on a miss. An unknown virtual host returns a declared HTTP error or closes a TLS passthrough connection with a diagnostic, rather than silently selecting an unrelated service.

#### H2. Complete SOCKS5 CONNECT negotiation

The typed dialer is the shared route/admission boundary. A tunnel dialer must apply required socket mark/device/source binding and fail on any error **before connect**; a direct dialer is selected only by explicit policy. DNS resolution for `Name` is performed by that dialer using the same egress policy.

```rust
use async_trait::async_trait;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone)]
pub enum ConnectTarget {
    Address(SocketAddr),
    Name { host: String, port: std::num::NonZeroU16 },
}

#[async_trait]
pub trait Dialer: Send + Sync {
    async fn connect(&self, target: ConnectTarget) -> io::Result<TcpStream>;
}

fn protocol_error(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

async fn socks_reply(stream: &mut TcpStream, code: u8, bound: SocketAddr) -> io::Result<()> {
    let mut reply = vec![5, code, 0];
    match bound.ip() {
        IpAddr::V4(ip) => {
            reply.push(1);
            reply.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            reply.push(4);
            reply.extend_from_slice(&ip.octets());
        }
    }
    reply.extend_from_slice(&bound.port().to_be_bytes());
    stream.write_all(&reply).await
}

async fn socks_target(stream: &mut TcpStream) -> io::Result<ConnectTarget> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).await?;
    let zero = SocketAddr::from(([0, 0, 0, 0], 0));
    if header[0] != 5 || header[2] != 0 {
        socks_reply(stream, 1, zero).await?;
        return Err(protocol_error("invalid SOCKS version/reserved field"));
    }
    if header[1] != 1 {
        socks_reply(stream, 7, zero).await?;
        return Err(protocol_error("only SOCKS CONNECT is supported"));
    }
    let address = match header[3] {
        1 => {
            let mut bytes = [0_u8; 4];
            stream.read_exact(&mut bytes).await?;
            Some(IpAddr::V4(Ipv4Addr::from(bytes)))
        }
        4 => {
            let mut bytes = [0_u8; 16];
            stream.read_exact(&mut bytes).await?;
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        3 => None,
        _ => {
            socks_reply(stream, 8, zero).await?;
            return Err(protocol_error("unsupported SOCKS address type"));
        }
    };
    let host = if address.is_none() {
        let length = stream.read_u8().await?;
        if length == 0 {
            socks_reply(stream, 8, zero).await?;
            return Err(protocol_error("empty SOCKS hostname"));
        }
        let mut bytes = vec![0_u8; usize::from(length)];
        stream.read_exact(&mut bytes).await?;
        let valid = bytes.is_ascii() && bytes.iter().all(|b| {
            b.is_ascii_alphanumeric() || matches!(*b, b'-' | b'.' | b'_')
        });
        if !valid {
            socks_reply(stream, 8, zero).await?;
            return Err(protocol_error("invalid SOCKS hostname"));
        }
        Some(String::from_utf8(bytes).map_err(|_| protocol_error("invalid hostname encoding"))?)
    } else {
        None
    };
    let port = stream.read_u16().await?;
    let Some(port) = std::num::NonZeroU16::new(port) else {
        socks_reply(stream, 1, zero).await?;
        return Err(protocol_error("SOCKS destination port must not be zero"));
    };
    match (address, host) {
        (Some(ip), None) => Ok(ConnectTarget::Address(SocketAddr::new(ip, port.get()))),
        (None, Some(host)) => Ok(ConnectTarget::Name { host, port }),
        _ => Err(protocol_error("invalid SOCKS target state")),
    }
}

async fn socks_handshake(
    client: &mut TcpStream,
    dialer: &dyn Dialer,
) -> io::Result<TcpStream> {
    let mut greeting = [0_u8; 2];
    client.read_exact(&mut greeting).await?;
    if greeting[0] != 5 || greeting[1] == 0 {
        return Err(protocol_error("invalid SOCKS greeting"));
    }
    let mut methods = vec![0_u8; usize::from(greeting[1])];
    client.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        client.write_all(&[5, 0xff]).await?;
        return Err(protocol_error("client did not offer supported authentication method"));
    }
    client.write_all(&[5, 0]).await?;
    let target = socks_target(client).await?;
    match dialer.connect(target).await {
        Ok(upstream) => {
            socks_reply(client, 0, upstream.local_addr()?).await?;
            Ok(upstream)
        }
        Err(error) => {
            let code = match error.kind() {
                io::ErrorKind::PermissionDenied => 2,
                io::ErrorKind::ConnectionRefused => 5,
                io::ErrorKind::TimedOut => 6,
                _ => 1,
            };
            socks_reply(client, code, SocketAddr::from(([0, 0, 0, 0], 0))).await?;
            Err(error)
        }
    }
}

pub async fn handle_socks_connect(
    mut client: TcpStream,
    dialer: &dyn Dialer,
    handshake_deadline: Duration,
    connection_lifetime: Duration,
) -> io::Result<(u64, u64)> {
    let mut upstream = tokio::time::timeout(
        handshake_deadline,
        socks_handshake(&mut client, dialer),
    ).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS handshake deadline expired"))??;
    tokio::time::timeout(
        connection_lifetime,
        tokio::io::copy_bidirectional(&mut client, &mut upstream),
    ).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connection lifetime expired"))?
}
```

Perform source-ACL admission before this handler. No-auth SOCKS is an explicit listener capability, not an implicit negotiation fallback; a listener requiring credentials needs a distinct authentication implementation and validation. `connection_lifetime` is a total lifetime, not an idle timeout; name it honestly and configure it. For idle-timeout semantics, use relay progress events and a resettable idle deadline. Cancellation/drain is supplied by the owning task set, and returned byte counts are not packet counts.

#### H3. Bounded, fragmentation-safe TLS ClientHello SNI extraction

This is a passthrough preface parser, not TLS termination or authentication. It reassembles handshake records, bounds lengths, and returns the exact wire bytes to forward.

```rust
use std::io;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};

pub struct TlsPreface {
    pub server_name: Option<String>,
    pub wire: Vec<u8>,
}

struct Bytes<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Bytes<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, count: usize) -> io::Result<&'a [u8]> {
        let end = self.offset.checked_add(count)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "TLS length overflow"))?;
        let value = self.bytes.get(self.offset..end)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated TLS structure"))?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> io::Result<usize> {
        let value = self.take(2)?;
        Ok(usize::from(u16::from_be_bytes([value[0], value[1]])))
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }
}

fn tls_invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn parse_server_names(bytes: &[u8]) -> io::Result<Option<String>> {
    let mut outer = Bytes::new(bytes);
    let length = outer.u16()?;
    let mut names = Bytes::new(outer.take(length)?);
    if outer.remaining() != 0 {
        return Err(tls_invalid("trailing SNI extension bytes"));
    }
    let mut host = None;
    while names.remaining() != 0 {
        let kind = names.u8()?;
        let length = names.u16()?;
        let value = names.take(length)?;
        if kind != 0 {
            continue;
        }
        if host.is_some() || value.is_empty() || value.len() > 253 {
            return Err(tls_invalid("duplicate or invalid SNI hostname"));
        }
        if !value.is_ascii() || value.iter().any(|b| {
            !b.is_ascii_alphanumeric() && !matches!(*b, b'-' | b'.')
        }) {
            return Err(tls_invalid("invalid SNI hostname characters"));
        }
        let name = std::str::from_utf8(value).map_err(|_| tls_invalid("invalid SNI encoding"))?;
        if name.split('.').any(|label| {
            label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-')
        }) {
            return Err(tls_invalid("invalid SNI hostname labels"));
        }
        host = Some(name.to_ascii_lowercase());
    }
    Ok(host)
}

fn client_hello_sni(body: &[u8]) -> io::Result<Option<String>> {
    let mut hello = Bytes::new(body);
    hello.take(2 + 32)?;
    let session_len = usize::from(hello.u8()?);
    if session_len > 32 {
        return Err(tls_invalid("invalid TLS session ID length"));
    }
    hello.take(session_len)?;
    let cipher_len = hello.u16()?;
    if cipher_len == 0 || cipher_len % 2 != 0 {
        return Err(tls_invalid("invalid TLS cipher-suite vector"));
    }
    hello.take(cipher_len)?;
    let compression_len = usize::from(hello.u8()?);
    if compression_len == 0 {
        return Err(tls_invalid("empty TLS compression-method vector"));
    }
    hello.take(compression_len)?;
    if hello.remaining() == 0 {
        return Ok(None);
    }
    let extension_len = hello.u16()?;
    let mut extensions = Bytes::new(hello.take(extension_len)?);
    if hello.remaining() != 0 {
        return Err(tls_invalid("trailing ClientHello bytes"));
    }
    let mut sni = None;
    let mut seen = std::collections::BTreeSet::new();
    while extensions.remaining() != 0 {
        let kind = extensions.u16()?;
        let length = extensions.u16()?;
        let value = extensions.take(length)?;
        if !seen.insert(kind) {
            return Err(tls_invalid("duplicate ClientHello extension"));
        }
        if kind == 0 {
            sni = parse_server_names(value)?;
        }
    }
    Ok(sni)
}

pub async fn read_tls_preface<R: AsyncRead + Unpin>(
    reader: &mut R,
    deadline: Duration,
) -> io::Result<TlsPreface> {
    tokio::time::timeout(deadline, async {
        let mut wire = Vec::new();
        let mut handshake = Vec::new();
        loop {
            let mut header = [0_u8; 5];
            reader.read_exact(&mut header).await?;
            if header[0] != 22 || header[1] != 3 {
                return Err(tls_invalid("expected a TLS handshake record"));
            }
            let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
            if length == 0 || length > 16_384 || wire.len() + 5 + length > 131_072 {
                return Err(tls_invalid("TLS preface size limit exceeded"));
            }
            let mut record = vec![0_u8; length];
            reader.read_exact(&mut record).await?;
            wire.extend_from_slice(&header);
            wire.extend_from_slice(&record);
            handshake.extend_from_slice(&record);
            if handshake.len() < 4 {
                continue;
            }
            if handshake[0] != 1 {
                return Err(tls_invalid("first handshake message must be ClientHello"));
            }
            let body_len = (usize::from(handshake[1]) << 16)
                | (usize::from(handshake[2]) << 8)
                | usize::from(handshake[3]);
            if body_len > 65_536 {
                return Err(tls_invalid("ClientHello exceeds 64 KiB"));
            }
            if handshake.len() >= body_len + 4 {
                let server_name = client_hello_sni(&handshake[4..body_len + 4])?;
                return Ok(TlsPreface { server_name, wire });
            }
        }
    }).await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS preface deadline expired"))?
}
```

A missing SNI is a routing outcome, not a guessed hostname. Encrypted ClientHello cannot be inspected by this parser; document that limitation and require an explicit default route if desired. Prefer a maintained TLS parser if adopting equivalent strict parsing support; fuzz whichever implementation is used. Do not forward the reassembled handshake buffer instead of `wire`, because that would destroy record framing.

#### H4. Message-aware HTTP forwarding, CONNECT, and Upgrade

This unit replaces the existing HTTP proxy's manual header reconstruction and first-request-only authentication. Every ordinary request passes through the admission port. The admission implementation chooses whether it consumes `Authorization` or `Proxy-Authorization`; the transport must not indiscriminately strip end-to-end origin credentials. `Dialer` is H2's policy-bound dialer.

```rust
use async_trait::async_trait;
use bytes::Bytes;
use http::header::{CONNECTION, HOST, UPGRADE};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use std::error::Error;
use std::net::SocketAddr;
use std::num::NonZeroU16;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use crate::transport::socks::{ConnectTarget, Dialer};

type BoxError = Box<dyn Error + Send + Sync>;
type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("{0}")]
    BadRequest(&'static str),
    #[error("request authentication is required")]
    Authentication(AuthenticationTarget),
    #[error("request is forbidden")]
    Forbidden,
    #[error("tunnel admission budget is exhausted")]
    Busy,
    #[error("upstream deadline expired")]
    Timeout,
    #[error("upstream failed: {0}")]
    Upstream(#[source] BoxError),
    #[error("invalid upstream protocol response: {0}")]
    UpstreamProtocol(&'static str),
}

#[derive(Debug, Clone, Copy)]
pub enum AuthenticationTarget {
    OriginBasic,
    ProxyBasic,
}

#[async_trait]
pub trait RequestAdmission: Send + Sync {
    async fn authorize(&self, headers: &mut HeaderMap) -> Result<(), ProxyError>;
}

pub struct ProxyContext {
    pub dialer: Arc<dyn Dialer>,
    pub admission: Arc<dyn RequestAdmission>,
    pub tasks: TaskTracker,
    pub tunnel_slots: Arc<tokio::sync::Semaphore>,
    pub cancellation: CancellationToken,
    pub connect_timeout: Duration,
    pub header_timeout: Duration,
    pub tunnel_lifetime: Duration,
}

fn empty_body() -> ProxyBody {
    Full::new(Bytes::new()).map_err(|never| match never {}).boxed_unsync()
}

fn failure_response(error: &ProxyError) -> Response<ProxyBody> {
    let status = match error {
        ProxyError::BadRequest(_) => StatusCode::BAD_REQUEST,
        ProxyError::Authentication(AuthenticationTarget::OriginBasic) => StatusCode::UNAUTHORIZED,
        ProxyError::Authentication(AuthenticationTarget::ProxyBasic) => StatusCode::PROXY_AUTHENTICATION_REQUIRED,
        ProxyError::Forbidden => StatusCode::FORBIDDEN,
        ProxyError::Busy => StatusCode::SERVICE_UNAVAILABLE,
        ProxyError::Timeout => StatusCode::GATEWAY_TIMEOUT,
        ProxyError::Upstream(_) | ProxyError::UpstreamProtocol(_) => StatusCode::BAD_GATEWAY,
    };
    let mut response = Response::new(
        Full::new(Bytes::from(status.canonical_reason().unwrap_or("Proxy error")))
            .map_err(|never| match never {})
            .boxed_unsync(),
    );
    *response.status_mut() = status;
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    match error {
        ProxyError::Authentication(AuthenticationTarget::OriginBasic) => {
            response.headers_mut().insert(
                http::header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"nfty\""),
            );
        }
        ProxyError::Authentication(AuthenticationTarget::ProxyBasic) => {
            response.headers_mut().insert(
                http::header::PROXY_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"nfty-proxy\""),
            );
        }
        _ => {}
    }
    response
}

fn authority_target(
    authority: &http::uri::Authority,
    default_port: Option<NonZeroU16>,
) -> Result<ConnectTarget, ProxyError> {
    if authority.as_str().contains('@') {
        return Err(ProxyError::BadRequest("userinfo is not allowed in an authority"));
    }
    let port = match (authority.port(), authority.port_u16()) {
        (Some(_), Some(value)) => NonZeroU16::new(value),
        (Some(_), None) => None,
        (None, _) => default_port,
    }.ok_or(ProxyError::BadRequest("missing or invalid destination port"))?;
    let host = authority.host();
    let host = host.strip_prefix('[').and_then(|v| v.strip_suffix(']')).unwrap_or(host);
    if host.is_empty() {
        return Err(ProxyError::BadRequest("missing destination host"));
    }
    if let Ok(ip) = host.parse() {
        return Ok(ConnectTarget::Address(SocketAddr::new(ip, port.get())));
    }
    Ok(ConnectTarget::Name { host: host.to_owned(), port })
}

fn request_authority(request: &Request<Incoming>) -> Result<http::uri::Authority, ProxyError> {
    if let Some(authority) = request.uri().authority() {
        return Ok(authority.clone());
    }
    let mut hosts = request.headers().get_all(HOST).iter();
    let host = hosts.next().ok_or(ProxyError::BadRequest("missing Host header"))?;
    if hosts.next().is_some() {
        return Err(ProxyError::BadRequest("duplicate Host header"));
    }
    host.to_str().map_err(|_| ProxyError::BadRequest("invalid Host header"))?
        .parse().map_err(|_| ProxyError::BadRequest("invalid Host authority"))
}

fn wants_upgrade(headers: &HeaderMap) -> bool {
    headers.contains_key(UPGRADE) && headers.get_all(CONNECTION).iter().any(|value| {
        value.to_str().is_ok_and(|text| {
            text.split(',').any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        })
    })
}

fn upgrade_protocols(headers: &HeaderMap) -> Result<Vec<String>, ProxyError> {
    let mut protocols = Vec::new();
    for value in headers.get_all(UPGRADE) {
        let value = value.to_str().map_err(|_| ProxyError::BadRequest("invalid Upgrade header"))?;
        for protocol in value.split(',').map(str::trim) {
            if protocol.is_empty() || !protocol.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-')
            }) {
                return Err(ProxyError::BadRequest("invalid Upgrade protocol"));
            }
            protocols.push(protocol.to_ascii_lowercase());
        }
    }
    Ok(protocols)
}

fn strip_hop_headers(headers: &mut HeaderMap, preserve_upgrade: bool) -> Result<(), ProxyError> {
    let mut named = Vec::new();
    for value in headers.get_all(CONNECTION) {
        let text = value.to_str().map_err(|_| ProxyError::BadRequest("invalid Connection header"))?;
        for token in text.split(',').map(str::trim).filter(|token| !token.is_empty()) {
            if preserve_upgrade && token.eq_ignore_ascii_case("upgrade") {
                continue;
            }
            named.push(HeaderName::from_bytes(token.as_bytes())
                .map_err(|_| ProxyError::BadRequest("invalid Connection token"))?);
        }
    }
    for name in named {
        headers.remove(name);
    }
    for name in ["connection", "proxy-connection", "keep-alive", "transfer-encoding", "te"] {
        headers.remove(name);
    }
    if preserve_upgrade {
        headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
    } else {
        headers.remove(UPGRADE);
    }
    Ok(())
}

async fn connect(context: &ProxyContext, target: ConnectTarget) -> Result<TcpStream, ProxyError> {
    tokio::time::timeout(context.connect_timeout, context.dialer.connect(target))
        .await.map_err(|_| ProxyError::Timeout)?
        .map_err(|error| ProxyError::Upstream(Box::new(error)))
}

fn track_connect_tunnel(
    context: &ProxyContext,
    client: hyper::upgrade::OnUpgrade,
    mut upstream: TcpStream,
    permit: tokio::sync::OwnedSemaphorePermit,
) {
    let cancellation = context.cancellation.clone();
    let lifetime = context.tunnel_lifetime;
    context.tasks.spawn(async move {
        let _permit = permit;
        let relay = async {
            let upgraded = client.await.map_err(std::io::Error::other)?;
            let mut client = TokioIo::new(upgraded);
            tokio::io::copy_bidirectional(&mut client, &mut upstream).await
        };
        tokio::select! {
            _ = cancellation.cancelled() => {}
            result = tokio::time::timeout(lifetime, relay) => {
                match result {
                    Ok(Ok(_bytes)) => {}
                    Ok(Err(error)) => eprintln!("CONNECT relay failed: {error}"),
                    Err(_) => eprintln!("CONNECT relay reached its configured lifetime"),
                }
            }
        }
    });
}

fn track_upgrade_tunnel(
    context: &ProxyContext,
    client: hyper::upgrade::OnUpgrade,
    upstream: hyper::upgrade::OnUpgrade,
    permit: tokio::sync::OwnedSemaphorePermit,
) {
    let cancellation = context.cancellation.clone();
    let lifetime = context.tunnel_lifetime;
    context.tasks.spawn(async move {
        let _permit = permit;
        let relay = async {
            let (client, upstream) = tokio::try_join!(client, upstream)
                .map_err(std::io::Error::other)?;
            let mut client = TokioIo::new(client);
            let mut upstream = TokioIo::new(upstream);
            tokio::io::copy_bidirectional(&mut client, &mut upstream).await
        };
        tokio::select! {
            _ = cancellation.cancelled() => {}
            result = tokio::time::timeout(lifetime, relay) => {
                match result {
                    Ok(Ok(_bytes)) => {}
                    Ok(Err(error)) => eprintln!("HTTP Upgrade relay failed: {error}"),
                    Err(_) => eprintln!("HTTP Upgrade relay reached its configured lifetime"),
                }
            }
        }
    });
}

async fn forward_request(
    mut request: Request<Incoming>,
    context: Arc<ProxyContext>,
) -> Result<Response<ProxyBody>, ProxyError> {
    context.admission.authorize(request.headers_mut()).await?;
    let authority = request_authority(&request)?;
    if request.method() == Method::CONNECT {
        let permit = context.tunnel_slots.clone().try_acquire_owned()
            .map_err(|_| ProxyError::Busy)?;
        let target = authority_target(&authority, None)?;
        let upstream = connect(&context, target).await?;
        let client_upgrade = hyper::upgrade::on(&mut request);
        track_connect_tunnel(&context, client_upgrade, upstream, permit);
        return Ok(Response::new(empty_body()));
    }
    if request.uri().scheme_str().is_some_and(|scheme| scheme != "http") {
        return Err(ProxyError::BadRequest("use CONNECT for an HTTPS forward-proxy destination"));
    }
    let target = authority_target(&authority, NonZeroU16::new(80))?;
    let upgrading = wants_upgrade(request.headers());
    let upgrade_permit = if upgrading {
        Some(context.tunnel_slots.clone().try_acquire_owned().map_err(|_| ProxyError::Busy)?)
    } else {
        None
    };
    let offered_protocols = if upgrading { upgrade_protocols(request.headers())? } else { Vec::new() };
    let client_upgrade = upgrading.then(|| hyper::upgrade::on(&mut request));
    strip_hop_headers(request.headers_mut(), upgrading)?;
    request.headers_mut().insert(HOST, HeaderValue::from_str(authority.as_str())
        .map_err(|_| ProxyError::BadRequest("invalid outbound Host"))?);
    let path = request.uri().path_and_query().map(|value| value.as_str()).unwrap_or("/");
    let origin_uri: Uri = path.parse().map_err(|_| ProxyError::BadRequest("invalid origin target"))?;
    *request.uri_mut() = origin_uri;
    let upstream = connect(&context, target).await?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(upstream))
        .await.map_err(|error| ProxyError::Upstream(Box::new(error)))?;
    let cancellation = context.cancellation.clone();
    context.tasks.spawn(async move {
        tokio::select! {
            _ = cancellation.cancelled() => {}
            result = connection.with_upgrades() => {
                if let Err(error) = result {
                    eprintln!("upstream HTTP connection failed: {error}");
                }
            }
        }
    });
    let mut response = tokio::time::timeout(context.header_timeout, sender.send_request(request))
        .await.map_err(|_| ProxyError::Timeout)?
        .map_err(|error| ProxyError::Upstream(Box::new(error)))?;
    let switched = response.status() == StatusCode::SWITCHING_PROTOCOLS;
    if switched {
        let client_upgrade = client_upgrade.ok_or(ProxyError::UpstreamProtocol("unsolicited upgrade"))?;
        let permit = upgrade_permit.ok_or(ProxyError::UpstreamProtocol("upgrade has no admission permit"))?;
        if !wants_upgrade(response.headers()) {
            return Err(ProxyError::UpstreamProtocol("missing upgrade connection semantics"));
        }
        let selected = upgrade_protocols(response.headers())
            .map_err(|_| ProxyError::UpstreamProtocol("invalid Upgrade protocol"))?;
        if selected.len() != 1 || !offered_protocols.contains(&selected[0]) {
            return Err(ProxyError::UpstreamProtocol("server selected an unoffered Upgrade protocol"));
        }
        track_upgrade_tunnel(&context, client_upgrade, hyper::upgrade::on(&mut response), permit);
    }
    strip_hop_headers(response.headers_mut(), switched)
        .map_err(|_| ProxyError::UpstreamProtocol("invalid hop-by-hop response headers"))?;
    Ok(response.map(|body| body.map_err(|error| -> BoxError { Box::new(error) }).boxed_unsync()))
}

pub async fn serve_http_proxy(
    stream: TcpStream,
    context: Arc<ProxyContext>,
) -> Result<(), hyper::Error> {
    let timeout = context.header_timeout;
    let cancellation = context.cancellation.clone();
    let service = service_fn(move |request| {
        let context = context.clone();
        async move {
            let response = match forward_request(request, context).await {
                Ok(response) => response,
                Err(error) => {
                    eprintln!("HTTP proxy request failed: {error}");
                    failure_response(&error)
                }
            };
            Ok::<_, std::convert::Infallible>(response)
        }
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder.timer(TokioTimer::new())
        .header_read_timeout(timeout)
        .max_buf_size(32 * 1024);
    tokio::select! {
        _ = cancellation.cancelled() => Ok(()),
        result = builder.serve_connection(TokioIo::new(stream), service).with_upgrades() => result,
    }
}
```

The outer listener must bound accepted connections and tracked tasks, enforce source admission, and choose the correct immutable route/egress snapshot. Upgrade/CONNECT tasks retain their own configured tunnel permit after the HTTP connection task hands off; otherwise upgrades would escape the listener's connection budget. Account for both pools in the total resource budget. The HTTP admission adapter selects origin versus proxy authentication explicitly; their challenges are not interchangeable. Capture authentication and route policy from one revision per request, and define whether credential revocation immediately closes existing upgraded streams. Add trailer, 100-continue, upgrade-token agreement, body-budget, and slow-upload tests before substituting this for the existing forwarding path. `header_timeout` for an upstream request is a response deadline and may include request-body transmission; do not document it as an idle timeout. Cloudflare reverse proxying uses a fixed validated origin and a TLS-capable dialer when requested; never reuse "guess HTTPS from port" logic.

### 3.10 Unit I - one command vocabulary for dispatch, help, and completion

**Replaces:** `handle_line` global precedence, context-specific operational guards, giant help printer, and independent completion grammar. Parsing and execution remain separate: this registry resolves a command and its argument contract; typed argument parsers then produce commands for the coordinator. Interactive actions cannot pass the API/batch boundary.

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Context {
    Operational,
    Root,
    Vip,
    Service,
    Gateway,
    GatewayEndpoint,
    Dns,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Execution {
    Read,
    EditCandidate,
    Operate,
    InteractiveOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArgumentKind {
    None,
    Text,
    File,
    Service,
    Gateway,
    Backend,
    Revision,
    Scope,
    Boolean,
    Balance,
    DnsType,
}

#[derive(Debug)]
pub struct CommandSpec {
    pub words: &'static [&'static str],
    pub aliases: &'static [&'static [&'static str]],
    pub contexts: &'static [Context],
    pub usage: &'static str,
    pub description: &'static str,
    pub execution: Execution,
    pub minimum_arguments: usize,
    pub maximum_arguments: Option<usize>,
    pub completion: ArgumentKind,
}

#[derive(Debug)]
pub struct ParsedCommand<'a> {
    pub spec: &'a CommandSpec,
    pub arguments: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum CommandParseError {
    #[error("unknown command in this context")]
    Unknown,
    #[error("ambiguous command registry entry")]
    Ambiguous,
    #[error("usage: {0}")]
    Arity(&'static str),
    #[error("interactive command is unavailable through this interface: {0}")]
    Interactive(&'static str),
}

fn starts_with_words(input: &[String], prefix: &[&str]) -> bool {
    input.len() >= prefix.len()
        && input.iter().zip(prefix).all(|(actual, expected)| actual.eq_ignore_ascii_case(expected))
}

pub fn resolve_command<'a>(
    specs: &'a [CommandSpec],
    context: Context,
    input: &[String],
    interactive: bool,
) -> Result<ParsedCommand<'a>, CommandParseError> {
    let mut matched = Vec::new();
    for spec in specs.iter().filter(|spec| spec.contexts.contains(&context)) {
        let lengths: Vec<_> = std::iter::once(spec.words).chain(spec.aliases.iter().copied())
            .filter(|prefix| starts_with_words(input, prefix))
            .map(|prefix| prefix.len())
            .collect();
        if let Some(length) = lengths.into_iter().max() {
            matched.push((length, spec));
        }
    }
    let length = matched.iter().map(|(length, _)| *length).max()
        .ok_or(CommandParseError::Unknown)?;
    let mut best = matched.into_iter().filter(|(candidate, _)| *candidate == length);
    let (_, spec) = best.next().ok_or(CommandParseError::Unknown)?;
    if best.next().is_some() {
        return Err(CommandParseError::Ambiguous);
    }
    let arguments = input[length..].to_vec();
    if arguments.len() < spec.minimum_arguments
        || spec.maximum_arguments.is_some_and(|maximum| arguments.len() > maximum)
    {
        return Err(CommandParseError::Arity(spec.usage));
    }
    if !interactive && spec.execution == Execution::InteractiveOnly {
        return Err(CommandParseError::Interactive(spec.usage));
    }
    Ok(ParsedCommand { spec, arguments })
}

pub fn render_help(specs: &[CommandSpec], context: Context) -> String {
    let mut lines: Vec<_> = specs.iter().filter(|spec| spec.contexts.contains(&context))
        .map(|spec| format!("{:<36} {}", spec.usage, spec.description))
        .collect();
    lines.sort();
    lines.join("\n")
}

#[derive(Debug, Default)]
pub struct CompletionSnapshot {
    pub files: Vec<String>,
    pub services: Vec<String>,
    pub gateways: Vec<String>,
    pub backends: Vec<String>,
    pub revisions: Vec<String>,
}

fn argument_candidates(kind: ArgumentKind, snapshot: &CompletionSnapshot) -> Vec<String> {
    let literals = |values: &[&str]| values.iter().map(|value| (*value).to_owned()).collect();
    match kind {
        ArgumentKind::File => snapshot.files.clone(),
        ArgumentKind::Service => snapshot.services.clone(),
        ArgumentKind::Gateway => snapshot.gateways.clone(),
        ArgumentKind::Backend => snapshot.backends.clone(),
        ArgumentKind::Revision => snapshot.revisions.clone(),
        ArgumentKind::Scope => literals(&["ro", "rw"]),
        ArgumentKind::Boolean => literals(&["on", "off"]),
        ArgumentKind::Balance => literals(&["round-robin", "sticky"]),
        ArgumentKind::DnsType => literals(&["a", "aaaa", "address", "cname", "txt", "srv", "mx", "ptr"]),
        ArgumentKind::None | ArgumentKind::Text => Vec::new(),
    }
}

pub fn complete_command(
    specs: &[CommandSpec],
    context: Context,
    complete_words: &[String],
    partial_word: &str,
    snapshot: &CompletionSnapshot,
) -> Vec<String> {
    let mut candidates = Vec::new();
    for spec in specs.iter().filter(|spec| spec.contexts.contains(&context)) {
        for spelling in std::iter::once(spec.words).chain(spec.aliases.iter().copied()) {
            if complete_words.len() < spelling.len() {
                if complete_words.iter().zip(spelling).all(|(word, expected)| word.eq_ignore_ascii_case(expected)) {
                    candidates.push(spelling[complete_words.len()].to_owned());
                }
            } else if starts_with_words(complete_words, spelling) {
                let argument_index = complete_words.len() - spelling.len();
                if spec.maximum_arguments.is_none_or(|maximum| argument_index < maximum) {
                    candidates.extend(argument_candidates(spec.completion, snapshot));
                }
            }
        }
    }
    let prefix = partial_word.to_ascii_lowercase();
    candidates.retain(|value| value.to_ascii_lowercase().starts_with(&prefix));
    candidates.sort();
    candidates.dedup();
    candidates
}
```

The `interactive` argument is boundary capability, not user input. Replace it with a tagged `CommandSource` if more sources are added. Completion captures one snapshot before calling this pure function; it must not reacquire `SharedState` in a nested helper. Token boundaries/quoting come from Unit B's lexer extended with an explicit incomplete-token result for an editor cursor, not another whitespace grammar.

**Complete registry content specification:** register the following families in all intended contexts, with longest-prefix matching and a uniqueness test. Do not keep hidden feature-specific global-command guards after migration.

| Family | Canonical commands / scope | Mandatory parser/result behavior |
|---|---|---|
| Navigation | `configure`, `exit`, `end`, `help`; entity selection in configuration contexts | Navigation changes session state only; API batch cannot enter interactive loops |
| Read/diagnose | `show`, `status`, `diff`, `validate`, `compile`, `probe`, `flows` | Return typed data/diagnostics, not print-and-success booleans |
| Transactions | `apply`, `apply confirm <duration>`, `confirm <revision>`, `rollback <revision>`, `export <path>`, `import <path>` | Explicit base revision, duration parsing, durable result; preserve legacy save/load via warned aliases |
| Root entities | `vip`, `gateway`, `service`, `dns`, `allow`, explicit removal | Exact entity grammar; clone/validate/replace; duplicate key/listener errors |
| Binding | `interface`, `dhcp`, `vlan`; explicit static/unmanaged/disabled forms | Same meaning in VIP and gateway contexts; no `dhcp off` interface-name accident |
| Service | `to`, `hostname`, `balance`, `mode`, `check`, `limit`, `allow`, `auth`, `cloudflare-dns`, `cloudflare-auth`, `key`, `port`, `proto` and typed `no` forms | Local endpoint kind is explicit; checks/auth/rates require compatible transport; rekeying is not a side effect |
| Gateway | `balance`, `killswitch`, `check`, `allow`, `hostname`, `tunnel`, `forward`, `api`, `ssh`, `dns`, `http-proxy`, `socks5` | Direct versus tunnel uplink restrictions; explicit single/multiple endpoint rule; `privoxy` deprecated alias |
| DNS configuration | `listen`, `domain`, `cache`, `auto-vips`, `auto-hosts`, `health-aware`, `all-servers`, `bogus-priv`, `domain-needed`, `upstream`, `forward`, every record type, `block`, `blocklist`, `route`, `bypass`, `raw` | Every field in section 1.4 has a parser, formatter, validation, consumer, and clearing/deletion test |
| DNS operations | `dns show`, `dns query`, `dns render`, `dns reload`, `dns flush`, `dns sync` | Read versus cache/control effects explicit; aliases `dig`, `conf`, `dnsmasq` resolve here, not by context-specific guard |
| WireGuard | `wg list`, `wg show <name>`, `wg status`, `wg import <name>`, `wg edit <name>`, `wg remove <name>` | `status` never opens a file; import/paste/file are distinct; editor is interactive-only; removal rejects live references |
| Cloudflare | `cf show`, `cf login`, `cf apply`, `cf logout`, `cf stop`, `cf clear` | One alias registry for `cloudflare`; external auth mode never changes on an API error; clear specifies remote-resource disposition |
| Discovery | `scan`, `adopt <discovery-id>`, host registration/removal | Stable discovery identity and explicit scope; adoption is separate from scanning |
| Administration | `drain <backend-id>`, `enable <backend-id>`, `password`, `bootstrap` | Unknown IDs are errors; password/editor/TTY commands forbidden in API batch; bootstrap produces validated candidate intent |

### 3.11 Unit J - owned listeners, PTYs, terminals, and child processes

#### J1. Bounded listener and accepted-connection lifetime

**Replaces:** detached per-connection spawning and aborting only the accept task. This loop owns all accepted tasks and reports their failures; the registry above it owns bind/retry/readiness and publishes listener identity.

```rust
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

fn report_client(result: Result<io::Result<()>, tokio::task::JoinError>) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(error)) => eprintln!("connection failed: {error}"),
        Err(error) if error.is_cancelled() => {}
        Err(error) => eprintln!("connection task failed: {error}"),
    }
}

pub async fn run_listener<F, Fut>(
    listener: TcpListener,
    maximum_connections: NonZeroUsize,
    stop_admission: CancellationToken,
    drain_timeout: Duration,
    handle: F,
) -> io::Result<()>
where
    F: Fn(TcpStream, SocketAddr) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = io::Result<()>> + Send + 'static,
{
    let permits = Arc::new(Semaphore::new(maximum_connections.get()));
    let mut clients = JoinSet::new();
    loop {
        let accept = async {
            let permit = permits.clone().acquire_owned().await
                .map_err(|_| io::Error::other("connection admission is closed"))?;
            let (stream, peer) = listener.accept().await?;
            Ok::<_, io::Error>((stream, peer, permit))
        };
        tokio::select! {
            biased;
            _ = stop_admission.cancelled() => break,
            result = clients.join_next(), if !clients.is_empty() => {
                if let Some(result) = result {
                    report_client(result);
                }
            }
            accepted = accept => {
                let (stream, peer, permit) = accepted?;
                let handle = handle.clone();
                clients.spawn(async move {
                    let _permit = permit;
                    handle(stream, peer).await
                });
            }
        }
    }
    drop(listener);
    let drained = tokio::time::timeout(drain_timeout, async {
        while let Some(result) = clients.join_next().await {
            report_client(result);
        }
    }).await;
    if drained.is_err() {
        clients.abort_all();
        while let Some(result) = clients.join_next().await {
            report_client(result);
        }
    }
    Ok(())
}
```

A component-level shutdown token stops admission; a separate connection cancellation policy may force-close upgrades/relays when the drain window expires. Include listener/connection IDs in the production diagnostic sink. For a failed bind, do not insert an "active" registry entry; for an unexpectedly completed listener task, remove it and reconcile again under bounded backoff.

#### J2. Nonblocking PTY with owned descriptors

**Replaces:** `src\ssh.rs:189-214,325-450`. The child must be the daemon **client**, not another controller. This Linux implementation uses nix to obtain `OwnedFd`, sets descriptor flags deliberately, performs only async-signal-safe syscalls in `pre_exec`, and never holds the session map guard during I/O.

```rust
use std::ffi::OsString;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::process::{Child, Command};

fn add_fd_flag(fd: &OwnedFd, get: libc::c_int, set: libc::c_int, flag: libc::c_int) -> io::Result<()> {
    // The descriptor remains owned for both syscalls.
    let current = unsafe { libc::fcntl(fd.as_raw_fd(), get) };
    if current < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd.as_raw_fd(), set, current | flag) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub struct Pty {
    fd: AsyncFd<OwnedFd>,
}

impl Pty {
    pub async fn read(&self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            let mut ready = self.fd.readable().await?;
            match ready.try_io(|inner| {
                // The writable slice covers exactly buffer.len() bytes.
                let count = unsafe {
                    libc::read(inner.get_ref().as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len())
                };
                if count >= 0 {
                    return Ok(count as usize);
                }
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EIO) {
                    return Ok(0);
                }
                Err(error)
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn write_all(&self, mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            let mut ready = self.fd.writable().await?;
            match ready.try_io(|inner| {
                // The readable slice covers exactly bytes.len() bytes.
                let count = unsafe {
                    libc::write(inner.get_ref().as_raw_fd(), bytes.as_ptr().cast(), bytes.len())
                };
                if count < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(count as usize)
            }) {
                Ok(Ok(0)) => return Err(io::Error::new(io::ErrorKind::WriteZero, "PTY write returned zero")),
                Ok(Ok(count)) => bytes = &bytes[count..],
                Ok(Err(error)) => return Err(error),
                Err(_would_block) => continue,
            }
        }
        Ok(())
    }

    pub fn resize(&self, columns: u32, rows: u32) -> io::Result<()> {
        let size = checked_size(columns, rows)?;
        if unsafe { libc::ioctl(self.fd.get_ref().as_raw_fd(), libc::TIOCSWINSZ, &size) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

fn checked_size(columns: u32, rows: u32) -> io::Result<libc::winsize> {
    let columns = u16::try_from(columns).ok().filter(|value| *value != 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid terminal width"))?;
    let rows = u16::try_from(rows).ok().filter(|value| *value != 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid terminal height"))?;
    Ok(libc::winsize { ws_row: rows, ws_col: columns, ws_xpixel: 0, ws_ypixel: 0 })
}

pub struct PtySession {
    pub pty: Arc<Pty>,
    child: Child,
}

impl PtySession {
    pub fn spawn_client(
        executable: &Path,
        arguments: &[OsString],
        columns: u32,
        rows: u32,
    ) -> io::Result<Self> {
        let size = checked_size(columns, rows)?;
        let pair = nix::pty::openpty(Some(&size), None::<&nix::sys::termios::Termios>)
            .map_err(io::Error::other)?;
        add_fd_flag(&pair.master, libc::F_GETFD, libc::F_SETFD, libc::FD_CLOEXEC)?;
        add_fd_flag(&pair.slave, libc::F_GETFD, libc::F_SETFD, libc::FD_CLOEXEC)?;
        add_fd_flag(&pair.master, libc::F_GETFL, libc::F_SETFL, libc::O_NONBLOCK)?;
        let pty = Arc::new(Pty { fd: AsyncFd::new(pair.master)? });
        let input = pair.slave.try_clone()?;
        let output = pair.slave.try_clone()?;
        let mut command = Command::new(executable);
        command.args(arguments)
            .stdin(Stdio::from(input))
            .stdout(Stdio::from(output))
            .stderr(Stdio::from(pair.slave))
            .kill_on_drop(true);
        // No allocation, locks, or Rust runtime work is performed after fork.
        unsafe {
            command.as_std_mut().pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn()?;
        Ok(Self { pty, child })
    }

    pub async fn close(mut self) -> io::Result<()> {
        if self.child.try_wait()?.is_none() {
            self.child.kill().await?;
        }
        Ok(())
    }
}
```

Linux PTY masters commonly return EIO after the slave closes; that specific mapping to EOF is intentional, not a blanket ignored I/O error. Cancellation must stop the SSH-to-PTY writer and PTY-to-SSH reader, release their `Arc`s, and call `close`. A channel map stores/clones the handle under a short guard, then drops the guard before awaiting write. If the client can spawn grandchildren, add a registered process-group lifecycle and signal that owned group; do not kill by executable name.

#### J3. Terminal restoration and process shutdown

```rust
use crossterm::{
    cursor::Show,
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::io;

pub struct TerminalSession {
    active: bool,
}

impl TerminalSession {
    pub fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        let session = Self { active: true };
        execute!(io::stdout(), EnterAlternateScreen)?;
        Ok(session)
    }

    pub fn restore(&mut self) -> io::Result<()> {
        if !self.active {
            return Ok(());
        }
        self.active = false;
        let screen = execute!(io::stdout(), LeaveAlternateScreen, Show);
        let raw = disable_raw_mode();
        match (screen, raw) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(screen), Err(raw)) => Err(io::Error::other(
                format!("screen restore failed: {screen}; raw-mode restore failed: {raw}"),
            )),
        }
    }
}

impl Drop for TerminalSession {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            eprintln!("terminal restoration failed: {error}");
        }
    }
}

pub async fn terminate_owned_child(
    child: &mut tokio::process::Child,
    grace: std::time::Duration,
) -> io::Result<()> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    let Some(pid) = child.id() else {
        return Err(io::Error::other("running child has no process ID"));
    };
    let pid = i32::try_from(pid).map_err(|_| io::Error::other("child PID exceeds platform range"))?;
    if unsafe { libc::kill(pid, libc::SIGTERM) } < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error);
        }
    }
    match tokio::time::timeout(grace, child.wait()).await {
        Ok(result) => { result?; Ok(()) }
        Err(_) => child.kill().await,
    }
}
```

Service processes such as dnsmasq/cloudflared use this retained-child ownership. Validate a candidate generation before stopping the current child; retain last-good config and executable arguments for recovery; distinguish `Starting`, `Ready`, `Exited`, and `Failed`; verify responsiveness rather than sleeping 80 ms. A configured-but-missing binary is an error. Restart policy belongs to the supervisor, not an unrelated health-triggered nft reload.

PID1 signal handling must use Tokio's Unix signal stream or a signal-safe notification mechanism. A general `waitpid(-1)` reaper must **not race Tokio's owners for registered children**: introduce one child registry and reap only adopted/unowned children, or centralize all child waiting in one process supervisor. Storage selection must use the declared label/UUID and validate filesystem/mount success; do not choose the first device ending in partition 2. Failed persistent storage readiness must block durable-commit claims.

#### J4. Pure DNS rendering and validated diagnostic transport

**Replaces:** `compile_dnsmasq_config`'s mixed filesystem/health/name-resolution work. Resolution produces one instance plan per listener-port and upstream-policy group. The compiler never guesses an upstream, interface, lease, or source of hosts. Health filtering has already been applied to the explicit synthesized-host input, not to unrelated static records.

The official [dnsmasq manual](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html), checked during this review, confirms: `--no-hosts` suppresses native `/etc/hosts`; quoted configuration values support escaped quotes/backslashes/control characters; SIGHUP clears DNS cache and reloads supported hosts data, but does not reread the main configuration. Use `--test` for candidate validation and `--keep-in-foreground` for supervised production execution. This external contract must also be verified against the exact packaged build.

```rust
use crate::ast::DnsRecord;
use std::collections::BTreeSet;
use std::fmt::Write;
use std::net::{IpAddr, Ipv6Addr};
use std::num::NonZeroU16;

#[derive(Debug, Clone)]
pub struct Resolver {
    pub address: IpAddr,
    pub port: NonZeroU16,
    pub interface: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ForwardZone {
    pub domain: String,
    pub resolvers: Vec<Resolver>,
}

#[derive(Debug, Clone)]
pub struct NftDnsSet {
    pub domains: Vec<String>,
    pub set_name: String,
}

#[derive(Debug, Clone, Copy)]
pub enum DnsFlag {
    AllServers,
    BogusPrivate,
    DomainNeeded,
}

#[derive(Debug, Clone)]
pub enum ExtraDnsOption {
    NegativeTtl(u32),
    MaximumTtl(u32),
    MaximumCacheTtl(u32),
    LocalTtl(u32),
    EdnsPacketMaximum(NonZeroU16),
    LogQueries,
}

pub struct DnsInstancePlan {
    pub addresses: BTreeSet<IpAddr>,
    pub port: NonZeroU16,
    pub domain: Option<String>,
    pub cache_size: u32,
    pub flags: Vec<DnsFlag>,
    pub resolvers: Vec<Resolver>,
    pub zones: Vec<ForwardZone>,
    pub records: Vec<DnsRecord>,
    pub hosts: Vec<(IpAddr, String)>,
    pub blocked_domains: Vec<String>,
    pub nft_sets: Vec<NftDnsSet>,
    pub extra: Vec<ExtraDnsOption>,
    pub hosts_path: String,
    pub allow_wildcard_bind: bool,
}

pub struct DnsFiles {
    pub configuration: String,
    pub hosts: String,
}

#[derive(Debug, thiserror::Error)]
pub enum DnsPlanError {
    #[error("{0}")]
    Invalid(String),
    #[error("formatting DNS configuration failed")]
    Format(#[from] std::fmt::Error),
}

fn dns_name(value: &str) -> Result<&str, DnsPlanError> {
    let unrooted = value.strip_suffix('.').unwrap_or(value);
    if unrooted.is_empty() || unrooted.len() > 253 || !unrooted.is_ascii()
        || unrooted.split('.').any(|label| {
            label.is_empty() || label.len() > 63
                || !label.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        })
    {
        return Err(DnsPlanError::Invalid(format!("invalid DNS name: {value:?}")));
    }
    Ok(value)
}

fn quoted(value: &str) -> Result<String, DnsPlanError> {
    if value.contains('\0') {
        return Err(DnsPlanError::Invalid("NUL is not allowed in a DNS text value".into()));
    }
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            ch => out.push(ch),
        }
    }
    out.push('"');
    Ok(out)
}

fn resolver_text(resolver: &Resolver) -> Result<String, DnsPlanError> {
    let mut value = format!("{}#{}", resolver.address, resolver.port);
    if let Some(interface) = &resolver.interface {
        if interface.is_empty() || interface.len() > 15
            || !interface.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        {
            return Err(DnsPlanError::Invalid("invalid resolved DNS egress interface".into()));
        }
        write!(value, "@{interface}")?;
    }
    Ok(value)
}

fn emit_record(record: &DnsRecord, conf: &mut String, _hosts: &mut String) -> Result<(), DnsPlanError> {
    match record {
        DnsRecord::A { name, ips } => {
            let name = dns_name(name)?;
            if ips.is_empty() {
                return Err(DnsPlanError::Invalid("A record requires at least one address".into()));
            }
            for ip in ips {
                writeln!(conf, "host-record={name},{ip}")?;
            }
        }
        DnsRecord::Aaaa { name, ip } => {
            let name = dns_name(name)?;
            let ip: Ipv6Addr = ip.parse().map_err(|_| DnsPlanError::Invalid("invalid AAAA address".into()))?;
            writeln!(conf, "host-record={name},{ip}")?;
        }
        DnsRecord::Address { domain, ip } => {
            writeln!(conf, "address=/{}/{ip}", dns_name(domain)?)?;
        }
        DnsRecord::Cname { alias, target } => {
            writeln!(conf, "cname={},{}", dns_name(alias)?, dns_name(target)?)?;
        }
        DnsRecord::Txt { name, text } => {
            dns_name(name)?;
            if text.len() > 255 {
                return Err(DnsPlanError::Invalid(
                    "this TXT form supports one string of at most 255 bytes; use an explicit multi-string record".into(),
                ));
            }
            writeln!(conf, "txt-record={name},{}", quoted(text)?)?;
        }
        DnsRecord::Srv { service, target, port, priority, weight } => {
            dns_name(service)?;
            if target != "." { dns_name(target)?; }
            writeln!(conf, "srv-host={service},{target},{port},{priority},{weight}")?;
        }
        DnsRecord::Mx { domain, target, preference } => {
            writeln!(conf, "mx-host={},{},{preference}", dns_name(domain)?, dns_name(target)?)?;
        }
        DnsRecord::Ptr { ip, name } => {
            let octets = ip.octets();
            writeln!(conf, "ptr-record={}.{}.{}.{}.in-addr.arpa,{}",
                octets[3], octets[2], octets[1], octets[0], dns_name(name)?)?;
        }
    }
    Ok(())
}

pub fn compile_dns_instance(plan: &DnsInstancePlan) -> Result<DnsFiles, DnsPlanError> {
    if plan.addresses.is_empty() {
        return Err(DnsPlanError::Invalid("DNS instance has no resolved listener address".into()));
    }
    if !plan.allow_wildcard_bind && plan.addresses.iter().any(IpAddr::is_unspecified) {
        return Err(DnsPlanError::Invalid("wildcard DNS binding was not explicitly enabled".into()));
    }
    let mut conf = String::from("no-resolv\nno-hosts\nbind-dynamic\n");
    writeln!(conf, "port={}\ncache-size={}", plan.port, plan.cache_size)?;
    writeln!(conf, "addn-hosts={}", quoted(&plan.hosts_path)?)?;
    for address in &plan.addresses {
        writeln!(conf, "listen-address={address}")?;
    }
    if let Some(domain) = &plan.domain {
        writeln!(conf, "domain={}", dns_name(domain)?)?;
    }
    for flag in &plan.flags {
        conf.push_str(match flag {
            DnsFlag::AllServers => "all-servers\n",
            DnsFlag::BogusPrivate => "bogus-priv\n",
            DnsFlag::DomainNeeded => "domain-needed\n",
        });
    }
    for resolver in &plan.resolvers {
        writeln!(conf, "server={}", resolver_text(resolver)?)?;
    }
    for zone in &plan.zones {
        dns_name(&zone.domain)?;
        if zone.resolvers.is_empty() {
            return Err(DnsPlanError::Invalid(format!("forward zone {} has no resolver", zone.domain)));
        }
        for resolver in &zone.resolvers {
            writeln!(conf, "server=/{}/{}", zone.domain, resolver_text(resolver)?)?;
        }
    }
    let mut hosts = String::new();
    for record in &plan.records {
        emit_record(record, &mut conf, &mut hosts)?;
    }
    for (address, name) in &plan.hosts {
        if address.is_unspecified() {
            return Err(DnsPlanError::Invalid("synthesized DNS host has an unspecified address".into()));
        }
        writeln!(hosts, "{address} {}", dns_name(name)?)?;
    }
    for domain in &plan.blocked_domains {
        let domain = dns_name(domain)?;
        writeln!(conf, "address=/{domain}/0.0.0.0")?;
        writeln!(conf, "address=/{domain}/::")?;
    }
    for set in &plan.nft_sets {
        if set.domains.is_empty() || set.set_name.is_empty()
            || !set.set_name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(DnsPlanError::Invalid("invalid resolved DNS nftset binding".into()));
        }
        for domain in &set.domains { dns_name(domain)?; }
        writeln!(conf, "nftset=/{}/4#ip#nfty#{}", set.domains.join("/"), set.set_name)?;
    }
    for option in &plan.extra {
        match option {
            ExtraDnsOption::NegativeTtl(value) => writeln!(conf, "neg-ttl={value}")?,
            ExtraDnsOption::MaximumTtl(value) => writeln!(conf, "max-ttl={value}")?,
            ExtraDnsOption::MaximumCacheTtl(value) => writeln!(conf, "max-cache-ttl={value}")?,
            ExtraDnsOption::LocalTtl(value) => writeln!(conf, "local-ttl={value}")?,
            ExtraDnsOption::EdnsPacketMaximum(value) => writeln!(conf, "edns-packet-max={value}")?,
            ExtraDnsOption::LogQueries => conf.push_str("log-queries\n"),
        }
    }
    Ok(DnsFiles { configuration: conf, hosts })
}
```

`allow_wildcard_bind` is an explicit opt-in in this adapter input; use a `BindPolicy` enum in the final domain model. `auto_vips`, `auto_hosts`, health policy, and downloaded blocklists affect the resolved `hosts`/record inputs; their omission from this renderer is deliberate removal of policy/discovery from formatting. Unknown `via` references fail during resolution. Replace arbitrary raw options with typed extras plus a reviewed advanced escape hatch; unsupported old raw options require migration errors, not silent omission.

For `query_udp_a_record`, use hickory-proto or another maintained DNS codec. A diagnostic query must generate a transaction ID, connect the UDP socket to the selected resolver, match response ID/question/type/class, inspect response code, retry TCP on TC, and respect one absolute deadline. Return `Answer`, `NoData`, `NxDomain`, `Refused`, `Malformed`, `Timeout`, or `Unavailable`; never return synthesized configuration as a live result.

For mDNS, reuse the DNS codec but not ordinary recursive-query semantics. Separate query parsing, QU/QM destination selection, cache-flush/TTL semantics, interface membership, and answer generation. Reconcile joins/leaves on interface events/timer even when no packet arrives; use actual interface index and prefix, set multicast TTL/source interface correctly, and implement an explicit loop-prevention policy for any repeater. If only an IPv4 A-record responder is implemented, reject the repeater/full-DNS-SD capability instead of advertising it.

### 3.12 Unit K - single-owner external reconciliation and honest provider errors

**Replaces:** `reconcile_with_cf_api`'s 423-line sequence and one detached reconcile thread per nft reload. Desired resources are built once from validated origin/auth policy; a single controller reconciles the newest generation. Remote operation errors retain ownership state and never change authentication mode.

```rust
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::error::Error;

type ProviderError = Box<dyn Error + Send + Sync>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManagedResource {
    pub remote_id: String,
    pub desired_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceIntent {
    pub logical_id: String,
    pub digest: String,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PendingRemoteOperation {
    Upsert {
        logical_id: String,
        idempotency_key: String,
        previous: Option<ManagedResource>,
        desired_digest: String,
    },
    Delete { logical_id: String, remote_id: String },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProviderLedger {
    pub resources: BTreeMap<String, ManagedResource>,
    pub pending: Option<PendingRemoteOperation>,
}

#[async_trait]
pub trait Provider: Send {
    async fn upsert(
        &mut self,
        desired: &ResourceIntent,
        owned_remote_id: Option<&str>,
        idempotency_key: &str,
    ) -> Result<String, ProviderError>;
    async fn delete_owned(&mut self, remote_id: &str) -> Result<(), ProviderError>;
    async fn recover_pending(&mut self, pending: &PendingRemoteOperation)
        -> Result<Option<ManagedResource>, ProviderError>;
}

#[async_trait]
pub trait LedgerStore: Send {
    async fn save(&mut self, ledger: &ProviderLedger) -> Result<(), ProviderError>;
}

#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    #[error("provider operation is pending recovery")]
    PendingRecovery,
    #[error("provider intent key does not match its logical ID")]
    IntentMismatch,
    #[error("{operation} for {logical_id} failed: {source}")]
    Operation {
        operation: &'static str,
        logical_id: String,
        #[source]
        source: ProviderError,
    },
}

async fn persist<S: LedgerStore>(
    store: &mut S,
    ledger: &ProviderLedger,
    logical_id: &str,
) -> Result<(), ReconcileError> {
    store.save(ledger).await.map_err(|source| ReconcileError::Operation {
        operation: "persist provider ownership",
        logical_id: logical_id.into(),
        source,
    })
}

pub async fn recover_provider<P: Provider, S: LedgerStore>(
    provider: &mut P,
    store: &mut S,
    ledger: &mut ProviderLedger,
) -> Result<(), ReconcileError> {
    let Some(pending) = ledger.pending.clone() else { return Ok(()) };
    let logical_id = match &pending {
        PendingRemoteOperation::Upsert { logical_id, .. }
        | PendingRemoteOperation::Delete { logical_id, .. } => logical_id.clone(),
    };
    let observed = provider.recover_pending(&pending).await.map_err(|source| {
        ReconcileError::Operation { operation: "recover provider operation", logical_id: logical_id.clone(), source }
    })?;
    let mut next = ledger.clone();
    match observed {
        Some(resource) => { next.resources.insert(logical_id.clone(), resource); }
        None => { next.resources.remove(&logical_id); }
    }
    next.pending = None;
    persist(store, &next, &logical_id).await?;
    *ledger = next;
    Ok(())
}

pub async fn reconcile_resources<P: Provider, S: LedgerStore>(
    generation: u64,
    desired: &BTreeMap<String, ResourceIntent>,
    provider: &mut P,
    store: &mut S,
    ledger: &mut ProviderLedger,
) -> Result<(), ReconcileError> {
    if ledger.pending.is_some() {
        return Err(ReconcileError::PendingRecovery);
    }
    if desired.iter().any(|(logical_id, intent)| logical_id != &intent.logical_id) {
        return Err(ReconcileError::IntentMismatch);
    }
    for (logical_id, intent) in desired {
        if ledger.resources.get(logical_id).is_some_and(|resource| resource.desired_digest == intent.digest) {
            continue;
        }
        let previous = ledger.resources.get(logical_id).cloned();
        let idempotency_key = format!("nfty:{generation}:{logical_id}:{}", intent.digest);
        let mut pending = ledger.clone();
        pending.pending = Some(PendingRemoteOperation::Upsert {
            logical_id: logical_id.clone(),
            idempotency_key: idempotency_key.clone(),
            previous: previous.clone(),
            desired_digest: intent.digest.clone(),
        });
        persist(store, &pending, logical_id).await?;
        *ledger = pending;
        let remote_id = provider.upsert(
            intent,
            previous.as_ref().map(|resource| resource.remote_id.as_str()),
            &idempotency_key,
        ).await.map_err(|source| ReconcileError::Operation {
            operation: "upsert owned provider resource",
            logical_id: logical_id.clone(),
            source,
        })?;
        let mut complete = ledger.clone();
        complete.resources.insert(logical_id.clone(), ManagedResource {
            remote_id,
            desired_digest: intent.digest.clone(),
        });
        complete.pending = None;
        persist(store, &complete, logical_id).await?;
        *ledger = complete;
    }
    let obsolete: Vec<_> = ledger.resources.iter()
        .filter(|(logical_id, _)| !desired.contains_key(*logical_id))
        .map(|(logical_id, resource)| (logical_id.clone(), resource.remote_id.clone()))
        .collect();
    for (logical_id, remote_id) in obsolete {
        let mut pending = ledger.clone();
        pending.pending = Some(PendingRemoteOperation::Delete {
            logical_id: logical_id.clone(),
            remote_id: remote_id.clone(),
        });
        persist(store, &pending, &logical_id).await?;
        *ledger = pending;
        provider.delete_owned(&remote_id).await.map_err(|source| ReconcileError::Operation {
            operation: "delete owned provider resource",
            logical_id: logical_id.clone(),
            source,
        })?;
        let mut complete = ledger.clone();
        complete.resources.remove(&logical_id);
        complete.pending = None;
        persist(store, &complete, &logical_id).await?;
        *ledger = complete;
    }
    Ok(())
}
```

Cloudflare does not provide one universal idempotency mechanism for every resource type. The concrete adapter must implement the supplied key through supported idempotency or explicit ownership metadata plus paginated lookup; **do not invent a Cloudflare header that supposedly guarantees it**. If an ambiguous post-timeout creation cannot be recovered safely, leave the operation pending and require explicit reconciliation rather than create another resource or adopt an unrelated matching hostname.

`recover_pending` distinguishes a confirmed deleted/nonexistent resource from an unavailable lookup; an HTTP error is not `Ok(None)`. The resource dependency graph orders tunnel, ingress, DNS, and Access changes. Provider status separately reports requested generation, converged generation, pending deletion, and last error. Connector process identity includes account/tunnel/token generation; changing credentials restarts the owned child after validation. `cf stop` changes explicit desired connector state so a later health event cannot silently undo it.

Use typed provider envelopes instead of success-shaped JSON defaults:

```rust
use serde::de::DeserializeOwned;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ApiFailure {
    pub code: i64,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct PageInfo {
    pub page: u32,
    pub total_pages: u32,
}

#[derive(Debug, Deserialize)]
pub struct Envelope<T> {
    pub success: bool,
    pub errors: Vec<ApiFailure>,
    pub result: Option<T>,
    pub result_info: Option<PageInfo>,
}

#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    #[error("invalid provider response: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("provider rejected the operation: {0:?}")]
    Rejected(Vec<ApiFailure>),
    #[error("provider success response has no result")]
    MissingResult,
}

pub fn decode_result<T: DeserializeOwned>(bytes: &[u8]) -> Result<(T, Option<PageInfo>), EnvelopeError> {
    let envelope: Envelope<T> = serde_json::from_slice(bytes)?;
    if !envelope.success {
        return Err(EnvelopeError::Rejected(envelope.errors));
    }
    let result = envelope.result.ok_or(EnvelopeError::MissingResult)?;
    Ok((result, envelope.result_info))
}
```

The HTTP adapter checks status, body-size budget, timeouts, and the provider envelope; enumerates all pages under an explicit budget; requires account selection when ambiguous; and never prints bearer tokens or raw secret-bearing requests. Access permission errors remain Access deployment errors. An explicit empty list is a valid provider result only after a successful, decoded, paginated response.

### 3.13 Unit L - one truthful status model and measurement pipeline

**Replaces:** inconsistent status/TUI/HTML interpretations of active config, gateway UP, DNS readiness, selected backends, and counters. WireGuard private/preshared keys and service Basic Auth passwords are redacted, while scoped `api:<port>` key visibility follows caller scope (`rw` and logged-in sessions can view `ro` and `rw` API keys in config/status; `ro` sessions see `ro` keys with `rw` keys redacted).

```rust
use serde::Serialize;
use std::fmt::Write;
use std::net::SocketAddr;
use std::time::Instant;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceKind {
    Service,
    Backend,
    Gateway,
    Tunnel,
    Dns,
    Api,
    Ssh,
    Cloudflare,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Readiness {
    Disabled,
    WaitingForAddress,
    Starting,
    Ready,
    Degraded,
    Failed,
    NotMonitored,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Administrative {
    Enabled,
    Drained,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MeasurementSource {
    NftCounter,
    Conntrack,
    UserspaceRelay,
    SocketInventory,
}

#[derive(Debug, Clone, Serialize)]
pub struct Measurement {
    pub source: MeasurementSource,
    pub bytes: Option<u64>,
    pub packets: Option<u64>,
    pub bytes_per_second: Option<f64>,
    pub packets_per_second: Option<f64>,
    pub reset: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResourceStatus {
    pub id: String,
    pub kind: ResourceKind,
    pub label: String,
    pub endpoint: Option<SocketAddr>,
    pub readiness: Readiness,
    pub administrative: Administrative,
    pub selected: bool,
    pub last_error: Option<String>,
    pub measurement: Option<Measurement>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PendingCommitStatus {
    pub revision: u64,
    pub confirm_by_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatusSnapshot {
    pub api_version: u32,
    pub desired_revision: u64,
    pub applied_revision: Option<u64>,
    pub durable_revision: u64,
    pub pending: Option<PendingCommitStatus>,
    pub resources: Vec<ResourceStatus>,
    pub last_operation_error: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct CounterSample {
    pub epoch: u64,
    pub at: Instant,
    pub bytes: u64,
    pub packets: u64,
}

#[derive(Debug, Default)]
pub struct CounterTracker {
    previous: Option<CounterSample>,
}

#[derive(Debug, thiserror::Error)]
#[error("counter sample time must increase; previous sample was retained")]
pub struct CounterSampleError;

impl CounterTracker {
    pub fn sample(&mut self, next: CounterSample) -> Result<Measurement, CounterSampleError> {
        if self.previous.is_some_and(|previous| next.at <= previous.at) {
            return Err(CounterSampleError);
        }
        let previous = self.previous.replace(next);
        let mut result = Measurement {
            source: MeasurementSource::NftCounter,
            bytes: Some(next.bytes),
            packets: Some(next.packets),
            bytes_per_second: None,
            packets_per_second: None,
            reset: false,
        };
        let Some(previous) = previous else { return Ok(result) };
        if next.epoch != previous.epoch || next.bytes < previous.bytes || next.packets < previous.packets {
            result.reset = true;
            return Ok(result);
        }
        let seconds = next.at.duration_since(previous.at).as_secs_f64();
        result.bytes_per_second = Some((next.bytes - previous.bytes) as f64 / seconds);
        result.packets_per_second = Some((next.packets - previous.packets) as f64 / seconds);
        Ok(result)
    }
}

pub fn render_status(snapshot: &StatusSnapshot) -> Result<String, std::fmt::Error> {
    let applied = snapshot.applied_revision.map(|r| r.to_string()).unwrap_or_else(|| "not applied".into());
    let mut out = format!(
        "Desired: {}  Applied: {}  Durable: {}\n",
        snapshot.desired_revision, applied, snapshot.durable_revision,
    );
    if let Some(pending) = &snapshot.pending {
        writeln!(out, "Pending confirmation: revision {} before {} ms since Unix epoch",
            pending.revision, pending.confirm_by_unix_ms)?;
    }
    if let Some(error) = &snapshot.last_operation_error {
        writeln!(out, "Last operation error: {error}")?;
    }
    for resource in &snapshot.resources {
        let endpoint = resource.endpoint.map(|e| e.to_string()).unwrap_or_else(|| "-".into());
        writeln!(out, "{}  {:?}  {}  {}  {:?}  {:?}  selected={}",
            resource.id, resource.kind, resource.label, endpoint,
            resource.readiness, resource.administrative, resource.selected)?;
        if let Some(error) = &resource.last_error {
            writeln!(out, "  error: {error}")?;
        }
    }
    Ok(out)
}

pub fn render_mark(mark: u32) -> String {
    format!("{mark:#x}")
}
```

Use explicit human labels rather than Debug formatting for the polished renderer, but keep the renderer free of domain decisions. `NotMonitored` is not `Ready`; desired/running config is not applied state; a configured gateway has no implied health. Userspace measurements set `packets = None` unless actual packets are measured. Socket inventory is not conntrack and must not appear as inferred NAT traffic.

Parse nft's JSON representation into named counter observations and aggregate only where the plan declares aggregation. The epoch changes on actual counter recreation/reset, not every unrelated config change. A single sampler provides rates to all views; renderer refresh cadence never enters the denominator.

The web refresh path should preserve the last good view and render errors as errors:

```javascript
const rows = document.getElementById("resource-rows");
const connectionState = document.getElementById("connection-state");
const tokenInput = document.getElementById("api-token");
let stopped = false;

function renderStatus(snapshot) {
  if (snapshot.api_version !== 2 || !Array.isArray(snapshot.resources)) {
    throw new Error("Unsupported status response");
  }
  const fragment = document.createDocumentFragment();
  for (const resource of snapshot.resources) {
    const row = document.createElement("tr");
    const values = [
      resource.id,
      resource.kind,
      resource.label,
      resource.endpoint ?? "-",
      resource.readiness,
      resource.administrative,
      resource.last_error ?? "",
    ];
    for (const value of values) {
      const cell = document.createElement("td");
      cell.textContent = String(value);
      row.appendChild(cell);
    }
    fragment.appendChild(row);
  }
  rows.replaceChildren(fragment);
}

async function refresh() {
  if (stopped) return;
  try {
    const headers = new Headers({ Accept: "application/json" });
    const token = tokenInput.value.trim();
    if (token) headers.set("Authorization", `Bearer ${token}`);
    const response = await fetch("/api/v2/status", {
      headers,
      cache: "no-store",
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) {
      throw new Error(
        response.status === 401
          ? "Authentication required or token rejected"
          : `Status request failed (${response.status})`,
      );
    }
    renderStatus(await response.json());
    connectionState.textContent = "Connected";
  } catch (error) {
    connectionState.textContent = `Disconnected; showing last good data: ${error.message}`;
  } finally {
    if (!stopped) setTimeout(refresh, 2000);
  }
}

window.addEventListener("pagehide", () => { stopped = true; });
refresh();
```

Required static elements are a password-type `api-token` input, `connection-state` text element, and `resource-rows` tbody. Never put a token into a URL or persist it automatically in browser storage. For TUI, keep selected stable resource/backend ID instead of row index; bind drain/enable commands to that ID and expected revision; render snapshots under Unit J's terminal guard. API errors must reach the UI as structured command results.

### 3.14 Unit M - dispatch before startup and a typed HTTP command boundary

**Replaces:** `main`'s unconditional startup and the API's direct mutation of `AppState`. This complete invocation planner separates offline commands, daemon startup, and daemon-client commands before any side effect occurs.

```rust
use clap::{Parser, Subcommand, ValueEnum};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Dataplane {
    Kernel,
    UserspaceTcp,
}

#[derive(Debug, Parser)]
#[command(name = "nfty", version, about = "Configure and operate the nfty network daemon")]
pub struct Cli {
    #[arg(short, long, help = "Explicit configuration file; missing files are errors")]
    pub file: Option<PathBuf>,
    #[arg(long, default_value = "/run/nfty/control.sock", help = "Daemon control socket")]
    pub control_socket: PathBuf,
    #[arg(short, long, help = "Execute a noninteractive command batch through the daemon")]
    pub command: Option<String>,
    #[command(subcommand)]
    pub subcommand: Option<CliCommand>,
}

#[derive(Debug, Subcommand)]
pub enum CliCommand {
    Shell,
    Daemon {
        #[arg(long, default_value = "127.0.0.1:9090")]
        api_bind: SocketAddr,
        #[arg(long)]
        ssh_bind: Option<SocketAddr>,
        #[arg(long, value_enum, default_value = "kernel")]
        dataplane: Dataplane,
        #[arg(long, help = "Initialize Linux appliance resources; required when running as PID 1")]
        appliance: bool,
        #[arg(long, help = "Explicitly initialize an empty configuration if no file exists")]
        init_empty: bool,
    },
    Watch,
    Status,
    Validate {
        #[arg(long, help = "Also verify capabilities and run the platform's nft syntax check")]
        platform: bool,
    },
    Compile,
    Apply {
        #[arg(long, help = "Require confirmation within this many seconds")]
        confirm_seconds: Option<u64>,
    },
    Confirm { revision: u64 },
    Rollback { revision: u64 },
    Reload,
}

#[derive(Debug)]
pub enum OfflineCommand {
    Validate { platform: bool },
    Compile,
}

#[derive(Debug)]
pub enum ClientCommand {
    Shell,
    Watch,
    Status,
    Batch(String),
    Apply { file: PathBuf, confirm_seconds: Option<u64> },
    Confirm(u64),
    Rollback(u64),
    Reload,
}

#[derive(Debug)]
pub enum Invocation {
    Offline { file: PathBuf, command: OfflineCommand },
    Client { socket: PathBuf, command: ClientCommand },
    Daemon {
        file: PathBuf,
        socket: PathBuf,
        api_bind: SocketAddr,
        ssh_bind: Option<SocketAddr>,
        dataplane: Dataplane,
        appliance: bool,
        init_empty: bool,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum InvocationError {
    #[error("--command cannot be combined with a subcommand")]
    ConflictingMode,
    #[error("PID 1 must run 'daemon --appliance', not a client or offline command")]
    Pid1Mode,
    #[error("confirmation duration must be in 1..=86400 seconds")]
    ConfirmationDuration,
    #[error("--file is not used by this command")]
    UnusedFile,
}

pub fn plan_invocation(cli: Cli, is_pid1: bool) -> Result<Invocation, InvocationError> {
    if cli.command.is_some() && cli.subcommand.is_some() {
        return Err(InvocationError::ConflictingMode);
    }
    if let Some(batch) = cli.command {
        if is_pid1 { return Err(InvocationError::Pid1Mode); }
        if cli.file.is_some() { return Err(InvocationError::UnusedFile); }
        return Ok(Invocation::Client { socket: cli.control_socket, command: ClientCommand::Batch(batch) });
    }
    let explicit_file = cli.file.is_some();
    let file = cli.file.unwrap_or_else(|| PathBuf::from("Nftyfile"));
    let command = cli.subcommand.unwrap_or(CliCommand::Shell);
    if is_pid1 && !matches!(&command, CliCommand::Daemon { appliance: true, .. }) {
        return Err(InvocationError::Pid1Mode);
    }
    let client = match command {
        CliCommand::Daemon { api_bind, ssh_bind, dataplane, appliance, init_empty } => {
            return Ok(Invocation::Daemon {
                file, socket: cli.control_socket, api_bind, ssh_bind, dataplane, appliance, init_empty,
            });
        }
        CliCommand::Compile => return Ok(Invocation::Offline { file, command: OfflineCommand::Compile }),
        CliCommand::Validate { platform } => {
            return Ok(Invocation::Offline { file, command: OfflineCommand::Validate { platform } });
        }
        CliCommand::Apply { confirm_seconds } => {
            if confirm_seconds.is_some_and(|seconds| !(1..=86_400).contains(&seconds)) {
                return Err(InvocationError::ConfirmationDuration);
            }
            return Ok(Invocation::Client {
                socket: cli.control_socket,
                command: ClientCommand::Apply { file, confirm_seconds },
            });
        }
        CliCommand::Shell => ClientCommand::Shell,
        CliCommand::Watch => ClientCommand::Watch,
        CliCommand::Status => ClientCommand::Status,
        CliCommand::Confirm { revision } => ClientCommand::Confirm(revision),
        CliCommand::Rollback { revision } => ClientCommand::Rollback(revision),
        CliCommand::Reload => ClientCommand::Reload,
    };
    if explicit_file {
        return Err(InvocationError::UnusedFile);
    }
    Ok(Invocation::Client { socket: cli.control_socket, command: client })
}
```

Preserve zero-flag appliance and LXD ergonomics: PID 1 / `--unikernel` boots directly into appliance mode and initializes an empty `/data/Nftyfile` when none exists yet (failing only when an explicitly passed `--file <path>` is missing), and running `nfty` with no arguments inside a container (`lxc exec nfty -- nfty`) opens the interactive shell without requiring explicit `--control-socket` or `--init-empty` flags.

`Offline::Compile` reads syntax/validated intent and explicit resolution inputs only. `Validate { platform: false }` never runs controllers. `platform: true` may inspect capabilities/run `nft --check` but does not apply configuration or start listeners. Daemon startup acquires its singleton lease, validates storage/capabilities, recovers Unit C, binds declared control endpoints, starts required controllers in every supported deployment mode, and publishes readiness only after acknowledgement.

The HTTP adapter should expose typed requests and forward them to the same command port:

```rust
use async_trait::async_trait;
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::runtime::status::StatusSnapshot;

#[derive(Debug, Clone)]
pub struct Principal {
    pub id: String,
    pub scope: PermissionScope,
    pub authenticated_revision: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionScope {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, Serialize)]
pub struct Operation {
    pub id: String,
    pub requested_revision: u64,
    pub state: OperationState,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OperationState {
    Queued,
    Preparing,
    Applying,
    AwaitingConfirmation,
    Succeeded,
    Failed,
    Recovering,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaceCandidate {
    pub expected_revision: u64,
    pub expected_candidate_revision: u64,
    pub nftyfile: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitRequest {
    pub request_id: String,
    pub session_id: String,
    pub expected_revision: u64,
    pub expected_candidate_revision: u64,
    pub confirm_seconds: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct CandidateView {
    pub session_id: String,
    pub base_revision: u64,
    pub candidate_revision: u64,
    pub validation_errors: Vec<FieldDiagnostic>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FieldDiagnostic {
    pub path: String,
    pub code: String,
    pub message: String,
    pub line: Option<usize>,
    pub column: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub api_version: u32,
    pub code: &'static str,
    pub message: String,
    pub diagnostics: Vec<FieldDiagnostic>,
}

pub struct ApiError {
    pub status: StatusCode,
    pub body: ErrorBody,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status;
        let mut response = (status, Json(self.body)).into_response();
        if status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static("Bearer realm=\"nfty\""),
            );
        }
        response
    }
}

fn write_required(principal: &Principal) -> Result<(), ApiError> {
    if principal.scope == PermissionScope::ReadWrite {
        return Ok(());
    }
    Err(ApiError {
        status: StatusCode::FORBIDDEN,
        body: ErrorBody {
            api_version: 2,
            code: "permission_denied",
            message: "this operation requires write permission".into(),
            diagnostics: Vec::new(),
        },
    })
}

#[async_trait]
pub trait ControlPort: Send + Sync {
    async fn status(&self, principal: &Principal) -> Result<StatusSnapshot, ApiError>;
    async fn replace_candidate(
        &self, principal: &Principal, session: &str, request: ReplaceCandidate,
    ) -> Result<CandidateView, ApiError>;
    async fn commit(&self, principal: &Principal, request: CommitRequest) -> Result<Operation, ApiError>;
    async fn confirm(&self, principal: &Principal, revision: u64) -> Result<Operation, ApiError>;
    async fn revert(&self, principal: &Principal, revision: u64) -> Result<Operation, ApiError>;
    async fn operation(&self, principal: &Principal, id: &str) -> Result<Operation, ApiError>;
}

type ApiState = Arc<dyn ControlPort>;

pub trait CredentialVerifier: Send + Sync {
    fn verify(&self, endpoint_id: &str, token: &str) -> Result<Principal, ApiError>;
}

#[derive(Clone)]
pub struct AuthenticationState {
    pub endpoint_id: Arc<str>,
    pub credentials: Arc<dyn CredentialVerifier>,
    pub request_timeout: std::time::Duration,
}

fn api_error(status: StatusCode, code: &'static str, message: impl Into<String>) -> ApiError {
    ApiError {
        status,
        body: ErrorBody {
            api_version: 2,
            code,
            message: message.into(),
            diagnostics: Vec::new(),
        },
    }
}

async fn authenticate(
    State(auth): State<AuthenticationState>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let token = match bearer_token(request.headers()) {
        Ok(token) => token,
        Err(error) => {
            let status = match error {
                BearerError::Missing | BearerError::UnsupportedScheme => StatusCode::UNAUTHORIZED,
                BearerError::Duplicate | BearerError::Encoding | BearerError::Syntax => StatusCode::BAD_REQUEST,
            };
            return api_error(status, "invalid_authorization", error.to_string()).into_response();
        }
    };
    let principal = match auth.credentials.verify(&auth.endpoint_id, token) {
        Ok(principal) => principal,
        Err(error) => return error.into_response(),
    };
    request.extensions_mut().insert(principal);
    match tokio::time::timeout(auth.request_timeout, next.run(request)).await {
        Ok(response) => response,
        Err(_) => api_error(StatusCode::REQUEST_TIMEOUT, "request_timeout", "request deadline expired").into_response(),
    }
}

fn json_request<T>(
    value: Result<Json<T>, axum::extract::rejection::JsonRejection>,
) -> Result<T, ApiError> {
    value.map(|Json(value)| value).map_err(|rejection| {
        api_error(rejection.status(), "invalid_request_body", rejection.body_text())
    })
}

fn path_value<T>(
    value: Result<Path<T>, axum::extract::rejection::PathRejection>,
) -> Result<T, ApiError> {
    value.map(|Path(value)| value).map_err(|rejection| {
        api_error(rejection.status(), "invalid_path", rejection.body_text())
    })
}

async fn status(
    State(control): State<ApiState>,
    Extension(principal): Extension<Principal>,
) -> Result<Json<StatusSnapshot>, ApiError> {
    Ok(Json(control.status(&principal).await?))
}

async fn replace_candidate(
    State(control): State<ApiState>,
    Extension(principal): Extension<Principal>,
    session: Result<Path<String>, axum::extract::rejection::PathRejection>,
    request: Result<Json<ReplaceCandidate>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<CandidateView>, ApiError> {
    write_required(&principal)?;
    let session = path_value(session)?;
    let request = json_request(request)?;
    Ok(Json(control.replace_candidate(&principal, &session, request).await?))
}

async fn commit(
    State(control): State<ApiState>,
    Extension(principal): Extension<Principal>,
    request: Result<Json<CommitRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<Operation>), ApiError> {
    write_required(&principal)?;
    let request = json_request(request)?;
    Ok((StatusCode::ACCEPTED, Json(control.commit(&principal, request).await?)))
}

async fn confirm(
    State(control): State<ApiState>,
    Extension(principal): Extension<Principal>,
    revision: Result<Path<u64>, axum::extract::rejection::PathRejection>,
) -> Result<(StatusCode, Json<Operation>), ApiError> {
    write_required(&principal)?;
    let revision = path_value(revision)?;
    Ok((StatusCode::ACCEPTED, Json(control.confirm(&principal, revision).await?)))
}

async fn revert(
    State(control): State<ApiState>,
    Extension(principal): Extension<Principal>,
    revision: Result<Path<u64>, axum::extract::rejection::PathRejection>,
) -> Result<(StatusCode, Json<Operation>), ApiError> {
    write_required(&principal)?;
    let revision = path_value(revision)?;
    Ok((StatusCode::ACCEPTED, Json(control.revert(&principal, revision).await?)))
}

async fn operation(
    State(control): State<ApiState>,
    Extension(principal): Extension<Principal>,
    id: Result<Path<String>, axum::extract::rejection::PathRejection>,
) -> Result<Json<Operation>, ApiError> {
    let id = path_value(id)?;
    Ok(Json(control.operation(&principal, &id).await?))
}

pub fn control_routes(control: ApiState, authentication: AuthenticationState) -> Router {
    Router::new()
        .route("/api/v2/status", get(status))
        .route("/api/v2/sessions/{session}/candidate", put(replace_candidate))
        .route("/api/v2/commits", post(commit))
        .route("/api/v2/commits/{revision}/confirm", post(confirm))
        .route("/api/v2/commits/{revision}/revert", post(revert))
        .route("/api/v2/operations/{id}", get(operation))
        .route_layer(axum::middleware::from_fn_with_state(authentication, authenticate))
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024))
        .with_state(control)
}

#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum BearerError {
    #[error("missing Authorization header")]
    Missing,
    #[error("duplicate Authorization headers")]
    Duplicate,
    #[error("invalid Authorization encoding")]
    Encoding,
    #[error("expected Bearer authentication")]
    UnsupportedScheme,
    #[error("expected exactly one nonempty Bearer token")]
    Syntax,
}

pub fn bearer_token(headers: &HeaderMap) -> Result<&str, BearerError> {
    let mut values = headers.get_all(axum::http::header::AUTHORIZATION).iter();
    let value = values.next().ok_or(BearerError::Missing)?;
    if values.next().is_some() {
        return Err(BearerError::Duplicate);
    }
    let value = value.to_str().map_err(|_| BearerError::Encoding)?;
    let (scheme, token) = value.split_once(' ').ok_or(BearerError::Syntax)?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(BearerError::UnsupportedScheme);
    }
    if token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(BearerError::Syntax);
    }
    Ok(token)
}
```

The credential verifier reads one committed endpoint-specific credential snapshot, performs no external I/O, and supplies its authentication revision. The command port revalidates permission if that revision is no longer current before accepting a mutation. Local Unix-socket identity comes from peer credentials/session authorization, never an HTTP header. Add the remaining typed query/job/credential/provider resources from section 4 through the same port pattern, not a second state writer. Also normalize router 404/405 responses and enforce the HTTP transport's header/connection limits; body size alone is not a slow-client deadline.

The `ControlPort` implementation owns session authorization, validation, both candidate/committed revision checks, operation IDs, and bounded queue admission. It delegates commits to Unit C and queries to Unit L. It must not return `202` unless the operation is durably/authoritatively accepted and retrievable, nor return an operation belonging to another unauthorized session. Deduplicate commit `request_id` by principal and request digest so a timed-out accepted request can be retried without creating another operation; a request timeout must not silently cancel an already accepted commit.

## 4. CLI, Config & API Contract Overhaul

### 4.1 Normative configuration and operation rules

1. **Parsing is pure.** Parse text to syntax with spans, lower to desired types, then validate the entire object graph. Name resolution, leases, filesystem resources, credential generation, and platform capability discovery are separate inputs/effects.
2. **Validation is complete and shared.** CLI, REPL, API JSON, file import, and provider import all use the same constructors and graph validator. `#[serde(default)]` supports schema evolution but is not a substitute for semantic validation; `deny_unknown_fields` prevents misspelled fields becoming silently unused configuration.
3. **A candidate is session-owned.** Replace/edit requires the base committed revision. An empty committed config remains active until another config is committed. Candidate auth/listeners/probes are never live.
4. **Apply has an operation identity.** Prepare all required local resources and verify tool capabilities before activation; persist recovery intent before effects; publish applied revision only after acknowledgement. Return a recoverable failure if any required step fails. Cloudflare convergence is a separate declared asynchronous dependency/status, not silent work spawned from nft compilation.
5. **Confirmed apply is durable.** Record baseline, trial, revision, initiator, and deadline. Any restart with unconfirmed state reverts before ordinary writes. Confirmation requires the exact trial revision and a live deadline. Rollback is itself a new revision and durable operation.
6. **Scoped API key visibility and secret redaction.** Logged-in REPL/SSH sessions and `rw` (read-write) API keys can view `ro` and `rw` `api:<port>` keys inside `show`, `Nftyfile`, `/api/v1/config`, and `/api/v1/status`, whereas `ro` (read-only) API keys can view `ro` keys and have `rw` keys redacted. WireGuard private/preshared keys and service Basic Auth passwords remain redacted in unprivileged status DTOs.
7. **Default behavior is explicit and ergonomic.** TCP services default to `tcp 5s` health probing unless `no check` / `check off` is explicitly set (and disabled checks round-trip losslessly); UDP services and direct gateways do not false-probe TCP; explicit empty DNS upstream is not default resolvers; unleased DHCP is not wildcard; all-drained is not fail-open.
8. **Incremental, non-breaking evolution.** Preserve `/api/v1/*` routes, brace-less and inline REPL forms, natural `ip:port` / `vip` service and gateway keys, and zero-flag appliance/LXD startup (`lxc exec nfty -- nfty`) while fixing state synchronization, protocol framing, and persistence bugs in place.

### 4.2 Validation rules that are currently missing or inconsistent

| Area | Validation required before a plan exists |
|---|---|
| Scalar bounds | Listen/backend ports nonzero; bounded weights and checked total; valid prefix/VLAN/interface byte length; nonzero intervals/timeouts; bounded rate/burst/cache/job sizes; no overflow or silent clamp |
| Identity | Stable entity IDs, URI/body consistency for compatibility API, map key consistency, unique allocated nft names, unique owned interface/mark/table/rule priority |
| References | Every VIP/service/gateway/tunnel/forward/DNS-route/credential reference resolves; referenced WG file exists and is valid; removed resources have no live desired references |
| Listener ownership | Address/port/protocol conflicts, wildcard versus specific bind overlap, L7 sharing versus separate service listeners, custom API/SSH/DNS internal target mapping |
| Address state | Static and DHCP mutually exclusive; required DHCP lease unresolved means waiting; no `0.0.0.0` backend sentinel; address family compatible with transport/kernel plan |
| Authentication | Basic Auth only on message-aware HTTP termination; no Basic Auth on TLS passthrough or raw nft forwarding; keys only on credential-capable endpoints; endpoint scope and principal permissions explicit |
| Egress | Direct versus tunnel modes exclusive; supported probe kind/target; explicit direct fallback; route scope unambiguous; all private/local network policies centralized; DNS resolution follows egress policy |
| WireGuard import | Supported sections and peer count; every required key/address/endpoint valid; unsupported fields rejected with source line; explicit AllowedIPs/MTU/keepalive behavior; secret file permissions |
| DNS | Valid names/address families, record arity/numeric options, escaped TXT, explicit multi-string TXT policy, no contradictory record ownership, safe blocklist names/URLs, bounded fetches, known nftset/gateway binding |
| Provider | Explicit account choice, supported token permissions, requested authentication mode, owned-resource/adoption policy, origin scheme/TLS verification, credential generation invalidates dependent controller state |
| Platform | Required tools/features/kernel modules/capabilities available; persistence mounted and writable; external shared resources identified; `ip_forward` and rp_filter policy deliberate |
| Command source | Interactive commands rejected from API/script-only paths; exact arity; complete command result and nonzero failure exit status |

Validation returns **all independent field diagnostics** with path and source position, then stops before mutation. Do not use a syntax-valid nft ruleset as a proxy for complete configuration validity.

### 4.3 HTTP contract specification and compatibility mapping

Keep `/api/v1/*` as the primary, first-class HTTP contract backed by a single coordinator boundary; optional `/api/v2` session/operation endpoints may be layered on top without deprecating or breaking `/api/v1/*`.

| Resource | Methods / behavior | Permissions and status |
|---|---|---|
| `/api/v1/status` (`/status`) | GET runtime & config snapshot with scoped API key redaction | Read (`ro` or `rw`); 200; `ro` redacts `rw` API keys |
| `/api/v1/config` (`/config`) | GET running/candidate config with scoped API key redaction | Read (`ro` or `rw`); 200; `rw` sees `ro`+`rw` keys, `ro` redacts `rw` keys |
| `/sessions` | POST create candidate session from an expected committed revision | Write; 201 + Location |
| `/sessions/{id}/candidate` | GET candidate metadata; PUT complete candidate; PATCH typed edits if introduced | Session-authorized; 200/204; expected revision mandatory |
| `/sessions/{id}/validation` | POST semantic/platform-check operation with explicit mode | Authorized session; 200 for completed pure validation, 202 for queued platform verification |
| `/commits` | POST commit candidate with optional bounded confirmation duration | Write; 202 + operation Location, or synchronous 200 only after verified completion |
| `/commits/{revision}/confirm` | POST confirm exact pending trial | Write and authorized initiator/admin policy; conflict/expired are not success |
| `/commits/{revision}/revert` | POST revert trial or request historical rollback under an explicit request type | Write; new revision; durable result |
| `/operations/{id}` | GET accepted/running/completed/error/recovery outcome | Authorized requester/admin; 200 or 404 |
| `/flows` | GET paginated/filterable observations with source/availability/truncation | Read; no scanning or persistence |
| `/scans` | POST bounded scan job | Operate/RW; 202; explicit scope, port set, limits |
| `/scans/{id}` | GET results; optional DELETE cancel owned job | Read/authorized job owner; discovery does not mutate config |
| `/backends/{id}/administrative-state` | PUT enabled/drained with revision | Write; exact target; no success for unknown ID |
| `/probes` | POST explicit probe job; GET job results through operations | Operate/RW; no config persistence |
| `/host-registrations/{name}` | GET/PUT/DELETE authoritative registration | Separate from resolver cache; clear deletion semantics |
| `/resolutions` | GET resolver observations; POST refresh job if needed | Read for query; RW for external work |
| `/tunnels` / `/tunnels/{id}` | Metadata query; validated import/edit/delete commands | Read DTOs never include private/preshared keys; live-reference deletion conflict |
| `/providers/cloudflare` | GET desired/observed metadata; PATCH explicit set/clear operations | Secret fields write-only; reconcile is an operation, not a log array with 200 |
| `/credentials` / `/credentials/{id}` | Create/rotate/revoke and list metadata | Privileged write; token returned only on creation/rotation; revocation binds to committed policy |
| `/commands` | Optional typed noninteractive command batch | Same registry/parser/result model as CLI; no editor/TUI/password prompt execution |

Current `/allow` and `/services/<key>` mutations translate to candidate edits plus an explicit commit request; legacy `apply=true` can map to a transactional edit+commit, not direct assignment. URI key must match body key during the compatibility period. Legacy GET scan must be removed or return an explicit migration error; do not retain side effects behind GET.

**Status/error rules:** 400 malformed syntax/body/header; 401 missing/invalid credentials with challenge; 403 authenticated but forbidden; 404 missing resource; 405 known path/wrong method with Allow; 408 inbound request deadline; 409 revision/resource/confirmation conflict; 413 body too large; 415 unsupported media type; 422 semantic config errors; 428 required revision precondition absent; 429 bounded queue/rate admission; 503 unavailable required controller/tool; 504 upstream/operation deadline; 500 unexpected internal error with an operation ID, not a debug dump. A validation report containing errors is never an applied configuration.

Make header/query behavior deterministic: exactly one supported Authorization header; no token in query strings; reject ambiguous duplicate lengths through the HTTP stack; normalize content type; use configured header/body/time/concurrency budgets; bind authentication to the actual listener and committed snapshot. Versioned aliases have identical authorization and error behavior.

### 4.4 Concrete diffs for build continuity and existing contract defects

These are **proposed diffs inside the report**, not applied changes.

#### Canonical protocol/scope traits

```diff
--- a/src/ast.rs
+++ b/src/ast.rs
@@
-#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
+#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
 pub enum Proto {
@@
+impl ApiKeyScope {
+    pub const fn as_str(self) -> &'static str {
+        match self {
+            Self::ReadOnly => "ro",
+            Self::ReadWrite => "rw",
+        }
+    }
+}
```

Replace the existing `ApiKeyScope` Display body with `f.write_str(self.as_str())`; retain its current serde aliases during migration. Unit B supplies the complete `RateLimit` Display replacement.

#### Gateway borrow lifetime and all-or-nothing editing

The complete replacement for the trailing mutation section of `handle_gateway_level_command` (`src\repl\mod.rs:2043-2078`) is:

```rust
let mut st = shared.write().map_err(|_| anyhow::anyhow!("configuration state is unavailable"))?;
let mut proposed = st.candidate.gateways.get(gw_key).cloned()
    .ok_or_else(|| anyhow::anyhow!("Gateway '{gw_key}' no longer exists"))?;
apply_gateway_directive(&mut proposed, trimmed)?;
let generated_key = if matches!(first_lower.as_str(), "key" | "api-key" | "apikey") {
    proposed.services.iter()
        .find(|service| service.kind == GatewayServiceKind::Api)
        .and_then(|service| service.api_keys.last().map(|key| (service.port, key.clone())))
} else {
    None
};
st.candidate.gateways.insert(gw_key.to_owned(), proposed);
st.sync_runtime_entries();
drop(st);
if let Some((port, key)) = generated_key {
    println!("gateway {gw_key} -> api:{port}: key {} ({})", key.key, key.scope);
} else {
    println!("gateway {gw_key}: {trimmed}");
}
Ok(())
```

This preserves the existing immediate command-output convention while removing the borrow error and partial entity mutation. Whole-config validation and removal of candidate-to-runtime synchronization follow in the coordinator migration; do not call this isolated build repair the final ownership fix.

#### Test actual JSON shape, not a nonexistent Value method

```diff
--- a/src/main.rs
+++ b/src/main.rs
@@
-        assert!(body_ro_get.contains(&ro_key));
-        assert!(!body_ro_get.contains(&rw_key));
+        let ro_keys = body_ro_get["running"]["services"]["169.254.1.4:9090"]["api_keys"]
+            .as_array().expect("config response contains an API key array");
+        assert_eq!(ro_keys[0]["key"].as_str(), Some(ro_key.as_str()));
+        assert_ne!(ro_keys[1]["key"].as_str(), Some(rw_key.as_str()));
+        assert!(!body_ro_get.to_string().contains(&rw_key));
@@
-        assert!(body_rw_get.contains(&ro_key));
-        assert!(body_rw_get.contains(&rw_key));
+        let rw_keys = body_rw_get["running"]["services"]["169.254.1.4:9090"]["api_keys"]
+            .as_array().expect("config response contains an API key array");
+        assert_eq!(rw_keys[0]["key"].as_str(), Some(ro_key.as_str()));
+        assert_eq!(rw_keys[1]["key"].as_str(), Some(rw_key.as_str()));
```

This verifies the required scoped key-visibility contract: `rw` callers can inspect both `ro` and `rw` `api:<port>` keys in `/api/v1/config`, while `ro` callers can view `ro` keys and have `rw` keys redacted. Endpoint authentication should also be tested through the HTTP transport/header parser in addition to direct router calls.

#### Correct the existing standalone example, then migrate the lifecycle contract

```diff
--- a/README.md
+++ b/README.md
@@
-sudo ./dist/standalone/nfty --file /etc/nfty/Nftyfile --apply --daemon
+sudo ./dist/standalone/nfty --file /etc/nfty/Nftyfile daemon
```

After Unit M lands, the explicit bind belongs to daemon arguments and reload must call the coordinator:

```diff
--- a/packaging/standalone/nfty.service
+++ b/packaging/standalone/nfty.service
@@
-ExecStart=/usr/local/bin/nfty --file /etc/nfty/Nftyfile --api-bind 127.0.0.1:9090 daemon
-ExecReload=/bin/kill -HUP $MAINPID
+ExecStart=/usr/local/bin/nfty --file /etc/nfty/Nftyfile daemon --api-bind 127.0.0.1:9090
+ExecReload=/usr/local/bin/nfty --control-socket /run/nfty/control.sock reload
```

The new reload client must wait for an actual operation result and return nonzero on failure. Do not add this ExecReload line before implementing the command.

#### Prevent accidental addition of the actual fallback host key

```diff
--- a/.gitignore
+++ b/.gitignore
@@
 nfty-auth.json
 nfty-cloudflare.json
+nfty_ssh_host_ed25519_key
```

Prefer eliminating cwd-based credential fallback entirely through an explicit credential-store directory. Ignore rules are a secondary safeguard, not the credential storage architecture.

### 4.5 Dependency and build structure specification

Keep one package initially. Add a library boundary so pure parser/formatter/planner/reducer tests do not require executable startup. Make the Linux adapters explicit and keep presentation/provider dependencies out of offline code paths.

Existing dependency declarations and the entire resolved graph were reviewed (`Cargo.toml:1-24`; `Cargo.lock:1-2954`). Multiple transitive versions are not automatically a defect. Do not spend the architecture budget on cosmetic deduplication. The meaningful build problems are the incompatible documented MSRV, missing feature/capability separation, no reproducible toolchain contract, and no isolated verification harness.

Keep the dependency footprint minimal to preserve fast builds and small static musl unikernel binaries. Prefer fixing protocol framing, HTTP parsing, and routing in place with existing dependencies (`tokio`, `serde`, `serde_json`, `ureq`, `clap`, `anyhow`, `libc`); treat any external crates below strictly as optional future candidates only if a specific subsystem warrants them:

```toml
# Optional future candidates only — do NOT add all of these to the static musl unikernel build:
# thiserror = "2"
# httparse = "1"
```

Use one HTTP client abstraction rather than leaving ureq and reqwest implementations of the same provider contract indefinitely. A maintained DNS codec and password KDF should be selected when those adapters land; do not hand-maintain another DNS/base64/TLS-auth implementation merely to avoid a small dependency. Resolve/pin the resulting graph with Cargo, choose the measured MSRV, add `rust-version` and a toolchain pin, and test both supported Linux targets. Do not manually edit the lockfile.

### 4.6 Packaging, configuration files, and distribution continuity

| ID / priority | File and exact evidence | Required remediation |
|---|---|---|
| P01 / P1 | Standalone unit sends unhandled SIGHUP (`packaging\standalone\nfty.service:9`); only PID1 installs SIGPWR/TERM/INT handlers (`src\unikernel.rs:190-198`). | Use a real reload command or a deliberately implemented signal-to-coordinator path; verify failed reload retains the previous revision. |
| P02 / P1 | Standalone starts no advanced daemon set; forwarding enablement is only `src\unikernel.rs:298` (`src\main.rs:153-174,201-221`). | Capability-driven daemon composition independent of PID1; explicit required sysctl management/validation. `apply_wireguard_gateways` does not itself enable forwarding. |
| P03 / P1 | LXD data migration copies only top-level regular files and ignores pull failures (`packaging\deploy-lxd.sh:34-47`). `wg` and other subdirectories/hidden files are lost despite the preservation claim at line 66. | Snapshot/archive the complete data tree with metadata; verify manifest/checksums and restore before switching mounts/rootfs. Keep old volume/image until health and revision verification succeed. |
| P04 / P1 | Deployment uses `lxc image delete` where alias deletion/promotion is intended (`packaging\deploy-lxd.sh:29,57-60`). Staging/final aliases can point to the same fingerprint. | Use alias operations for alias changes; identify images by immutable fingerprint; never delete the promoted image through a staging alias. |
| P05 / P2 | Fixed remote defaults, pool, staging alias and `/tmp` paths; unquoted interpolated remote identifiers; `sleep 3` plus `lxc list` as readiness (`packaging\deploy-lxd.sh:7-10,16-64`). | Validated arguments, unique deployment workspace/lock, explicit pool, real API/control readiness and expected durable revision; bounded rollback on failure. |
| P06 / P2 | Standalone archive is always named linux-x86_64 while `cargo build --release` uses the host target (`packaging\standalone\build-standalone.sh:10-18`). | Select/verify target triple, derive artifact naming from it, include runtime capability/dependency manifest and license notices. |
| P07 / P1 | x86 image silently omits optional BusyBox/nft/WG/dnsmasq/editor inputs; assumes `/usr/bin/nft` and `/usr/bin/dnsmasq`; WG shared libraries are not collected; dynamic loader handling is nested in nft inclusion (`packaging\unikernel\build-unikernel.sh:31-91`). | Required feature manifest and preflight; fail missing required tools; inspect every packaged executable's interpreter/library closure and actual compiled capabilities. Do not equate file existence with working functionality. |
| P08 / P1 | x86 kernel is a hardcoded host kernel with first-glob fallback, no matching modules/modprobe applet, and a fixed 64 MiB boot partition (`packaging\unikernel\build-unikernel.sh:34,122-154`). | Pinned kernel/config/module set, dependency-complete initramfs, computed capacity checks, boot smoke tests. A static Rust binary does not make the complete appliance self-contained. |
| P09 / P2 | Image maps `/bin/sh`, `/bin/bash`, `/bin/su` to nfty, not a shell (`packaging\unikernel\build-unikernel.sh:23-29`; `packaging\rk3588s\build-rk3588s.sh:118-124`). | Specify exactly which compatibility entry points nfty implements; package a real shell if any helper/hook expects shell syntax. Verify udhcpc hook invocation end-to-end. |
| P10 / P2 | ARM package filenames mix stable/edge inputs and latest cloudflared; downloads have no checksum/signature manifest; extraction failures are suppressed (`packaging\rk3588s\build-rk3588s.sh:27-85,159-177`). | Pin immutable artifacts and digests, verify downloads/extractions, record provenance, and fail incomplete rootfs assembly. No claim is made here that a particular remote URL currently fails. |
| P11 / P1 | Unknown/default board uses Orange Pi DTB; generic bootloader payload is Rock5b RK3588; requested optional EDK2 can fall back; kernel extraction searches gzip magic (`packaging\rk3588s\build-rk3588s.sh:74-77,208-235,354-360`). | Validated board/SoC/firmware/DTB matrix, explicit unsupported-board error, no silent firmware-mode downgrade, verified kernel image format and size. Do not advertise "universal" boot support without hardware evidence. |
| P12 / P2 | ARM includes vi but editor paths request nano (`packaging\rk3588s\build-rk3588s.sh:89-96`; `src\features\wireguard.rs:338-417`). CA/terminfo inputs are opportunistic. | Editor capability selection and explicit fallback order; validate terminal/CA requirements for enabled SSH/provider features. |
| P13 / P1 | `packaging\unikernel\ops_config.json:11` names missing `Nftyfile.example`; its `/Nftyfile` path differs from normal persistent convention (`1-21`). | Either retire the stale packaging target explicitly or maintain a real example and prove this boot/runtime model supports required Linux features. Do not keep an unverified second appliance contract. |
| P14 / P2 | `.cargo\config.toml:1-7` hardcodes cross tools but no tested toolchain/sysroot provisioning; README prerequisites omit parts of the full image chain (`README.md:303-313`). | Hermetic target toolchain manifest and preflight for Rust/C/linker/kernel/image/firmware tools. Validate static/dynamic closure per artifact. |
| P15 / P2 | `.gitignore:1-8` omits the actual private host-key fallback (`src\ssh.rs:452-480`); obsolete CF fallback naming remains. | Explicit state directory and the narrowly scoped ignore correction above; verify no generated credentials enter artifacts or source control. |
| P16 / P2 | `Cargo.toml:1-6` lacks license metadata; packaging copy/archive steps omit repository license and bundled-component notices. `LICENSE:1-201` is Apache-2.0. | Add appropriate package license metadata and include applicable license/provenance notices in distribution manifests. This is distribution continuity, not a legal compliance certification. |
| P17 / P1 | PID1 chooses the first available partition-2 candidate rather than the declared `nfty-data` label/UUID and can continue on ephemeral `/data` (`src\unikernel.rs:190-313`; image labels in both builders). | Resolve the intended storage identity, verify filesystem/mount and durable-write readiness, and expose degraded boot instead of claiming persisted operation. |

A deployment sequence should be: validate artifact manifest -> create immutable full data backup -> provision candidate image/volume -> verify boot and control-plane readiness -> verify migrated config/credential/resource identity -> switch -> retain rollback assets for an explicit interval -> clean up only known owned staging artifacts. The current fixed sleep, partial copy, and image deletion sequence does not meet that contract.

## 5. Comprehensive Engineering Execution Plan

### 5.1 Sequencing and change-control rules

Do not begin by splitting the biggest file into arbitrary smaller files. First make invalid states/errors explicit, then establish one owner for effects, then extract functions behind those boundaries, and finally change user-facing contracts with migration tests. Each pull request should have one behavioral invariant and a compatibility statement.

The dependency graph is:

```text
S1.1 build/test boundary
  -> S1.2 domain identities and capability model
  -> S1.3 error and diagnostic hierarchy
  -> S1.4 pure syntax / validated intent / canonical output

S1.2 + S1.3 + S1.4
  -> S2.1 revisioned coordinator and candidate sessions
  -> S2.2 durable journal and independent confirmation deadline
  -> S2.3 owned platform/resource controllers
  -> S2.4 generation-safe observations and shared status

S2.1 + S2.3 + S2.4
  -> S3.1 parser/command decomposition
  -> S3.2 nft/WG/DHCP/DNS planning decomposition
  -> S3.3 protocol parsing and relay decomposition
  -> S3.4 provider/SSH/PID1/presentation decomposition

S1.4 + S2.2 + relevant S3 units
  -> S4.1 CLI/API/config compatibility adapters
  -> S4.2 every-field/every-route contract tests
  -> S4.3 documentation and distribution alignment
  -> S4.4 isolated end-to-end qualification and rollout
```

S1.3 can proceed alongside S1.2 after the build boundary exists; pure fixtures and packaging manifests can be prepared in parallel without changing runtime behavior. Do not parallelize competing rewrites of `AppState`/apply/persistence across independent branches without agreeing on the coordinator contract first.

### Stage 1: Domain Model, Types & Error Hierarchy Standardization

| Work item | Prerequisites | Engineering work and completion gate |
|---|---|---|
| S1.1 Restore build continuity and isolate tests | None | Fix B01-B04 with minimal behavior change. Introduce `src\lib.rs` and move pure tests out of executable startup. Separate tests that require platform effects. Gate: all targets including test code type-check; pure tests invoke zero process/network/storage adapters. |
| S1.2 Establish the domain vocabulary | S1.1 | Stable service/backend/VIP/gateway/tunnel/credential IDs; explicit local endpoint kind, address mode, target resolution, uplink/origin/auth capability, bounded scalar types, separate administrative drain. Covers C09-C17/C30-C32, R07/R10, N01/N05/N06/N11. Gate: invalid combinations cannot construct a validated plan and IDs survive address/display/order changes. |
| S1.3 Standardize errors and effect outcomes | S1.1 | Typed syntax/validation/permission/conflict/capability/process/provider/persistence/recovery errors; source chains and operation IDs; no simulated success on unavailable tools. Covers R04/R16, U01/U04/U10/U11, C22/C25. Gate: each injected failure produces an explicit failure/recovery state and no false applied revision. |
| S1.4 Separate syntax, intent, observations, and canonical output | S1.2 + S1.3 | Quote-aware bounded grammar, exact arity, all-or-nothing lowering, explicit defaults/clearing, full semantic serializer. Remove DNS/lease/ip-command reads from parser/AST. Covers C03-C10/C18-C20/C28/C29/C33, U06/U07. Gate: every stored field survives semantic round-trip, and pure parsing/formatting performs no external I/O. |
| S1.5 Define credential and import schemas | S1.2 + S1.3 | Versioned credential store and modern password KDF; explicit missing/corrupt/unsupported version; strict WG supported schema; provider configuration versus observations; safe names and paths. Covers C08/C24/C25/C31, R16, N15, P15. Gate: malformed persisted data cannot initialize default credentials or silently discard imported intent. |
| S1.6 Establish measured toolchain contract | S1.1 | Resolve/document actual MSRV and target toolchains, add `rust-version`/pin, validate lockfile; select only dependencies used by extracted units. Covers B05/P14/P16. Gate: documented oldest toolchain consumes the lockfile and checks all declared supported targets. |

**Stage 1 acceptance examples:** global rate limit round-trips as global; explicit `/20` on eth0 remains `/20`; disabled check remains disabled; empty upstream remains empty; local SSH policy survives formatting; partial inline WG is rejected; duplicate nft resource name is rejected before `nft`; a backend IP change does not change administrative ID; a TXT value containing quote, semicolon, hash, backslash, and UTF-8 survives within the declared wire-size policy.

### Stage 2: Module Decoupling & State Ownership Restructuring

| Work item | Prerequisites | Engineering work and completion gate |
|---|---|---|
| S2.1 Single daemon writer and immutable read snapshots | S1.2-S1.4 | Bounded command port; per-session candidates with revision checks; CLI/SSH/TUI/API become clients; remove candidate fallback and disk-as-running refresh. Covers R01/R02/R05/R06, U02/U03, C12/C29. Gate: one writer owns effects; creating/editing a candidate starts no listener/probe/auth policy. |
| S2.2 Durable persistence and confirmed commits | S2.1 + S1.5 | Atomic store, configured paths including empty config, intent/recovery journal, independent deadline, startup recovery, bounded history, no persistence-to-IPC edge. Covers C01/C02/C24, R03/R08, U02, P17. Gate: disconnect/restart/crash at every transaction step yields committed baseline, confirmed target, or explicit recoverable degraded state; never silent divergence. |
| S2.3 Owned local resource controllers | S2.1 + S2.2 | One allocation ledger for WG interfaces/marks/tables/rules; owned VIP/VLAN/macvlan/DHCP lifecycle; stable nftsets/counters; one listener registry and retained child processes; explicit capability plan. Covers R09-R15, C11-C19/C23, N01-N06/N11, P01/P02/P07-P09/P12. Gate: unrelated `wg*`/`mv-*` resources remain untouched and unchanged managed resources are not recreated. |
| S2.4 Generation-safe observations and status | S2.1 + S2.3 | Separate health, resolver cache, DHCP observations, measurements, discovery jobs, and public status projection; one scheduler/sampler per subject. Covers R07/R18-R20, U09, C16-C18, N14. Gate: delayed old probes cannot affect current routing; all views agree on readiness/drain/selection and measurement source. |
| S2.5 Single provider reconciler and credential generation | S2.2 + S2.3 | Coalesced Cloudflare generations, typed errors, explicit ownership/adoption, durable pending deletions, no auth downgrade, retained connector child. Covers C21-C23, R13, N10, U10. Gate: timeout/retry cannot silently orphan/duplicate/adopt resources; requested Access policy never becomes Basic Auth automatically. |
| S2.6 Process/session lifecycle | S2.1 + S2.3 + S1.5 | Owned PTY descriptors and child sessions, daemon-client SSH shell, terminal RAII, PID1 signal/reaping/storage contract. Covers R14-R17, C25, P09/P12/P17. Gate: channel close and service shutdown leave no owned client/process/FD tasks, and PID1 never exits via the old signal callback. |

**Stage 2 failure-injection matrix:** fail each write, fsync, rename, directory fsync, process spawn, stdin write, child exit, command timeout, interface operation, nft check/apply, DNS validation/readiness, provider operation, and ledger acknowledgement. For every failure, assert desired/applied/durable revisions and resource ownership explicitly. A test that only asserts an error string is insufficient.

### Stage 3: Function Decomposition & Control Flow Overhaul

| Work item | Prerequisites | File-by-file transformation and gate |
|---|---|---|
| S3.1 Syntax and command reducers | S1.4 + S2.1 | Replace parser's context-object shuffling with syntax tree and per-context lowering. Replace root/VIP/service/gateway/DNS REPL matches with parsed typed edits. Route help/completion through the registry. Covers all parser and REPL functions in section 3.1, U05-U08, C26/C33. Gate: command matrix has one dispatch target, exact arity, correct context, help entry, completion grammar, and transactional reducer test. |
| S3.2 Planning and platform adapters | S2.3 + S2.4 | Split compiler into admission/selection/routing/translation/schema/delta rendering; extract address/lease and WG controllers; pure DNS plan/render; one typed process executor. Covers `compiler.rs`, `dns.rs`, `wireguard.rs`, `unikernel.rs`, N01-N06/N15/N16. Gate: pure plans are snapshot-testable; OS mutation only through owned adapters; policy refresh retains DNS sets/counters and stable marks. |
| S3.3 Stream protocol handlers | S2.3 + S2.4 | Replace HTTP/SOCKS single reads, preserve buffered bytes, implement incremental TLS preface, scope vhost routing, use per-request auth and explicit Upgrade transition, share admission/dial/relay. Covers N07-N11 and gateway/vhost/Cloudflare/fallback handlers. Gate: fragmentation/coalescing tests pass at every byte boundary; no unsupported capability is accepted. |
| S3.4 Health, resolver, discovery, flows | S2.4 | Bounded workers, explicit scan scope and stable adoption IDs, typed probe errors, cache provenance/expiry, source-specific flow decoders, one counter sampler. Covers R07/R18-R20, N13/N14, scanner/health/flows modules. Gate: resource budgets are measurable and enforced; absence of data is distinguishable from observation failure. |
| S3.5 DNS/mDNS controllers | S2.3 + S3.2 + S3.3 | Split record policy/compiler/process/query transport; interface-event membership reconcile; correct mDNS response destination/TTL and explicit repeater limits. Covers C18-C20, R12, N12/N13/N16. Gate: exact packaged dnsmasq behavior and declared mDNS feature subset pass isolated tests. |
| S3.6 Provider, SSH, presentation | S2.5 + S2.6 + S2.4 | Decompose Cloudflare resource operations and CLI, credentials/PTy/protocol adapters, status/TUI/web into pure projection/rendering. Covers C21-C25/C31, R13-R17, U09-U11. Gate: no renderer/controller reads another layer's persistence directly; every failed task reaches status/diagnostics. |
| S3.7 Remove obsolete coupling and wrappers | All relevant S3 items | Remove dead wrappers, old direct `SharedState` mutation paths, duplicated weighted selectors, endpoint-string identity helpers, raw HTTP/base64 parsers, and self-IPC compatibility code. Covers U12 and superseded implementations. Gate: dependency scan shows no AST/parser -> process/file/network edge, no presentation -> platform mutation edge, and no persistence -> API edge. |

Function-scope targets should be enforced through review, not arbitrary line-limit lint failures: each orchestrator reads as a sequence of named phases; each protocol state transition has explicit input/output and bounded buffering; each helper owns one error category; deeply nested matches become guard clauses or typed-state transitions. A 60-line cohesive codec can be clearer than ten forwarding wrappers. Do not replace a 500-line function with a 500-line trait and claim decoupling.

### Stage 4: Control Plane, CLI, Config & Documentation Alignment

| Work item | Prerequisites | Engineering work and completion gate |
|---|---|---|
| S4.1 CLI/API lifecycle and compatibility | S2.2 + S3.1 + S3.3 | Typed clap binds/modes/conflicts; clients do not start daemons; shared noninteractive command results; v2 DTOs/errors/permissions/revisions; v1 adapter only. Covers C12/C26/C27/C29/C31, U01-U08, P01/P02. Gate: every existing route/command has an explicit preserved, migrated, deprecated, or rejected mapping. |
| S4.2 Config-to-execution contract qualification | S1.4 + S3.2-S3.6 | Execute every field row in section 1.4 through parse -> canonical format -> validate -> plan -> fake apply -> status; run transport-specific capability tests. Covers all C findings and N01-N16. Gate: no accepted field is ignored, changes meaning, or bypasses the common validator. |
| S4.3 Documentation and packaging alignment | S4.1 + S4.2 + S1.6 | Generate help/examples/route schemas from actual command/DTO sources; correct README promises; repair service/image/deploy manifests and full data migration. Covers B05, C01-C33, P01-P17. Gate: every README command parses, every required artifact exists, and every advertised feature has target evidence. |
| S4.4 Isolated Linux/container/VM/board qualification | S4.2 + S4.3 | Network namespaces/disposable VMs, process failure injection, boot/reboot, confirmed rollback, retained storage and resource ownership; hardware matrix for ARM. Gate: target-specific reports demonstrate readiness and persistent state, not only successful image creation. |
| S4.5 Rollout and retirement | S4.4 | Backup, dry-run migration, opt-in new contracts, canary deployment, observe revision/readiness/error metrics, document rollback, retire legacy forms on a stated release boundary. Gate: rollback restores complete data/resource identity; compatibility adapters have a removal date and tests until removal. |

### 5.2 Exact test obligations

| Test group | Required cases and measurable assertions |
|---|---|
| Build/type continuity | Normal binary, library, and test targets compile; B01-B04 covered explicitly; documented MSRV reads the lockfile; both supported Linux target configurations checked. |
| Pure parsing | No filesystem/DNS/process calls; balanced/unbalanced/extra braces; inline blocks; comments/semicolons in quotes; escaped quote/backslash/newline; unknown directive/trailing token; input/token/depth limits at limit and limit+1. |
| Canonical round-trip | Every field and enum variant; eth0/non-eth0 prefix; local endpoint policy; DNS none/empty/false; check disabled; global/per-IP rate; partial inline WG rejected; no observed lease serialized; semantic equality, not substring snapshots alone. |
| Numeric/domain boundaries | Ports 0/1/65535/65536; weights 0/1/100/101 and JSON overflow; prefix 0/31/32/33; VLAN 0/1/4094/4095; interface/name limits; rate/burst total overflow; malformed AAAA/SRV/MX; zero duration; invalid boolean spelling. |
| Identity | Distinct names sanitizing to the same old nft ID; same port TCP versus UDP; disambiguated service rename/port change; backend IP/DNS change retains administrative identity; gateway reorder retains interface/mark/table/priority. |
| Transactions | Two clients edit the same base; two edits of one candidate race; empty config commit; custom path; disconnected confirmed session; confirm at deadline-1/deadline/deadline+1; crash before/after every journal/effect step; failed compensation remains visible and blocks writes. |
| Inactive candidates | Candidate key cannot authenticate; candidate listener cannot bind; candidate DNS/health/WG/provider work does not run; empty committed config does not select candidate. |
| Platform errors | Missing binary, permission denied, malformed nft, closed stdin, nonzero exit, oversized stdout/stderr, timeout/kill/reap failure, failed VIP step, failed DNS readiness; no case reports verified/applied success. |
| Resource ownership | Foreign `wg0`/`mv-*`/routing rule/nft object untouched; exact managed cleanup only; unchanged resources execute zero update commands; removed listeners stop admission and obey configured drain behavior; failed listeners retry without stale active entries. |
| Routing/admission | Global/local ACL union semantics; unresolved ACL names; direct gateway denial; all private ranges including 192.168/16; overlapping gateway rejection; route/bypass precedence; established return pinning; per-gateway killswitch; transparent/NAT shared backend isolation. |
| Selection | Eligible primaries before backups; drained never selected; all down yields declared failure; unknown-health policy explicit; weight distribution matches configured ratios over complete ticket cycles; memory O(number of backends), not O(sum of weights). |
| HTTP | Headers fragmented at every byte; body in first read preserved exactly; chunked body/trailers; duplicate Host/length rejection; invalid authority/port; 100-continue; keep-alive with second unauthenticated request; proper CONNECT/Upgrade prefetched bytes; per-request auth; body/header/timeout/concurrency budgets. |
| TLS | ClientHello split across TCP reads and TLS records; maximum accepted length and one above; short/truncated vectors; duplicate SNI/extensions; no SNI; unknown host; cross-VIP fallback forbidden; ECH behavior explicitly documented; original wire bytes unchanged. |
| SOCKS5 | Greeting/request/payload coalesced and fragmented at every boundary; no acceptable method; invalid reserved field; unsupported BIND/UDP; invalid/zero port; IPv4/domain/IPv6 capability; correct failure reply; no lost initial application payload. |
| Tunnel-bound dial | Failed mark/device/source bind prevents connect; name resolution follows selected tunnel; no implicit direct fallback; no stale route generation; timeout cancels/reaps all owned work. |
| DNS | Custom listen port on VIP and gateway; explicit empty resolver list; no-hosts behavior; all record types and deletion isolation; AAAA sinkhole; unknown route gateway rejected; health only affects declared generated records; nftset survives policy refresh; cached lookup after refresh still has routing state. |
| DNS process/query | Candidate `--test` failure retains old daemon; missing/crashed child becomes unavailable; readiness requires an answer; SIGHUP cache behavior measured; ID/question/peer/rcode/TC checks; TCP fallback; malformed packets never become apparent success. |
| mDNS | Membership updates without incoming packets; removed interface leave; container `eth0@ifN` and custom names; actual prefix/interface-index behavior; multicast TTL/source, QU/QM, duplicate suppression and repeater loop policy; no unleased/uncommitted announcements. |
| Probes/cache | Concurrency never exceeds configured budget; identical endpoint/different policy stays independent; old-generation completion rejected; disabled check produces no task; gateway kind/target honored; expired DNS observations removed without deleting authoritative registrations. |
| Discovery | `/32` exactly one requested IP; `/31` exactly two; out-of-budget scope errors without clamp; port-product budget; no current-thread runtime deadlock; no config persistence on scan; stable adoption target and ambiguous match error. |
| Metrics/flows | First sample, zero elapsed time, counter decrease/recreation, duplicate nft counters, established traffic, TCP/UDP sharing, actual time denominator, source unavailable versus empty, decimal mark 257 rendered `0x101`, userspace packets absent rather than fabricated. |
| Credential/API projection | Logged-in REPL/SSH sessions and `rw` API keys can view `ro` and `rw` `api:<port>` keys in `show` / `Nftyfile` / `/api/v1/config` / `/api/v1/status`, while `ro` API keys see `ro` keys with `rw` keys redacted; private/preshared WG keys and Basic passwords remain redacted from unprivileged read DTOs; candidate/revoked keys rejected; endpoint scope enforced; corrupt store never resets credentials. |
| Cloudflare | Multiple accounts/pages; rejected token; Access permission failure does not downgrade; first backend down/drained; explicit origin TLS; lost response after create; failed delete retains ownership; pre-existing unowned record not adopted; token generation restarts connector; stopped desired state stays stopped. |
| SSH/TUI/PID1 | Spawn failure closes descriptors; resize boundaries; concurrent input without map-lock await; channel close terminates/reaps client; no second daemon; raw-mode restoration on every error; owned versus orphan reaping; signal shutdown; persistent mount failure reported. |
| Packaging/deploy | Target/artifact architecture matches; every required executable/interpreter/library/module present; checksums verified; unsupported board fails; full nested/hidden data survives migration; aliases promoted without deleting image; readiness and expected durable revision checked; rollback asset retained. |
| Documentation | Every documented CLI invocation parses; every Nftyfile example lowers/round-trips; route/schema fixtures match implementation; flags/defaults/prompts/limits/capability matrices generated or tested; no absent example artifact; no unsupported universal-boot/cache/auth claims. |

Use deterministic fake clocks/resolvers/process runners/provider clients first. These tests must prove absence of effects where required, not merely compare generated text. Fuzz parsers/codecs independently from live sockets. Property-test round-trip and weighted selection with bounded inputs. Only then run real Linux/network/process integration in a disposable, explicitly owned environment.

### 5.3 Validation commands and isolation policy for implementation work

These commands are **future engineering gates**, not commands executed during this read-only audit:

```text
cargo check --locked --all-targets
cargo test --locked --lib
cargo test --locked --test control_plane
cargo check --locked --release --target x86_64-unknown-linux-musl
cargo check --locked --release --target aarch64-unknown-linux-musl
```

The library/integration targets in this plan must exist and use fake effect ports before those test selectors are relied on. Add clippy/format gates using the repository's selected toolchain after the build baseline is restored. Run only the smallest relevant suite per change, then the full qualified matrix at release boundaries.

Real nft/ip/WG/DHCP/DNS tests require dedicated namespaces or VMs and explicit owned resource names, never the operator's live interfaces. Image builders/deployment scripts require disposable output/storage targets. No test may call a production provider account or use `/data` by default. Hardware boot support requires actual board evidence; source inspection cannot establish it.

### 5.4 Traceability and completion criteria

| Findings | Primary resolution stages |
|---|---|
| B01-B04 | S1.1; regression checks in S4.2 |
| B05 | S1.6, S4.3 |
| C01-C02, C24, C29 | S2.1-S2.2, S4.1-S4.2 |
| C03-C10, C32-C33 | S1.2-S1.4, S3.1-S3.2, S4.2 |
| C11-C17 | S1.2, S2.3-S2.4, S3.2-S3.3, S4.2 |
| C18-C20, C28 | S1.4, S2.4, S3.5, S4.2-S4.3 |
| C21-C23 | S2.5, S3.3/S3.6, S4.2 |
| C25, C31 | S1.5, S2.6, S3.6, S4.1-S4.2 |
| C26-C27, C30 | S3.1, S4.1/S4.3 |
| R01-R08 | S2.1-S2.4 |
| R09-R17 | S2.3/S2.5/S2.6, relevant S3 adapters |
| R18-R20 | S2.4, S3.4/S3.6 |
| N01-N06 | S1.2, S2.3, S3.2 |
| N07-N11 | S2.3, S3.3 |
| N12-N16 | S3.2/S3.4/S3.5 |
| U01-U04 | S1.3, S2.1-S2.2, S4.1 |
| U05-U08 | S1.4, S3.1, S4.1 |
| U09-U12 | S2.4, S3.4/S3.6/S3.7 |
| P01-P17 | S1.6, S2.3/S2.6, S4.3-S4.5 |

The architecture is not complete merely because functions are shorter. Completion means: no hidden parser/runtime effects; no candidate activation; no ignored accepted config fields; no false success on unavailable platform; no independent control-plane writer; no deletion without ownership; no protocol dependence on TCP read boundaries; no secret-bearing read DTO; no unpersisted confirmed rollback; and no documentation/build artifact claim without an executable contract or explicitly stated support limitation.
