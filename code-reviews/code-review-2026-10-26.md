# Code review - 2026-10-26

## Scope and interpretation

This is a static review of the current source, packaging, and documentation,
compared with `code-review-2026-10-25.md`. No builds, tests, application code,
deployment scripts, or network operations were run. Line references describe
the source at review time, before subsequent fixes. Findings describe behavior
visible in the code, not verified behavior on a deployed appliance.

The intentional ACL-based management-access model is not itself a finding.
The authentication findings below concern configured API-key scopes, secret
redaction, or policies that the application already promises to enforce.

The earlier build-continuity issues involving `ApiKeyScope::as_str`, `Proto:
Hash`, the gateway-edit borrow, and the JSON test's string handling have source
changes addressing them. The previous improvements to disabled checks, several
formatting cases, drained backends, and saved WireGuard-profile redaction are
partial; they do not resolve the lifecycle and policy issues below.

## Findings

### 1. Configuration and recovery

**R1 - Candidate configuration can become active without a commit.** When
running is empty, `AppState::active_config` returns the candidate. Disk
synchronization can also replace running state without applying the new
configuration (`src\state.rs:144-201`). Background listeners, probes, and
authentication use that state. An empty committed configuration is valid and
must not activate staged edits.

**R2 - Apply can advance state before effects succeed.** The CLI, API, and
daemon have separate apply paths; several replace `running` or report success
before or without checking the nftables result (`src\repl\mod.rs:2429-2502`,
`src\api.rs:738-765,956-990`, `src\main.rs:201-215,255-272`). VIP, DHCP,
WireGuard, DNS, Cloudflare, and nftables operations are not one atomic
transaction. Failures must be surfaced, and state must not claim a successful
activation when a required operation failed.

**R3 - Persistence can diverge from the requested configuration.**
`persist_to_storage` marks the text as written before checking the write,
prefers `/data` over an explicitly configured non-`/data` path, and refuses to
persist an intentionally empty configuration. It also sends a fixed-port
loopback request after persistence, including from API requests, allowing
self-notification and repeated reapplication (`src\unikernel.rs:505-586`,
`src\api.rs:537-540`). Storage errors and notification failures are ignored.

**R4 - Confirmed rollback is not durable or independently owned.** A trial
configuration is persisted immediately, while its timer is kept in the
initiating process. Timeout and manual rollback ignore apply failures and do not
reliably persist the baseline (`src\repl\mod.rs:2460-2548`,
`src\health.rs:498-529`). Process exit, restart, or a one-shot command can leave
the trial active without a working rollback timer.

**R5 - nftables failures can be reported as success.** Missing `nft`, permission
errors, and child wait errors produce `ok = true`; a failed stdin write is also
ignored (`src\compiler.rs:1378-1439`). This makes validation and apply status
unreliable and can select a success-shaped fallback without verifying that the
ruleset was installed.

**R6 - Startup and inspection commands have operational side effects.** Every
invocation starts background tasks and an API listener before dispatch; PID-1
startup and standalone daemon startup also use separate apply paths
(`src\main.rs:148-190,201-215`). Read-only commands and secondary sessions do
not have a single authoritative controller or a consistent view of applied
state.

### 2. Access, framing, and HTTP behavior

**R7 - Incomplete HTTP requests can reach mutation handlers.** The request
reader returns partial input on EOF, timeout, or read error; accepts malformed
`Content-Length` as zero; does not reject transfer encoding or conflicting
lengths; and has no separate header limit or total request deadline
(`src\api.rs:311-355`). A mutation must not execute until its complete request
has been framed and validated.

**R8 - Scoped keys are checked globally rather than against the receiving
listener.** Source ACLs are checked by listener port, but an API key from any
service or gateway is accepted on any permitted port (`src\ast.rs:1437-1507`,
`src\api.rs:265-305,421-436`). This breaks the association between a configured
listener and its own `ro`/`rw` keys. Preserve ACL-only access where configured,
while enforcing keys where that listener requires them.

**R9 - Read-only configuration responses expose other secrets.**
`redacted_for_readonly` masks only read-write API keys, leaving inline
WireGuard private keys and service/Cloudflare Basic Auth passwords in structured
and formatted configuration responses (`src\ast.rs:1510-1530`,
`src\api.rs:578-624,715-733,1013-1033`). Read-only API keys should remain
visible as documented, but secret material must not be.

**R10 - The web console interpolates untrusted values into HTML and inline
handlers.** Scanned banners, hostnames, configuration strings, and other values
are inserted into `innerHTML`, including quoted `onclick` arguments
(`src\api.rs:2298-2318,2415-2660`). A discovered service or configuration
value can therefore alter the operator's page. Browser-stored credentials
increase the consequences.

**R11 - Configured service authentication is not consistently enforced.**
The L7 proxy checks Basic Auth only when the first read resembles HTTP; TLS
passthrough skips that check, and the kernel L4 path does not provide HTTP
authentication (`src\features\vhost_mdns.rs:404-435`,
`src\compiler.rs:633-743`). Cloudflare Access API errors can also switch an
email policy to a different local-password policy
(`src\features\cloudflare.rs:242-267,754-807`). Unsupported combinations should
be rejected or explicitly degraded, not silently treated as enforced.

**R12 - First-read proxy parsing is not stream-safe.** HTTP Host, TLS SNI,
Basic Auth, and the HTTP proxy request are interpreted from a single read
(`src\features\vhost_mdns.rs:201-273,324-338`,
`src\features\cloudflare.rs:330-347`,
`src\features\gateway_proxy.rs:310-335`). Normal TCP fragmentation can cause
valid requests to be dropped or forwarded without the intended processing.
The SOCKS5 handshake also accepts no-auth without checking the client's offered
methods (`src\features\gateway_proxy.rs:425-456`).

### 3. Dataplane and feature correctness

**R13 - Down backends can be reselected.** If every primary and backup is down,
`active_backends_for_service` falls back to non-drained down targets
(`src\state.rs:258-310`). This contradicts health-aware failover. Unknown
health can remain eligible, but a known-down or administratively drained target
should not be silently selected.

**R14 - WireGuard proxy routing can leak outside the selected tunnel.** The
gateway proxy ignores failures from `SO_MARK`, `SO_BINDTODEVICE`, and source
binding; hostname resolution occurs before tunnel selection
(`src\features\gateway_proxy.rs:170-238`). A configured killswitch therefore
does not establish that the userspace connection or DNS lookup used the tunnel.

**R15 - WireGuard resource ownership and identity are unsafe.** Tunnel indices,
interface names, routing tables, and marks depend on configuration ordering,
and cleanup deletes any unmatched `wg*` interface
(`src\features\wireguard.rs:107-266`). This can disturb unrelated interfaces
or remap existing resources. Reconciliation needs stable, explicitly owned
resources and checked operation results.

**R16 - DNS configuration and status can disagree with intent.** Explicit
upstreams append to the default public resolvers; an empty upstream list is
displayed as the defaults even though the generated config has no servers
(`src\parser.rs:2505-2520`, `src\features\dns.rs:148-160,630-641`,
`src\repl\status.rs:394-401`). DNS listener ports and multi-gateway tunnel
selection also require a consistent, validated execution model.

**R17 - Configuration parsing accepts unfinished blocks.** At EOF the parser
commits or discards partially constructed contexts instead of rejecting an
unclosed block (`src\parser.rs:768-806,1216-1247`). A truncated configuration
can therefore parse as a different, apparently valid configuration.

**R18 - Boot storage discovery can select or format unrelated devices.**
PID-1 tries filesystem mounts using device-name guesses, then formats a disk
whose first MiB is zero if no mount succeeds (`src\unikernel.rs:226-266,
378-441`). An unrelated or partially initialized device is not safe to format
implicitly. Storage ownership and initialization must be explicit.

**R19 - Resource and protocol supervision can report stale success.** Dynamic
API ports are not removed, gateway proxy task handles are retained after task
failure, and dnsmasq's PID-file check verifies only that a PID exists
(`src\api.rs:109-145`, `src\features\gateway_proxy.rs:19-62`,
`src\features\dns.rs:407-443`). Retained listeners and recycled PIDs can
misrepresent readiness or target an unrelated process.

### 4. Packaging and contracts

**R20 - Packaging and documentation do not consistently match runtime
behavior.** The standalone unit sends SIGHUP without a corresponding reload
handler; the ARM image seeds an empty configuration while the getting-started
guide says every appliance receives a default gateway; documentation also
describes a UNIX control socket absent from the source
(`packaging\standalone\nfty.service:9`, `src\unikernel.rs:282-287`,
`packaging\rk3588s\build-rk3588s.sh:154,196-198`,
`docs\getting-started.md`, `docs\interactive-cli-and-tui.md`). Deployment
documentation should describe actual behavior, not an unimplemented contract.

## Source-change status

The following describes changes made after the review, not verified outcomes.
**No code, tests, builds, linters, deployment scripts, or network operations
were run.** Focused regression tests were added in source but remain unrun.
“Addressed in source” means the identified path was changed; it is not a
claim that the implementation compiles or works correctly in production.
“Partial” means an important part of the original risk remains.

| Finding | Status | Changes and remaining limits |
| :--- | :--- | :--- |
| R1 | Addressed in source | Running stays authoritative even when empty; disk refresh no longer promotes uncommitted candidate state. |
| R2 | Partial | More apply operations are checked and failures trigger best-effort restoration. Apply still spans multiple subsystems, restoration may fail, and asynchronous Cloudflare changes are not transactional. |
| R3 | Partial | Configuration writes use the configured path, support empty files, and report errors; only config-changing HTTP routes trigger Nftyfile persistence. Secondary notification can fail after local apply and save, and competing processes can still diverge. |
| R4 | Partial | Confirmed apply is restricted to long-running controllers, keeps the baseline on disk, and reports rollback failures. Its timer is process-local and cannot guarantee rollback after a crash. |
| R5 | Addressed in source | nftables execution, input, and child failures are reported rather than converted to success. |
| R6 | Partial | Only controllers start the API and background supervisors; secondary drain/enable requests are forwarded to the controller. Sessions still have separate state, and some configuration operations apply locally before notification. |
| R7 | Addressed in source | Requests are bounded by header/body limits and a total deadline; incomplete, conflicting, or unsupported framing is rejected before routing. |
| R8 | Addressed in source | Configured keys are checked against the receiving port and shared keyed ports use the least privilege. ACL-only access remains supported; loopback internal IPC trusts local processes. |
| R9 | Addressed in source | Read-only configuration responses also mask inline WireGuard private keys and service/Cloudflare authentication material. |
| R10 | Partial | Values interpolated into the web console were escaped or moved away from unsafe inline argument interpolation. A browser-level verification and complete injection audit have not been performed. |
| R11 | Partial | Local service Basic Auth is rejected on apply because it cannot be enforced on all paths; Cloudflare email-policy errors no longer silently switch to appliance-password authentication. Cloudflare provisioning remains asynchronous and non-transactional. |
| R12 | Partial | Proxy and virtual-host prefix reads are bounded and accumulate fragments, and SOCKS5 checks offered methods. A TLS ClientHello split across records remains unsupported and fails closed. |
| R13 | Addressed in source | Known-down and drained targets are excluded, with fail-closed handling when none remain; healthy shared HTTP/TLS virtual hosts can still be routed. Ambiguous same-address service bindings are rejected, subject to the wildcard limitation in R26. |
| R14 | Partial | Tunnel socket setup errors are checked and tunneled destinations require an IPv4 literal or cached address. A cached name may have been resolved outside the tunnel, so this does not establish DNS confinement. |
| R15 | Partial | Named profiles use stable derived interface identities; cleanup is limited by ownership markers, and routing operations are checked. Markers are not strong isolation, external routing-table collisions are possible, and upgrades can require manual cleanup. |
| R16 | Partial | Explicit DNS upstreams replace defaults and status reflects an empty list; conflicting listener/tunnel combinations receive additional validation. Process supervision and cache integrity still need runtime verification. |
| R17 | Addressed in source | Unterminated Nftyfile blocks are rejected. |
| R18 | Addressed in source | Boot storage discovery no longer automatically formats guessed devices; persistent storage must be provisioned and labeled explicitly. |
| R19 | Partial | Listener/proxy supervision and PID checks were tightened; Cloudflare retries failed or stopped connectors. The web status badge now reports controller state rather than a hard-coded active claim. PID identity checks and daemon behavior remain unverified, and Cloudflare coordination is process-local. |
| R20 | Partial | A controller SIGHUP reload handler, image seed changes, safer LXD deployment steps, and documentation corrections were added. Packaging and deployment behavior have not been exercised. |

## Additional findings and residual risks

**R21 - DHCP lease lifecycle and interface ownership remain incomplete.**
The DHCP hook does not reliably remove stale lease files and addresses on
deconfiguration; renewal can leave an older secondary address. Some hook and
sysctl failures are still unchecked. Macvlan markers and MAC checks reduce
accidental cleanup, but are not strong ownership; unmarked legacy interfaces
need verifiable DHCP/lease evidence or manual inspection. Existing VLAN
interfaces are not fully ownership-verified. DHCP process identification
also relies on the arguments surviving BusyBox daemonization, which has not
been verified.

**R22 - Controller state is still split across processes.** Secondary status
and watch sessions do not share the controller's live health or drain state.
Drain/enable commands now go to the controller, but matching multiple endpoints
can partially succeed. Other secondary operations still apply and persist
locally before notification, and a failed notification can leave views divergent.
The internal loopback HTTP header grants read-write access without a key; the
design therefore trusts all local processes that can reach the listener.

**R23 - Host registrations and discovery have separate consistency limits.**
Explicit mappings are written atomically to `/data/hosts.json` under a
cross-process lock and take precedence over automatic discovery. Scanning no
longer silently registers hosts. A registration deletion does not prevent
DNS or `/etc/hosts` from rediscovering the name, and external edits or failed
controller notification can leave in-memory state stale.

**R24 - Scan and blocklist bounds are incomplete.** Scans are limited to
`/24`–`/32` targets with bounded per-scan probing and reverse lookups, but
concurrent independent scans have no global limit. Empty or unusable DNS
blocklist caches are no longer treated as valid; nonempty stale caches are
retained on fetch failure with a warning, but their complete integrity is not
verified.

**R25 - Cloudflare and WireGuard ownership still need stronger coordination.**
Cloudflare reconciliation is serialized and generation-checked only within
one process; an in-flight reconcile elsewhere can race a stop or settings
change. Remote changes are not transactional. WireGuard profile files now
receive owner-only permissions on new saves, but existing files may retain
older permissions. Derived names can change interfaces during an upgrade,
and older routing rules can lack the new ownership sidecars.

**R26 - Listener overlap and L7 original-destination selection can be ambiguous.**
After nftables redirect, if the original VIP cannot be identified, the
virtual-host listener can fall back to another service with the same hostname.
Avoid duplicate hostnames across VIPs until original-destination handling is
redesigned and verified. Apply now rejects overlapping services with the same
address, port, and protocol except for distinct TCP virtual hosts on ports 80
and 443. It does not fully detect overlaps between wildcard and specific VIP
bindings; avoid those combinations.

**R27 - Service rate-limit behavior was overstated.** The rate guards run in
the NAT prerouting chain, so they do not limit every packet in established
flows. Unmatched ACL/rate guards now produce an explicit drop for ordinary
service bindings. Per-service rate limits on shared HTTP/TLS virtual hosts
are rejected because one host's earlier NAT rule could otherwise bypass
another host's limit. These changes have not been verified against nftables.

The broader requirements for a single authoritative controller, durable
transactions, strong resource ownership, protocol-capability validation, and
isolated acceptance tests remain open. None of the changes above establishes
end-to-end atomicity or production readiness.
