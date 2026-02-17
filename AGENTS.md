# AGENTS.md

Guide for AI agents working on the `pia-freshtomato` project.

## Overview

**Purpose**: Automated PIA WireGuard VPN setup for FreshTomato routers.

**Environment**: FreshTomato 2025.5+, BusyBox 1.37.0, ash shell (POSIX), PHP 8.3, curl 8.17, OpenSSL 3.0

**Files**: `pia_wireguard.sh` (main), `pia_config` (runtime state), `README.md` (docs)

The script is assumed to start once with parameters after router startup, and then called every 15 mins via a cron job

---

## Design Principles

### 1. Idempotency
Functions must be safe to run multiple times. Check state before acting:
```bash
function_name() {
  [ -f pia_config ] && . ./pia_config
  [ -n "${cached_value:-}" ] && echo '[=] Already configured' && return 0
  # Do work, save state
  printf "%s\n%s\n" "$(grep -v '^prefix_' pia_config 2>/dev/null || true)" "new_vars" > pia_config
}
```

### 2. Self-Sufficiency
Functions validate their own prerequisites. Don't rely on caller setup.

### 3. Fail Fast
Use `error_exit()` with context: `[ -z "${token:-}" ] && error_exit "token not set"`

---

## Conventions

### Shell
- `#!/usr/bin/env ash` (BusyBox POSIX shell, no bashisms)
- `set -eu` (exit on error/undefined, NO `-o pipefail`)
- Lint with `shellcheck shell=dash`

### Variables
**Prefixes**: `pia_*` (user config), `var_*` (local), `region_*` (cached), `token*` (session), `auth_*` (WireGuard), `peer_*` (keys), `portforward_*` (port data)

**Always use**: `${variable:-}` not `$variable` (prevents `set -u` failures)

### Output
```bash
'[ ]' In progress   '[*]' Info       '[~]' Retry
'[=]' Skip         '[+]' Success    '[-]' Cleanup   '[!]' Warning/Error
```
Log errors/warnings: `logger -t pia_wireguard "message"`

### Retry Pattern (inline, exponential backoff)
```bash
local var_attempt=1 var_backoff=1
while [ "${var_attempt}" -le 5 ]; do
  [ "${var_attempt}" -gt 1 ] && echo "[~] Retry ${var_attempt}/5 (backoff: ${var_backoff}s)..." && sleep "${var_backoff}" && var_backoff=$((var_backoff * 2))
  command_to_retry && break
  var_attempt=$((var_attempt + 1))
done
[ "${var_attempt}" -le 5 ] || error_exit "Failed after 5 attempts"
```

### Config Management
Load: `[ -f pia_config ] && . ./pia_config`
Save: `printf "%s\n%s\n" "$(grep -v '^prefix_' pia_config 2>/dev/null || true)" "new_vars" > pia_config`

### JSON Parsing
Use PHP: `result=$(echo "$json" | php -r '$d=json_decode(stream_get_contents(STDIN)); echo "key=\"$d->value\"\n";')`
Don't use `jq` (unavailable) or complex `awk`/`sed`

### Input Validation
Always validate: `echo "${ip}" | grep -q '^[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}$' || error_exit "Invalid IP"`

---

## Architecture

### State (`pia_config`)
Three layers: User config (`pia_*`), cached metadata (`certificate`, `region_*` including `region_pf`), session state (`token`, `auth_*`, `peer_*`, `portforward_*`). `region_pf` is set by `get_region()` from the server list (whether the region supports port forwarding) and is used by `get_portforward()` / `set_portforward()` to skip when the region does not support PF.

**Cascade invalidation**: Region change clears dependent state: `grep -v '^region_\|^token=\|^auth_\|^peer_\|^portforward_'`. On get_auth or set_wg failure the script also clears `region_*`, `token`, and `auth_*` so the next run refetches the serverlist and selects the first reachable server (failover). When `healthcheck_tunnel()` fails before provisioning, the same pattern clears `region_*`, `token`, `auth_*`, `peer_*`, and `portforward_*` so the next run does a full rebuild including PF reacquisition.

### Tunnel Healthcheck
`healthcheck_tunnel()` runs twice per execution: once before provisioning (to detect a broken tunnel and trigger rebuild) and once after (to verify the tunnel is working). Checks: interface presence (`/sys/class/net/wg0`), TX transfer increase after a ping probe, handshake age < 300s, and return-path liveness (ping 10.0.0.1 via wg0). On failure before provisioning, region/token/auth/peer/portforward_* state is cleared for a full rebuild.

### Port Forwarding (PF) token lifecycle
- **Main gate**: The PF block (get_portforward, set_portforward) runs only when `pia_pf` is not `false`. The functions themselves check `region_pf` and skip (return 0 with `[=] Region does not support port forwarding`) when the region does not support PF; `pia_pf` is never overwritten by the script.
- **State**: `portforward_signature`, `portforward_payload`, `portforward_port`, `portforward_exp` (expiry epoch; set when parsing getSignature response).
- **Reuse**: Cached token is reused only when `portforward_exp` is set and remaining validity is >= 7 days (604800s). Near expiry the script clears `portforward_*` and reacquires via getSignature.
- **Bind failure**: If bindPort returns non-OK, the script clears `portforward_*` and returns 0 (non-fatal) so the next cron run reacquires the token in `get_portforward()`. Do not call `get_portforward()` from `set_portforward()`.
- **NAT idempotency**: Use `iptables -t nat -S PIA_NAT` and `grep -F` for full rule shape (`--dport ${portforward_port}` plus REDIRECT/DNAT target) so port or target changes are detected and rules are rewritten.
- **DuckDNS**: Runs when `pia_duckdns` is not `false` (independent of `pia_pf`). Always updates the A record (VPN IP). The TXT record (port) is updated only when `portforward_port` is set (i.e. when PF ran for this region); otherwise the port part is skipped.

### IPv6 Leak Prevention
`set_ipv6()` drops all routed IPv6 traffic via a dedicated `PIA_FORWARD_V6` ip6tables chain to prevent leaks bypassing the VPN. LAN-to-LAN IPv6 is unaffected (handled by bridge at layer 2, never enters FORWARD).

### WAN and PIA API
All PIA API traffic that must work when the tunnel is broken (get_cert, get_region, get_token, get_auth) uses DoH (`--doh-url "https://1.1.1.1/dns-query"`) and is bound to the default-route interface (`--interface`). WAN interface is detected in each function from the main routing table: `ip route show table main default` (device name). No config override (e.g. no `pia_wan_interface`). Port-forward API (getSignature, bindPort) stays on `--interface wg0`.

### Routing
- Table 1337: `default dev wg0` plus throw routes so local traffic falls through to main:
  - Bridge discovery: `ip -o route show proto kernel` with `*"dev br"*` (LAN prefixes).
  - 169.254.0.0/16 (link-local) for Avahi/Bonjour.
  - 224.0.0.0/4 (multicast) for local discovery/streaming.
- suppress_prefixlength 1 is not used (requires kernel 3.x+; FreshTomato uses 2.6). Do not add a throw for 10.0.0.0/8 (PIA DNS 10.0.0.0/24 must go via VPN).
- Policy: `ip rule add not fwmark 0xf0b table 1337` (unmarked → VPN, marked → direct).
- Split tunnel: `ipset` + `iptables -t mangle` marks bypass IPs with `0xf0b`

### iptables Chains
Custom chains (`PIA_*`) for isolation: `INPUT`, `FORWARD`, `POSTROUTING`, `MANGLE`, `NAT`, `PORTFORWARD`

---

## Security

### Validation
Validate all user input (IPs, ports, formats) with regex to prevent injection

### Sensitive Data
- Temp files: `pia_tmp_*` (trap cleanup)
- Config: credentials in `pia_config` (git-ignored)

### Verification
- Server list: RSA signature with hardcoded pubkey (`openssl dgst -sha256 -verify`)
- TLS: pinned certificate (`curl --cacert`)

---

## Pitfalls

1. **IPv6 Socket Error**: Disable IPv6 in `init_module()` immediately after creating `wg0`: `echo 1 > /proc/sys/net/ipv6/conf/wg0/disable_ipv6`
2. **Variable Expansion**: Always use `${var:-}` not `$var` (prevents `set -u` exit)
3. **OpenSSL Base64**: Always use `-A` flag for base64 operations to prevent line wrapping (76 char default breaks encoded data): `openssl base64 -A` for encode, `openssl base64 -A -d` for decode. **Exception**: When decoding multi-line base64 input that's already wrapped (like PIA's signature from API), omit `-A`: `echo "${var_signature}" | openssl base64 -d` (see `get_region` in `pia_wireguard.sh`)
4. **Module Loading**: Use `modprobe -a` for multiple modules (`modprobe -a ip_set ip_set_hash_ip xt_set`), check availability with `modprobe -n` before attempting to load, handle gracefully if unavailable (optional features like split tunneling)

## Performance

- Read config once (not in loops)
- Filter before pipes (`ip route show | grep pattern | while`)
- Use exponential backoff for retries

## Style

- 2 spaces, no tabs, < 120 char lines
- Comments explain WHY, not WHAT
- Function order: helpers, `init_*`, `get_*`, `set_*`, main

---

## Pre-Change Checklist

1. Idempotent? (safe to run multiple times)
2. Self-sufficient? (validates own prerequisites)
3. Error handling? (clear messages with context)
4. Logging? (`logger -t pia_wireguard`)
5. Input validation? (prevent injection)
6. Retry pattern? (exponential backoff)
7. Atomic writes? (no corruption on interrupt)
8. Output conventions? (`[ ]`, `[+]`, `[=]`, etc.)
9. Documented? (README.md/AGENTS.md updated)
