# pia-freshtomato
Script to set up PIA WireGuard on FreshTomato

## Setup

### Quick Setup (FreshTomato)

This sets up the VPN to start automatically after each reboot and stay healthy via cron.

**1. WAN Up script (Administration > Scripts > WAN Up):**

Paste the following, replacing `<USERNAME>` and `<PASSWORD>` with your PIA credentials:

```bash
cd /tmp
curl -sO https://raw.githubusercontent.com/rveznaver/pia-freshtomato/refs/heads/main/pia_wireguard.sh
chmod +x pia_wireguard.sh
pia_user='<USERNAME>' pia_pass='<PASSWORD>' ./pia_wireguard.sh
```

This downloads the script to `/tmp` and runs it every time the WAN interface comes up (including after reboot). Credentials are saved to `pia_config` on first run.

**2. Cron job (Administration > Scheduler):**

Enable a custom cron entry (e.g. Custom 1) to run every 15 minutes:

```
*/15 * * * * cd /tmp && ./pia_wireguard.sh
```

The cron run does not need credentials — they are already saved in `pia_config` from the WAN Up run. The script is idempotent: it skips stages that are already configured and only rebuilds if the healthcheck detects a problem.

**3. Save and reboot.**

The VPN will come up automatically after the router boots and WAN connects. Every 15 minutes, cron re-runs the script to maintain the tunnel, rebind port forwarding, and recover from any failures.

**Note:** `/tmp` is in RAM on FreshTomato and cleared on reboot. The WAN Up script re-downloads the script each boot. If you prefer persistence, use JFFS (`/jffs`) instead of `/tmp`.

### Basic Usage (No Port Forwarding)
```bash
ssh root@<ROUTER_IP>
curl -O https://raw.githubusercontent.com/rveznaver/pia-freshtomato/refs/heads/main/pia_wireguard.sh
chmod +x pia_wireguard.sh
pia_user='<USERNAME>' pia_pass='<PASSWORD>' ./pia_wireguard.sh
```

### Forward to Another Device
```bash
pia_user='<USERNAME>' pia_pass='<PASSWORD>' pia_pf='192.168.1.100:8080' ./pia_wireguard.sh
```

### Forward to Router Itself
```bash
pia_user='<USERNAME>' pia_pass='<PASSWORD>' pia_pf='0.0.0.0:22' ./pia_wireguard.sh
```

### With Custom Region
```bash
pia_user='<USERNAME>' pia_pass='<PASSWORD>' pia_vpn='us_california' ./pia_wireguard.sh
```

### All Options
```bash
pia_user='<USERNAME>' \
pia_pass='<PASSWORD>' \
pia_vpn='uk_london' \
pia_pf='192.168.1.100:8080' \
pia_bypass='1.2.3.4 5.6.7.8' \
pia_duckdns='mydomain:duckdns-token' \
./pia_wireguard.sh
```

### Disable VPN Bypass
```bash
pia_user='<USERNAME>' pia_pass='<PASSWORD>' pia_bypass='false' ./pia_wireguard.sh
```

## Features
- **Idempotent**: Safe to run multiple times, only configures what's needed
- **Robust**: Automatic retries with exponential backoff for flaky operations
- **Secure**: RSA signature verification of PIA server list, TLS certificate pinning for API calls
- **Modular**: Each stage is independent and can be run separately
- **Tunnel healthcheck**: Verifies handshake age, TX transfer, and return-path liveness on every run; unhealthy tunnel triggers automatic rebuild
- **Region change detection**: Automatically clears dependent state when switching regions
- **Server failover**: Parses all meta/WG servers in a region; selects first reachable; on auth or tunnel failure clears region so the next run refetches and tries another server
- **WAN recovery**: PIA API traffic (serverlist, token, auth) uses DoH and the default-route interface so the script can recover when the tunnel is up but broken (within one cron interval)
- **IPv6 leak prevention**: Drops all routed IPv6 traffic via ip6tables to prevent leaks bypassing the VPN; LAN-to-LAN IPv6 is unaffected
- **Port forwarding**: Forward to devices or router itself with automatic NAT configuration
- **Split tunnelling**: Optional VPN bypass for specific IPs (enabled by default for Google RCS)
- **Dynamic DNS**: Optional DuckDNS updates with VPN IP and forwarded port
- **Custom iptables chains**: Clean rule isolation using named chains (PIA_*)
- **Syslog logging**: Automatic logging of errors, warnings, and important events
- **Visual feedback**: Clear status indicators for all operations
- **Input validation**: Validates all user inputs to prevent injection attacks

## Requirements
- FreshTomato >= 2025.5 or compatible Linux distro
- WireGuard kernel module (`wg`)
- `curl` for API requests
- `php` (or `php-cli`) for JSON parsing
- `openssl` for RSA signature verification and base64 encoding/decoding
- `ipset` with kernel modules: `ip_set`, `ip_set_hash_ip`, `xt_set` for VPN bypass
- Standard POSIX tools: `sed`, `grep`

## Configuration Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `pia_user` | Yes | - | PIA username |
| `pia_pass` | Yes | - | PIA password |
| `pia_vpn` | No | `ca_ontario` | PIA region ID (e.g., `us_california`, `uk_london`) |
| `pia_pf` | No | `false` | Port forwarding destination in format `IP:PORT` (use `0.0.0.0:PORT` for router) |
| `pia_bypass` | No | Google RCS IPs | Space-separated IPs to bypass VPN (set to `false` to disable) |
| `pia_duckdns` | No | `false` | DuckDNS dynamic DNS in format `DOMAIN:TOKEN` |

## Example Output

### Basic Run (Defaults)
```
[ ] Initializing script...
[*] pia_vpn (region) not set, defaulting to ca_ontario (Ontario, Canada)
[*] pia_pf (port forwarding) not set, defaulting to false
[*] pia_bypass (split tunneling by IP) not set, defaulting to Google RCS servers
[*] pia_duckdns (DuckDNS dynamic DNS) not set, defaulting to false
[+] Script ready
[ ] Initializing WireGuard...
[+] WireGuard ready
[ ] Downloading PIA certificate...
[+] Certificate ready
[=] No session state, skipping healthcheck
[ ] Fetching PIA region info...
[*] Server list signature verified
[+] Region info ready (selected ...)
[ ] Generating PIA token...
[+] Token ready
[ ] Generating peer keys...
[+] Keys ready
[ ] Authenticating to PIA...
[+] Auth ready
[ ] Configuring WireGuard...
[+] WireGuard ready
[ ] Configuring firewall...
[+] Firewall ready
[ ] Configuring IPv6 leak prevention...
[+] IPv6 leak prevention ready
[ ] Configuring routes...
[+] Routes ready
[ ] Checking tunnel health...
[=] Tunnel healthy (handshake age: 2s)
[ ] Configuring VPN bypass...
[+] VPN bypass ready
```

### With Port Forwarding and DuckDNS
```
[ ] Requesting port forward...
[+] Port forward ready
[ ] Configuring port forward NAT...
[*] Port binding: timer refreshed
[+] Port forward NAT ready
[ ] Updating DuckDNS...
[+] DNS records updated: mydomain.duckdns.org A=66.56.80.87 TXT=26640
```

### Subsequent Run (Idempotent)
```
[ ] Initializing script...
[+] Script ready
[ ] Initializing WireGuard...
[+] WireGuard ready
[=] Certificate already exists
[ ] Checking tunnel health...
[=] Tunnel healthy (handshake age: 45s)
[=] Region info already exists (cached server reachable)
[=] Token already exists
[=] Keys already exist
[=] Auth already exists
[=] WireGuard already configured
[=] Firewall already configured
[=] IPv6 leak prevention already configured
[=] Routes already configured
[ ] Checking tunnel health...
[=] Tunnel healthy (handshake age: 45s)
[=] VPN bypass already configured
```

## Status Indicators
- `[ ]` - Starting/in progress
- `[+]` - Successfully completed
- `[=]` - Skipped (already configured)
- `[!]` - Error or warning
- `[~]` - Change detected / Retry in progress
- `[*]` - Informational message
- `[-]` - Cleanup action

## How It Works

The script runs through these stages sequentially:

1. **init_script**: Validates credentials, sets defaults, saves config
2. **init_module**: Loads WireGuard kernel module, creates `wg0` interface
3. **get_cert**: Downloads and caches PIA certificate
4. **healthcheck_tunnel** (pre-flight): Checks tunnel health; if unhealthy, clears session state to trigger a full rebuild
5. **get_region**: Fetches region server information, verifies signature, selects first reachable server
6. **get_token**: Generates authentication token
7. **gen_peer**: Generates WireGuard key pair
8. **get_auth**: Authenticates with PIA and gets server details
9. **set_wg**: Configures WireGuard interface and brings it up
10. **set_firewall**: Configures iptables rules for VPN traffic
11. **set_ipv6**: Drops routed IPv6 traffic to prevent leaks bypassing the VPN
12. **set_routes**: Sets up policy-based routing
13. **healthcheck_tunnel** (verification): Confirms tunnel is healthy; exits with error if not
14. **set_bypass** (optional): Configures IPs to bypass VPN (enabled by default for Google RCS)
15. **get_portforward** (optional): Requests port forwarding from PIA (skipped if the region does not support PF)
16. **set_portforward** (optional): Configures NAT rules for port forwarding
17. **set_duckdns** (optional): Updates DuckDNS with VPN IP and forwarded port

If you set `pia_pf` but the selected region does not support port forwarding, the script skips the PF and DuckDNS steps and logs that the region does not support port forwarding.

All configuration is saved to `pia_config` file for persistence across runs.

### Policy Routing Architecture

The script uses Linux policy-based routing to direct traffic through the VPN:

1. **Custom routing table (1337)**: Contains routes through `wg0` (VPN interface) plus throw routes for bridge interfaces so LAN traffic falls through to the main table. (An alternative using `ip rule ... table main suppress_prefixlength 1` would avoid throw routes but requires kernel 3.x+; FreshTomato uses kernel 2.6.)
2. **Policy rule**: `ip rule add not fwmark 0xf0b table 1337`
   - All packets **without** mark `0xf0b` use the VPN table
   - Packets **with** mark `0xf0b` skip the VPN and use the main routing table
3. **WireGuard fwmark**: WireGuard itself marks its control traffic with `0xf0b` to prevent routing loops
4. **Bypass marking**: Split-tunnel bypass uses the same mark (`0xf0b`) to exclude specific destinations from the VPN

## Idempotency

The script is fully idempotent - running it multiple times will:
- Skip stages that are already configured
- Only perform necessary work
- Safely handle region changes by clearing dependent state

This makes it safe to:
- Run in cron jobs for connection maintenance
- Re-run after network issues
- Switch regions by changing `pia_vpn` variable

## Notes

### VPN Bypass for Specific IPs

By default, the script configures Google RCS servers to bypass the VPN (fixes RCS not working over PIA VPN - see: https://support.adamnet.works/t/enabler-and-domain-requirements-for-rcs-messages/1307).

**Default bypass IPs (Google RCS servers):**
```
216.239.36.127 216.239.36.131 216.239.36.132 216.239.36.133 216.239.36.134 216.239.36.135 216.239.36.145
```

**To disable bypass:**
```bash
pia_user='user' pia_pass='pass' pia_bypass='false' ./pia_wireguard.sh
```

**To use custom IPs:**
```bash
pia_user='user' pia_pass='pass' pia_bypass='1.2.3.4 5.6.7.8' ./pia_wireguard.sh
```

The bypass works by:
1. Loading required kernel modules: `ip_set`, `ip_set_hash_ip`, `xt_set`
2. Creating an `ipset` named `pia_bypass` containing the IP addresses
3. Using iptables mangle table to mark packets **before routing decision**:
   - Hooks `PREROUTING` chain for all non-VPN ingress (`! -i wg0`) to catch LAN-originated traffic
   - Hooks `OUTPUT` chain to catch router-originated traffic (pings, cron jobs, etc.)
4. Packets destined to bypass IPs get marked with fwmark `0xf0b`
5. Policy routing rule `ip rule add not fwmark 0xf0b table 1337` ensures marked packets skip the VPN table and use the main routing table instead

This approach requires no knowledge of LAN interface names (e.g., `br0`) and works for any network topology.

**Note:** If ipset modules are not available, the script will skip VPN bypass and continue.

### Domain-Based VPN Bypass (dnsmasq)

In addition to static IPs, you can bypass the VPN for entire domains using FreshTomato's built-in dnsmasq. When a client resolves a matching domain, dnsmasq automatically adds the resolved IP(s) to the `pia_bypass` ipset. This covers all subdomains and keeps the set up to date as DNS responses change.

**Step 1 — Init script (Administration > Scripts > Init):**

The ipset must be created before dnsmasq starts, otherwise dnsmasq silently ignores the `ipset=` directives.

```bash
# Load ipset modules and create the set early so dnsmasq can use it
modprobe -a ip_set ip_set_hash_ip xt_set 2>/dev/null
ipset create pia_bypass hash:ip timeout 86400 -exist 2>/dev/null
```

**Step 2 — dnsmasq configuration (Advanced > DHCP/DNS > Dnsmasq Custom configuration):**

```
# VPN bypass: add resolved IPs to ipset for split tunnelling
ipset=/netflix.com/spotify.com/pia_bypass
```

**Step 3 — Restart dnsmasq** (or save settings in the web UI, which does it automatically):

```bash
service dnsmasq restart
```

**Verify it works (run on the router via SSH):**

```bash
nslookup netflix.com 127.0.0.1
ipset list pia_bypass | tail -10
```

Resolved IPs should appear in the set with a countdown timeout.

**Notes:**
- dnsmasq adds IPs on resolution but never removes them — entries auto-expire after 24 hours (configurable via the `timeout` value in the Init script)
- Static bypass IPs set by the script are permanent (`timeout 0`) and never expire
- The iptables rules are unchanged — they match on the `pia_bypass` ipset regardless of how entries were added
- Devices using DNS-over-HTTPS or hardcoded DNS servers bypass dnsmasq entirely, so their resolved IPs won't be added to the set

### Port Forwarding

The script supports forwarding PIA's assigned port to:

**Another device on your LAN:**
```bash
pia_pf='192.168.1.100:8080' ./pia_wireguard.sh
```
Uses DNAT to forward traffic to the specified device.

**Router itself (e.g., SSH):**
```bash
pia_pf='0.0.0.0:22' ./pia_wireguard.sh
```
Uses REDIRECT (more efficient for local services) to forward to the router's SSH or other services.

**Custom Chains:**

The script uses custom iptables chains to isolate all PIA-related rules:
- `PIA_INPUT` - Security rules for VPN input (blocks unsolicited inbound)
- `PIA_FORWARD` - Security rules for VPN forwarding (allows outbound only)
- `PIA_POSTROUTING` - NAT masquerading for VPN traffic
- `PIA_NAT` - Port forwarding DNAT/REDIRECT rules
- `PIA_PORTFORWARD` - Port access exceptions for forwarded traffic
- `PIA_MANGLE` - VPN bypass packet marking (hooks: `PREROUTING ! -i wg0` and `OUTPUT`)
- `PIA_FORWARD_V6` - IPv6 leak prevention (drops all routed IPv6)

This provides clean separation and makes debugging easier. Chains are only flushed and rebuilt when reconfiguration is needed (idempotent behaviour).

### Syslog Logging

The script automatically logs to syslog:
- Script start and completion
- All errors (specific error messages)
- Warnings (non-fatal issues)
- Important changes (region changes, config changes)

View logs:
```bash
grep pia_wireguard /var/log/messages
```

### Verifying VPN Bypass

To verify that split-tunnel bypass is working correctly:

**Check policy routing:**
```bash
ip rule show | grep 'not from all fwmark 0xf0b lookup 1337'
```
Should show exactly one rule.

**Check mangle chain hooks:**
```bash
iptables -t mangle -S PREROUTING | grep PIA_MANGLE
iptables -t mangle -S OUTPUT | grep PIA_MANGLE
```
Should show `! -i wg0 -j PIA_MANGLE` in PREROUTING and `-j PIA_MANGLE` in OUTPUT.

**Test router-originated bypass:**
```bash
# Clear counters
iptables -t mangle -Z PIA_MANGLE

# Ping a bypass IP (Google RCS server by default)
ping -c1 -W2 216.239.36.127 >/dev/null 2>&1 || true

# Check if marking occurred
iptables -t mangle -vnL PIA_MANGLE
```
The counters should increase, confirming packets are being marked before routing.

### Expose acquired port on the internet

The script has built-in support for DuckDNS dynamic DNS updates.

**Setup:**
1. Create an account on https://www.duckdns.org/
2. Create a domain (e.g., `myserver`)
3. Get your token from the DuckDNS dashboard
4. Run the script:

```bash
pia_user='user' \
pia_pass='pass' \
pia_pf='192.168.1.100:22' \
pia_duckdns='myserver:your-duckdns-token' \
./pia_wireguard.sh
```

**Connect using:**
```bash
ssh $(dig +short myserver.duckdns.org) -p $(dig +short TXT myserver.duckdns.org | tr -d '"')
```

The script automatically updates:
- **A record**: Your VPN's public IP address (PIA server IP)
- **TXT record**: The forwarded port number

**Note:** DuckDNS only works when port forwarding (`pia_pf`) is enabled.
