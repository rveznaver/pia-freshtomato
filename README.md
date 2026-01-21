# pia-freshtomato
Script to set up PIA WireGuard on FreshTomato

## Features
- **Idempotent**: Safe to run multiple times, only configures what's needed
- **Robust**: Automatic retries with exponential backoff for flaky operations
- **Modular**: Each stage is independent and can be run separately
- **Region change detection**: Automatically clears dependent state when switching regions
- **Port forwarding**: Optional port forwarding with automatic NAT configuration
- **Visual feedback**: Clear status indicators for all operations

## Requirements
- FreshTomato >= 2024.3 or compatible Linux distro
- WireGuard kernel module (`wg`)
- `curl` for API requests
- `php` (or `php-cli`) for JSON parsing and base64 encoding
- Standard POSIX tools: `sed`, `grep`, `awk`, `iptables`, `ip`

## Setup

### Basic Usage (No Port Forwarding)
```bash
scp -O pia_wireguard.sh root@<ROUTER_IP>:
ssh root@<ROUTER_IP>
pia_user='<USERNAME>' pia_pass='<PASSWORD>' ./pia_wireguard.sh
```

### With Port Forwarding
```bash
pia_user='<USERNAME>' pia_pass='<PASSWORD>' pia_pf='<LOCAL_IP>:<LOCAL_PORT>' ./pia_wireguard.sh
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
./pia_wireguard.sh
```

## Configuration Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `pia_user` | Yes | - | PIA username |
| `pia_pass` | Yes | - | PIA password |
| `pia_vpn` | No | `ca_ontario` | PIA region ID (e.g., `us_california`, `uk_london`) |
| `pia_pf` | No | `false` | Port forwarding destination in format `IP:PORT` |
| `pia_bypass` | No | Google RCS IPs | Space-separated IPs to bypass VPN (set to `false` to disable) |

## Example Output
```
[ ] Initializing script...
[*] pia_vpn (region) not set, defaulting to ca_ontario (Ontario, Canada)
[*] pia_pf (port forwarding) not set, defaulting to false
[+] Script ready
[ ] Initializing WireGuard...
[+] WireGuard ready
[ ] Downloading PIA certificate...
[+] Certificate ready
[ ] Fetching PIA region info...
[+] Region info ready
[ ] Generating PIA token...
[+] Token ready
[ ] Generating peer keys...
[+] Keys ready
[ ] Authenticating to PIA...
[+] Auth ready
[ ] Configuring WireGuard...
[-] Removing existing peers
[~] Retry 2/5 (backoff: 1s)...
[+] WireGuard ready
[ ] Configuring firewall...
[-] Removing existing wg0 firewall rules
[+] Firewall ready
[ ] Configuring routes...
[-] Flushing routing table 1337
[-] Removing old policy rule
[+] Routes ready
```

## Status Indicators
- `[ ]` - Starting/in progress
- `[+]` - Successfully completed
- `[=]` - Skipped (already configured)
- `[!]` - Error
- `[~]` - Change detected / Retry in progress
- `[*]` - Informational message
- `[-]` - Cleanup action

## How It Works

The script runs through these stages sequentially:

1. **init_script**: Validates credentials, sets defaults, saves config
2. **init_module**: Loads WireGuard kernel module, creates `wg0` interface
3. **get_cert**: Downloads and caches PIA certificate
4. **get_region**: Fetches region server information
5. **get_token**: Generates authentication token
6. **gen_peer**: Generates WireGuard key pair
7. **get_auth**: Authenticates with PIA and gets server details
8. **set_wg**: Configures WireGuard interface and brings it up
9. **set_firewall**: Configures iptables rules for VPN traffic
10. **set_routes**: Sets up policy-based routing
11. **set_bypass** (optional): Configures IPs to bypass VPN (enabled by default for Google RCS)
12. **get_portforward** (optional): Requests port forwarding from PIA
13. **set_portforward** (optional): Configures NAT rules for port forwarding

All configuration is saved to `pia_config` file for persistence across runs.

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

The bypass works by adding `ip rule` entries that route specified IPs through the main routing table instead of the VPN.

### Expose acquired port on the internet
1. create an account on https://www.duckdns.org/
2. add to `pia_refresh.sh`:
```bash
# update duckdns
duckdns_token='<REDACTED>'
duckdns_domain='<REDACTED>'
curl -sGm 5 "https://www.duckdns.org/update?domains=$duckdns_domain&token=$duckdns_token&ip=$pia_vpn_wg_ip"
curl -sGm 5 "https://www.duckdns.org/update?domains=$duckdns_domain&token=$duckdns_token&txt=$pia_port"
```
3. connect using:
```bash
ssh $(dig +short YOURDOMAIN.duckdns.org) -p $(dig +short TXT YOURDOMAIN.duckdns.org | tr -d '"')
```
