#!/usr/bin/env ash
# shellcheck shell=dash

set -eu  # Exit on error or undefined variable

# requirements:
# - FreshTomato >= 2024.3 or some Linux distro
# - wg kernel module for WireGuard
# - curl for API requests
# - php for JSON parsing and base64 encoding
# - Standard POSIX tools: sed, grep, awk

export PATH='/bin:/usr/bin:/sbin:/usr/sbin' # set PATH in case we run inside a cron
if ! type "php" >/dev/null 2>&1; then php () { php-cli "$@" ; }; fi # FreshTomato PHP is called php-cli

# Cleanup temporary files on exit
trap 'rm -f tmp_*' EXIT

init_script() {
  echo 'Initializing script...'
  # Load existing config if available
  # shellcheck disable=SC1091
  [ -f pia_config ] && . ./pia_config
  
  # Validate required variables
  [ -z "${pia_user:-}" ] && { echo 'ERROR: pia_user not set'; exit 1; }
  [ -z "${pia_pass:-}" ] && { echo 'ERROR: pia_pass not set'; exit 1; }
  
  # Set default region if not set
  if [ -z "${pia_vpn:-}" ]; then
    echo 'pia_vpn (region) not set, defaulting to ca_ontario (Ontario, Canada)'
    pia_vpn='ca_ontario'
  fi
  # Set default port forwarding if not set
  if [ -z "${pia_pf:-}" ]; then
    echo 'pia_pf (port forwarding) not set, defaulting to false'
    pia_pf='false'
  fi
  
  # Save credentials to config (preserve other variables)
  local vars_init
  vars_init=$(cat <<EOF
pia_user="$pia_user"
pia_pass="$pia_pass"
pia_vpn="$pia_vpn"
pia_pf="$pia_pf"
EOF
  )
  printf "%s\n%s\n" "$(grep -v '^pia_' pia_config 2>/dev/null || true)" "$vars_init" > pia_config
  
  echo 'Script initialized'
}

init_module() {
  echo 'Initializing WireGuard...'
  modprobe wireguard || { echo "ERROR: Failed to load wireguard module"; exit 1; }
  ip link show wg0 >/dev/null 2>&1 || ip link add wg0 type wireguard || { echo "ERROR: Failed to create wg0 interface"; exit 1; }
  echo 'WireGuard ready'
}

get_cert() {
  echo 'Downloading PIA certificate...'
  # Load config to check if cert exists
  # shellcheck disable=SC1091
  [ -f pia_config ] && . ./pia_config
  
  # Skip if certificate already exists (idempotent)
  if [ -n "${certificate:-}" ]; then
    echo 'Certificate already exists'
    echo 'Certificate ready'
    return 0
  fi
  
  # Download certificate
  local var_cert
  var_cert=$(curl --retry 5 --retry-all-errors -Ss 'https://raw.githubusercontent.com/pia-foss/manual-connections/master/ca.rsa.4096.crt')
  [ -n "$var_cert" ] || { echo "ERROR: Certificate download failed"; exit 1; }
  
  # Save to config (base64 encoded using PHP)
  printf "%s\n%s\n" "$(grep -v '^certificate=' pia_config 2>/dev/null || true)" "certificate=\"$(echo "$var_cert" | php -r 'echo base64_encode(file_get_contents("php://stdin"));')\"" > pia_config
  
  echo 'Certificate ready'
}

get_region() {
  echo 'Fetching PIA region info...'
  # Load config to check if region info exists
  # shellcheck disable=SC1091
  [ -f pia_config ] && . ./pia_config
  
  # Check if region changed (cascade invalidation)
  if [ -n "${region_id:-}" ] && [ "${region_id}" != "$pia_vpn" ]; then
    echo "Region changed from $region_id to $pia_vpn, clearing dependent data..."
    # Clear region, token, auth, and portforward data
    printf "%s\n" "$(grep -v '^region_\|^token=\|^auth_\|^portforward_' pia_config 2>/dev/null || true)" > pia_config
    # Reload config after clearing
    # shellcheck disable=SC1091
    [ -f pia_config ] && . ./pia_config
  fi

  # Skip if region info already exists for current region (idempotent)
  if [ -n "${region_meta_cn:-}" ] && [ -n "${region_wg_cn:-}" ] && [ "${region_id:-}" = "$pia_vpn" ]; then
    echo 'Region info already exists'
    echo 'Region info ready'
    return 0
  fi
  
  local var_php vars_region
  # PHP code to extract region info
  var_php=$(cat <<'EOF'
    $r = current(array_filter(json_decode($argn)->regions, fn($x) => $x->id == "REGION_ID"));
    if (!$r) die("ERROR: Region 'REGION_ID' not found\n");
    $mt = $r->servers->meta[0];
    $wg = $r->servers->wg[0];
    echo "region_id=\"REGION_ID\"\n";
    echo "region_meta_cn=\"$mt->cn\"\n";
    echo "region_meta_ip=\"$mt->ip\"\n";
    echo "region_wg_cn=\"$wg->cn\"\n";
    echo "region_wg_ip=\"$wg->ip\"\n";
    echo "region_wg_port=\"1337\"\n";
EOF
  )
  var_php=$(echo "$var_php" | sed "s/REGION_ID/$pia_vpn/g")
  vars_region=$(curl --retry 5 --retry-all-errors -Ss 'https://serverlist.piaservers.net/vpninfo/servers/v7' | head -1 | php -R "$var_php")
  [ -n "$vars_region" ] || { echo "ERROR: Failed to fetch region info"; exit 1; }
  printf "%s\n%s\n" "$(grep -v '^region_' pia_config 2>/dev/null || true)" "$vars_region" > pia_config
  echo 'Region info ready'
}

get_token() {
  echo 'Generating PIA token...'
  # Load region info from config
  # shellcheck disable=SC1091
  [ -f pia_config ] && . ./pia_config
  
  # Skip if token already exists (idempotent)
  if [ -n "${token:-}" ]; then
    echo 'Token already exists'
    echo 'Token ready'
    return 0
  fi
  
  # Validate required variables are loaded
  [ -z "${pia_user:-}" ] && { echo "ERROR: pia_user not set"; exit 1; }
  [ -z "${pia_pass:-}" ] && { echo "ERROR: pia_pass not set"; exit 1; }
  [ -z "${region_meta_cn:-}" ] && { echo "ERROR: region_meta_cn not set"; exit 1; }
  [ -z "${region_meta_ip:-}" ] && { echo "ERROR: region_meta_ip not set"; exit 1; }
  [ -z "${certificate:-}" ] && { echo "ERROR: certificate not set"; exit 1; }
  # Write certificate file (needed by curl)
  echo "$certificate" | php -r 'echo base64_decode(file_get_contents("php://stdin"));' > tmp_pia_cert
  [ -s tmp_pia_cert ] || { echo "ERROR: Failed to decode certificate"; exit 1; }
  local var_token
  var_token=$(curl --retry 5 --retry-all-errors -Ss -u "$pia_user:$pia_pass" --connect-to "$region_meta_cn::$region_meta_ip:" --cacert tmp_pia_cert "https://$region_meta_cn/authv3/generateToken" | php -r 'echo json_decode(stream_get_contents(STDIN))->token ?? "";')
  # Remove certificate file
  rm -f tmp_pia_cert
  [ -n "$var_token" ] || { echo "ERROR: Failed to generate token"; exit 1; }
  printf "%s\n%s\n" "$(grep -v '^token=' pia_config 2>/dev/null || true)" "token=\"$var_token\"" > pia_config
  echo 'Token ready'
}

gen_peer() {
  echo 'Generating peer keys...'
  # Load config to check if keys exist
  # shellcheck disable=SC1091
  [ -f pia_config ] && . ./pia_config
  
  # Skip if keys already exist (idempotent)
  if [ -n "${peer_prvkey:-}" ] && [ -n "${peer_pubkey:-}" ]; then
    echo 'Keys already exist'
    echo 'Keys ready'
    return 0
  fi
  
  # Generate new keys
  local var_prvkey var_pubkey
  var_prvkey=$(wg genkey)
  var_pubkey=$(echo "$var_prvkey" | wg pubkey)
  # Save to config
  printf "%s\n%s\n%s\n" "$(grep -v '^peer_' pia_config 2>/dev/null || true)" "peer_prvkey=\"$var_prvkey\"" "peer_pubkey=\"$var_pubkey\"" > pia_config
  
  echo 'Keys ready'
}

get_auth() {
  echo 'Authenticating to PIA...'
  # Load config
  # shellcheck disable=SC1091
  [ -f pia_config ] && . ./pia_config
  # Skip if auth already exists (idempotent)
  if [ -n "${auth_peer_ip:-}" ] && [ -n "${auth_server_key:-}" ] && [ -n "${auth_server_vip:-}" ]; then
    echo 'Auth already exists'
    echo 'Auth ready'
    return 0
  fi
  # Validate required variables are loaded
  [ -z "${region_wg_cn:-}" ] && { echo "ERROR: region_wg_cn not set"; exit 1; }
  [ -z "${region_wg_ip:-}" ] && { echo "ERROR: region_wg_ip not set"; exit 1; }
  [ -z "${region_wg_port:-}" ] && { echo "ERROR: region_wg_port not set"; exit 1; }
  [ -z "${token:-}" ] && { echo "ERROR: token not set"; exit 1; }
  [ -z "${peer_pubkey:-}" ] && { echo "ERROR: peer_pubkey not set"; exit 1; }
  [ -z "${certificate:-}" ] && { echo "ERROR: certificate not set"; exit 1; }
  # Write certificate file (needed by curl)
  echo "$certificate" | php -r 'echo base64_decode(file_get_contents("php://stdin"));' > tmp_pia_cert
  [ -s tmp_pia_cert ] || { echo "ERROR: Failed to decode certificate"; exit 1; }
  local var_php vars_auth
  # PHP code to parse auth response
  var_php=$(cat <<'EOF'
    $d = json_decode(stream_get_contents(STDIN));
    echo "auth_peer_ip=\"$d->peer_ip\"\n";
    echo "auth_server_key=\"$d->server_key\"\n";
    echo "auth_server_vip=\"$d->server_vip\"\n";
EOF
  )
  vars_auth=$(curl --retry 10 --retry-all-errors -GSs --connect-to "$region_wg_cn::$region_wg_ip:" --cacert tmp_pia_cert --data-urlencode "pt=$token" --data-urlencode "pubkey=$peer_pubkey" "https://$region_wg_cn:$region_wg_port/addKey" | php -r "$var_php")
  # Remove certificate file
  rm -f tmp_pia_cert
  [ -n "$vars_auth" ] || { echo "ERROR: Failed to authenticate"; exit 1; }
  printf "%s\n%s\n" "$(grep -v '^auth_' pia_config 2>/dev/null || true)" "$vars_auth" > pia_config
  echo 'Auth ready'
}

set_wg() {
  echo 'Configuring WireGuard...'
  # Load config
  # shellcheck disable=SC1091
  [ -f pia_config ] && . ./pia_config
  # Skip if WireGuard already configured (idempotent)
  if ip link show wg0 2>/dev/null | grep -q 'state UP' && \
     ip addr show wg0 2>/dev/null | grep -q "${auth_peer_ip:-}" && \
     wg show wg0 peers 2>/dev/null | grep -q "^${auth_server_key:-}$" && \
     [ "$(wg show wg0 peers 2>/dev/null | wc -l)" -eq 1 ]; then
    echo 'WireGuard already configured'
    echo 'WireGuard ready'
    return 0
  fi
  # Validate required variables are loaded
  [ -z "${peer_prvkey:-}" ] && { echo "ERROR: peer_prvkey not set"; exit 1; }
  [ -z "${auth_server_key:-}" ] && { echo "ERROR: auth_server_key not set"; exit 1; }
  [ -z "${region_wg_ip:-}" ] && { echo "ERROR: region_wg_ip not set"; exit 1; }
  [ -z "${region_wg_port:-}" ] && { echo "ERROR: region_wg_port not set"; exit 1; }
  [ -z "${auth_peer_ip:-}" ] && { echo "ERROR: auth_peer_ip not set"; exit 1; }
  # Write private key file (needed by wg command)
  echo "$peer_prvkey" > tmp_peer_prvkey
  # Remove existing peers
  for p in $(wg show wg0 peers 2>/dev/null); do wg set wg0 peer "$p" remove; done
  # Configure WireGuard
  wg set wg0 fwmark 0xf0b private-key tmp_peer_prvkey peer "$auth_server_key" endpoint "$region_wg_ip:$region_wg_port" persistent-keepalive 25 allowed-ips '0.0.0.0/0'
  # Remove private key file
  rm -f tmp_peer_prvkey
  ip addr flush dev wg0
  ip addr replace "$auth_peer_ip" dev wg0
  # Bring up interface with retry (often fails first attempt)
  local var_attempt=1 var_backoff=1
  while [ $var_attempt -le 5 ]; do
    if [ $var_attempt -gt 1 ]; then
      echo "  Retry $var_attempt/5 (backoff: ${var_backoff}s)..."
      sleep "$var_backoff"
      var_backoff=$((var_backoff * 2))
    fi
    ip link set wg0 up && break
    var_attempt=$((var_attempt + 1))
  done
  [ $var_attempt -le 5 ] || { echo "ERROR: Failed to bring up wg0 after 5 attempts"; exit 1; }
  # Disable IPv6 (PIA does not support it yet)
  sysctl -w net.ipv6.conf.wg0.disable_ipv6=1 >/dev/null 2>&1 || true
  echo 'WireGuard ready'
}

set_routes() {
  echo 'Configuring routes...'
  # Skip if routes already configured (idempotent)
  if ip route show table 1337 | grep -q 'default dev wg0' && ip rule list | grep -q 'not from all fwmark 0xf0b lookup 1337'; then
    echo 'Routes already configured'
    echo 'Routes ready'
    return 0
  fi
  # Clear custom routing table
  ip route flush table 1337
  # Add local network route (keeps LAN traffic on local network)
  local var_lan_route
  var_lan_route=$(ip route show dev br0 | cut -d' ' -f1)
  [ -n "$var_lan_route" ] || { echo "ERROR: No route found for br0"; exit 1; }
  ip route add "$var_lan_route" dev br0 table 1337
  # Set default route through VPN
  ip route add default dev wg0 table 1337
  # Remove old policy rule if exists
  ip rule delete fwmark 0xf0b 2>/dev/null || true
  # Add policy rule: use table 1337 for all packets NOT marked with 0xf0b
  ip rule add not fwmark 0xf0b table 1337
  echo 'Routes ready'
}

set_firewall() {
  echo 'Configuring firewall...'
  # Skip if firewall already configured (idempotent)
  if iptables -C INPUT -i wg0 -m state --state NEW -j DROP 2>/dev/null && \
     iptables -C FORWARD -i wg0 -m state --state NEW -j DROP 2>/dev/null && \
     iptables -C FORWARD -o wg0 -j ACCEPT 2>/dev/null && \
     iptables -t nat -C POSTROUTING -o wg0 -j MASQUERADE 2>/dev/null; then
    echo 'Firewall already configured'
    echo 'Firewall ready'
    return 0
  fi
  # Remove all existing wg0 rules (clean slate)
  for var_table in '' 'nat'; do
    iptables-save ${var_table:+-t} "$var_table" | awk '/wg0/ && /^-A/ {sub(/^-A/, "-D"); print}' | while read -r var_rule; do
      # shellcheck disable=SC2086
      iptables ${var_table:+-t} "$var_table" $var_rule 2>/dev/null || true
    done
  done
  # Block NEW incoming connections from VPN
  iptables -I INPUT -i wg0 -m state --state NEW -j DROP
  # Block NEW forwarded connections from VPN
  iptables -I FORWARD -i wg0 -m state --state NEW -j DROP
  # Allow all forwarded traffic going out through VPN
  iptables -I FORWARD -o wg0 -j ACCEPT
  # NAT/masquerade all traffic going out through VPN
  iptables -t nat -I POSTROUTING -o wg0 -j MASQUERADE
  echo 'Firewall ready'
}

get_portforward() {
  echo 'Requesting port forward...'
  # Load config
  # shellcheck disable=SC1091
  [ -f pia_config ] && . ./pia_config
  # Skip if port forward already exists (idempotent)
  if [ -n "${portforward_port:-}" ] && [ -n "${portforward_signature:-}" ] && [ -n "${portforward_payload:-}" ]; then
    echo 'Port forward already exists'
    echo 'Port forward ready'
    return 0
  fi
  # Validate required variables
  [ -z "${region_wg_cn:-}" ] && { echo "ERROR: region_wg_cn not set"; exit 1; }
  [ -z "${auth_server_vip:-}" ] && { echo "ERROR: auth_server_vip not set"; exit 1; }
  [ -z "${token:-}" ] && { echo "ERROR: token not set"; exit 1; }
  [ -z "${certificate:-}" ] && { echo "ERROR: certificate not set"; exit 1; }
  # Write certificate file (needed by curl)
  echo "$certificate" | php -r 'echo base64_decode(file_get_contents("php://stdin"));' > tmp_pia_cert
  [ -s tmp_pia_cert ] || { echo "ERROR: Failed to decode certificate"; exit 1; }
  # Request port forward signature
  local var_php vars_portforward
  var_php=$(cat <<'EOF'
    $d = json_decode(stream_get_contents(STDIN));
    echo "portforward_signature=\"$d->signature\"\n";
    echo "portforward_payload=\"$d->payload\"\n";
    echo "portforward_port=\"" . json_decode(base64_decode($d->payload))->port . "\"\n";
EOF
  )
  vars_portforward=$(curl --retry 10 --retry-all-errors -GSs --connect-to "$region_wg_cn::$auth_server_vip:" --cacert tmp_pia_cert --data-urlencode "token=$token" "https://$region_wg_cn:19999/getSignature" --interface wg0 | php -r "$var_php")
  # Remove certificate file
  rm -f tmp_pia_cert
  [ -n "$vars_portforward" ] || { echo "ERROR: Failed to get port forward"; exit 1; }
  # Save to config
  printf "%s\n%s\n" "$(grep -v '^portforward_' pia_config 2>/dev/null || true)" "$vars_portforward" > pia_config
  echo 'Port forward ready'
}

set_portforward() {
  echo 'Configuring port forward NAT...'
  # Load config
  # shellcheck disable=SC1091
  [ -f pia_config ] && . ./pia_config
  # Validate required variables
  [ -z "${region_wg_cn:-}" ] && { echo "ERROR: region_wg_cn not set"; exit 1; }
  [ -z "${auth_server_vip:-}" ] && { echo "ERROR: auth_server_vip not set"; exit 1; }
  [ -z "${portforward_signature:-}" ] && { echo "ERROR: portforward_signature not set"; exit 1; }
  [ -z "${portforward_payload:-}" ] && { echo "ERROR: portforward_payload not set"; exit 1; }
  [ -z "${portforward_port:-}" ] && { echo "ERROR: portforward_port not set"; exit 1; }
  [ -z "${pia_pf:-}" ] && { echo "ERROR: pia_pf not set"; exit 1; }
  [ -z "${certificate:-}" ] && { echo "ERROR: certificate not set"; exit 1; }
  # Validate pia_pf format (must be IP:PORT)
  echo "$pia_pf" | grep -q '^[0-9.]\+:[0-9]\+$' || { echo "ERROR: pia_pf must be in format IP:PORT (e.g., 192.168.1.10:2022)"; exit 1; }
  # Write certificate file (needed by curl)
  echo "$certificate" | php -r 'echo base64_decode(file_get_contents("php://stdin"));' > tmp_pia_cert
  [ -s tmp_pia_cert ] || { echo "ERROR: Failed to decode certificate"; exit 1; }
  # Bind port with PIA (always refresh binding)
  curl -sGm 5 --connect-to "$region_wg_cn::$auth_server_vip:" --cacert tmp_pia_cert --data-urlencode "payload=$portforward_payload" --data-urlencode "signature=$portforward_signature" "https://$region_wg_cn:19999/bindPort" --interface wg0
  # Remove certificate file
  rm -f tmp_pia_cert
  # Skip NAT configuration if already set (idempotent)
  if iptables -t nat -C PREROUTING -i wg0 -p tcp --dport "$portforward_port" -j DNAT --to-destination "$pia_pf" 2>/dev/null; then
    echo 'Port forward NAT already configured'
    echo 'Port forward NAT ready'
    return 0
  fi
  # Configure NAT rules
  local var_pf_ip="${pia_pf%:*}" var_pf_port="${pia_pf#*:}"
  iptables -t nat -I PREROUTING -i wg0 -p tcp --dport "$portforward_port" -j DNAT --to-destination "$pia_pf"
  iptables -I FORWARD -i wg0 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT -d "$var_pf_ip" -p tcp --dport "$var_pf_port"
  echo 'Port forward NAT ready'
}

init_script
init_module
get_cert
get_region
get_token
gen_peer
get_auth
set_wg
set_routes
set_firewall

if [ "${pia_pf:-false}" != 'false' ]; then
  get_portforward
  set_portforward
fi

### OPTIONAL ###
### Force wireguard traffic over specific interface
# ip route list metric 50 | while read r; do ip route del $r; done
# ip route add $region_wg_ip/32 via 10.71.0.1 dev wlp2s0 metric 50
