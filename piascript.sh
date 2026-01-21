#!/usr/bin/env ash
# shellcheck shell=dash

set -eu  # Exit on error or undefined variable

# requirements:
# - FreshTomato >= 2024.3 or some Linux distro
# - wg kernel module for WireGuard
# - curl for API requests
# - php for JSON parsing and base64 encoding
# - Standard POSIX tools: sed, grep

export PATH='/bin:/usr/bin:/sbin:/usr/sbin' # set PATH in case we run inside a cron
if ! type "php" >/dev/null 2>&1; then php () { php-cli "$@" ; }; fi # FreshTomato PHP is called php-cli

retry() {
  local var_attempt=1 var_backoff=1
  while [ $var_attempt -le 5 ]; do
    if [ $var_attempt -gt 1 ]; then
      echo "  Retry $var_attempt/5 (backoff: ${var_backoff}s)..."
      sleep "$var_backoff"
      var_backoff=$((var_backoff * 2))
    fi
    "$@" && return 0
    var_attempt=$((var_attempt + 1))
  done
  echo "ERROR: Failed after 5 attempts: $*"
  exit 1
}

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
    echo 'pia_vpn not set, defaulting to ca (Montreal, Canada)'
    pia_vpn='ca'
  fi
  
  # Save credentials to config (preserve other variables)
  local vars_init
  vars_init=$(cat <<EOF
pia_user="$pia_user"
pia_pass="$pia_pass"
pia_vpn="$pia_vpn"
EOF
)
  printf "%s\n%s\n" "$(grep -v '^pia_user=\|^pia_pass=\|^pia_vpn=' pia_config 2>/dev/null || true)" "$vars_init" > pia_config
  
  echo 'Script initialized'
}

init_module() {
  echo 'Initializing WireGuard...'
  modprobe wireguard || { echo "ERROR: Cannot load wireguard module"; exit 1; }
  ip link show wg0 >/dev/null 2>&1 || ip link add wg0 type wireguard || { echo "ERROR: Cannot create wg0 interface"; exit 1; }
  echo 'WireGuard ready'
}

get_cert() {
  echo 'Downloading PIA certificate...'
  # Load config to check if cert exists
  # shellcheck disable=SC1091
  [ -f pia_config ] && . ./pia_config
  
  # Skip if certificate already exists (idempotent)
  if [ -n "${certificate:-}" ] && [ -f pia_cert ]; then
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
  
  # Write certificate file
  echo "$var_cert" > pia_cert
  
  echo 'Certificate ready'
}

get_region() {
  echo 'Fetching PIA region info...'
  # Load config to check if region info exists
  # shellcheck disable=SC1091
  [ -f pia_config ] && . ./pia_config
  
  # Skip if region info already exists (idempotent)
  if [ -n "${region_meta_cn:-}" ] && [ -n "${region_wg_cn:-}" ]; then
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
  . ./pia_config
  
  # Skip if token already exists (idempotent)
  if [ -n "${token:-}" ]; then
    echo 'Token already exists'
    echo 'Token ready'
    return 0
  fi
  
  # Validate required variables are loaded
  [ -z "${region_meta_cn:-}" ] || [ -z "${region_meta_ip:-}" ] && { echo "ERROR: Region info not available"; exit 1; }
  local var_token
  var_token=$(curl --retry 5 --retry-all-errors -Ss -u "$pia_user:$pia_pass" --connect-to "$region_meta_cn::$region_meta_ip:" --cacert pia_cert "https://$region_meta_cn/authv3/generateToken" | php -r 'echo json_decode(stream_get_contents(STDIN))->token ?? "";')
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

init_script
init_module
get_cert
get_region
get_token
gen_peer

echo 'Authenticating to PIA...'
curl --retry 10 --retry-all-errors -GSs --connect-to "$pia_vpn_wg_cn::$pia_vpn_wg_ip:" --cacert pia_cert --data-urlencode "pt=$(cat pia_token)" --data-urlencode "pubkey=$peer_pubkey" "https://$pia_vpn_wg_cn:$pia_vpn_wg_port/addKey" | tr -d '\n' > pia_auth
peer_ip=$(cat pia_auth | php -R 'echo json_decode($argn)->peer_ip;')
server_key=$(cat pia_auth | php -R 'echo json_decode($argn)->server_key;')
server_vip=$(cat pia_auth | php -R 'echo json_decode($argn)->server_vip;')

### OPTIONAL ###
### Force wireguard traffic over specific interface
# ip route list metric 50 | while read r; do ip route del $r; done
# ip route add $pia_vpn_wg_ip/32 via 10.71.0.1 dev wlp2s0 metric 50
### Disable IPv6 with sysctl as PIA does not yet support it
# sysctl net.ipv6.conf.wg0.disable_ipv6=1

echo 'Configuring WireGuard...'
for p in $(wg show wg0 peers); do wg set wg0 peer "$p" remove; done
wg set wg0 fwmark 0xf0b private-key peer_prvkey peer "$server_key" endpoint "$pia_vpn_wg_ip:$pia_vpn_wg_port" persistent-keepalive 25 allowed-ips '0.0.0.0/0'
ip addr flush dev wg0
ip addr replace "$peer_ip" dev wg0
sleep 5
ip link set wg0 up

echo 'Configuring routes...'
ip route flush table 1337
ip route add $(ip route show dev br0 | cut -d' ' -f1) dev br0 table 1337
ip route add default dev wg0 table 1337
ip rule delete fwmark 0xf0b # ignore RNETLINK error
ip rule add not fwmark 0xf0b table 1337

echo 'Configuring NAT...'
iptables-save | grep -v wg0 | iptables-restore
iptables -I INPUT -i wg0 -m state --state NEW -j DROP
iptables -I FORWARD -i wg0 -m state --state NEW -j DROP
iptables -I FORWARD -o wg0 -j ACCEPT
iptables -t nat -I POSTROUTING -o wg0 -j MASQUERADE

echo 'Requesting port forward...'
curl --retry 10 --retry-all-errors -GSs --connect-to "$pia_vpn_wg_cn::$server_vip:" --cacert pia_cert --data-urlencode "token=$(cat pia_token)" "https://$pia_vpn_wg_cn:19999/getSignature" --interface wg0 | tr -d '\n' > pia_paysig
pia_signature=$(cat pia_paysig | php -R 'echo json_decode($argn)->signature;')
pia_payload=$(cat pia_paysig | php -R 'echo json_decode($argn)->payload;')
pia_port=$(cat pia_paysig | php -R 'echo json_decode(base64_decode(json_decode($argn)->payload))->port;')

echo 'Setting up port with NAT...'
curl -sGm 5 --connect-to "$pia_vpn_wg_cn::$server_vip:" --cacert pia_cert --data-urlencode "payload=$pia_payload" --data-urlencode "signature=$pia_signature" "https://$pia_vpn_wg_cn:19999/bindPort" --interface wg0
iptables -t nat -I PREROUTING -i wg0 -p tcp --dport $pia_port -j DNAT --to-destination 192.168.2.10:2022
iptables -I FORWARD -i wg0 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT -d 192.168.2.10 -p tcp --dport 2022

echo 'Writing out pia_refresh script for port rebinding...'
cat <<'EOF' > pia_refresh
export PATH='/bin:/usr/bin:/sbin:/usr/sbin' # set PATH in case we run inside a cron
if ! type "php" >/dev/null 2>&1; then php () { php-cli "$@" ; }; fi # FreshTomato PHP is called php-cli

# vars for port forwarding API refresh
pia_vpn_wg_ip=$(cat pia_region | php -R 'echo json_decode($argn)->servers->wg[0]->ip;')
pia_vpn_wg_cn=$(cat pia_region | php -R 'echo json_decode($argn)->servers->wg[0]->cn;')
server_vip=$(cat pia_auth | php -R 'echo json_decode($argn)->server_vip;')
pia_signature=$(cat pia_paysig | php -R 'echo json_decode($argn)->signature;')
pia_payload=$(cat pia_paysig | php -R 'echo json_decode($argn)->payload;')
pia_port=$(cat pia_paysig | php -R 'echo json_decode(base64_decode(json_decode($argn)->payload))->port;')

# scheduler config: every 15 mins
# cd /tmp/home/root && ./pia_refresh
logger "refresh PIA forward $pia_vpn_wg_ip:$pia_port - $(curl -sGm 5 --connect-to "$pia_vpn_wg_cn::$server_vip:" --cacert pia_cert --data-urlencode "payload=${pia_payload}" --data-urlencode "signature=${pia_signature}" "https://${pia_vpn_wg_cn}:19999/bindPort" --interface wg0)"
EOF
chmod +x pia_refresh

echo 'Done.'
