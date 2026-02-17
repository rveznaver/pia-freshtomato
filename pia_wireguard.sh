#!/usr/bin/env ash
# shellcheck shell=dash

set -eu  # Exit on error or undefined variable

# requirements:
# - FreshTomato >= 2025.5 or some Linux distro
# - wg kernel module for WireGuard
# - curl for API requests
# - php for JSON parsing
# - openssl for RSA signature verification and base64 encoding/decoding
# - ipset with kernel modules: ip_set, ip_set_hash_ip, xt_set for VPN bypass
# - Standard POSIX tools: sed, grep

export PATH='/bin:/usr/bin:/sbin:/usr/sbin' # set PATH in case we run inside a cron
if ! type "php" >/dev/null 2>&1; then php () { php-cli "$@" ; }; fi # FreshTomato PHP is called php-cli

# Cleanup temporary files on exit
trap 'rm -f pia_tmp_*' EXIT

# Error handler - logs to syslog and exits
error_exit() {
  echo "[!] ERROR: $1" >&2
  logger -t pia_wireguard "ERROR: $1"
  exit 1
}

healthcheck_tunnel() {
  # Load config
  # shellcheck disable=SC1091
  [ -f pia_config ] && . ./pia_config

  # Skip on first run (no session state to check)
  [ -n "${auth_peer_ip:-}" ] || {
    echo '[=] No session state, skipping healthcheck'
    return 0
  }

  echo '[ ] Checking tunnel health...'

  [ -d /sys/class/net/wg0 ] || {
    echo '[*] wg0 not ready yet'
    logger -t pia_wireguard "[*] wg0 not ready yet"
    return 1
  }

  # TX check (matches official client transfer monitoring)
  local var_tx_before var_tx_after
  var_tx_before=$(wg show wg0 transfer 2>/dev/null | awk 'NR==1 {print $3+0}')

  # RX substitute: FreshTomato WG RX counter is always 0, so ping confirms
  # the return path is working. Also generates traffic on a fresh tunnel.
  # Multi-probe: retry on transient loss; fallback target guards against
  # PIA metadata server being down. Happy path returns near-instantly.
  ping -I wg0 -c 1 -W 2 10.0.0.1 >/dev/null 2>&1 \
    || ping -I wg0 -c 1 -W 2 10.0.0.1 >/dev/null 2>&1 \
    || ping -I wg0 -c 1 -W 2 1.1.1.1 >/dev/null 2>&1 \
    || {
    echo '[*] Connectivity probe failed (no return path)'
    logger -t pia_wireguard '[*] Connectivity probe failed (no return path)'
    return 1
  }

  var_tx_after=$(wg show wg0 transfer 2>/dev/null | awk 'NR==1 {print $3+0}')
  [ "${var_tx_after}" -gt "${var_tx_before}" ] || {
    echo "[*] TX did not increase after probe (before=${var_tx_before} after=${var_tx_after})"
    logger -t pia_wireguard "[*] TX did not increase (before=${var_tx_before} after=${var_tx_after})"
    return 1
  }

  local var_timeout=300 # 5 minutes
  local var_handshake_epoch var_now var_handshake_age
  var_handshake_epoch=$(wg show wg0 latest-handshakes 2>/dev/null | awk 'NR==1 {print $2+0}')
  var_now=$(date +%s)
  var_handshake_age=$((var_now - var_handshake_epoch))
  # Empty/invalid/zero epoch coerces to 0 via awk +0, producing an age
  # equal to var_now (~decades), which always exceeds the timeout.
  [ "${var_handshake_age}" -lt "${var_timeout}" ] || {
    echo "[*] Handshake too old (${var_handshake_age}s)"
    logger -t pia_wireguard "[*] Handshake too old (${var_handshake_age}s)"
    return 1
  }

  echo "[=] Tunnel healthy (handshake age: ${var_handshake_age}s)"
  return 0
}

init_script() {
  echo '[ ] Initializing script...'
  # Load config
  # shellcheck disable=SC1091
  [ -f pia_config ] && . ./pia_config

  # Validate required variables
  [ -z "${pia_user:-}" ] && error_exit "pia_user not set"
  [ -z "${pia_pass:-}" ] && error_exit "pia_pass not set"

  # Set default region if not set
  if [ -z "${pia_vpn:-}" ]; then
    echo '[*] pia_vpn (region) not set, defaulting to ca_ontario (Ontario, Canada)'
    pia_vpn='ca_ontario'
  fi
  # Set default port forwarding if not set
  if [ -z "${pia_pf:-}" ]; then
    echo '[*] pia_pf (port forwarding) not set, defaulting to false'
    pia_pf='false'
  fi
  # Validate pia_pf format (must be IP:PORT or false)
  if [ "${pia_pf}" != 'false' ]; then
    echo "${pia_pf}" | grep -q '^[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}:[0-9]\{1,5\}$' || error_exit "pia_pf must be in format IP:PORT (e.g., 192.168.1.10:22)"
  fi
  # Set default bypass IPs if not set (Google RCS servers)
  if [ -z "${pia_bypass:-}" ]; then
    echo '[*] pia_bypass (split tunneling by IP) not set, defaulting to Google RCS servers'
    pia_bypass='216.239.36.127 216.239.36.131 216.239.36.132 216.239.36.133 216.239.36.134 216.239.36.135 216.239.36.145'
  fi
  # Validate bypass IPs (prevent injection)
  if [ "${pia_bypass}" != 'false' ]; then
    for ip in ${pia_bypass}; do
      echo "${ip}" | grep -q '^[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}$' || error_exit "Invalid IP in pia_bypass: ${ip}"
    done
  fi
  # Set default DuckDNS if not set
  if [ -z "${pia_duckdns:-}" ]; then
    echo '[*] pia_duckdns (DuckDNS dynamic DNS) not set, defaulting to false'
    pia_duckdns='false'
  fi
  # Validate pia_duckdns format (must be DOMAIN:TOKEN or false)
  if [ "${pia_duckdns}" != 'false' ]; then
    echo "${pia_duckdns}" | grep -q ':' || error_exit "pia_duckdns must be in format DOMAIN:TOKEN"
  fi

  # Save credentials to config (preserve other variables)
  local vars_init
  vars_init=$(cat <<EOF
pia_user="${pia_user}"
pia_pass="${pia_pass}"
pia_vpn="${pia_vpn}"
pia_pf="${pia_pf}"
pia_bypass="${pia_bypass}"
pia_duckdns="${pia_duckdns}"
EOF
  )
  printf "%s\n%s\n" "$(grep -v '^pia_' pia_config 2>/dev/null || true)" "${vars_init}" > pia_config

  echo '[+] Script ready'
}

init_module() {
  echo '[ ] Initializing WireGuard...'
  modprobe wireguard || error_exit "Failed to load wireguard module"
  ip link show | grep -q 'wg0' || ip link add wg0 type wireguard || error_exit "Failed to create wg0 interface"

  # Disable IPv6 on wg0 immediately after creation (PIA does not support IPv6)
  # This prevents "Could not create IPv6 socket" error when bringing up the interface
  if [ -d /proc/sys/net/ipv6/conf/wg0 ]; then
    echo 1 > /proc/sys/net/ipv6/conf/wg0/disable_ipv6 2>/dev/null || {
      echo "[!] WARNING: Could not disable IPv6 on wg0"
      logger -t pia_wireguard "WARNING: Could not disable IPv6 on wg0"
    }
  fi

  echo '[+] WireGuard ready'
}

get_cert() {
  echo '[ ] Downloading PIA certificate...'
  # Load config
  # shellcheck disable=SC1091
  [ -f pia_config ] && . ./pia_config

  # Skip if certificate already exists (idempotent)
  if [ -n "${certificate:-}" ]; then
    echo '[=] Certificate already exists'
    return 0
  fi

  # WAN interface for PIA API (recovery when tunnel is broken)
  local var_wan
  var_wan=$(ip route show table main 2>/dev/null | awk '/^default / {print $5; exit}')
  [ -z "${var_wan:-}" ] && error_exit "WAN interface not found"

  # Download certificate
  local var_cert
  var_cert=$(curl --doh-url "https://1.1.1.1/dns-query" --interface "${var_wan}" --retry 5 -Ss 'https://raw.githubusercontent.com/pia-foss/manual-connections/master/ca.rsa.4096.crt')
  [ -n "${var_cert}" ] || error_exit "Certificate download failed"

  # Save to config (base64 encoded)
  local var_cert_encoded
  var_cert_encoded=$(echo "${var_cert}" | openssl base64 -A)
  printf "%s\n%s\n" "$(grep -v '^certificate=' pia_config 2>/dev/null || true)" "certificate=\"${var_cert_encoded}\"" > pia_config

  echo '[+] Certificate ready'
}

get_region() {
  echo '[ ] Fetching PIA region info...'
  # Load config
  # shellcheck disable=SC1091
  [ -f pia_config ] && . ./pia_config

  # Check if region changed (cascade invalidation)
  if [ -n "${region_id:-}" ] && [ "${region_id}" != "${pia_vpn}" ]; then
    echo "[~] Region changed from ${region_id} to ${pia_vpn}, clearing dependent data..."
    logger -t pia_wireguard "Region changed from ${region_id} to ${pia_vpn}"
    # Clear region, token, auth, and portforward data
    printf "%s\n" "$(grep -v '^region_\|^token=\|^auth_\|^portforward_' pia_config 2>/dev/null || true)" > pia_config
    # Reload config after clearing
    # shellcheck disable=SC1091
    [ -f pia_config ] && . ./pia_config
  fi

  # WAN interface for PIA API (recovery when tunnel is broken)
  local var_wan
  var_wan=$(ip route show table main 2>/dev/null | awk '/^default / {print $5; exit}')
  [ -z "${var_wan:-}" ] && error_exit "WAN interface not found"

  # Optional connectivity test for cached server; skip refetch if both meta and WG reachable
  if [ -n "${region_cn:-}" ] && [ -n "${region_meta_ip:-}" ] && [ -n "${region_wg_ip:-}" ] && \
     [ "${region_id:-}" = "${pia_vpn}" ]; then
    [ -z "${certificate:-}" ] || { echo "${certificate}" | openssl base64 -A -d > pia_tmp_cert 2>/dev/null; }
    if [ -s pia_tmp_cert ]; then
      if curl --doh-url "https://1.1.1.1/dns-query" --interface "${var_wan}" -sS -o /dev/null -m 5 --connect-to "${region_cn}::${region_meta_ip}:" --cacert pia_tmp_cert "https://${region_cn}/" 2>/dev/null && \
         curl --doh-url "https://1.1.1.1/dns-query" --interface "${var_wan}" -sS -o /dev/null -m 5 --connect-to "${region_cn}::${region_wg_ip}:" --cacert pia_tmp_cert "https://${region_cn}:1337/" 2>/dev/null; then
        rm -f pia_tmp_cert
        echo '[=] Region info already exists (cached server reachable)'
        return 0
      fi
    fi
    echo '[~] Connectivity failed for cached server, refetching serverlist'
    logger -t pia_wireguard "Connectivity failed for cached server, refetching serverlist"
  fi

  # Fetch server list with signature
  local var_response var_json var_signature
  var_response=$(curl --doh-url "https://1.1.1.1/dns-query" --interface "${var_wan}" --retry 5 -Ss 'https://serverlist.piaservers.net/vpninfo/servers/v7')
  var_json=$(echo "${var_response}" | head -1)
  var_signature=$(echo "${var_response}" | tail -n 6)

  # Verify signature using PIA's hardcoded RSA public key
  # https://github.com/pia-foss/manual-connections/issues/21
  cat > pia_tmp_pubkey <<'EOF'
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzLYHwX5Ug/oUObZ5eH5P
rEwmfj4E/YEfSKLgFSsyRGGsVmmjiXBmSbX2s3xbj/ofuvYtkMkP/VPFHy9E/8ox
Y+cRjPzydxz46LPY7jpEw1NHZjOyTeUero5e1nkLhiQqO/cMVYmUnuVcuFfZyZvc
8Apx5fBrIp2oWpF/G9tpUZfUUJaaHiXDtuYP8o8VhYtyjuUu3h7rkQFoMxvuoOFH
6nkc0VQmBsHvCfq4T9v8gyiBtQRy543leapTBMT34mxVIQ4ReGLPVit/6sNLoGLb
gSnGe9Bk/a5V/5vlqeemWF0hgoRtUxMtU1hFbe7e8tSq1j+mu0SHMyKHiHd+OsmU
IQIDAQAB
-----END PUBLIC KEY-----
EOF
  echo "${var_signature}" | openssl base64 -d > pia_tmp_sig
  printf "%s" "${var_json}" > pia_tmp_json
  if ! openssl dgst -sha256 -verify pia_tmp_pubkey -signature pia_tmp_sig pia_tmp_json >/dev/null 2>&1; then
    rm -f pia_tmp_sig pia_tmp_json pia_tmp_pubkey
    error_exit "Server list signature verification failed"
  fi
  rm -f pia_tmp_sig pia_tmp_json pia_tmp_pubkey
  echo '[*] Server list signature verified'

  # PHP: validate region (offline, port_forward), output region_id and meta/wg lists
  local var_php vars_region
  var_php=$(cat <<'EOF'
    $r = current(array_filter(json_decode(stream_get_contents(STDIN))->regions, fn($x) => $x->id == "REGION_ID"));
    if (!$r) die("ERROR: Region 'REGION_ID' not found\n");
    if (!empty($r->offline)) die("ERROR: Region REGION_ID is offline\n");
    echo "region_id=\"REGION_ID\"\n";
    echo "region_pf=\"" . (empty($r->port_forward) ? "false" : "true") . "\"\n";
    echo "region_wg_port=\"1337\"\n";
    $wg_ip = array_column(json_decode(json_encode($r->servers->wg), true), "ip", "cn");
    $pairs = array_filter(array_map(fn($m) => isset($wg_ip[$m->cn]) ? "{$m->cn}#{$m->ip}#{$wg_ip[$m->cn]}" : null, $r->servers->meta));
    echo "region_list=\"" . implode(",", $pairs) . "\"\n";
EOF
  )
  var_php=$(echo "${var_php}" | sed "s/REGION_ID/${pia_vpn}/g")
  vars_region=$(echo "${var_json}" | php -r "${var_php}" 2>/dev/null)
  [ -z "${vars_region}" ] && error_exit "Failed to parse region or region validation failed"
  echo "${vars_region}" | grep -q '^ERROR:' && error_exit "${vars_region}"

  # Parse region_list (comma-separated items, each item is cn#meta_ip#wg_ip, matched by cn)
  local var_region_list
  var_region_list=$(echo "${vars_region}" | grep '^region_list=' | cut -d= -f2- | tr -d '"' | sed 's/,/\n/g')
  [ -n "${var_region_list}" ] || error_exit "No meta or WG servers in region"

  # Certificate for connectivity probe
  echo "${certificate}" | openssl base64 -A -d > pia_tmp_cert 2>/dev/null
  [ -s pia_tmp_cert ] || error_exit "Certificate not available for connectivity test"

  # First reachable (cn, meta_ip, wg_ip) pair wins
  local var_line var_cn var_meta_ip var_wg_ip var_region_pf var_found
  var_found='false'

  var_region_pf=$(echo "${vars_region}" | grep '^region_pf=' | head -1 | cut -d= -f2- | tr -d '"')
  [ -z "${var_region_pf:-}" ] && var_region_pf='false'

  while [ -n "${var_region_list}" ]; do
    var_line=$(echo "${var_region_list}" | sed -n '1p')
    var_cn=$(echo "${var_line}" | cut -d# -f1)
    var_meta_ip=$(echo "${var_line}" | cut -d# -f2)
    var_wg_ip=$(echo "${var_line}" | cut -d# -f3)
    if curl --doh-url "https://1.1.1.1/dns-query" --interface "${var_wan}" -sS -o /dev/null -m 5 --connect-to "${var_cn}::${var_meta_ip}:" --cacert pia_tmp_cert "https://${var_cn}/" 2>/dev/null && \
       curl --doh-url "https://1.1.1.1/dns-query" --interface "${var_wan}" -sS -o /dev/null -m 5 --connect-to "${var_cn}::${var_wg_ip}:" --cacert pia_tmp_cert "https://${var_cn}:1337/" 2>/dev/null; then
      printf "%s\n" "$(grep -v '^region_' pia_config 2>/dev/null || true)" "region_id=\"${pia_vpn}\"" "region_cn=\"${var_cn}\"" "region_meta_ip=\"${var_meta_ip}\"" "region_wg_ip=\"${var_wg_ip}\"" "region_wg_port=\"1337\"" "region_pf=\"${var_region_pf}\"" > pia_config
      echo "[+] Region info ready (selected ${var_cn})"
      logger -t pia_wireguard "Selected ${var_cn}"
      var_found='true'
      break
    fi
    var_region_list=$(echo "${var_region_list}" | sed '1d')
  done
  rm -f pia_tmp_cert
  [ "${var_found}" = 'true' ] || error_exit "No reachable server in region ${pia_vpn}"
}

get_token() {
  echo '[ ] Generating PIA token...'
  # Load config
  # shellcheck disable=SC1091
  [ -f pia_config ] && . ./pia_config

  # Skip if token already exists (idempotent)
  if [ -n "${token:-}" ]; then
    echo '[=] Token already exists'
    return 0
  fi

  # Validate required variables
  [ -z "${pia_user:-}" ] && error_exit "pia_user not set"
  [ -z "${pia_pass:-}" ] && error_exit "pia_pass not set"
  [ -z "${region_cn:-}" ] && error_exit "region_cn not set"
  [ -z "${region_meta_ip:-}" ] && error_exit "region_meta_ip not set"
  [ -z "${certificate:-}" ] && error_exit "certificate not set"
  # WAN interface for PIA API (recovery when tunnel is broken)
  local var_wan
  var_wan=$(ip route show table main 2>/dev/null | awk '/^default / {print $5; exit}')
  [ -z "${var_wan:-}" ] && error_exit "WAN interface not found"
  # Write certificate file (needed by curl)
  echo "${certificate}" | openssl base64 -A -d > pia_tmp_cert
  [ -s pia_tmp_cert ] || error_exit "Failed to decode certificate"
  local var_php var_token
  # Parse token from JSON; meta API has status+token, public v2 API has token only
  var_php=$(cat <<'EOF'
    $d = json_decode(stream_get_contents(STDIN));
    if (!$d || (isset($d->status) && $d->status !== "OK")) exit(1);
    echo $d->token ?? "";
EOF
  )
  # Try region meta generateToken first
  # shellcheck disable=SC2310  # php is a function wrapper for php-cli on FreshTomato
  if ! var_token=$(curl --doh-url "https://1.1.1.1/dns-query" --interface "${var_wan}" --retry 5 -Ss -u "${pia_user}:${pia_pass}" --connect-to "${region_cn}::${region_meta_ip}:" --cacert pia_tmp_cert "https://${region_cn}/authv3/generateToken" | php -r "${var_php}"); then
    echo '[~] Meta token failed, trying public token API...'
    # Fallback: public token endpoint
    if ! var_token=$(curl --doh-url "https://1.1.1.1/dns-query" --interface "${var_wan}" --retry 5 -Ss -X POST -F "username=${pia_user}" -F "password=${pia_pass}" "https://www.privateinternetaccess.com/api/client/v2/token" | php -r "${var_php}"); then
      # Both failed: clear region so next run re-selects server pair
      printf "%s\n" "$(grep -v '^region_\|^token=\|^auth_\|^portforward_' pia_config 2>/dev/null || true)" > pia_config
      error_exit "Token generation failed (meta and public API); region cleared for next run"
    fi
  fi
  # Remove certificate file
  rm -f pia_tmp_cert
  [ -n "${var_token}" ] || error_exit "Failed to parse token"
  printf "%s\n%s\n" "$(grep -v '^token=' pia_config 2>/dev/null || true)" "token=\"${var_token}\"" > pia_config
  echo '[+] Token ready'
}

gen_peer() {
  echo '[ ] Generating peer keys...'
  # Load config
  # shellcheck disable=SC1091
  [ -f pia_config ] && . ./pia_config

  # Skip if keys already exist (idempotent)
  if [ -n "${peer_prvkey:-}" ] && [ -n "${peer_pubkey:-}" ]; then
    echo '[=] Keys already exist'
    return 0
  fi

  # Generate new keys
  local var_prvkey var_pubkey
  var_prvkey=$(wg genkey)
  var_pubkey=$(echo "${var_prvkey}" | wg pubkey)
  # Save to config
  printf "%s\n%s\n%s\n" "$(grep -v '^peer_' pia_config 2>/dev/null || true)" "peer_prvkey=\"${var_prvkey}\"" "peer_pubkey=\"${var_pubkey}\"" > pia_config

  echo '[+] Keys ready'
}

get_auth() {
  echo '[ ] Authenticating to PIA...'
  # Load config
  # shellcheck disable=SC1091
  [ -f pia_config ] && . ./pia_config
  # Skip if auth already exists (idempotent)
  if [ -n "${auth_peer_ip:-}" ] && [ -n "${auth_server_key:-}" ] && [ -n "${auth_server_vip:-}" ]; then
    echo '[=] Auth already exists'
    return 0
  fi
  # Validate required variables
  [ -z "${region_cn:-}" ] && error_exit "region_cn not set"
  [ -z "${region_wg_ip:-}" ] && error_exit "region_wg_ip not set"
  [ -z "${region_wg_port:-}" ] && error_exit "region_wg_port not set"
  [ -z "${token:-}" ] && error_exit "token not set"
  [ -z "${peer_pubkey:-}" ] && error_exit "peer_pubkey not set"
  [ -z "${certificate:-}" ] && error_exit "certificate not set"
  # WAN interface for PIA API (recovery when tunnel is broken)
  local var_wan
  var_wan=$(ip route show table main 2>/dev/null | awk '/^default / {print $5; exit}')
  [ -z "${var_wan:-}" ] && error_exit "WAN interface not found"
  # Write certificate file (needed by curl)
  echo "${certificate}" | openssl base64 -A -d > pia_tmp_cert
  [ -s pia_tmp_cert ] || error_exit "Failed to decode certificate"
  local var_php vars_auth
  # PHP code validates status before parsing
  var_php=$(cat <<'EOF'
    $d = json_decode(stream_get_contents(STDIN));
    if (!$d || ($d->status ?? "") !== "OK") exit(1);
    echo "auth_peer_ip=\"$d->peer_ip\"\n";
    echo "auth_server_key=\"$d->server_key\"\n";
    echo "auth_server_vip=\"$d->server_vip\"\n";
EOF
  )
  # shellcheck disable=SC2310  # php is a function wrapper for php-cli on FreshTomato
  if ! vars_auth=$(curl --doh-url "https://1.1.1.1/dns-query" --interface "${var_wan}" --retry 10 -GSs --connect-to "${region_cn}::${region_wg_ip}:" --cacert pia_tmp_cert --data-urlencode "pt=${token}" --data-urlencode "pubkey=${peer_pubkey}" "https://${region_cn}:${region_wg_port}/addKey" | php -r "${var_php}"); then
    printf "%s\n" "$(grep -v '^region_\|^token=\|^auth_' pia_config 2>/dev/null || true)" > pia_config
    logger -t pia_wireguard "WireGuard authentication failed, cleared region/token/auth for failover"
    error_exit "WireGuard authentication failed"
  fi
  # Remove certificate file
  rm -f pia_tmp_cert
  [ -n "${vars_auth}" ] || error_exit "Failed to parse auth response"
  printf "%s\n%s\n" "$(grep -v '^auth_' pia_config 2>/dev/null || true)" "${vars_auth}" > pia_config
  echo '[+] Auth ready'
}

set_wg() {
  echo '[ ] Configuring WireGuard...'
  # Load config
  # shellcheck disable=SC1091
  [ -f pia_config ] && . ./pia_config
  # Skip if WireGuard already configured (idempotent)
  # shellcheck disable=SC2312  # Piped commands used for state checks, failures expected
  if ip link show up | grep -q 'wg0' && \
     ip addr show wg0 2>/dev/null | grep -q "${auth_peer_ip:-}" && \
     wg show wg0 peers 2>/dev/null | grep -q "^${auth_server_key:-}$" && \
     [ "$(wg show wg0 peers 2>/dev/null | wc -l)" -eq 1 ]; then
    echo '[=] WireGuard already configured'
    return 0
  fi
  # Validate required variables
  [ -z "${peer_prvkey:-}" ] && error_exit "peer_prvkey not set"
  [ -z "${auth_server_key:-}" ] && error_exit "auth_server_key not set"
  [ -z "${region_wg_ip:-}" ] && error_exit "region_wg_ip not set"
  [ -z "${region_wg_port:-}" ] && error_exit "region_wg_port not set"
  [ -z "${auth_peer_ip:-}" ] && error_exit "auth_peer_ip not set"
  # Write private key file (needed by wg command)
  echo "${peer_prvkey}" > pia_tmp_prvkey
  # Remove existing peers
  # shellcheck disable=SC2312  # Used to check if peers exist, empty output expected
  if [ -n "$(wg show wg0 peers 2>/dev/null)" ]; then
    echo '[-] Removing existing peers'
    for p in $(wg show wg0 peers 2>/dev/null); do wg set wg0 peer "${p}" remove; done
  fi
  # Configure WireGuard
  wg set wg0 fwmark 0xf0b private-key pia_tmp_prvkey peer "${auth_server_key}" endpoint "${region_wg_ip}:${region_wg_port}" persistent-keepalive 25 allowed-ips '0.0.0.0/0'
  # Remove private key file
  rm -f pia_tmp_prvkey
  ip addr flush dev wg0
  ip addr replace "${auth_peer_ip}" dev wg0
  # Bring up interface with retry (often fails first attempt)
  local var_attempt=1 var_backoff=1
  while [ "${var_attempt}" -le 5 ]; do
    if [ "${var_attempt}" -gt 1 ]; then
      echo "[~] Retry ${var_attempt}/5 (backoff: ${var_backoff}s)..."
      sleep "${var_backoff}"
      var_backoff=$((var_backoff * 2))
    fi
    ip link set wg0 up && break
    var_attempt=$((var_attempt + 1))
  done
  if [ "${var_attempt}" -gt 5 ]; then
    printf "%s\n" "$(grep -v '^region_\|^token=\|^auth_' pia_config 2>/dev/null || true)" > pia_config
    logger -t pia_wireguard "Failed to bring up wg0 after 5 attempts, cleared region/token/auth for failover"
    error_exit "Failed to bring up wg0 after 5 attempts"
  fi
  echo '[+] WireGuard ready'
}

set_firewall() {
  echo '[ ] Configuring firewall...'

  # Check if chains exist and have rules (idempotent)
  if iptables -L PIA_INPUT -n >/dev/null 2>&1 && \
     iptables -L PIA_FORWARD -n >/dev/null 2>&1 && \
     iptables -t nat -L PIA_POSTROUTING -n >/dev/null 2>&1 && \
     iptables -t nat -L PIA_POSTROUTING -n 2>/dev/null | grep -q MASQUERADE; then
    echo '[=] Firewall already configured'
    return 0
  fi

  # Create custom chains
  iptables -N PIA_INPUT 2>/dev/null || true
  iptables -N PIA_FORWARD 2>/dev/null || true
  iptables -t nat -N PIA_POSTROUTING 2>/dev/null || true

  # Flush chains (clean slate)
  iptables -F PIA_INPUT
  iptables -F PIA_FORWARD
  iptables -t nat -F PIA_POSTROUTING

  # Hook chains into main chains (remove old hooks first)
  iptables -D INPUT -i wg0 -j PIA_INPUT 2>/dev/null || true
  iptables -D FORWARD -i wg0 -j PIA_FORWARD 2>/dev/null || true
  iptables -D FORWARD -o wg0 -j PIA_FORWARD 2>/dev/null || true
  iptables -t nat -D POSTROUTING -o wg0 -j PIA_POSTROUTING 2>/dev/null || true

  iptables -I INPUT -i wg0 -j PIA_INPUT
  iptables -I FORWARD -i wg0 -j PIA_FORWARD
  iptables -I FORWARD -o wg0 -j PIA_FORWARD
  iptables -t nat -I POSTROUTING -o wg0 -j PIA_POSTROUTING

  # Add rules inside custom chains
  iptables -A PIA_INPUT -m state --state NEW -j DROP
  iptables -A PIA_FORWARD -i wg0 -m state --state NEW -j DROP
  iptables -A PIA_FORWARD -o wg0 -j ACCEPT
  iptables -t nat -A PIA_POSTROUTING -j MASQUERADE

  echo '[+] Firewall ready'
}

set_ipv6() {
  echo '[ ] Configuring IPv6 leak prevention...'

  # Check if already configured (idempotent)
  if ip6tables -L PIA_FORWARD_V6 -n >/dev/null 2>&1; then
    echo '[=] IPv6 leak prevention already configured'
    return 0
  fi

  # Drop all routed IPv6 traffic to prevent leaks bypassing the VPN
  # LAN-to-LAN IPv6 is unaffected (handled by bridge at layer 2, never enters FORWARD)
  ip6tables -N PIA_FORWARD_V6 2>/dev/null || true
  ip6tables -F PIA_FORWARD_V6
  ip6tables -A PIA_FORWARD_V6 -j DROP
  ip6tables -D FORWARD -j PIA_FORWARD_V6 2>/dev/null || true
  ip6tables -I FORWARD -j PIA_FORWARD_V6

  echo '[+] IPv6 leak prevention ready'
}

set_routes() {
  echo '[ ] Configuring routes...'
  # Skip if routes already configured (idempotent)
  if ip route show table 1337 | grep -q 'default dev wg0' && ip rule list | grep -q 'not from all fwmark 0xf0b lookup 1337'; then
    echo '[=] Routes already configured'
    return 0
  fi
  # Clear custom routing table
  echo '[-] Flushing routing table 1337'
  ip route flush table 1337

  # Add throw routes for all bridge interfaces (LAN prefixes fall through to main table).
  # suppress_prefixlength 1 would avoid this but requires kernel 3.x+; FreshTomato uses 2.6.
  local prefix rest
  ip -o route show proto kernel | while read -r prefix rest; do
    case ${rest} in
      *"dev br"*) ip route replace throw "${prefix}" table 1337 && echo "[+] LAN exception added: ${prefix}";;
      *) ;;
    esac
  done

  # Link-local (169.254.0.0/16) for Avahi/Bonjour; may not appear as bridge route on all systems
  ip route replace throw 169.254.0.0/16 table 1337 2>/dev/null && echo "[+] LAN exception added: 169.254.0.0/16 (link-local)"
  # Multicast (224.0.0.0/4) for local discovery and streaming; keep off VPN
  ip route replace throw 224.0.0.0/4 table 1337 2>/dev/null && echo "[+] LAN exception added: 224.0.0.0/4 (multicast)"

  # Set default route through VPN
  ip route add default dev wg0 table 1337
  # Remove old policy rule if exists
  echo '[-] Removing old policy rule'
  ip rule del not fwmark 0xf0b table 1337 2>/dev/null || true
  # Add policy rule: use table 1337 for all packets NOT marked with 0xf0b
  ip rule add not fwmark 0xf0b table 1337
  echo '[+] Routes ready'
}

set_bypass() {
  echo '[ ] Configuring VPN bypass...'
  # Load config
  # shellcheck disable=SC1091
  [ -f pia_config ] && . ./pia_config

  # Load required kernel modules for ipset support
  if ! modprobe -a ip_set ip_set_hash_ip xt_set 2>/dev/null; then
    echo "[!] WARNING: ipset modules not available, skipping VPN bypass"
    logger -t pia_wireguard "WARNING: Skipping VPN bypass"
    return 0
  fi

  # Check if already configured (idempotent — subset check preserves externally added entries)
  if ipset list pia_bypass >/dev/null 2>&1 && \
     iptables -t mangle -L PIA_MANGLE -n >/dev/null 2>&1 && \
     iptables -t mangle -L PIA_MANGLE -n 2>/dev/null | grep -q 'match-set pia_bypass'; then
    local var_all_present=1
    for ip in ${pia_bypass}; do
      ipset test pia_bypass "${ip}" 2>/dev/null || { var_all_present=0; break; }
    done
    if [ "${var_all_present}" -eq 1 ]; then
      echo '[=] VPN bypass already configured'
      return 0
    fi
    echo '[!] Bypass IPs missing from ipset, reconfiguring...'
    logger -t pia_wireguard "Bypass IPs missing from ipset, reconfiguring..."
  fi

  # Create ipset with 24h auto-expiry (no flush — preserves externally added entries)
  ipset create pia_bypass hash:ip timeout 86400 -exist 2>/dev/null

  # Ensure all static bypass IPs are in the set (timeout 0 = permanent)
  for ip in ${pia_bypass}; do
    ipset add pia_bypass "${ip}" timeout 0 -exist
  done

  # Create/clear marking chain (idempotent)
  iptables -t mangle -N PIA_MANGLE 2>/dev/null || true
  iptables -t mangle -F PIA_MANGLE

  # Remove any legacy/ineffective hook (marking after VPN ingress is too late)
  iptables -t mangle -D PREROUTING -i wg0 -j PIA_MANGLE 2>/dev/null || true

  # PREROUTING for all *non-wg0* ingress
  # This covers LAN and any other non-VPN interfaces without knowing their names.
  iptables -t mangle -D PREROUTING ! -i wg0 -j PIA_MANGLE 2>/dev/null || true
  iptables -t mangle -I PREROUTING ! -i wg0 -j PIA_MANGLE

  # OUTPUT for router-originated traffic (local processes)
  iptables -t mangle -D OUTPUT -j PIA_MANGLE 2>/dev/null || true
  iptables -t mangle -I OUTPUT -j PIA_MANGLE

  # Mark rule: packets destined to bypass IPs get the fwmark that *skips* the VPN table
  iptables -t mangle -C PIA_MANGLE -m set --match-set pia_bypass dst -j MARK --set-mark 0xf0b 2>/dev/null || \
    iptables -t mangle -A PIA_MANGLE -m set --match-set pia_bypass dst -j MARK --set-mark 0xf0b

  echo '[+] VPN bypass ready'
}

get_portforward() {
  echo '[ ] Requesting port forward...'
  # Load config
  # shellcheck disable=SC1091
  [ -f pia_config ] && . ./pia_config
  [ "${region_pf:-false}" != 'true' ] && echo '[!] Region does not support port forwarding' && return 0
  # Reuse cached PF token if expiration is set and >= 7 days (604800 seconds)
  if [ -n "${portforward_exp:-}" ]; then
    local var_remaining=$((portforward_exp - $(date +%s)))
    if [ "${var_remaining}" -ge 604800 ]; then
      echo '[=] Port forward already exists'
      return 0
    fi
    echo '[~] Port forward near expiry, reacquiring'
    printf "%s\n" "$(grep -v '^portforward_' pia_config 2>/dev/null || true)" > pia_config
  fi
  # Validate required variables
  [ -z "${region_cn:-}" ] && error_exit "region_cn not set"
  [ -z "${auth_server_vip:-}" ] && error_exit "auth_server_vip not set"
  [ -z "${token:-}" ] && error_exit "token not set"
  [ -z "${certificate:-}" ] && error_exit "certificate not set"
  # Write certificate file (needed by curl)
  echo "${certificate}" | openssl base64 -A -d > pia_tmp_cert
  [ -s pia_tmp_cert ] || error_exit "Failed to decode certificate"
  # Request port forward signature
  local var_php vars_portforward
  var_php=$(cat <<'EOF'
    $d = json_decode(stream_get_contents(STDIN));
    if (!$d || ($d->status ?? "") !== "OK") exit(1);
    $p = json_decode(base64_decode($d->payload));
    $expires_epoch = strtotime($p->expires_at ?? "");
    if ($expires_epoch === false) exit(1);
    echo "portforward_signature=\"$d->signature\"\n";
    echo "portforward_payload=\"$d->payload\"\n";
    echo "portforward_port=\"" . $p->port . "\"\n";
    echo "portforward_exp=\"" . $expires_epoch . "\"\n";
EOF
  )
  # shellcheck disable=SC2310  # php is a function wrapper for php-cli on FreshTomato
  if ! vars_portforward=$(curl --retry 10 -GSs --connect-to "${region_cn}::${auth_server_vip}:" --cacert pia_tmp_cert --data-urlencode "token=${token}" "https://${region_cn}:19999/getSignature" --interface wg0 | php -r "${var_php}"); then
    printf "%s\n" "$(grep -v '^portforward_' pia_config 2>/dev/null || true)" > pia_config
    error_exit "Port forward signature failed"
  fi
  # Remove certificate file
  rm -f pia_tmp_cert
  [ -n "${vars_portforward}" ] || error_exit "Failed to parse port forward response"
  # Save to config
  printf "%s\n%s\n" "$(grep -v '^portforward_' pia_config 2>/dev/null || true)" "${vars_portforward}" > pia_config
  echo '[+] Port forward ready'
}

set_portforward() {
  echo '[ ] Configuring port forward NAT...'
  # Load config
  # shellcheck disable=SC1091
  [ -f pia_config ] && . ./pia_config
  [ "${region_pf:-false}" != 'true' ] && echo '[!] Region does not support port forwarding' && return 0
  # Validate required variables
  [ -z "${region_cn:-}" ] && error_exit "region_cn not set"
  [ -z "${auth_server_vip:-}" ] && error_exit "auth_server_vip not set"
  [ -z "${portforward_signature:-}" ] && error_exit "portforward_signature not set"
  [ -z "${portforward_payload:-}" ] && error_exit "portforward_payload not set"
  [ -z "${portforward_port:-}" ] && error_exit "portforward_port not set"
  [ -z "${pia_pf:-}" ] && error_exit "pia_pf not set"
  [ -z "${certificate:-}" ] && error_exit "certificate not set"
  # Validate pia_pf format (must be IP:PORT)
  echo "${pia_pf}" | grep -q '^[0-9.]\+:[0-9]\+$' || error_exit "pia_pf must be in format IP:PORT (e.g., 192.168.1.10:2022)"
  # Write certificate file (needed by curl)
  echo "${certificate}" | openssl base64 -A -d > pia_tmp_cert
  [ -s pia_tmp_cert ] || error_exit "Failed to decode certificate"
  # Bind port with PIA (always refresh binding)
  local var_bind_response var_bind_status var_bind_message
  var_bind_response=$(curl --retry 3 -sGm 5 --connect-to "${region_cn}::${auth_server_vip}:" --cacert pia_tmp_cert --data-urlencode "payload=${portforward_payload}" --data-urlencode "signature=${portforward_signature}" "https://${region_cn}:19999/bindPort" --interface wg0) || true
  # Remove certificate file
  rm -f pia_tmp_cert
  # Parse response
  # shellcheck disable=SC2310
  var_bind_status=$(echo "${var_bind_response}" | php -r 'echo json_decode(stream_get_contents(STDIN))->status ?? "";' 2>/dev/null) || true
  # shellcheck disable=SC2310
  var_bind_message=$(echo "${var_bind_response}" | php -r 'echo json_decode(stream_get_contents(STDIN))->message ?? "";' 2>/dev/null) || true
  if [ "${var_bind_status}" = "OK" ]; then
    echo "[*] Port binding: ${var_bind_message}"
  else
    echo "[!] WARNING: Port bind failed"
    logger -t pia_wireguard "WARNING: Port bind failed, clearing portforward_* for next run"
    printf "%s\n" "$(grep -v '^portforward_' pia_config 2>/dev/null || true)" > pia_config
    return 0
  fi

  # Parse IP and port from pia_pf
  local var_pf_ip="${pia_pf%:*}" var_pf_port="${pia_pf#*:}"

  # Check if already configured (idempotent) — match full rule shape from iptables -S
  local var_nat_rules
  var_nat_rules=$(iptables -t nat -S PIA_NAT 2>/dev/null) || true
  if [ -n "${var_nat_rules}" ] && iptables -L PIA_PORTFORWARD -n >/dev/null 2>&1; then
    if [ "${var_pf_ip}" = "0.0.0.0" ]; then
      if echo "${var_nat_rules}" | grep -F -- "--dport ${portforward_port}" | grep -qF "REDIRECT --to-ports ${var_pf_port}"; then
        echo '[=] Port forward already configured'
        return 0
      fi
    else
      if echo "${var_nat_rules}" | grep -F -- "--dport ${portforward_port}" | grep -qF "DNAT --to-destination ${pia_pf}"; then
        echo '[=] Port forward already configured'
        return 0
      fi
    fi
    echo '[~] Port forward configuration changed, reconfiguring...'
  fi

  # Create custom chains
  iptables -t nat -N PIA_NAT 2>/dev/null || true
  iptables -N PIA_PORTFORWARD 2>/dev/null || true

  # Flush chains (clean slate)
  iptables -t nat -F PIA_NAT
  iptables -F PIA_PORTFORWARD

  # Hook chains into main chains (remove old hooks first)
  iptables -t nat -D PREROUTING -i wg0 -j PIA_NAT 2>/dev/null || true
  iptables -D INPUT -i wg0 -j PIA_PORTFORWARD 2>/dev/null || true
  iptables -D FORWARD -i wg0 -j PIA_PORTFORWARD 2>/dev/null || true

  iptables -t nat -I PREROUTING -i wg0 -j PIA_NAT
  iptables -I INPUT -i wg0 -j PIA_PORTFORWARD
  iptables -I FORWARD -i wg0 -j PIA_PORTFORWARD

  # Add rules based on mode
  if [ "${var_pf_ip}" = "0.0.0.0" ]; then
    # Router mode - REDIRECT and INPUT
    iptables -t nat -A PIA_NAT -p tcp --dport "${portforward_port}" -j REDIRECT --to-ports "${var_pf_port}"
    iptables -A PIA_PORTFORWARD -p tcp --dport "${var_pf_port}" -m state --state NEW -j ACCEPT
    echo "[+] Port ${portforward_port} redirected to router port ${var_pf_port}"
  else
    # Forward mode - DNAT and FORWARD
    iptables -t nat -A PIA_NAT -p tcp --dport "${portforward_port}" -j DNAT --to-destination "${pia_pf}"
    iptables -A PIA_PORTFORWARD -m state --state NEW,RELATED,ESTABLISHED -d "${var_pf_ip}" -p tcp --dport "${var_pf_port}" -j ACCEPT
    echo "[+] Port ${portforward_port} forwarded to ${pia_pf}"
  fi
}

set_duckdns() {
  echo '[ ] Updating DuckDNS...'
  # Load config
  # shellcheck disable=SC1091
  [ -f pia_config ] && . ./pia_config

  # Validate and split pia_duckdns (format: domain:token)
  [ -z "${pia_duckdns:-}" ] && error_exit "pia_duckdns not set"
  echo "${pia_duckdns}" | grep -q ':' || error_exit "pia_duckdns must be in format DOMAIN:TOKEN"

  local var_domain var_token
  var_domain="${pia_duckdns%%:*}"
  var_token="${pia_duckdns#*:}"

  [ -z "${var_domain}" ] && error_exit "DuckDNS domain is empty"
  [ -z "${var_token}" ] && error_exit "DuckDNS token is empty"
  [ -z "${region_wg_ip:-}" ] && error_exit "region_wg_ip not set"

  # Update DuckDNS A record (IP address)
  local var_response_ip
  var_response_ip=$(curl -sSGm 5 "https://www.duckdns.org/update?domains=${var_domain}&token=${var_token}&ip=${region_wg_ip}" 2>&1) || error_exit "DuckDNS IP update failed: ${var_response_ip}"
  [ "${var_response_ip}" = "OK" ] || error_exit "DuckDNS IP update failed: ${var_response_ip}"

  # Update DuckDNS TXT record (port) when port forwarding is active
  if [ -n "${portforward_port:-}" ]; then
    local var_response_txt
    var_response_txt=$(curl -sSGm 5 "https://www.duckdns.org/update?domains=${var_domain}&token=${var_token}&txt=${portforward_port}" 2>&1) || error_exit "DuckDNS TXT update failed: ${var_response_txt}"
    [ "${var_response_txt}" = "OK" ] || error_exit "DuckDNS TXT update failed: ${var_response_txt}"
    echo "[+] DNS records updated: ${var_domain}.duckdns.org A=${region_wg_ip} TXT=${portforward_port}"
  else
    echo "[+] DNS record updated: ${var_domain}.duckdns.org A=${region_wg_ip}"
  fi
}

logger -t pia_wireguard "PIA WireGuard script started"

init_script
init_module
get_cert

# shellcheck disable=SC2310
if ! healthcheck_tunnel; then
  logger -t pia_wireguard "WARNING: Tunnel unhealthy, rebuilding VPN"
  printf "%s\n" "$(grep -v '^region_\|^token=\|^auth_\|^peer_\|^portforward_' pia_config 2>/dev/null || true)" > pia_config
fi

get_region
get_token
gen_peer
get_auth
set_wg
set_firewall
set_ipv6
set_routes

# shellcheck disable=SC2310
healthcheck_tunnel || error_exit "Tunnel healthcheck failed"

if [ "${pia_bypass:-false}" != 'false' ]; then
  set_bypass
fi

if [ "${pia_pf:-false}" != 'false' ]; then
  get_portforward
  set_portforward
fi

if [ "${pia_duckdns:-false}" != 'false' ]; then
  set_duckdns
fi

### OPTIONAL
### Force wireguard traffic over specific interface (this is just an example)
# if ! ip route show | grep -q "${region_wg_ip}/32 via 10.71.0.1 dev wlp2s0 metric 50"; then
#   ip route list metric 50 | while read -r r; do ip route del "${r}"; done
#   ip route add ${region_wg_ip}/32 via 10.71.0.1 dev wlp2s0 metric 50
# fi

logger -t pia_wireguard "PIA WireGuard script completed"
