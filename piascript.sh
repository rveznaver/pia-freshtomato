#!/usr/bin/env ash

# requirements:
# - FreshTomato >= 2024.3
# - wg kernel module for WireGuard
# - curl and wget for API requests
# - php-cli for JSON parsing
# - tr for removing newlines in API responses

# set PATH in case we run inside a cron
export PATH='/bin:/usr/bin:/sbin:/usr/sbin'

echo 'Setting up WireGuard kernel module...'
modprobe wireguard # init interface
ip link add wg0 type wireguard # disregard RNETLINK File exists error

# PIA info
[ -z "$pia_user" ] && { echo 'pia_user not set'; exit 1; }
[ -z "$pia_pass" ] && { echo 'pia_pass not set'; exit 1; }
[ -z "$pia_vpn" ]  && { echo 'pia_vpn not set, defaulting to ca (Montreal, Canada)'; pia_vpn='ca'; }

echo 'Downloading PIA certificate...'
curl --retry 10 --retry-all-errors -Ss 'https://raw.githubusercontent.com/pia-foss/manual-connections/master/ca.rsa.4096.crt' -o pia_cert

echo 'Setting up PIA region...'
curl --retry 10 --retry-all-errors -Ss 'https://serverlist.piaservers.net/vpninfo/servers/v6' | head -1 | php-cli -R 'echo json_encode(array_values(array_filter(json_decode($argn)->regions, fn($r) => $r->id == "'"$pia_vpn"'"))[0]);' > pia_region
pia_vpn_meta_cn=$(cat pia_region | php-cli -R 'echo json_decode($argn)->servers->meta[0]->cn;')
pia_vpn_meta_ip=$(cat pia_region | php-cli -R 'echo json_decode($argn)->servers->meta[0]->ip;')
pia_vpn_wg_cn=$(cat pia_region | php-cli -R 'echo json_decode($argn)->servers->wg[0]->cn;')
pia_vpn_wg_ip=$(cat pia_region | php-cli -R 'echo json_decode($argn)->servers->wg[0]->ip;')
pia_vpn_wg_port='1337'

echo 'Generating PIA token...'
curl --retry 10 --retry-all-errors -SGs -u "$pia_user:$pia_pass" --connect-to "$pia_vpn_meta_cn::$pia_vpn_meta_ip:" --cacert pia_cert https://$pia_vpn_meta_cn/authv3/generateToken | tr -d '\n' | php-cli -R 'echo json_decode($argn)->token;' > pia_token

echo 'Generating WireGuard keys...'
wg genkey > peer_prvkey
peer_pubkey=$(cat peer_prvkey | wg pubkey)

echo 'Authenticating to PIA...'
curl --retry 10 --retry-all-errors -GSs --connect-to "$pia_vpn_wg_cn::$pia_vpn_wg_ip:" --cacert pia_cert --data-urlencode "pt=$(cat pia_token)" --data-urlencode "pubkey=$peer_pubkey" "https://$pia_vpn_wg_cn:$pia_vpn_wg_port/addKey" | tr -d '\n' > pia_auth
peer_ip=$(cat pia_auth | php-cli -R 'echo json_decode($argn)->peer_ip;')
server_key=$(cat pia_auth | php-cli -R 'echo json_decode($argn)->server_key;')
server_vip=$(cat pia_auth | php-cli -R 'echo json_decode($argn)->server_vip;')

### OPTIONAL ###
### Force wireguard traffic over specific interface
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
pia_signature=$(cat pia_paysig | php-cli -R 'echo json_decode($argn)->signature;')
pia_payload=$(cat pia_paysig | php-cli -R 'echo json_decode($argn)->payload;')
pia_port=$(cat pia_paysig | php-cli -R 'echo json_decode(base64_decode(json_decode($argn)->payload))->port;')

echo 'Setting up port with NAT...'
curl -sGm 5 --connect-to "$pia_vpn_wg_cn::$server_vip:" --cacert pia_cert --data-urlencode "payload=$pia_payload" --data-urlencode "signature=$pia_signature" "https://$pia_vpn_wg_cn:19999/bindPort" --interface wg0
iptables -t nat -I PREROUTING -i wg0 -p tcp --dport $pia_port -j DNAT --to-destination 192.168.2.10:2022
iptables -I FORWARD -i wg0 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT -d 192.168.2.10 -p tcp --dport 2022

echo 'Writing out pia_refresh script for port rebinding...'
cat <<'EOF' > pia_refresh
# vars for port forwarding API refresh
pia_vpn_wg_ip=$(cat pia_region | php-cli -R 'echo json_decode($argn)->servers->wg[0]->ip;')
pia_vpn_wg_cn=$(cat pia_region | php-cli -R 'echo json_decode($argn)->servers->wg[0]->cn;')
server_vip=$(cat pia_auth | php-cli -R 'echo json_decode($argn)->server_vip;')
pia_signature=$(cat pia_paysig | php-cli -R 'echo json_decode($argn)->signature;')
pia_payload=$(cat pia_paysig | php-cli -R 'echo json_decode($argn)->payload;')
pia_port=$(cat pia_paysig | php-cli -R 'echo json_decode(base64_decode(json_decode($argn)->payload))->port;')

# scheduler config: every 15 mins
# cd /tmp/home/root && ./pia_refresh
logger "refresh PIA forward $pia_vpn_wg_ip:$pia_port - $(/usr/sbin/curl -sGm 5 --connect-to "$pia_vpn_wg_cn::$server_vip:" --cacert pia_cert --data-urlencode "payload=${pia_payload}" --data-urlencode "signature=${pia_signature}" "https://${pia_vpn_wg_cn}:19999/bindPort" --interface wg0)"
EOF
chmod +x pia_refresh

echo 'Done.'
