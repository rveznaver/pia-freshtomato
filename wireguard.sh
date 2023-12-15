#!/usr/bin/env ash

# requirements:
# - php-cli for JSON parsing
# - wg module for WireGuard

# set up file descriptor files for process substition
[ -L /dev/fd ] || ln -s /proc/self/fd /dev/fd

# token generation
pia_user='<REPLACE_WITH_USERNAME>'
pia_pass='<REPLACE_WITH_PASSWORD>'
pia_cert=$(curl -s 'https://raw.githubusercontent.com/pia-foss/manual-connections/master/ca.rsa.4096.crt')
pia_token=$(curl -sLX POST 'https://www.privateinternetaccess.com/api/client/v2/token' -F "username=$pia_user" -F "password=$pia_pass" | php-cli -R 'echo json_decode($argn)->token;')

# endpoint selection (id=="zagreb" for Croatia)
pia_server=$(curl -s 'https://serverlist.piaservers.net/vpninfo/servers/v6' | head -1 | php-cli -R 'echo json_encode(array_values(array_filter(json_decode($argn)->regions, function ($r) { return $r->id=="zagreb"; }))[0]->servers->wg[0]);')
pia_cn=$(echo $pia_server | php-cli -R 'echo json_decode($argn)->cn;')
pia_ip=$(echo $pia_server | php-cli -R 'echo json_decode($argn)->ip;')
pia_port='1337'

# key generation
wg_genkey="$(wg genkey)"
wg_pubkey="$(echo "$wg_genkey" | wg pubkey)"

# authentication
pia_auth="$(curl -s -G --connect-to "$pia_cn::$pia_ip:" --cacert <(echo "$pia_cert") --data-urlencode "pt=${pia_token}" --data-urlencode "pubkey=$wg_pubkey" "https://${pia_cn}:1337/addKey")"
pia_pubkey=$(echo $pia_auth | php-cli -R 'echo json_decode($argn)->server_key;')
wg_ip=$(echo $pia_auth | php-cli -R 'echo json_decode($argn)->peer_ip;')

# init interface
modprobe wireguard
ip link add wg0 type wireguard

# configure interface
wg set wg0 fwmark 51820 private-key <(echo "$wg_genkey") peer "$pia_pubkey" endpoint "$pia_ip:$pia_port" persistent-keepalive 25 allowed-ips '0.0.0.0/0,::/0'
ip link set wg0 up
ip addr flush dev wg0
ip addr add "$wg_ip" dev wg0

# configure NAT 
iptables -I INPUT -i wg0 -m state --state NEW -j DROP
iptables -I FORWARD -i wg0 -m state --state NEW -j DROP
iptables -I FORWARD -o wg0 -j ACCEPT
iptables -t nat -I POSTROUTING -o wg0 -j MASQUERADE

# configure routes
ip route add 0.0.0.0/1 dev wg0
ip route add 128.0.0.0/1 dev wg0
eval "ip route add $pia_ip/32 $(ip route show default 0.0.0.0/0 | sed 's/default //')"


# manual route deletion:

# ip route del 0.0.0.0/1 dev wg0
# ip route del 128.0.0.0/1 dev wg0
# ip route del 172.98.71.145/32 via 10.71.0.1 dev eth2

# iptables -D INPUT -i wg0 -m state --state NEW -j DROP
# iptables -D FORWARD -o wg0 -j ACCEPT
# iptables -D FORWARD -i wg0 -m state --state NEW -j DROP
# iptables -t nat -D POSTROUTING -o wg0 -j MASQUERADE
