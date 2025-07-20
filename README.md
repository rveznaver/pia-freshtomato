# pia-freshtomato
Script to set up PIA wireguard on FreshTomato

## Setup
```bash
ssh root@<ROUTER_IP>
curl -O https://raw.githubusercontent.com/rveznaver/pia-freshtomato/refs/heads/main/piascript.sh
pia_user='<REDACTED>' pia_pass='<REDACTED>' ./piascript.sh
```

Output:
```
Setting up WireGuard kernel module...
RTNETLINK answers: File exists
pia_vpn not set, defaulting to ca (Montreal, Canada)
Downloading PIA certificate...
Setting up PIA region...
Generating PIA token...
Generating WireGuard keys...
Warning: writing to world accessible file.
Consider setting the umask to 077 and trying again.
Authenticating to PIA...
Configuring WireGuard...
Configuring routes...
Configuring NAT...
Requesting port forward...
Setting up port with NAT...
{
    "status": "OK",
    "message": "port scheduled for add"
}
Writing out pia_refresh script for port rebinding...
Done.
```

## Notes
### RCS not working over PIA VPN
see: https://support.adamnet.works/t/enabler-and-domain-requirements-for-rcs-messages/1307
```bash
ip rule add to 216.239.36.127 lookup main
ip rule add to 216.239.36.131 lookup main
ip rule add to 216.239.36.132 lookup main
ip rule add to 216.239.36.133 lookup main
ip rule add to 216.239.36.134 lookup main
ip rule add to 216.239.36.135 lookup main
ip rule add to 216.239.36.145 lookup main
```

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
