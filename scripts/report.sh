#!/bin/sh
# report.sh — quick diagnostics. Invoked via `docker exec <container> report.sh`.
set -u

echo "== Processes =="
for p in charon sing-box; do
    pid=$(pgrep -x "$p" 2>/dev/null | head -1)
    if [ -n "$pid" ]; then echo "  $p UP   pid=$pid"; else echo "  $p NOT RUNNING"; fi
done

echo
echo "== Interfaces and routing =="
ip -4 -o addr show 2>/dev/null | sed 's/^/  /'
ip rule show 2>/dev/null | sed 's/^/  /'
# `cmd | sed || fallback` never runs the fallback: the pipeline's status is sed's.
if ! ip route show table 200 2>/dev/null | grep -q .; then
    echo "  (table 200 empty — policy route not installed)"
else
    ip route show table 200 2>/dev/null | sed 's/^/  /'
fi

echo
echo "== IKE connections =="
swanctl --list-conns 2>/dev/null | sed 's/^/  /' || echo "  (vici not answering)"

echo
echo "== Established SAs =="
swanctl --list-sas 2>/dev/null | sed 's/^/  /' || echo "  (vici not answering)"

echo
echo "== XFRM state/policies =="
ip xfrm state 2>/dev/null | head -20 | sed 's/^/  /'
ip xfrm policy 2>/dev/null | head -20 | sed 's/^/  /'

echo
echo "== Certificates =="
# pki is the tool that ships in this image (the openssl CLI does not), and it
# prints the same fields.
for c in /etc/swanctl/x509/server-cert.pem /etc/swanctl/x509ca/ca-cert.pem; do
    if [ -f "$c" ]; then
        printf '  %s\n' "$c"
        pki --print --in "$c" 2>/dev/null | grep -E 'subject:|issuer:|notAfter' | sed 's/^/    /'
    else
        printf '  %s MISSING\n' "$c"
    fi
done

echo
echo "== Egress (via the chain) =="
echo "  tun peer configured as socks ${CHAIN_SOCKS_HOST:-vpndogs-router}:${CHAIN_SOCKS_PORT:-1070}"

echo
echo "== Config (secrets redacted) =="
# This output is what users paste into issue trackers: redact the whole value,
# not just its first field — IPSEC_USERS is the one with N passwords in it.
env | grep -E '^(VPN_|CHAIN_|LOG_LEVEL|IPSEC_)' | sed \
    -e 's/^\(IPSEC_USERS=\).*/\1<redacted>/' \
    -e 's/^\(IPSEC_PSK=\).*/\1<redacted>/' | sort | sed 's/^/  /'