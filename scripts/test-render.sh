#!/usr/bin/env bash
# test-render.sh — contract tests for `entrypoint.sh`: config rendering and env
# validation (docker mode also covers the boot path, added with those cases).
#
#   ./build.sh && scripts/test-render.sh    # in-image (docker) mode
#   scripts/test-render.sh --local          # host mode: render cases only
#
# Local mode exists so the render contract is testable without docker (bash+jq
# only); docker mode proves the same contracts hold inside the image.
set -uo pipefail

IMG="${IMAGE:-strongswan-server:latest}"
MODE=docker
[ "${1:-}" = "--local" ] && MODE=local

HERE="$(cd "$(dirname "$0")" && pwd)"
ENTRY="$HERE/entrypoint.sh"
fail=0
LAST_OUT=""

FIX_ENV=(IPSEC_USERS=alice:secret1,bob:secret2 IPSEC_PSK=psk9 VPN_SERVER_ADDR=vpn.example.com)
FIX_DE=() # same fixture as docker `-e` flags
for kv in "${FIX_ENV[@]}"; do FIX_DE+=(-e "$kv"); done

render_run() { # render_run KEY=VAL... -> stdout+stderr, exit status preserved
    local host_env=() docker_env=() kv
    for kv in "$@"; do
        host_env+=("$kv")
        docker_env+=(-e "$kv")
    done
    if [ "$MODE" = local ]; then
        env "${host_env[@]}" bash "$ENTRY" render 2>&1
    else
        docker run --rm --network none "${docker_env[@]}" \
            --entrypoint /usr/local/bin/entrypoint.sh "$IMG" render 2>&1
    fi
}

render() { # render KEY=VAL... -> rendered configs (exit status ignored)
    render_run "$@" || true
}

subcmd() { # subcmd <arg>... -> entrypoint.sh subcommand output
    if [ "$MODE" = local ]; then
        bash "$ENTRY" "$@"
    else
        docker run --rm --network none --entrypoint /usr/local/bin/entrypoint.sh "$IMG" "$@"
    fi
}

image_run() { # image_run docker-args... -> image with the fixture env applied
    docker run --rm "${FIX_DE[@]}" "$@"
}

# block <name> <rendered-text> -> just that block's body
block() { printf '%s\n' "$2" | awk -v b="# === $1 ===" '$0==b{f=1;next} /^# === /{f=0} f'; }

assert() { # name jq-filter json
    local name="$1" filter="$2" json="$3" res
    if res="$(printf '%s' "$json" | jq -e "$filter" 2>&1)"; then
        echo "$name: PASS"
    else
        echo "$name: FAIL"
        printf '%s\n' "$res" >&2
        fail=1
    fi
}

eq() { # name want got
    if [[ "$2" == "$3" ]]; then
        echo "$1: PASS"
    else
        echo "$1: FAIL"
        printf '  want: %s\n  got:  %s\n' "$2" "$3" >&2
        fail=1
    fi
}

has() { # name needle haystack
    if [[ "$3" == *"$2"* ]]; then
        echo "$1: PASS"
    else
        echo "$1: FAIL"
        printf '  missing %q in:\n%s\n' "$2" "$3" >&2
        fail=1
    fi
}

lacks() { # name needle haystack
    if [[ "$3" != *"$2"* ]]; then
        echo "$1: PASS"
    else
        echo "$1: FAIL"
        printf '  unexpected %q in:\n%s\n' "$2" "$3" >&2
        fail=1
    fi
}

occurrences() { # occurrences needle haystack -> integer
    local n=0 rest="$2"
    while [[ "$rest" == *"$1"* ]]; do
        rest="${rest#*"$1"}"
        n=$((n + 1))
    done
    printf '%s' "$n"
}

exit_is() { # name want cmd...  (stdout+stderr in $LAST_OUT)
    local name="$1" want="$2" got=0
    shift 2
    LAST_OUT="$("$@" 2>&1)" || got=$?
    eq "$name" "$want" "$got"
}

fatal_is() { # fatal_is name want_msg KEY=VAL... — render exits 2 and says why
    local name="$1" msg="$2" got=0 out
    shift 2
    out="$(render_run "$@" 2>&1)" || got=$?
    eq "$name exit" 2 "$got"
    has "$name msg" "$msg" "$out"
}

if [ "$MODE" = local ]; then
    echo "== test-render.sh (local mode: host bash+jq, render cases only) =="
else
    echo "== test-render.sh (docker mode: image $IMG) =="
fi

# ---------------------------------------------------------------------------
# render cases (run in both modes)
# ---------------------------------------------------------------------------

# Case 1: fixture env — both connections, pinned proposals, pools, secrets
out="$(render "${FIX_ENV[@]}")"
swanctl="$(block swanctl.conf "$out")"
eq "case1 encap exactly twice (per connection, not per child)" 2 \
    "$(occurrences 'encap = yes' "$swanctl")"
has "case1 ikev2 version" "version = 2" "$swanctl"
has "case1 ikev1 version" "version = 1" "$swanctl"
has "case1 ikev2 proposals" \
    "proposals = chacha20poly1305-prfsha256-x25519, aes128gcm16-prfsha256-x25519, aes128-sha256-modp2048" "$swanctl"
has "case1 ikev2 esp proposals" "esp_proposals = chacha20poly1305, aes128gcm16, aes128-sha256" "$swanctl"
has "case1 ikev1 proposals" \
    "proposals = aes128-sha256-modp2048, aes128-sha1-modp2048, aes128-sha1-modp1024" "$swanctl"
has "case1 ikev1 esp proposals" "esp_proposals = aes128gcm16, aes128-sha256, aes128-sha1" "$swanctl"
has "case1 eap-mschapv2 remote auth" "auth = eap-mschapv2" "$swanctl"
has "case1 pubkey local auth" "auth = pubkey" "$swanctl"
has "case1 psk local auth" "auth = psk" "$swanctl"
eq "case1 local_ts in both children" 2 "$(occurrences 'local_ts = 0.0.0.0/0' "$swanctl")"
has "case1 default pool" "addrs = 10.10.10.0/24" "$swanctl"
has "case1 default client dns" "dns = 1.1.1.1" "$swanctl"
eq "case1 both user ids rendered" 2 \
    "$(( $(occurrences 'id-1 = alice' "$swanctl") + $(occurrences 'id-1 = bob' "$swanctl") ))"
eq "case1 one secret per user plus psk" 3 "$(occurrences 'secret = ' "$swanctl")"
eq "case1 user passwords rendered" 2 \
    "$(( $(occurrences 'secret = secret1' "$swanctl") + $(occurrences 'secret = secret2' "$swanctl") ))"
has "case1 psk secret rendered" "secret = psk9" "$swanctl"
has "case1 psk accepts any identity" "id-1 = %any" "$swanctl"

# Case 2: env overrides flow into pool/dns/socks; sing-box tun shape is pinned
out="$(render "${FIX_ENV[@]}" VPN_POOL=10.99.0.0/22 CLIENT_DNS=9.9.9.9 \
    CHAIN_SOCKS_HOST=router2 CHAIN_SOCKS_PORT=2080)"
swanctl="$(block swanctl.conf "$out")"
sbx="$(block sing-box.json "$out")"
has "case2 pool override" "addrs = 10.99.0.0/22" "$swanctl"
has "case2 dns override" "dns = 9.9.9.9" "$swanctl"
assert "case2 sing-box shape" '
    .inbounds[0].type == "tun"
    and .inbounds[0].interface_name == "tun0"
    and .inbounds[0].mtu == 1380
    and .inbounds[0].auto_route == false
    and (.outbounds[] | select(.tag == "chain-out") | .type) == "socks"
    and (.outbounds[] | select(.tag == "chain-out") | .server) == "router2"
    and (.outbounds[] | select(.tag == "chain-out") | .server_port) == 2080
    and .route.final == "chain-out"
' "$sbx"

# Case 3: SERVER_SAN type flips between IP literal and FQDN (Review Focus 3)
params_ip="$(block cert-params "$(render "${FIX_ENV[@]}" VPN_SERVER_ADDR=203.0.113.7)")"
params_dns="$(block cert-params "$(render "${FIX_ENV[@]}")")"
has "case3 IP literal -> IP: SAN" "SERVER_SAN=IP:203.0.113.7" "$params_ip"
has "case3 IP literal -> DN" "SERVER_DN=CN=203.0.113.7" "$params_ip"
has "case3 FQDN -> DNS: SAN" "SERVER_SAN=DNS:vpn.example.com" "$params_dns"
has "case3 FQDN -> DN" "SERVER_DN=CN=vpn.example.com" "$params_dns"

# Case 4: a password may contain colons — split on the FIRST colon only (Review Focus 2)
swanctl="$(block swanctl.conf "$(render IPSEC_USERS=a:b:c IPSEC_PSK=psk9 VPN_SERVER_ADDR=vpn.example.com)")"
has "case4 user is text before first colon" "id-1 = a" "$swanctl"
has "case4 password keeps its colons" "secret = b:c" "$swanctl"
lacks "case4 no secret invented from the rest" "id-1 = b" "$swanctl"

# Case 5: garbage IPSEC_USERS is fatal and names the offending entry (Review Focus 1)
fatal_is "case5 entry without colon" "FATAL: IPSEC_USERS entry without ':'" \
    IPSEC_USERS=alice IPSEC_PSK=psk9 VPN_SERVER_ADDR=vpn.example.com
fatal_is "case5 empty username" "FATAL: IPSEC_USERS entry with empty username" \
    IPSEC_USERS=:secret IPSEC_PSK=psk9 VPN_SERVER_ADDR=vpn.example.com
fatal_is "case5 duplicate username" "FATAL: duplicate IPSEC_USERS entry 'alice'" \
    IPSEC_USERS=alice:x,alice:y IPSEC_PSK=psk9 VPN_SERVER_ADDR=vpn.example.com

# Case 6: the rest of the env contract — required vars, pool CIDR, log level
fatal_is "case6 missing IPSEC_USERS" "FATAL: IPSEC_USERS is required" \
    IPSEC_PSK=psk9 VPN_SERVER_ADDR=vpn.example.com
fatal_is "case6 missing IPSEC_PSK" "FATAL: IPSEC_PSK is required" \
    IPSEC_USERS=alice:x VPN_SERVER_ADDR=vpn.example.com
fatal_is "case6 missing VPN_SERVER_ADDR" "FATAL: VPN_SERVER_ADDR is required" \
    IPSEC_USERS=alice:x IPSEC_PSK=psk9
fatal_is "case6 bad VPN_POOL" "FATAL: VPN_POOL is not a valid CIDR" \
    "${FIX_ENV[@]}" VPN_POOL=not-a-cidr
fatal_is "case6 bad LOG_LEVEL" "FATAL: LOG_LEVEL must be 0-4" \
    "${FIX_ENV[@]}" LOG_LEVEL=9

# Case 7: cidr_overlap primitive (the boot-time pool-vs-own-subnet guard uses it)
exit_is "case7 overlap detected" 0 subcmd selftest-cidr 10.10.10.0/24 10.10.10.5/32
exit_is "case7 disjoint allowed" 1 subcmd selftest-cidr 10.10.10.0/24 192.168.1.0/24

# ---------------------------------------------------------------------------
# boot cases (docker mode only — they need a netns, /dev/net/tun and the daemons)
# ---------------------------------------------------------------------------
if [ "$MODE" = docker ]; then
    vol="ipsec-certs-test-$$"
    docker volume rm -f "$vol" >/dev/null 2>&1 || true

    # Case 8: first boot generates CA + server cert into the mounted volume
    exit_is "case8 cert generation" 0 \
        image_run -v "$vol":/etc/swanctl -e BOOT_STAGE=certs-only "$IMG"
    has "case8 certs generated" "cert generation complete" "$LAST_OUT"
    eq "case8 all four cert files" \
        "certs/server-cert.pem
private/ca-key.pem
private/server-key.pem
x509ca/ca-cert.pem" \
        "$(docker run --rm -v "$vol":/etc/swanctl --entrypoint /bin/sh "$IMG" \
            -c 'cd /etc/swanctl && ls x509ca/ca-cert.pem private/ca-key.pem certs/server-cert.pem private/server-key.pem 2>&1')"

    # Case 9: rendered configs land at their real paths and sing-box accepts ours
    exit_is "case9 configs render" 0 \
        image_run -v "$vol":/etc/swanctl -e BOOT_STAGE=configs-only "$IMG"
    has "case9 sing-box config valid" "sing-box config ok" "$LAST_OUT"
    eq "case9 configs landed" "/etc/sing-box/config.json
/etc/strongswan.d/vpndogs.conf
/etc/swanctl/swanctl.conf" \
        "$(docker run --rm -v "$vol":/etc/swanctl --entrypoint /bin/sh "$IMG" \
            -c 'ls /etc/swanctl/swanctl.conf /etc/strongswan.d/vpndogs.conf /etc/sing-box/config.json 2>&1')"

    # Case 10: live boot — charon accepts both connections (strongest check)
    exit_is "case10 live boot loads both conns" 0 \
        docker run --rm --cap-add NET_ADMIN --cap-add NET_RAW \
            -v "$vol":/etc/swanctl -e BOOT_STAGE=load-only "${FIX_DE[@]}" "$IMG"
    has "case10 ikev2 conn loaded" "loaded connection 'rw-eap'" "$LAST_OUT"
    has "case10 ikev1 conn loaded" "loaded connection 'rw-psk'" "$LAST_OUT"

    # Case 11: a second boot reuses the CA, so client-imported CAs stay valid
    ca_fingerprint() { # -> sha256 of the CA cert as it stands in the volume
        image_run -v "$vol":/etc/swanctl -e BOOT_STAGE=certs-only "$IMG" >/dev/null 2>&1 || return 1
        docker run --rm -v "$vol":/etc/swanctl --entrypoint /bin/sh "$IMG" \
            -c 'sha256sum /etc/swanctl/x509ca/ca-cert.pem | cut -d" " -f1'
    }
    ca1="$(ca_fingerprint)"; ca2="$(ca_fingerprint)"
    eq "case11 CA reused across boots" "$ca1" "$ca2"

    # Case 12: a pool overlapping the container's own subnet is fatal (Review Focus 4)
    exit_is "case12 pool overlap fatal" 2 \
        docker run --rm --cap-add NET_ADMIN --cap-add NET_RAW \
            -e BOOT_STAGE=certs-only -e VPN_POOL=172.17.0.0/16 "${FIX_DE[@]}" "$IMG"
    has "case12 overlap message" "FATAL: VPN_POOL overlaps" "$LAST_OUT"

    docker volume rm -f "$vol" >/dev/null 2>&1 || true
fi

exit "$fail"