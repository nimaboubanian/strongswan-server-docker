#!/usr/bin/env bash
# entrypoint.sh — strongSwan roadwarrior server for the vpndogs inbound node.
#
#   entrypoint.sh                 boot: certs -> configs -> sing-box + charon
#   entrypoint.sh render          print every rendered config (test path)
#   entrypoint.sh selftest-cidr A B   exit 0 if CIDR A and CIDR B overlap
set -euo pipefail

VPN_POOL="${VPN_POOL:-10.10.10.0/24}"
CLIENT_DNS="${CLIENT_DNS:-1.1.1.1}"
CHAIN_SOCKS_HOST="${CHAIN_SOCKS_HOST:-vpndogs-router}"
CHAIN_SOCKS_PORT="${CHAIN_SOCKS_PORT:-1070}"
LOG_LEVEL="${LOG_LEVEL:-1}"
TUN_IFACE="tun0"

# AEAD-first. ChaCha20 is IKEv2-only; IKEv1 takes one algorithm per kind, so its
# list is the classic GCM/SHA suites legacy routers actually negotiate.
IKEV2_IKE_PROPOSALS="chacha20poly1305-prfsha256-x25519, aes128gcm16-prfsha256-x25519, aes128-sha256-modp2048"
IKEV2_ESP_PROPOSALS="chacha20poly1305, aes128gcm16, aes128-sha256"
IKEV1_IKE_PROPOSALS="aes128-sha256-modp2048, aes128-sha1-modp2048, aes128-sha1-modp1024"
IKEV1_ESP_PROPOSALS="aes128gcm16, aes128-sha256, aes128-sha1"

SWANCTL_DIR="/etc/swanctl"
STRONGSWAN_D="/etc/strongswan.d"
SINGBOX_CONF="/etc/sing-box/config.json"
ROUTER_TABLE=200

log() { echo "[entrypoint] $*" >&2; }
fatal() { echo "FATAL: $*" >&2; exit 2; }

# --- env parsing -----------------------------------------------------------

declare -a EAP_USERS=()

parse_users() {
    local entries=() entry user pass seen=" "
    IFS=',' read -r -a entries <<<"$IPSEC_USERS"
    for entry in "${entries[@]}"; do
        [[ "$entry" == *:* ]] || fatal "IPSEC_USERS entry without ':' — expected user:pass (got '$entry')"
        user="${entry%%:*}"
        pass="${entry#*:}"   # first colon only: passwords may contain colons
        [[ -n "$user" ]] || fatal "IPSEC_USERS entry with empty username (got '$entry')"
        [[ "$seen" != *" $user "* ]] || fatal "duplicate IPSEC_USERS entry '$user'"
        seen="$seen$user "
        EAP_USERS+=("$user"$'\t'"$pass")
    done
}

validate_env() {
    [[ -n "${IPSEC_USERS:-}" ]] || fatal "IPSEC_USERS is required (user:pass,user2:pass2)"
    [[ -n "${IPSEC_PSK:-}" ]] || fatal "IPSEC_PSK is required (IKEv1 shared secret)"
    [[ -n "${VPN_SERVER_ADDR:-}" ]] ||
        fatal "VPN_SERVER_ADDR is required (public IP or DNS name; clients check it against the server certificate)"
    [[ "$LOG_LEVEL" =~ ^[0-4]$ ]] || fatal "LOG_LEVEL must be 0-4, got '$LOG_LEVEL'"
    [[ "$CHAIN_SOCKS_PORT" =~ ^[0-9]+$ ]] || fatal "CHAIN_SOCKS_PORT must be a port number, got '$CHAIN_SOCKS_PORT'"
    is_ipv4_cidr "$VPN_POOL" || fatal "VPN_POOL is not a valid CIDR, got '$VPN_POOL'"
    is_ipv4_addr "$CLIENT_DNS" || fatal "CLIENT_DNS is not a valid IPv4 address, got '$CLIENT_DNS'"
    parse_users
}

# --- CIDR helpers ----------------------------------------------------------

is_ipv4_addr() {
    local -a o=()
    local part
    IFS=. read -r -a o <<<"$1"
    [[ "${#o[@]}" -eq 4 ]] || return 1
    for part in "${o[@]}"; do
        [[ "$part" =~ ^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$ ]] || return 1
    done
}

is_ipv4_cidr() {
    [[ "$1" == */* ]] || return 1
    is_ipv4_addr "${1%%/*}" || return 1
    local mask="${1##*/}"
    [[ "$mask" =~ ^(0|[0-9]|[12][0-9]|3[0-2])$ ]]
}

ip_to_int() {
    local a b c d
    IFS=. read -r a b c d <<<"$1"
    printf '%d\n' "$(( (a << 24) | (b << 16) | (c << 8) | d ))"
}

cidr_overlap() { # exit 0 when the two CIDRs share any address
    local a="$1" b="$2" ai bi ma mb diff
    ai="$(ip_to_int "${a%%/*}")"
    bi="$(ip_to_int "${b%%/*}")"
    ma=$(( 0xFFFFFFFF << (32 - ${a##*/}) & 0xFFFFFFFF ))
    mb=$(( 0xFFFFFFFF << (32 - ${b##*/}) & 0xFFFFFFFF ))
    diff=$(( (ai ^ bi) & 0xFFFFFFFF ))
    (( (diff & ma) == 0 || (diff & mb) == 0 ))
}

# --- renderers -------------------------------------------------------------

render_strongswan_conf() {
    # A drop-in, not a replacement: Alpine's own strongswan.conf carries the
    # modular plugin includes charon needs to load at all.
    cat <<EOF
charon {
    filelog {
        /dev/stderr {
            time_format = %T
            default = $LOG_LEVEL
        }
    }
}
EOF
}

render_swanctl_conf() {
    local user pass
    cat <<EOF
connections {
    rw-eap {
        version = 2
        local_addrs = 0.0.0.0
        pools = vpn-pool
        encap = yes
        fragmentation = yes
        mobike = yes
        proposals = $IKEV2_IKE_PROPOSALS
        local {
            auth = pubkey
            certs = server-cert.pem
        }
        remote {
            auth = eap-mschapv2
            eap_id = %any
        }
        children {
            rw-eap-child {
                local_ts = 0.0.0.0/0
                esp_proposals = $IKEV2_ESP_PROPOSALS
            }
        }
    }
    rw-psk {
        version = 1
        local_addrs = 0.0.0.0
        pools = vpn-pool
        encap = yes
        proposals = $IKEV1_IKE_PROPOSALS
        local {
            auth = psk
        }
        remote {
            auth = psk
        }
        children {
            rw-psk-child {
                local_ts = 0.0.0.0/0
                esp_proposals = $IKEV1_ESP_PROPOSALS
            }
        }
    }
}
pools {
    vpn-pool {
        addrs = $VPN_POOL
        dns = $CLIENT_DNS
    }
}
secrets {
    ikev1-psk {
        id-1 = %any
        secret = $IPSEC_PSK
    }
EOF
    for entry in "${EAP_USERS[@]}"; do
        IFS=$'\t' read -r user pass <<<"$entry"
        cat <<EOF
    eap-$user {
        id-1 = $user
        secret = $pass
    }
EOF
    done
    echo "}"
}

render_singbox_conf() {
    # auto_route stays off on purpose: the entrypoint owns routing via a policy
    # rule so only decrypted pool-source traffic enters the tun.
    jq -n --arg host "$CHAIN_SOCKS_HOST" --argjson port "$CHAIN_SOCKS_PORT" '{
        log: {level: "warn"},
        inbounds: [{
            type: "tun",
            tag: "tun-in",
            interface_name: "tun0",
            address: ["198.18.0.1/30"],
            mtu: 1380,
            auto_route: false,
            strict_route: false
        }],
        outbounds: [
            {type: "direct", tag: "direct-out"},
            {type: "socks", tag: "chain-out", server: $host, server_port: $port}
        ],
        route: {final: "chain-out"}
    }'
}

cert_params() {
    local san_type=DNS
    if [[ "$VPN_SERVER_ADDR" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        san_type=IP
    fi
    echo "SERVER_SAN=${san_type}:${VPN_SERVER_ADDR}"
    echo "SERVER_DN=CN=${VPN_SERVER_ADDR}"
}

cmd_render() {
    validate_env
    echo "# === strongswan.conf ==="
    render_strongswan_conf
    echo "# === swanctl.conf ==="
    render_swanctl_conf
    echo "# === sing-box.json ==="
    render_singbox_conf
    echo "# === cert-params ==="
    cert_params
}

case "${1:-}" in
    render)
        cmd_render
        ;;
    selftest-cidr)
        shift
        cidr_overlap "$@"
        ;;
    *)
        echo "boot not implemented yet (Task 3)" >&2
        exit 1
        ;;
esac