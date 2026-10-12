# strongswan-server

strongSwan IPsec server that remote clients dial **into**, with every decrypted
packet handed to the vpndogs chain (`vpndogs-router:1070`) so inbound clients
inherit the stack's routing: domestic direct, sb-cluster proxied, blackhole
where configured.

It is an optional inbound node for the vpndogs stack — enable it with
`COMPOSE_PROFILES=ipsec-inbound` in the stack's `.env`.

## What it accepts

| Client | Port | Config |
|---|---|---|
| Native IKEv2 (Windows / iOS / macOS / Android) | 500, 4500 | `VPN_SERVER_ADDR` as server, EAP username/password from `IPSEC_USERS`, import the CA first |
| strongSwan-based clients | 1061 (→ 4500) | same EAP credentials, server on `host:1061` |
| Legacy IKEv1 routers | 500 | shared secret = `IPSEC_PSK`, main mode — see [docs/router-site-to-site.md](docs/router-site-to-site.md) |

IKEv1 is main mode only — aggressive mode is deliberately not offered (it is a
known offline PSK-cracking surface).

Ciphers are AEAD-first: ChaCha20-Poly1305 and AES-GCM-128, with classic SHA
suites only as interop fallbacks for old routers. All IPsec rides UDP
(`encap = yes`), because raw ESP (IP protocol 50) cannot cross Docker port
publishing.

## Running it

```sh
cp .env.example .env    # then set IPSEC_USERS, IPSEC_PSK, VPN_SERVER_ADDR
./build.sh
docker compose up -d
```

Inside the vpndogs stack, use `deploy/compose.yaml` — it is the same service,
gated behind the `ipsec-inbound` profile and wired to the router's healthcheck.

## Configuration

| Var | Meaning | Default |
|---|---|---|
| `IPSEC_USERS` | `user:pass,user2:pass2` EAP credentials — **required** | — |
| `IPSEC_PSK` | IKEv1 shared secret — **required** | — |
| `VPN_SERVER_ADDR` | public IP or DNS name clients dial; becomes the cert CN+SAN — **required** | — |
| `VPN_POOL` | client address pool | `10.10.10.0/24` |
| `CLIENT_DNS` | DNS pushed to clients | `1.1.1.1` |
| `CHAIN_SOCKS_HOST` / `CHAIN_SOCKS_PORT` | egress SOCKS | `vpndogs-router` / `1070` |
| `LOG_LEVEL` | charon log level, 0–4 | `1` |

`IPSEC_USERS` entries split on the **first** colon, so passwords may contain
colons. A duplicate username, an entry without a colon, a username outside
letters/digits/`_@+-`, or a value carrying `# { } " '` or a line break is fatal,
not ignored — those characters silently truncate or break a strongSwan config
file. Certificate keys are RSA-3072 because native Windows/iOS/macOS IKEv2
clients reject Ed25519.

`VPN_POOL` must not overlap the container's own subnet — the entrypoint refuses
to boot if it does, because that would silently black-hole decrypted traffic.

Missing or malformed required vars exit with a `FATAL:` line and the container
restart-loops (the stack's established pattern); the rest of the stack is
unaffected.

## The CA certificate

Native IKEv2 clients need the server's CA to verify it. It is generated on first
boot into the `ipsec-certs` volume:

```sh
docker compose cp ipsec:/etc/swanctl/x509ca/ca-cert.pem ./vpndogs-ca.pem
```

Import that file into the client, then configure the connection with
`VPN_SERVER_ADDR` as the server address. Delete the volume and every client has
to re-import — that is the cost of not keeping the volume.

## Diagnostics

```sh
docker compose exec ipsec report.sh
```

Prints process state, interfaces and the policy route, loaded connections and
SAs, XFRM state, certificate subjects/expiry, and the config with secrets
redacted.

## End-to-end checklist

The automated suite stops at "charon accepted the config" — no SA is ever
established by a test. After deploying, walk this once:

```sh
docker compose exec ipsec report.sh
```

1. **Both connections loaded** — `rw-eap` and `rw-psk` under *IKE connections*.
2. **Processes up** — charon and sing-box both `UP`, and `ps -ef` shows charon
   as a child of the starter (if the starter supervises a charon that is gone,
   the process tree is not what the supervisor expects).
3. **A client connects**, then:
4. **SA present** — the client's address appears under *Established SAs*.
5. **The outbound XFRM policy is narrowed to that address.** `ip xfrm policy`
   inside the container must show the outbound policy narrowed to the assigned
   virtual IP (`src 10.10.10.x dst 0.0.0.0/0`) — **not** `0.0.0.0/0`. If either
   side negotiated a wildcard, charon also ESP-encrypts sing-box's own SOCKS
   traffic to the router, and the policy route cannot prevent it (XFRM output
   runs before the routing decision the rule governs): the tunnel goes nowhere
   and the router connection dies with it.
6. **Policy route present** — `ip route show table 200` shows
   `default dev tun0`.
7. **Egress goes through the chain** — from the client, the egress IP is the
   sb-cluster's, and domestic/blackholed destinations behave as
   `configs/check.sh` describes on the host side.

## Testing

```sh
./build.sh && scripts/test-render.sh     # in-image contracts (61 checks)
scripts/test-render.sh --local           # render contracts only, host bash+jq
```

Covers rendered config (connections, proposals, pools, secrets, cert SAN),
env validation failures, first-boot cert generation, CA reuse across boots, a
live charon accepting both connections, and the pool-overlap guard.

## Troubleshooting

**Host ports 500/4500 are taken.** IKE needs UDP 500 and 4500; if the host runs
its own IPsec/L2TP daemon, publishing fails or packets go to the wrong daemon.
Stop the host's daemon, or publish different host ports — but then native IKEv2
clients and legacy routers cannot reach you (they hardcode 500/4500); only
strongSwan-based clients can use a custom port (1061).

**Client connects but the SA passes no traffic, and the host is not at fault on
ports.** Check the *host* kernel modules first — a container shares the host
kernel, so these must be present there, not in the image:

```sh
lsmod | grep -E '^(ip_compat|af_alg|crypto_user|xfrm_user)'
# if anything is missing:
sudo modprobe ip_compat af_alg crypto_user xfrm_user
```

`ip_compat` is what ESP-in-UDP encapsulation rides on, and `af_alg` +
`crypto_user` are what ChaCha20-Poly1305 / AES-GCM ESP use. Without them the SA
negotiates and then carries nothing, and the symptom looks like a routing
problem rather than a missing module.

**Client connects but no traffic.** Check `report.sh`: the tun must exist and the
policy route must be installed. Then check the router: if it is down, decrypted
traffic has nowhere to go (the node stays up, IKE SAs persist). `depends_on`
gates startup, but a router that dies later still breaks egress.

**Restarts on its own.** `docker compose logs ipsec` — a `FATAL:` line means bad
env; anything else means a daemon died three times in a row.

**EAP clients say the server is untrusted.** The client is checking
`VPN_SERVER_ADDR` against the certificate's SAN. It must match exactly what the
client is told to dial, and the imported CA must be the one from this instance's
volume.