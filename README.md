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
| Legacy IKEv1 routers | 500 | shared secret = `IPSEC_PSK`, main mode |

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
colons. A duplicate username or an entry without a colon is fatal, not ignored.

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