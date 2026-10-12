#!/usr/bin/env bash
# build.sh — build the image via buildx on the host network.
# Direct network access is the default; set BUILD_PROXY (e.g.
# socks5://127.0.0.1:1081) to route the build through a proxy instead.
# NOTE: use socks5://, NOT socks5h:// — buildkit's Go ignores the socks5h
# scheme in HTTP(S)_PROXY and falls back to a direct (here: 403'd) fetch.
# Host network is not cosmetic: buildkit's default bridge cannot resolve
# dl-cdn.alpinelinux.org here, so apk finds no packages at all.
set -euo pipefail

BUILDER="ipsec-build${BUILD_PROXY:+-proxy}"
IMAGE="${IMAGE:-strongswan-server:latest}"

PROXY_ARGS=()
if [[ -n "${BUILD_PROXY:-}" ]]; then
    PROXY_ARGS=(--driver-opt "env.HTTP_PROXY=$BUILD_PROXY" --driver-opt "env.HTTPS_PROXY=$BUILD_PROXY")
fi

# The layer cache lives in the builder container, so a per-run builder name (and
# `buildx rm` at exit) means every build re-downloads alpine and re-runs apk.
# Reuse the builder instead. Its driver opts are frozen at create time, hence
# the separate proxy/non-proxy names.
if ! docker buildx inspect "$BUILDER" >/dev/null 2>&1; then
    docker buildx create --name "$BUILDER" --driver docker-container \
        --driver-opt network=host \
        "${PROXY_ARGS[@]}" >/dev/null
fi

export BUILDX_BUILDER="$BUILDER"
docker buildx build --load -t "$IMAGE" "$@".
echo done