ARG BASE_IMAGE=docker.io/library/alpine:3.24
FROM ${BASE_IMAGE}

ARG SINGBOX_VERSION=1.14.2
ARG TARGETARCH=amd64

RUN apk add --no-cache bash curl jq tini ca-certificates iproute2 strongswan

RUN set -eux; \
    curl -fsSL -o /tmp/sing_box.tar.gz \
        "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${TARGETARCH}-musl.tar.gz"; \
    tar -xzf /tmp/sing_box.tar.gz -C /tmp \
        "sing-box-${SINGBOX_VERSION}-linux-${TARGETARCH}-musl/sing-box"; \
    mv "/tmp/sing-box-${SINGBOX_VERSION}-linux-${TARGETARCH}-musl/sing-box" /usr/local/bin/sing-box; \
    chmod +x /usr/local/bin/sing-box; \
    rm -rf /tmp/sing_box.tar.gz "/tmp/sing-box-${SINGBOX_VERSION}-linux-${TARGETARCH}-musl"; \
    sing-box version

COPY --chmod=755 scripts /usr/local/bin

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/entrypoint.sh"]