#!/usr/bin/env bash
# build.sh — build the image from this checkout.
set -euo pipefail

docker build -t strongswan-server:latest .
echo done