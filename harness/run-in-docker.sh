#!/bin/sh
# Builds Linux binaries and runs an integration test in a privileged
# container: agent-integration.sh (default) or the script named by $1.
# Requires Docker with a kernel that supports WireGuard and nftables.
set -eu
cd "$(dirname "$0")/.."
ARCH=$(docker info --format '{{.Architecture}}' | sed 's/x86_64/amd64/; s/aarch64/arm64/')
GOOS=linux GOARCH=$ARCH CGO_ENABLED=0 go build -o "bin/linux-$ARCH/" ./cmd/...
exec docker run --rm --privileged \
  -v "$PWD/bin/linux-$ARCH:/plait/bin:ro" \
  -v "$PWD/harness:/plait/harness:ro" \
  -v "$PWD/internal/ui/static:/plait/static:ro" \
  alpine:3.20 sh "/plait/harness/${1:-agent-integration.sh}"
