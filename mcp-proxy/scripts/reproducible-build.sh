#!/bin/sh
# Canonical reproducible build of obsigna-mcp (ADR-0033).
#
# Single source of the determinism flags shared by the two CI rebuilds — Gate B
# (mcp-proxy.yml, cross-path byte-identity) and the release attestation
# (release-mcp-proxy.yml, rebuild-matches-artifact). Keep these flags in lockstep
# with the obsigna-mcp build in mcp-proxy/.goreleaser.yaml: CGO off (no host C
# toolchain bytes), -trimpath (no absolute build paths), -buildvcs=false (no git
# stamp — the release LICENSE-copy hook would otherwise dirty the tree), and a
# version stamp that derives only from the tag.
#
# Usage: reproducible-build.sh <module-dir> <output-path> [version]
#   version  when given, stamps -X main.version=v<version> to match the released
#            build; omit it for the cross-path determinism check, where both
#            builds just need identical (any) flags.
#
# GOWORK, GOOS, and GOARCH are read from the environment so callers choose
# workspace vs published-module resolution and the target platform.
set -eu

module_dir="$1"
out="$2"
version="${3:-}"

ldflags="-s -w"
if [ -n "$version" ]; then
  ldflags="$ldflags -X main.version=v${version}"
fi

cd "$module_dir"
CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "$ldflags" -o "$out" ./cmd/obsigna-mcp
