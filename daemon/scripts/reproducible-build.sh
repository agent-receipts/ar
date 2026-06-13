#!/bin/sh
# Canonical reproducible build of a daemon-module binary (ADR-0031/0034).
#
# Single source of the determinism flags shared by the two CI rebuilds — Gate B
# (daemon.yml, cross-path byte-identity) and the release attestation
# (release-obsigna.yml, rebuild-matches-artifact). Keep these flags in lockstep
# with the daemon-module builds in daemon/.goreleaser.yaml: CGO off (no host C
# toolchain bytes), -trimpath (no absolute build paths), -buildvcs=false (no git
# stamp — the release LICENSE-copy hook would otherwise dirty the tree), and a
# version stamp that derives only from the tag.
#
# Usage: reproducible-build.sh <daemon-module-dir> <output-path> [version] [cmd]
#   version  when given, stamps -X main.version=v<version> to match the released
#            build; omit it for the cross-path determinism check, where both
#            builds just need identical (any) flags. The obsigna CLI carries no
#            version symbol in its goreleaser build (-s -w only), so attest it
#            with an empty version.
#   cmd      main package to build; defaults to ./cmd/obsigna-daemon. The release
#            attest also rebuilds ./cmd/obsigna (the CLI) through this argument,
#            so the daemon module's two attested binaries share one script.
#
# GOWORK, GOOS, and GOARCH are read from the environment so callers choose
# workspace vs published-module resolution and the target platform.
set -eu

daemon_dir="$1"
out="$2"
version="${3:-}"
cmd="${4:-./cmd/obsigna-daemon}"

ldflags="-s -w"
if [ -n "$version" ]; then
  ldflags="$ldflags -X main.version=v${version}"
fi

cd "$daemon_dir"
CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "$ldflags" -o "$out" "$cmd"
