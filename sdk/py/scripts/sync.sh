#!/usr/bin/env bash
# Sync Python SDK dependencies.
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"

cd "$(dirname "$0")/.."
exec uv sync "$@"
