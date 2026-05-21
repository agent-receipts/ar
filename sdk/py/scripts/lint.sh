#!/usr/bin/env bash
# Lint + format-check the Python SDK with ruff.
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"

cd "$(dirname "$0")/.."
uv run ruff check "$@"
uv run ruff format --check .
