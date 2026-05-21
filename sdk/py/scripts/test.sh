#!/usr/bin/env bash
# Run the Python SDK test suite. Bakes in the PATH for uv so the
# allowlist sees a single stable command form across worktrees.
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"

cd "$(dirname "$0")/.."
exec uv run pytest "$@"
