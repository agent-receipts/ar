#!/usr/bin/env bash
# Lint files after Claude edits them.
# Runs the appropriate linter based on file path and extension.
# Exit 0: linting passed (or not applicable). Exit 2: linting failed.

set -euo pipefail

if ! command -v jq >/dev/null 2>&1; then
  echo "lint-on-edit: jq is not installed; skipping lint hook" >&2
  exit 0
fi

INPUT=$(cat)
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')

if [ -z "$FILE_PATH" ]; then
  exit 0
fi

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-.}"

# Determine which component was edited and run the appropriate linter
case "$FILE_PATH" in
  */sdk/go/* | */mcp-proxy/*)
    if [[ "$FILE_PATH" == *.go ]]; then
      COMPONENT_DIR=$(echo "$FILE_PATH" | sed -E 's|(.*/(sdk/go|mcp-proxy))(/.*)?|\1|')
      cd "$COMPONENT_DIR"
      BAD=$(gofmt -l "$FILE_PATH")
      if [ -n "$BAD" ]; then
        gofmt -d "$FILE_PATH" >&2
        echo "gofmt: $FILE_PATH needs formatting" >&2
        exit 2
      fi
    fi
    ;;
  */sdk/ts/*)
    if [[ "$FILE_PATH" == *.ts || "$FILE_PATH" == *.js ]]; then
      cd "$PROJECT_DIR/sdk/ts"
      pnpm exec biome check "$FILE_PATH" >&2 || { echo "biome: $FILE_PATH has issues" >&2; exit 2; }
    fi
    ;;
  */sdk/py/*)
    if [[ "$FILE_PATH" == *.py ]]; then
      cd "$PROJECT_DIR/sdk/py"
      uv run ruff check "$FILE_PATH" >&2 || { echo "ruff: $FILE_PATH has issues" >&2; exit 2; }
    fi
    ;;
  *.sh)
    if command -v shellcheck >/dev/null 2>&1; then
      shellcheck "$FILE_PATH" >&2 || { echo "shellcheck: $FILE_PATH has issues" >&2; exit 2; }
    else
      echo "lint-on-edit: shellcheck not installed; skipping lint for $FILE_PATH" >&2
    fi
    ;;
esac

exit 0
