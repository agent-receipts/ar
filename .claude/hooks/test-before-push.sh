#!/usr/bin/env bash
# Run tests before git push.
# Detects which components have committed changes relative to the upstream
# branch and runs their tests.
# Exit 0: tests passed. Exit 2: tests failed.

set -euo pipefail

# Only run for `git push` commands. The hook config `if` filter
# isn't being honoured by the harness in this environment, so we
# re-check here from the tool_input payload on stdin.
HOOK_INPUT="$(cat || true)"
if [ -n "$HOOK_INPUT" ]; then
  CMD=$(printf '%s' "$HOOK_INPUT" | python3 -c 'import json,sys;d=json.loads(sys.stdin.read() or "{}");print((d.get("tool_input") or {}).get("command",""))' 2>/dev/null || true)
  case "$CMD" in
    "git push"|"git push "*) ;;
    *) exit 0 ;;
  esac
fi

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-.}"
FAILED=0

get_changed_files() {
  cd "$PROJECT_DIR"
  if git rev-parse --verify '@{upstream}' >/dev/null 2>&1; then
    git diff --name-only '@{upstream}'..HEAD
    return
  fi

  local default_branch_ref merge_base
  default_branch_ref=$(git symbolic-ref --quiet --short refs/remotes/origin/HEAD 2>/dev/null || true)
  if [ -n "$default_branch_ref" ]; then
    merge_base=$(git merge-base "$default_branch_ref" HEAD 2>/dev/null || true)
    if [ -n "$merge_base" ]; then
      git diff --name-only "$merge_base"..HEAD
      return
    fi
  fi

  # No comparison base — run all test suites to be safe
  printf '%s\n' "sdk/go/" "sdk/ts/" "sdk/py/" "mcp-proxy/"
}

CHANGED_FILES=$(get_changed_files)

if [ -z "$CHANGED_FILES" ]; then
  exit 0
fi

run_if_changed() {
  local pattern="$1"
  local dir="$2"
  shift 2

  if echo "$CHANGED_FILES" | grep -q "$pattern"; then
    echo "Running tests: $dir" >&2
    (cd "$PROJECT_DIR/$dir" && "$@") >&2 || FAILED=1
  fi
}

run_if_changed "^sdk/go/" "sdk/go" go test ./...
run_if_changed "^sdk/ts/" "sdk/ts" pnpm test
run_if_changed "^sdk/py/" "sdk/py" uv run pytest
run_if_changed "^mcp-proxy/" "mcp-proxy" go test ./...

# mcp-proxy also depends on sdk/go
if echo "$CHANGED_FILES" | grep -q "^sdk/go/" && ! echo "$CHANGED_FILES" | grep -q "^mcp-proxy/"; then
  echo "Running tests: mcp-proxy (sdk/go dependency changed)" >&2
  (cd "$PROJECT_DIR/mcp-proxy" && go test ./...) >&2 || FAILED=1
fi

if [ "$FAILED" -ne 0 ]; then
  echo "Tests failed — fix before pushing." >&2
  exit 2
fi

exit 0
