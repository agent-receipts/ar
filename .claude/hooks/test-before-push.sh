#!/usr/bin/env bash
# Run tests before `git push` to catch regressions in changed components.
#
# Wired as PreToolUse:Bash in .claude/settings.json. Claude Code's hook
# `matcher` field is a regex on tool names — there is no built-in way to
# restrict by command content, so this hook fires on every Bash invocation
# and filters here. Without that filter, every `ls` / `git status` would
# re-trigger the full test matrix.
#
# Stdin protocol: Claude Code passes a JSON object containing
# `.tool_input.command`. We parse it, exit 0 immediately for any command
# that isn't a `git push`, and only fall through to the test runners for
# real pushes. Robust to missing `jq` (uses sed fallback) and to non-JSON
# input (treats empty COMMAND as not-a-push, exits 0).
#
# Exits:
#   0  not a `git push`, or all relevant tests passed
#   2  one or more component test suites failed; do not push

set -euo pipefail

# --- Filter: only run for `git push` -----------------------------------------

extract_command() {
  local input="${1:-}"
  [ -z "$input" ] && return 0
  if command -v jq >/dev/null 2>&1; then
    printf '%s' "$input" | jq -r '.tool_input.command // empty' 2>/dev/null
  else
    printf '%s' "$input" | sed -n 's/.*"command"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1
  fi
}

TOOL_INPUT="$(cat 2>/dev/null || true)"
COMMAND="$(extract_command "$TOOL_INPUT")"

# Match `git push` either at the start of the command or after whitespace.
# This covers env-var prefixes (`FOO=bar git push`) and shell-list operators
# (`&& git push`, `; git push`, `|| git push`) since each is followed by a
# space in normal shell usage. Avoids false positives like `echo "git push"`.
case "$COMMAND" in
  "git push"*|*" git push"*) ;;
  *) exit 0 ;;
esac

# --- Run tests for changed components ----------------------------------------

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
