#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<EOF
Usage: $(basename "$0") <module> <version>

Create a GitHub Release for a module in this monorepo.

Modules:
  sdk-go       Go SDK         (tag: sdk/go/vVERSION)
  sdk-ts       TypeScript SDK (tag: sdk-ts-vVERSION)
  sdk-py       Python SDK     (tag: sdk-py-vVERSION)
  mcp-proxy    MCP proxy      (tag: mcp-proxy/vVERSION)

Examples:
  $(basename "$0") sdk-go 0.2.0
  $(basename "$0") sdk-ts 0.3.0
  $(basename "$0") mcp-proxy 0.1.0
EOF
  exit 1
}

fail() { echo "error: $1" >&2; exit 1; }

[[ $# -eq 2 ]] || usage

MODULE="$1"
VERSION="$2"

# Validate version format
[[ "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?(\+([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?$ ]] || \
  fail "invalid version '$VERSION' — expected semver (e.g. 0.2.0, 1.0.0-beta.1)"

# Ensure we're on main and up to date
BRANCH=$(git branch --show-current)
[[ "$BRANCH" == "main" ]] || fail "must be on main branch (currently on $BRANCH)"
git fetch origin main --quiet
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main)
[[ "$LOCAL" == "$REMOTE" ]] || fail "local main is not up to date with origin — run git pull"

# Ensure working tree is clean
[[ -z "$(git status --porcelain)" ]] || fail "working tree is not clean — commit or stash changes first"

case "$MODULE" in
  sdk-go)
    TAG="sdk/go/v${VERSION}"
    DIR="sdk/go"
    ;;
  sdk-ts)
    TAG="sdk-ts-v${VERSION}"
    DIR="sdk/ts"
    ;;
  sdk-py)
    TAG="sdk-py-v${VERSION}"
    DIR="sdk/py"
    ;;
  mcp-proxy)
    TAG="mcp-proxy/v${VERSION}"
    DIR="mcp-proxy"
    ;;
  *)
    fail "unknown module '$MODULE' — run with no args for usage"
    ;;
esac

# Check tag doesn't already exist (locally or on remote)
git fetch origin --tags --quiet
git tag -l "$TAG" | grep -q . && fail "tag $TAG already exists"
git ls-remote --tags origin "refs/tags/$TAG" | grep -q . && fail "tag $TAG already exists on origin"

echo "==> Releasing $MODULE v$VERSION (tag: $TAG)"
echo ""

# Module-specific checks
case "$MODULE" in
  sdk-go)
    echo "--- Running Go checks in $DIR"
    (cd "$DIR" && go vet ./... && go test ./...)
    ;;
  mcp-proxy)
    echo "--- Checking for replace directive in $DIR/go.mod"
    if grep -Eq '^[[:space:]]*replace[[:space:]]' "$DIR/go.mod"; then
      fail "$DIR/go.mod contains a replace directive — remove it and point to a published sdk/go version before releasing"
    fi
    echo "--- Running Go checks in $DIR"
    (cd "$DIR" && go vet ./... && go test ./...)
    ;;
  sdk-ts)
    echo "--- Checking package.json version matches"
    PKG_VERSION=$(node -p "require('./$DIR/package.json').version")
    if [[ "$PKG_VERSION" != "$VERSION" ]]; then
      fail "$DIR/package.json version is $PKG_VERSION but releasing $VERSION — update package.json first"
    fi
    echo "--- Running TypeScript checks in $DIR"
    (cd "$DIR" && pnpm install --frozen-lockfile && pnpm run typecheck && pnpm test && pnpm run build)
    ;;
  sdk-py)
    echo "--- Checking pyproject.toml version matches"
    PY_VERSION=$(python3 -c "
import tomllib, pathlib
p = pathlib.Path('$DIR/pyproject.toml')
print(tomllib.loads(p.read_text())['project']['version'])
")
    if [[ "$PY_VERSION" != "$VERSION" ]]; then
      fail "$DIR/pyproject.toml version is $PY_VERSION but releasing $VERSION — update pyproject.toml first"
    fi
    echo "--- Running Python checks in $DIR"
    (cd "$DIR" && uv run pytest)
    ;;
esac

echo ""
echo "--- All checks passed"
echo ""
echo "Will create release:"
echo "  Tag:    $TAG"
echo "  Title:  $MODULE v$VERSION"
echo ""
read -rp "Proceed? [y/N] " confirm
[[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }

REPO_URL=$(gh repo view --json url -q '.url')
gh release create "$TAG" --title "$MODULE v$VERSION" --generate-notes
echo ""
echo "==> Released $MODULE v$VERSION"
echo "    ${REPO_URL}/releases/tag/$TAG"
