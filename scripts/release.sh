#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<EOF
Usage: $(basename "$0") [--dry-run] <module> <version>

Create a GitHub Release for a module in this monorepo.

Modules:
  sdk-go       Go SDK                 (tag: sdk/go/vVERSION)
  sdk-ts       TypeScript SDK         (tag: sdk-ts-vVERSION)
  sdk-py       Python SDK             (tag: sdk-py-vVERSION)
  mcp-proxy    MCP proxy              (tag: mcp-proxy/vVERSION)
  daemon       agent-receipts daemon  (tag: daemon/vVERSION)

Flags:
  --dry-run    Validate everything and print the actions, but do not push
               tags or create releases.

Notes:
  - Pre-release versions (e.g. 0.8.0-alpha.1) are automatically marked
    as GitHub pre-releases.
  - mcp-proxy and daemon push the tag only and let release-mcp-proxy.yml /
    release-daemon.yml build binaries and create the GitHub Release. Other
    modules use 'gh release create' directly.

Examples:
  $(basename "$0") sdk-go 0.2.0
  $(basename "$0") --dry-run mcp-proxy 0.8.0-alpha.1
  $(basename "$0") daemon 0.8.0-alpha.1
EOF
  exit 1
}

fail() { echo "error: $1" >&2; exit 1; }

# cd to repo root so the script works from any directory
cd "$(git rev-parse --show-toplevel)"

# Preflight: ensure common tools are available
command -v git >/dev/null 2>&1 || fail "git is not installed"
command -v gh >/dev/null 2>&1 || fail "gh CLI is not installed — see https://cli.github.com"
gh auth status >/dev/null 2>&1 || fail "gh is not authenticated — run gh auth login"

DRY_RUN=false
ARGS=()
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    -h|--help) usage ;;
    *) ARGS+=("$arg") ;;
  esac
done
[[ ${#ARGS[@]} -eq 2 ]] || usage

MODULE="${ARGS[0]}"
VERSION="${ARGS[1]}"

# Validate version format. PEP 440 pre-release form (e.g. 0.8.0a1) is
# accepted only for sdk-py because PyPI rejects SemVer-style hyphenated
# pre-releases. Go modules (sdk-go, mcp-proxy, daemon) and the npm
# module (sdk-ts) require SemVer; accepting PEP 440 there would silently
# create tags that go.mod / npm cannot resolve.
SEMVER_RE='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?(\+([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?$'
PEP440_PRE_RE='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(a|b|rc)[0-9]+$'
case "$MODULE" in
  sdk-py)
    [[ "$VERSION" =~ $SEMVER_RE ]] || [[ "$VERSION" =~ $PEP440_PRE_RE ]] || \
      fail "invalid version '$VERSION' for sdk-py — expected SemVer (e.g. 0.5.0, 1.0.0-beta.1) or PEP 440 pre-release (e.g. 0.8.0a1)"
    ;;
  sdk-go|sdk-ts|mcp-proxy|daemon)
    [[ "$VERSION" =~ $SEMVER_RE ]] || \
      fail "invalid version '$VERSION' for $MODULE — expected SemVer (e.g. 0.2.0, 1.0.0-beta.1). PEP 440 form (e.g. 0.8.0a1) is accepted only for sdk-py."
    ;;
  *)
    fail "unknown module '$MODULE' — run with no args for usage"
    ;;
esac

# Ensure we're on main and up to date
BRANCH=$(git branch --show-current)
[[ "$BRANCH" == "main" ]] || fail "must be on main branch (currently on $BRANCH)"
git fetch origin main --quiet
LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main)
[[ "$LOCAL" == "$REMOTE" ]] || fail "local main is not up to date with origin — run git pull"

# Ensure working tree is clean
[[ -z "$(git status --porcelain)" ]] || fail "working tree is not clean — commit or stash changes first"

# Go modules don't support build metadata in tags
case "$MODULE" in
  sdk-go|mcp-proxy|daemon)
    [[ "$VERSION" != *+* ]] || fail "Go module versions cannot contain build metadata (+...)"
    ;;
esac

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
  daemon)
    TAG="daemon/v${VERSION}"
    DIR="daemon"
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
    command -v go >/dev/null 2>&1 || fail "go is not installed"
    echo "--- Running Go checks in $DIR"
    (cd "$DIR" && go vet ./... && go test ./...)
    ;;
  mcp-proxy)
    command -v go >/dev/null 2>&1 || fail "go is not installed"
    echo "--- Checking for replace directive in $DIR/go.mod"
    if grep -Eq '^[[:space:]]*replace[[:space:]]' "$DIR/go.mod"; then
      fail "$DIR/go.mod contains a replace directive — remove it and point to a published sdk/go version before releasing"
    fi
    echo "--- Running Go checks in $DIR"
    (cd "$DIR" && go vet ./... && go test ./...)
    ;;
  daemon)
    command -v go >/dev/null 2>&1 || fail "go is not installed"
    echo "--- Checking for replace directive in $DIR/go.mod"
    if grep -Eq '^[[:space:]]*replace[[:space:]]' "$DIR/go.mod"; then
      fail "$DIR/go.mod contains a replace directive — remove it and point to a published sdk/go version before releasing"
    fi
    echo "--- Running Go checks in $DIR"
    # GOWORK=off ensures vet/test resolve from daemon/go.mod (published sdk/go)
    # rather than the in-tree ./sdk/go wired up by the repo-root go.work.
    # -tags=integration is intentionally omitted: integration tests spawn node
    # and uv subprocess emitters that require the full TS/Python SDK setup,
    # which is not guaranteed on a release operator's machine. CI covers those.
    (cd "$DIR" && GOWORK=off go vet ./... && GOWORK=off go test -race ./...)
    ;;
  sdk-ts)
    command -v node >/dev/null 2>&1 || fail "node is not installed"
    command -v pnpm >/dev/null 2>&1 || fail "pnpm is not installed"
    echo "--- Checking package.json version matches"
    PKG_VERSION=$(node -p "require('./$DIR/package.json').version")
    if [[ "$PKG_VERSION" != "$VERSION" ]]; then
      fail "$DIR/package.json version is $PKG_VERSION but releasing $VERSION — update package.json first"
    fi
    echo "--- Running TypeScript checks in $DIR"
    (cd "$DIR" && pnpm install --frozen-lockfile && pnpm run typecheck && pnpm test && pnpm run build)
    ;;
  sdk-py)
    command -v uv >/dev/null 2>&1 || fail "uv is not installed — see https://docs.astral.sh/uv"
    echo "--- Checking pyproject.toml version matches"
    PY_VERSION=$(cd "$DIR" && uv run python -c "
import tomllib, pathlib
p = pathlib.Path('pyproject.toml')
print(tomllib.loads(p.read_text())['project']['version'])
")
    if [[ "$PY_VERSION" != "$VERSION" ]]; then
      fail "$DIR/pyproject.toml version is $PY_VERSION but releasing $VERSION — update pyproject.toml first"
    fi
    echo "--- Running Python checks in $DIR"
    (cd "$DIR" && uv sync --frozen --all-extras && uv run pytest)
    ;;
esac

echo ""
echo "--- All checks passed"
echo ""

PRERELEASE=false
# Strip SemVer build metadata before detecting pre-release: build metadata
# (anything after '+') can legally contain '-', so a naive *-* glob would
# misclassify e.g. 1.2.3+build-4 as a pre-release. Also flag PEP 440
# pre-release suffixes (e.g. 0.8.0a1) which use no '-' separator.
CORE_VERSION="${VERSION%%+*}"
if [[ "$CORE_VERSION" == *-* ]] || [[ "$CORE_VERSION" =~ [0-9]+(a|b|rc)[0-9]+$ ]]; then
  PRERELEASE=true
fi

echo "Will create release:"
echo "  Tag:         $TAG"
echo "  Title:       $MODULE v$VERSION"
[[ "$PRERELEASE" == "true" ]] && echo "  Pre-release: yes"
if [[ "$MODULE" == "mcp-proxy" ]]; then
  echo "  Action:      push tag only; release-mcp-proxy.yml builds binaries and creates the GitHub Release"
elif [[ "$MODULE" == "daemon" ]]; then
  echo "  Action:      push tag only; release-daemon.yml builds binaries and creates the GitHub Release"
else
  echo "  Action:      gh release create"
fi
echo ""

if [[ "$DRY_RUN" == "true" ]]; then
  echo "==> Dry run; not pushing tag or creating release."
  exit 0
fi

read -rp "Proceed? [y/N] " confirm
[[ "$confirm" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 0; }

REPO_URL=$(gh repo view --json url -q '.url')

if [[ "$MODULE" == "mcp-proxy" || "$MODULE" == "daemon" ]]; then
  # release-mcp-proxy.yml / release-daemon.yml owns release creation; we only
  # push the tag. Avoids "release already exists" conflict between this script
  # and the workflow when both call gh release create against the same tag.
  case "$MODULE" in
    mcp-proxy) WORKFLOW="release-mcp-proxy.yml" ;;
    daemon)    WORKFLOW="release-daemon.yml" ;;
  esac
  git tag "$TAG"
  git push origin "$TAG"
  echo ""
  echo "==> Pushed tag $TAG"
  echo "    ${WORKFLOW} builds binaries and creates the GitHub Release."
  echo "    ${REPO_URL}/actions/workflows/${WORKFLOW}"
else
  PRERELEASE_FLAG=()
  [[ "$PRERELEASE" == "true" ]] && PRERELEASE_FLAG=("--prerelease")
  gh release create "$TAG" --title "$MODULE v$VERSION" --generate-notes "${PRERELEASE_FLAG[@]}"
  echo ""
  echo "==> Released $MODULE v$VERSION"
  echo "    ${REPO_URL}/releases/tag/$TAG"
fi
