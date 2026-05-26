// Sync canonical spec versions from spec/v<X.Y.Z>/spec.md into the
// Starlight content collection, so each version is published at
// /spec/v<X.Y.Z>/ on the live site. Per ADR-0021 D4 this is the
// lightweight site-build step that fulfils the per-version URL contract.
//
// Run automatically via the predev / prebuild npm scripts. Generated
// files are gitignored; the spec sources under spec/v*/spec.md remain
// the single source of truth.

import {
  readFileSync,
  writeFileSync,
  readdirSync,
  mkdirSync,
  existsSync,
  rmSync,
} from "node:fs";
import { join, dirname, posix } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { execFileSync } from "node:child_process";

const GITHUB_BLOB = "https://github.com/agent-receipts/ar/blob";

// Rewrite repo-relative markdown links to absolute GitHub URLs so the
// rendered site can resolve them. The source spec uses relative paths
// like `../schema/foo.json` that resolve fine inside the repo, but
// `/spec/v0.4.0/` on the site has no sibling `schema/` or `taxonomy/`
// routes — those artifacts are not (and per ADR-0021 shouldn't be)
// re-served under the spec page tree. GitHub is the canonical viewer
// for the artifact files; pointing there keeps a single source of
// truth.
//
// Links are pinned to the version's release tag (`spec-v<X.Y.Z>`), not
// `main`: a permanent per-version page must reference the schema and
// taxonomy as they were at that release, so a later spec release can't
// retroactively change what an older page links to (ADR-0021 D2).
export function rewriteRelativeLinks(body, version) {
  const baseDir = `spec/${version}`;
  const ref = `spec-${version}`;
  return body.replace(/\]\((\.{1,2}\/[^)\s#]+)(#[^)]*)?\)/g, (m, rel, anchor) => {
    const repoPath = posix.normalize(`${baseDir}/${rel}`);
    return `](${GITHUB_BLOB}/${ref}/${repoPath}${anchor || ""})`;
  });
}

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..");
const specRoot = join(repoRoot, "spec");
const outDir = join(repoRoot, "site", "src", "content", "docs", "spec");

const VERSION_RE = /^v(\d+)\.(\d+)\.(\d+)$/;

function semverKey(name) {
  const m = name.match(VERSION_RE);
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

function semverCompare(a, b) {
  const A = semverKey(a);
  const B = semverKey(b);
  for (let i = 0; i < 3; i++) {
    if (A[i] !== B[i]) return A[i] - B[i];
  }
  return 0;
}

// Parse the output of `git tag -l` into the set of released version names
// ("v0.4.0", …). Only exact spec-v<X.Y.Z> tags count: prerelease tags
// (spec-v0.4.0-rc1) and other artifacts (context-v1) have no matching
// spec/v<X.Y.Z>/ directory and must not gate publishing. Kept pure (no git
// call) so it is unit-testable.
export function parseReleasedTags(tagOutput) {
  const released = new Set();
  for (const line of tagOutput.split("\n")) {
    const m = line.trim().match(/^spec-(v\d+\.\d+\.\d+)$/);
    if (m) released.add(m[1]);
  }
  return released;
}

// The release signal for a spec version is a pushed `spec-v<X.Y.Z>` git
// tag (ADR-0021 D4), not the mere presence of a spec/v<X.Y.Z>/ directory on
// main. Return the set of version names ("v0.4.0", …) that have such a tag.
// Requires tag history: a normal local clone has it; CI must check out with
// fetch-depth: 0 (or fetch-tags: true). If git is unavailable we return an
// empty set rather than crash — nothing publishes, which is the safe
// failure mode (a missing page is recoverable; a wrongly-pinned one is not).
function releasedVersions() {
  let out;
  try {
    out = execFileSync("git", ["tag", "-l", "spec-v*"], {
      cwd: repoRoot,
      encoding: "utf8",
    });
  } catch (err) {
    console.error(`sync-spec: unable to read git tags: ${err.message}`);
    return new Set();
  }
  return parseReleasedTags(out);
}

// A version is published — appearing in the index, the per-version routes,
// and the `latest` computation — only when both its spec.md exists and a
// matching spec-v<X.Y.Z> release tag has been pushed (ADR-0021 D4). A
// directory without spec.md is malformed; a directory without a tag is
// in-flight (drafted on a feature branch, or merged ahead of its release
// tag). Either case is silently ignored, so we never publish a page — or a
// link to one — before the version is actually released.
function main() {
  const released = releasedVersions();
  const versions = readdirSync(specRoot, { withFileTypes: true })
    .filter((d) => d.isDirectory() && VERSION_RE.test(d.name))
    .map((d) => d.name)
    .filter((v) => existsSync(join(specRoot, v, "spec.md")))
    .filter((v) => released.has(v))
    .sort(semverCompare);

  if (versions.length === 0) {
    console.warn(
      "sync-spec: no released spec versions found — a spec/v<X.Y.Z>/ directory " +
        "publishes only once a matching spec-v<X.Y.Z> git tag exists; " +
        "skipping /spec/ page generation",
    );
  } else {
    writeSpecPages(versions);
  }

  publishContexts();
}

function writeSpecPages(versions) {
  if (existsSync(outDir)) rmSync(outDir, { recursive: true });
  mkdirSync(outDir, { recursive: true });

  const latest = versions[versions.length - 1];

  for (const v of versions) {
    const src = join(specRoot, v, "spec.md");
    // Strip a leading H1 if present — Starlight already renders the page
    // title from frontmatter, so leaving the spec's own H1 in place would
    // produce two stacked headings.
    const raw = readFileSync(src, "utf8").replace(/^#\s+.+\n+/, "");
    const body = rewriteRelativeLinks(raw, v);
    // Force the route slug to preserve the dots in the semver — Starlight's
    // default slug derivation strips them ("v0.4.0" → "v040"), but ADR-0021
    // D2 commits to /spec/v<X.Y.Z>/ as the literal canonical URL.
    const front = [
      "---",
      `title: Agent Receipts Protocol — Specification ${v}`,
      `description: Full text of the Agent Receipts Protocol Specification at ${v}.`,
      `slug: spec/${v}`,
      "---",
      "",
      "",
    ].join("\n");
    writeFileSync(join(outDir, `${v}.md`), front + body);
  }

  // /spec/latest/ — the mutable alias from ADR-0021 D2. Implemented as a
  // meta-refresh redirect page so the URL bar reflects the actual version
  // the reader lands on (auditors should be citing /spec/v<X.Y.Z>/, not
  // /spec/latest/). No-JS / pre-redirect users still see a plain link.
  const latestPage = [
    "---",
    `title: Agent Receipts Protocol — Specification (latest)`,
    `description: Mutable alias for the current released spec version (${latest}).`,
    `slug: spec/latest`,
    "head:",
    "  - tag: meta",
    "    attrs:",
    "      http-equiv: refresh",
    `      content: "0; url=/spec/${latest}/"`,
    "---",
    "",
    `Redirecting to the latest released spec version, [${latest}](/spec/${latest}/).`,
    "",
    `If you are citing the spec, please use the [permanent per-version URL](/spec/${latest}/) directly rather than this alias.`,
    "",
  ].join("\n");
  writeFileSync(join(outDir, "latest.md"), latestPage);

  const indexLines = [
    "---",
    "title: Agent Receipts Protocol — Spec Versions",
    "description: Index of released Agent Receipts Protocol Specification versions.",
    "---",
    "",
    "Released spec versions. Each URL below is permanent (per [ADR-0021](https://github.com/agent-receipts/ar/blob/main/docs/adr/0021-spec-and-context-versioning.md)) and links to the full text of that version.",
    "",
    "| Version | Status | Link |",
    "| --- | --- | --- |",
  ];
  for (const v of versions) {
    const status = v === latest ? "**current**" : "released";
    indexLines.push(`| ${v} | ${status} | [/spec/${v}/](/spec/${v}/) |`);
  }
  indexLines.push("");
  writeFileSync(join(outDir, "index.md"), indexLines.join("\n"));

  console.log(
    `sync-spec: wrote ${versions.length} version page(s) (${versions.join(", ")}); current = ${latest}`,
  );
}

// --- JSON-LD context publishing ---------------------------------------
//
// Every Agent Receipt's @context array references
// https://agentreceipts.ai/context/v<N> (no extension, no trailing slash).
// Per ADR-0021 D3 each context version is published at its permanent URL.
//
// Static-asset publishing: copy spec/context/v<N>/context.jsonld into
// site/public/context/v<N>. Astro serves site/public/* verbatim from the
// site root, so a file at site/public/context/v1 lands at /context/v1.
// The file has no extension to match the URL receipts already reference;
// JSON-LD validators parse on content, not MIME.

function publishContexts() {
  const CONTEXT_VERSION_RE = /^v(\d+)$/;
  const contextSrcRoot = join(specRoot, "context");
  const contextOutRoot = join(repoRoot, "site", "public", "context");

  if (!existsSync(contextSrcRoot)) return;

  const contextVersions = readdirSync(contextSrcRoot, { withFileTypes: true })
    .filter((d) => d.isDirectory() && CONTEXT_VERSION_RE.test(d.name))
    .map((d) => d.name)
    .filter((v) => existsSync(join(contextSrcRoot, v, "context.jsonld")))
    .sort((a, b) => Number(a.slice(1)) - Number(b.slice(1)));

  if (existsSync(contextOutRoot)) rmSync(contextOutRoot, { recursive: true });
  if (contextVersions.length > 0) {
    mkdirSync(contextOutRoot, { recursive: true });
    for (const v of contextVersions) {
      const src = join(contextSrcRoot, v, "context.jsonld");
      const dst = join(contextOutRoot, v);
      writeFileSync(dst, readFileSync(src, "utf8"));
    }
    console.log(
      `sync-spec: published ${contextVersions.length} JSON-LD context(s) (${contextVersions.join(", ")}) to /context/`,
    );
  }
}

// Run the publishing pipeline only when invoked directly (predev / prebuild /
// `pnpm sync-spec`). Importing this module — e.g. from the unit tests — must
// not touch the filesystem or shell out to git.
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
