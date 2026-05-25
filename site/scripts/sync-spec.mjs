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
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

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

const versions = readdirSync(specRoot, { withFileTypes: true })
  .filter((d) => d.isDirectory() && VERSION_RE.test(d.name))
  .map((d) => d.name)
  .sort(semverCompare);

if (versions.length === 0) {
  console.error("sync-spec: no spec/v<X.Y.Z>/ directories found");
  process.exit(1);
}

if (existsSync(outDir)) rmSync(outDir, { recursive: true });
mkdirSync(outDir, { recursive: true });

const latest = versions[versions.length - 1];

for (const v of versions) {
  const src = join(specRoot, v, "spec.md");
  if (!existsSync(src)) {
    console.warn(`sync-spec: ${v}/spec.md missing, skipping`);
    continue;
  }
  // Strip a leading H1 if present — Starlight already renders the page
  // title from frontmatter, so leaving the spec's own H1 in place would
  // produce two stacked headings.
  const body = readFileSync(src, "utf8").replace(/^#\s+.+\n+/, "");
  const front = [
    "---",
    `title: Agent Receipts Protocol — Specification ${v}`,
    `description: Full text of the Agent Receipts Protocol Specification at ${v}.`,
    "---",
    "",
    "",
  ].join("\n");
  writeFileSync(join(outDir, `${v}.md`), front + body);
}

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
