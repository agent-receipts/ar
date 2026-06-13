// Sync blog posts from site/src/content/docs/blog/ into this site's content
// collection so obsigna.dev/blog/ mirrors agentreceipts.ai/blog/.
//
// The blog source of truth lives in site/. Generated files here are
// gitignored; do not edit them directly.
//
// Runs automatically via the predev / prebuild npm scripts.

import {
  readdirSync,
  readFileSync,
  writeFileSync,
  mkdirSync,
  existsSync,
  rmSync,
} from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const srcDir = join(here, "..", "..", "site", "src", "content", "docs", "blog");
const outDir = join(here, "..", "src", "content", "docs", "blog");

// agentreceipts.ai is the canonical home for the blog. obsigna.dev mirrors it,
// so each mirrored page points its canonical URL back at the original to avoid
// duplicate-content penalties across the two domains.
const CANONICAL_BASE = "https://agentreceipts.ai/blog/";

export function canonicalUrl(file) {
  const slug = file.replace(/\.mdx?$/, "");
  return slug === "index" ? CANONICAL_BASE : `${CANONICAL_BASE}${slug}/`;
}

// Inject a `rel="canonical"` link into the page's frontmatter `head`, unless the
// source already declares one (some posts self-canonicalize to agentreceipts.ai
// at the source, which is already correct once mirrored).
export function withCanonical(content, file) {
  const fm = content.match(/^---\n([\s\S]*?)\n---/);
  if (!fm) return content;
  if (/rel:\s*canonical/.test(fm[1])) return content;
  const inject = [
    "head:",
    "  - tag: link",
    "    attrs:",
    "      rel: canonical",
    `      href: ${canonicalUrl(file)}`,
  ].join("\n");
  return content.replace(fm[0], () => `---\n${fm[1]}\n${inject}\n---`);
}

function main() {
  if (!existsSync(srcDir)) {
    console.warn(`sync-blog: source directory not found: ${srcDir}`);
    return;
  }

  if (existsSync(outDir)) rmSync(outDir, { recursive: true });
  mkdirSync(outDir, { recursive: true });

  const files = readdirSync(srcDir).filter((f) => f.endsWith(".mdx") || f.endsWith(".md"));
  for (const file of files) {
    const content = readFileSync(join(srcDir, file), "utf8");
    writeFileSync(join(outDir, file), withCanonical(content, file));
  }

  console.log(`sync-blog: synced ${files.length} file(s) from site/blog`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main();
}
