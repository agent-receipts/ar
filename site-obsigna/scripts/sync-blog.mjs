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

function main() {
  if (!existsSync(srcDir)) {
    console.warn(`sync-blog: source directory not found: ${srcDir}`);
    return;
  }

  if (existsSync(outDir)) rmSync(outDir, { recursive: true });
  mkdirSync(outDir, { recursive: true });

  const files = readdirSync(srcDir).filter((f) => f.endsWith(".mdx") || f.endsWith(".md"));
  for (const file of files) {
    writeFileSync(join(outDir, file), readFileSync(join(srcDir, file)));
  }

  console.log(`sync-blog: synced ${files.length} file(s) from site/blog`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main();
}
