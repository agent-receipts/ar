import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalUrl, withCanonical } from "./sync-blog.mjs";

test("canonicalUrl maps a post slug to its agentreceipts.ai URL", () => {
  assert.equal(
    canonicalUrl("daemon-process-separation.mdx"),
    "https://agentreceipts.ai/blog/daemon-process-separation/",
  );
  assert.equal(canonicalUrl("post.md"), "https://agentreceipts.ai/blog/post/");
});

test("canonicalUrl maps the index to the blog root", () => {
  assert.equal(canonicalUrl("index.mdx"), "https://agentreceipts.ai/blog/");
});

test("withCanonical injects a canonical link into frontmatter head", () => {
  const input = `---\ntitle: A Post\ndescription: Hi\n---\n\nBody.\n`;
  const out = withCanonical(input, "a-post.mdx");
  assert.match(out, /^---\ntitle: A Post\ndescription: Hi\nhead:\n/);
  assert.match(
    out,
    /rel: canonical\n {6}href: https:\/\/agentreceipts\.ai\/blog\/a-post\/\n---/,
  );
  assert.ok(out.endsWith("Body.\n"), "body is preserved");
});

test("withCanonical leaves a self-canonicalizing post untouched", () => {
  const input = `---\ntitle: A Post\nhead:\n  - tag: link\n    attrs:\n      rel: canonical\n      href: https://agentreceipts.ai/blog/a-post/\n---\n\nBody.\n`;
  assert.equal(withCanonical(input, "a-post.mdx"), input);
});

test("withCanonical leaves content without frontmatter untouched", () => {
  const input = "no frontmatter here\n";
  assert.equal(withCanonical(input, "x.mdx"), input);
});
