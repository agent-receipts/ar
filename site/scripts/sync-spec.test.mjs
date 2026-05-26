import { test } from "node:test";
import assert from "node:assert/strict";

import { parseReleasedTags, rewriteRelativeLinks } from "./sync-spec.mjs";

const BLOB = "https://github.com/agent-receipts/ar/blob";

test("parseReleasedTags keeps exact spec-vX.Y.Z tags", () => {
  const set = parseReleasedTags("spec-v0.4.0\nspec-v0.5.0\n");
  assert.deepEqual([...set].sort(), ["v0.4.0", "v0.5.0"]);
});

test("parseReleasedTags ignores prereleases, other artifacts, and noise", () => {
  const tags = [
    "spec-v0.4.0",
    "spec-v0.4.0-rc1", // prerelease — no matching spec/v<X.Y.Z>/ dir
    "spec-v1.2", // not full semver
    "context-v1", // different artifact
    "spec-vX.Y.Z", // non-numeric
    "", // blank line
    "  spec-v0.9.0  ", // surrounding whitespace tolerated
  ].join("\n");
  assert.deepEqual([...parseReleasedTags(tags)].sort(), ["v0.4.0", "v0.9.0"]);
});

test("parseReleasedTags returns an empty set for empty output", () => {
  assert.equal(parseReleasedTags("").size, 0);
});

test("rewriteRelativeLinks pins cross-references to the version's release tag", () => {
  const out = rewriteRelativeLinks(
    "See [schema](../schema/agent-receipt.schema.json).",
    "v0.4.0",
  );
  assert.equal(
    out,
    `See [schema](${BLOB}/spec-v0.4.0/spec/schema/agent-receipt.schema.json).`,
  );
});

test("rewriteRelativeLinks preserves anchors and normalizes ..", () => {
  const out = rewriteRelativeLinks(
    "[t](../spec/taxonomy/action-types.json#risk)",
    "v0.5.0",
  );
  assert.equal(
    out,
    `[t](${BLOB}/spec-v0.5.0/spec/spec/taxonomy/action-types.json#risk)`,
  );
});

test("rewriteRelativeLinks leaves absolute links untouched", () => {
  const out = rewriteRelativeLinks(
    "[home](https://agentreceipts.ai) and [rel](./x.json)",
    "v0.4.0",
  );
  assert.equal(
    out,
    `[home](https://agentreceipts.ai) and [rel](${BLOB}/spec-v0.4.0/spec/v0.4.0/x.json)`,
  );
});
