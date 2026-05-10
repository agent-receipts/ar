#!/usr/bin/env node

/**
 * Test helper: Emit a frame using the TypeScript SDK.
 * Usage: node emit_ts.mjs <socket_path> <session_id> <channel> <tool_name> <decision>
 *
 * Must be run from the repo root with sdk/ts built (run: pnpm -C sdk/ts build).
 */

import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { existsSync } from "fs";
import process from "process";

const __dirname = dirname(fileURLToPath(import.meta.url));
const distPath = join(__dirname, "..", "..", "sdk", "ts", "dist", "emitter.js");

if (!existsSync(distPath)) {
  console.error(
    `TypeScript SDK dist/ not found at ${distPath}. Run: pnpm -C sdk/ts build`
  );
  process.exit(1);
}

import { Emitter } from "../../sdk/ts/dist/emitter.js";

const [socketPath, sessionId, channel, toolName, decision] = process.argv.slice(2);

if (!socketPath || !sessionId || !channel || !toolName || !decision) {
  console.error("Usage: emit_ts.mjs <socket> <session> <channel> <tool> <decision>");
  process.exit(1);
}

const emitter = new Emitter({
  socketPath,
  sessionId,
  debugLog: (message, attrs) => {
    console.error(`${message}:`, attrs);
  },
});

const result = await emitter.emit({
  channel,
  tool: { name: toolName },
  decision,
});

if (result instanceof Error) {
  console.error(`Emit failed: ${result.message}`);
  process.exit(1);
}

process.exit(0);
