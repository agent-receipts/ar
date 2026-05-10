#!/usr/bin/env node

/**
 * Test helper: Emit a frame using the TypeScript SDK.
 * Usage: node emit_ts.mjs <socket_path> <session_id> <channel> <tool_name> <decision>
 *
 * Must be run from the repo root.
 */

import { Emitter } from "../../sdk/ts/dist/emitter.js";
import process from "process";

const [socketPath, sessionId, channel, toolName, decision] = process.argv.slice(2);

if (!socketPath || !sessionId || !channel || !toolName || !decision) {
  console.error("Usage: emit_ts.mjs <socket> <session> <channel> <tool> <decision>");
  process.exit(1);
}

const emitter = new Emitter({
  socketPath,
  sessionId,
});

const result = await emitter.emit({
  channel,
  tool: { name: toolName },
  decision,
});

process.exit(result ? 0 : 1);
