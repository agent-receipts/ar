/**
 * Thin fire-and-forget emitter for the agent-receipts daemon's local Unix
 * domain socket. Emit forwards a tool-call frame to the daemon, which
 * captures peer credentials, canonicalises (RFC 8785), signs (Ed25519), and
 * persists the receipt. The emitter does NO crypto, NO canonicalisation, and
 * holds NO chain state — those moved to the daemon per ADR-0010 (daemon
 * process separation, 2026-05-03).
 *
 * Concurrency: emit() is safe to call from multiple async contexts on a
 * single Emitter instance. The internal write is serialised so concurrent
 * calls cannot interleave bytes on the same socket connection.
 *
 * Failure model: emit() MUST NOT block the agent on the daemon. When the
 * socket is unreachable (daemon not started, socket file missing, broken
 * connection) emit() logs a debug-level drop and returns null within
 * milliseconds. Returns an error only for caller bugs (missing channel,
 * missing tool name, invalid decision, invalid JSON, emitter already closed)
 * — situations a retry could not fix.
 */

import { randomUUID } from "node:crypto";
import { createConnection } from "node:net";
import { platform } from "node:os";
import { join } from "node:path";

/** Maximum allowed frame size in bytes (1 MiB). Must match daemon's socket.MaxFrameSize. */
export const MAX_FRAME_SIZE = 1 << 20;

/** Wire format version. Must match daemon's pipeline.SupportedFrameVersion. */
export const SUPPORTED_FRAME_VERSION = "1";

/** Dial timeout in milliseconds — caps how long emit() blocks reaching the daemon. */
const DIAL_TIMEOUT_MS = 25;

/** Write deadline in milliseconds — caps how long a single frame write can block. */
const WRITE_TIMEOUT_MS = 100;

/** Valid decision values (must be lowercase to match the wire format). */
const VALID_DECISIONS = new Set(["allowed", "denied", "pending"]);

/** Tool identifies the tool the agent invoked. server is optional. */
export interface EmitTool {
	/** Optional server qualifier. When absent the action type is "channel.name". */
	server?: string;
	/** Tool name. Required and non-empty. */
	name: string;
}

/** One tool invocation to forward to the daemon. */
export interface EmitEvent {
	/** Stable channel identifier (required, non-empty). */
	channel: string;
	tool: EmitTool;
	/**
	 * Raw JSON string for the tool input. Forwarded verbatim — NOT
	 * re-serialised. Must be valid JSON if provided.
	 */
	input?: string;
	/**
	 * Raw JSON string for the tool output. Forwarded verbatim — NOT
	 * re-serialised. Must be valid JSON if provided.
	 */
	output?: string;
	/** Human-readable error message when the tool call failed. */
	error?: string;
	/** Policy decision for this call. */
	decision: "allowed" | "denied" | "pending";
}

/** Options for constructing an Emitter. */
export interface EmitterOptions {
	/**
	 * Override the daemon socket path. When unset, resolved from the
	 * AGENTRECEIPTS_SOCKET env var then the per-OS default.
	 */
	socketPath?: string;
	/**
	 * Supply a host session identifier instead of generating a fresh UUID v4.
	 * Per ADR-0010 OQ4, use the host's session id when available so a single
	 * agent loop produces one logical session. An empty string is ignored and
	 * a UUID is generated instead.
	 */
	sessionId?: string;
	/**
	 * Logger function for debug-level drop diagnostics. Defaults to no-op.
	 * Pass `console.debug` or a structured logger to surface drops.
	 */
	debugLog?: (message: string, attrs: Record<string, string>) => void;
}

/** Wire frame sent to the daemon (field names must match exactly). */
interface WireFrame {
	v: string;
	ts_emit: string;
	session_id: string;
	channel: string;
	tool: {
		server?: string;
		name: string;
	};
	input?: unknown;
	output?: unknown;
	error?: string;
	decision: string;
}

/**
 * Returns the per-OS default path for the daemon socket.
 *
 * Resolution order:
 * 1. AGENTRECEIPTS_SOCKET environment variable (any platform).
 * 2. macOS: $TMPDIR/agentreceipts/events.sock (TMPDIR defaults to /tmp).
 * 3. Linux with $XDG_RUNTIME_DIR set: $XDG_RUNTIME_DIR/agentreceipts/events.sock.
 * 4. Linux fallback: /run/agentreceipts/events.sock.
 * 5. Other platforms: empty string — pass socketPath explicitly.
 */
export function defaultSocketPath(): string {
	const envPath = process.env.AGENTRECEIPTS_SOCKET;
	if (envPath) {
		return envPath;
	}
	const os = platform();
	if (os === "darwin") {
		const tmpdir = process.env.TMPDIR ?? "/tmp";
		return join(tmpdir, "agentreceipts", "events.sock");
	}
	if (os === "linux") {
		const xdgRuntime = process.env.XDG_RUNTIME_DIR;
		if (xdgRuntime) {
			return join(xdgRuntime, "agentreceipts", "events.sock");
		}
		return "/run/agentreceipts/events.sock";
	}
	return "";
}

/**
 * RFC3339Nano timestamp: Node's toISOString() produces milliseconds only
 * ("2026-05-07T12:34:56.789Z"). Extend to nanosecond-resolution zeros to
 * match Go's time.RFC3339Nano format ("2026-05-07T12:34:56.789000000Z").
 */
function rfc3339Nano(): string {
	return new Date().toISOString().replace(/\.(\d{3})Z$/, ".$1000000Z");
}

/**
 * Emitter is the daemon-socket client. Construct with `new Emitter(...)`,
 * fire events with `emit()`, release the socket with `close()`.
 *
 * The session_id is generated once at construction (UUID v4) and remains
 * stable for the lifetime of this instance — including across daemon
 * reconnects (ADR-0010 OQ4).
 *
 * Construction does NOT dial the daemon — dialing is lazy on the first
 * `emit()` so that constructing an emitter cannot fail because the daemon
 * happens to be down at the moment.
 */
export class Emitter {
	readonly sessionId: string;

	private readonly socketPath: string;
	private readonly debugLog: (
		message: string,
		attrs: Record<string, string>,
	) => void;

	private conn: ReturnType<typeof createConnection> | null = null;
	private closed = false;
	// Serialise writes so concurrent emit() calls cannot interleave bytes.
	private writeQueue: Promise<void> = Promise.resolve();

	constructor(options: EmitterOptions = {}) {
		const socketPath = options.socketPath ?? defaultSocketPath();
		if (!socketPath) {
			throw new Error(
				`emitter: no default socket path on ${platform()}; set AGENTRECEIPTS_SOCKET or pass socketPath`,
			);
		}
		this.socketPath = socketPath;
		this.sessionId = options.sessionId?.trim()
			? options.sessionId
			: randomUUID();
		this.debugLog = options.debugLog ?? (() => {});
	}

	/**
	 * Emit sends one event to the daemon. Returns null even when the daemon
	 * is unreachable: dial and write failures are logged at debug level and
	 * the conn is reset for re-dial on the next emit(). Returns an Error only
	 * for caller bugs (emitter closed, oversized frame, invalid event fields,
	 * malformed input/output JSON) — situations a retry could not fix.
	 */
	async emit(ev: EmitEvent): Promise<Error | null> {
		// Validate caller-supplied fields first (before acquiring the write lock).
		if (this.closed) {
			return new Error("emitter: closed");
		}
		if (!ev.channel) {
			return new Error("emitter: missing channel");
		}
		if (!ev.tool.name) {
			return new Error("emitter: missing tool.name");
		}
		if (!VALID_DECISIONS.has(ev.decision)) {
			return new Error(
				`emitter: invalid decision "${ev.decision}" (want allowed|denied|pending)`,
			);
		}
		if (ev.input !== undefined && !isValidJson(ev.input)) {
			return new Error("emitter: input is not valid JSON");
		}
		if (ev.output !== undefined && !isValidJson(ev.output)) {
			return new Error("emitter: output is not valid JSON");
		}

		const wireFrame: WireFrame = {
			v: SUPPORTED_FRAME_VERSION,
			ts_emit: rfc3339Nano(),
			session_id: this.sessionId,
			channel: ev.channel,
			tool: {
				...(ev.tool.server ? { server: ev.tool.server } : {}),
				name: ev.tool.name,
			},
			...(ev.input !== undefined ? { input: parseJsonRaw(ev.input) } : {}),
			...(ev.output !== undefined ? { output: parseJsonRaw(ev.output) } : {}),
			...(ev.error ? { error: ev.error } : {}),
			decision: ev.decision,
		};

		const body = Buffer.from(JSON.stringify(wireFrame), "utf8");
		if (body.length > MAX_FRAME_SIZE) {
			return new Error(
				`emitter: frame too large: ${body.length} bytes (max ${MAX_FRAME_SIZE})`,
			);
		}

		// Serialise into the write queue so concurrent calls do not interleave.
		return this.enqueueWrite(body);
	}

	/**
	 * Close releases the underlying connection. After Close, subsequent emit()
	 * calls return an Error. Safe to call multiple times.
	 */
	close(): void {
		if (this.closed) {
			return;
		}
		this.closed = true;
		if (this.conn !== null) {
			this.conn.destroy();
			this.conn = null;
		}
	}

	/**
	 * Enqueue a serialised write onto the sequential write queue. All calls
	 * run in order; a failed write drops and resets the connection.
	 */
	private enqueueWrite(body: Buffer): Promise<Error | null> {
		const next = this.writeQueue.then(() => this.doWrite(body));
		// Keep the queue moving even if doWrite rejects (it shouldn't, but guard it).
		this.writeQueue = next.then(
			() => {},
			() => {},
		);
		return next;
	}

	/**
	 * doWrite dials if needed, then writes the framed body. Returns null on
	 * success, logs and returns null on transient errors (fire-and-forget).
	 *
	 * If the write fails on a previously-established connection (e.g. the
	 * daemon restarted), the dead connection is discarded and one transparent
	 * re-dial + re-write is attempted before giving up.
	 */
	private async doWrite(body: Buffer): Promise<Error | null> {
		const dialErr = await this.dialIfNeeded();
		if (dialErr !== null) {
			this.logDrop("dial", dialErr);
			return null;
		}

		const writeErr = await this.writeFrame(body);
		if (writeErr !== null) {
			// Discard the dead connection.
			this.conn?.destroy();
			this.conn = null;

			// One transparent retry: re-dial and try again.
			const redialErr = await this.dialIfNeeded();
			if (redialErr !== null) {
				this.logDrop("dial", redialErr);
				return null;
			}
			const retryErr = await this.writeFrame(body);
			if (retryErr !== null) {
				this.logDrop("write", retryErr);
				// TypeScript narrows this.conn to null after the earlier assignment;
				// re-dial may have set it to a new socket, so capture before clearing.
				const deadConn = this.conn as ReturnType<
					typeof createConnection
				> | null;
				this.conn = null;
				deadConn?.destroy();
			}
		}
		return null;
	}

	/** Dial the daemon socket if not already connected. */
	private dialIfNeeded(): Promise<Error | null> {
		if (this.conn !== null) {
			return Promise.resolve(null);
		}
		return new Promise((resolve) => {
			const timer = setTimeout(() => {
				socket.destroy();
				resolve(new Error(`dial timeout after ${DIAL_TIMEOUT_MS}ms`));
			}, DIAL_TIMEOUT_MS);

			const socket = createConnection({ path: this.socketPath }, () => {
				clearTimeout(timer);
				this.conn = socket;
				resolve(null);
			});

			socket.once("error", (err) => {
				clearTimeout(timer);
				resolve(err);
			});
		});
	}

	/** Write a 4-byte big-endian length prefix followed by the body. */
	private writeFrame(body: Buffer): Promise<Error | null> {
		return new Promise((resolve) => {
			if (this.conn === null) {
				resolve(new Error("no connection"));
				return;
			}
			const conn = this.conn;

			const header = Buffer.allocUnsafe(4);
			header.writeUInt32BE(body.length, 0);
			const frame = Buffer.concat([header, body]);

			const timer = setTimeout(() => {
				resolve(new Error(`write timeout after ${WRITE_TIMEOUT_MS}ms`));
			}, WRITE_TIMEOUT_MS);

			conn.write(frame, (err) => {
				clearTimeout(timer);
				if (err) {
					resolve(err);
				} else {
					resolve(null);
				}
			});
		});
	}

	private logDrop(stage: string, err: Error): void {
		this.debugLog("agent-receipts emitter dropped event", {
			stage,
			socket: this.socketPath,
			err: err.message,
		});
	}
}

/** Returns true if the string is syntactically valid JSON. */
function isValidJson(s: string): boolean {
	try {
		JSON.parse(s);
		return true;
	} catch {
		return false;
	}
}

/**
 * Parse a raw JSON string into a value that will be serialised verbatim by
 * JSON.stringify. Using JSON.parse ensures the value round-trips correctly
 * without double-encoding.
 */
function parseJsonRaw(s: string): unknown {
	return JSON.parse(s);
}
