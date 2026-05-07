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
import { createConnection, type Socket } from "node:net";
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
	 * Raw JSON string for the tool input. Forwarded verbatim — the exact
	 * bytes are embedded in the frame without re-parsing or reformatting,
	 * so the daemon's RFC 8785 canonicalisation sees the same bytes the
	 * caller produced. Must be valid JSON if provided.
	 */
	input?: string;
	/**
	 * Raw JSON string for the tool output. Forwarded verbatim — the exact
	 * bytes are embedded in the frame without re-parsing or reformatting,
	 * so the daemon's RFC 8785 canonicalisation sees the same bytes the
	 * caller produced. Must be valid JSON if provided.
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

/**
 * Wire frame sent to the daemon (field names must match exactly).
 *
 * input/output are sentinel placeholder strings during JSON.stringify; the
 * encoded sentinels are then replaced with the caller's raw JSON bytes so
 * the daemon hashes the verbatim input/output the caller produced.
 */
interface WireFrame {
	v: string;
	ts_emit: string;
	session_id: string;
	channel: string;
	tool: {
		server?: string;
		name: string;
	};
	input?: string;
	output?: string;
	error?: string;
	decision: string;
}

/**
 * Sentinel placeholders for verbatim input/output pass-through. These strings
 * are placed into the frame in the input/output slots, then JSON.stringify
 * encodes them as JSON string literals (with surrounding quotes). After
 * stringification we splice the encoded sentinel out and splice the caller's
 * raw JSON bytes in, so the daemon's RFC 8785 canonicalisation sees the
 * exact bytes the caller produced (no whitespace normalisation, no key
 * reordering, no number reformatting).
 *
 * Sentinels include random hex so they cannot collide with caller content
 * even if the caller deliberately tries to forge them.
 */
const RAW_INPUT_SENTINEL = `__AR_RAW_INPUT_${randomUUID()}__`;
const RAW_OUTPUT_SENTINEL = `__AR_RAW_OUTPUT_${randomUUID()}__`;

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

	private conn: Socket | null = null;
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
		const trimmedSessionId = options.sessionId?.trim();
		this.sessionId = trimmedSessionId ? trimmedSessionId : randomUUID();
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

		// Build the frame with sentinel placeholder strings for input/output.
		// JSON.stringify will encode these as JSON string literals; we then
		// splice the raw caller-supplied JSON bytes in so the daemon hashes
		// the exact bytes the caller produced (verbatim pass-through).
		const wireFrame: WireFrame = {
			v: SUPPORTED_FRAME_VERSION,
			ts_emit: rfc3339Nano(),
			session_id: this.sessionId,
			channel: ev.channel,
			tool: {
				...(ev.tool.server ? { server: ev.tool.server } : {}),
				name: ev.tool.name,
			},
			...(ev.input !== undefined ? { input: RAW_INPUT_SENTINEL } : {}),
			...(ev.output !== undefined ? { output: RAW_OUTPUT_SENTINEL } : {}),
			...(ev.error ? { error: ev.error } : {}),
			decision: ev.decision,
		};

		let serialised = JSON.stringify(wireFrame);
		if (ev.input !== undefined) {
			// Match "input":"<sentinel>" so the replacement can never target
			// another field even if the sentinel appears elsewhere in the frame.
			// Use a function replacement so '$' sequences in ev.input are not
			// interpreted as String.prototype.replace special patterns.
			const input = ev.input;
			serialised = serialised.replace(
				`"input":${JSON.stringify(RAW_INPUT_SENTINEL)}`,
				() => `"input":${input}`,
			);
		}
		if (ev.output !== undefined) {
			const output = ev.output;
			serialised = serialised.replace(
				`"output":${JSON.stringify(RAW_OUTPUT_SENTINEL)}`,
				() => `"output":${output}`,
			);
		}
		const body = Buffer.from(serialised, "utf8");
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
	 * re-dial + re-write is attempted before giving up. The transparent
	 * retry exists because Node buffers writes optimistically: a write that
	 * "succeeded" earlier may turn out to have been on a stale socket the
	 * kernel only reports as dead on the next attempt, so the FIRST emit
	 * after a daemon restart would otherwise be lost without anyone seeing
	 * a transient failure.
	 */
	private async doWrite(body: Buffer): Promise<Error | null> {
		const dialErr = await this.dialIfNeeded();
		if (dialErr !== null) {
			this.logDrop("dial", dialErr);
			return null;
		}

		const conn = this.conn;
		if (conn === null) {
			// Closed between dial and write; drop silently.
			return null;
		}

		const writeErr = await this.writeFrame(conn, body);
		if (writeErr === null) {
			return null;
		}

		// First write failed: the conn is dead. Discard it, then attempt
		// one transparent re-dial + re-write.
		this.discardConn(conn);

		const redialErr = await this.dialIfNeeded();
		if (redialErr !== null) {
			this.logDrop("dial", redialErr);
			return null;
		}
		const newConn = this.conn;
		if (newConn === null) {
			return null;
		}
		const retryErr = await this.writeFrame(newConn, body);
		if (retryErr !== null) {
			this.logDrop("write", retryErr);
			this.discardConn(newConn);
		}
		return null;
	}

	/** Dial the daemon socket if not already connected. */
	private dialIfNeeded(): Promise<Error | null> {
		if (this.conn !== null) {
			return Promise.resolve(null);
		}
		if (this.closed) {
			return Promise.resolve(new Error("emitter: closed"));
		}
		return new Promise((resolve) => {
			let settled = false;
			const settle = (err: Error | null) => {
				if (settled) {
					return;
				}
				settled = true;
				clearTimeout(timer);
				resolve(err);
			};

			const timer = setTimeout(() => {
				socket.destroy();
				settle(new Error(`dial timeout after ${DIAL_TIMEOUT_MS}ms`));
			}, DIAL_TIMEOUT_MS);

			const socket = createConnection({ path: this.socketPath }, () => {
				// Attach a permanent error listener BEFORE settling. Without
				// it, any later 'error' event on this socket (peer reset,
				// daemon crash, EPIPE on a half-open conn) crashes the host
				// process via Node's unhandled-'error' rule. The listener
				// also discards the dead conn so the next emit() re-dials
				// transparently.
				socket.on("error", (err) => this.handleSocketError(socket, err));
				// If close() ran while we were dialing, drop this freshly
				// connected socket on the floor — the caller already asked
				// to release resources.
				if (this.closed) {
					socket.destroy();
					settle(new Error("emitter: closed"));
					return;
				}
				this.conn = socket;
				settle(null);
			});

			socket.once("error", (err) => {
				// Dial-time error: 'connect' never fired, so the permanent
				// listener was never installed and this once-listener is
				// the only one. settle() also clears the dial timer.
				settle(err);
			});
		});
	}

	/**
	 * Permanent socket error listener. Discards the dead conn so the next
	 * emit() re-dials, and logs the drop. This listener is what prevents
	 * a peer reset from crashing the host process via Node's unhandled-
	 * 'error' rule.
	 */
	private handleSocketError(socket: Socket, err: Error): void {
		this.logDrop("socket", err);
		// Only forget conn if it still points at this socket; a later dial
		// may have replaced it and we don't want to drop the live one.
		if (this.conn === socket) {
			this.conn = null;
		}
		socket.destroy();
	}

	/** Discard a connection: forget it if current, then destroy. */
	private discardConn(socket: Socket): void {
		if (this.conn === socket) {
			this.conn = null;
		}
		socket.destroy();
	}

	/** Write a 4-byte big-endian length prefix followed by the body. */
	private writeFrame(conn: Socket, body: Buffer): Promise<Error | null> {
		return new Promise((resolve) => {
			let settled = false;
			const settle = (err: Error | null) => {
				if (settled) {
					return;
				}
				settled = true;
				clearTimeout(timer);
				resolve(err);
			};

			const header = Buffer.allocUnsafe(4);
			header.writeUInt32BE(body.length, 0);

			const timer = setTimeout(() => {
				settle(new Error(`write timeout after ${WRITE_TIMEOUT_MS}ms`));
			}, WRITE_TIMEOUT_MS);

			// Write header and body as two sequential calls to avoid allocating
			// a concat buffer for every emit (avoids one copy of the full frame).
			conn.write(header);
			conn.write(body, (err) => {
				settle(err ?? null);
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
