import { DatabaseSync } from "node:sqlite";
import type {
	AgentReceipt,
	OutcomeStatus,
	RiskLevel,
} from "../receipt/types.js";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS receipts (
  id TEXT PRIMARY KEY,
  chain_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  action_type TEXT NOT NULL,
  risk_level TEXT NOT NULL,
  status TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  issuer_id TEXT NOT NULL,
  principal_id TEXT,
  receipt_json TEXT NOT NULL,
  receipt_hash TEXT NOT NULL,
  previous_receipt_hash TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_receipts_chain ON receipts(chain_id, sequence);
CREATE INDEX IF NOT EXISTS idx_receipts_action ON receipts(action_type);
CREATE INDEX IF NOT EXISTS idx_receipts_risk ON receipts(risk_level);
CREATE INDEX IF NOT EXISTS idx_receipts_timestamp ON receipts(timestamp);
`;

/**
 * Filters for querying receipts.
 */
export interface ReceiptQuery {
	chainId?: string;
	actionType?: string;
	riskLevel?: RiskLevel;
	status?: OutcomeStatus;
	/** Return receipts with timestamp >= after (ISO 8601). */
	after?: string;
	/** Return receipts with timestamp <= before (ISO 8601). */
	before?: string;
	/** Maximum number of results. */
	limit?: number;
}

/**
 * Summary statistics for the receipt store.
 */
export interface StoreStats {
	total: number;
	chains: number;
	byRisk: { risk_level: string; count: number }[];
	byStatus: { status: string; count: number }[];
	byAction: { action_type: string; count: number }[];
}

interface ReceiptRow {
	receipt_json: string;
}

const DEFAULT_QUERY_LIMIT = 10000;

/**
 * Parse a receipt JSON string from the store, with error context.
 */
function parseReceiptJson(json: string, context: string): AgentReceipt {
	try {
		return JSON.parse(json) as AgentReceipt;
	} catch (cause) {
		throw new Error(`Corrupt receipt in store (${context}): ${cause}`);
	}
}

/**
 * SQLite-backed receipt store.
 */
export class ReceiptStore {
	private db: DatabaseSync;

	constructor(dbPath: string) {
		this.db = new DatabaseSync(dbPath);
		this.db.exec(SCHEMA);
	}

	/**
	 * Insert a signed receipt into the store.
	 */
	insert(receipt: AgentReceipt, receiptHash: string): void {
		const subject = receipt.credentialSubject;
		this.db
			.prepare(
				`INSERT INTO receipts
				(id, chain_id, sequence, action_type, risk_level, status,
				 timestamp, issuer_id, principal_id, receipt_json, receipt_hash,
				 previous_receipt_hash)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			)
			.run(
				receipt.id,
				subject.chain.chain_id,
				subject.chain.sequence,
				subject.action.type,
				subject.action.risk_level,
				subject.outcome.status,
				subject.action.timestamp,
				receipt.issuer.id,
				subject.principal.id,
				JSON.stringify(receipt),
				receiptHash,
				subject.chain.previous_receipt_hash,
			);
	}

	/**
	 * Retrieve a receipt by its id.
	 */
	getById(id: string): AgentReceipt | undefined {
		const row = this.db
			.prepare("SELECT receipt_json FROM receipts WHERE id = ?")
			.get(id) as ReceiptRow | undefined;
		return row ? parseReceiptJson(row.receipt_json, `id=${id}`) : undefined;
	}

	/**
	 * Retrieve all receipts in a chain, ordered by sequence.
	 */
	getChain(chainId: string): AgentReceipt[] {
		const rows = this.db
			.prepare(
				"SELECT receipt_json FROM receipts WHERE chain_id = ? ORDER BY sequence ASC",
			)
			.all(chainId) as unknown as ReceiptRow[];
		return rows.map((r) =>
			parseReceiptJson(r.receipt_json, `chain=${chainId}`),
		);
	}

	/**
	 * Query receipts with optional filters.
	 */
	query(filters: ReceiptQuery): AgentReceipt[] {
		const conditions: string[] = [];
		const params: string[] = [];

		if (filters.chainId !== undefined) {
			conditions.push("chain_id = ?");
			params.push(filters.chainId);
		}
		if (filters.actionType !== undefined) {
			conditions.push("action_type = ?");
			params.push(filters.actionType);
		}
		if (filters.riskLevel !== undefined) {
			conditions.push("risk_level = ?");
			params.push(filters.riskLevel);
		}
		if (filters.status !== undefined) {
			conditions.push("status = ?");
			params.push(filters.status);
		}
		if (filters.after !== undefined) {
			conditions.push("timestamp >= ?");
			params.push(filters.after);
		}
		if (filters.before !== undefined) {
			conditions.push("timestamp <= ?");
			params.push(filters.before);
		}

		const where =
			conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

		const limit = filters.limit ?? DEFAULT_QUERY_LIMIT;
		params.push(String(limit));

		const rows = this.db
			.prepare(
				`SELECT receipt_json FROM receipts ${where} ORDER BY timestamp ASC LIMIT ?`,
			)
			.all(...params) as unknown as ReceiptRow[];

		return rows.map((r) => parseReceiptJson(r.receipt_json, "query"));
	}

	/**
	 * Get summary statistics for the store.
	 */
	stats(): StoreStats {
		const total = (
			this.db.prepare("SELECT COUNT(*) as count FROM receipts").get() as {
				count: number;
			}
		).count;

		const chains = (
			this.db
				.prepare("SELECT COUNT(DISTINCT chain_id) as count FROM receipts")
				.get() as { count: number }
		).count;

		const byRisk = this.db
			.prepare(
				"SELECT risk_level, COUNT(*) as count FROM receipts GROUP BY risk_level ORDER BY count DESC",
			)
			.all() as unknown as { risk_level: string; count: number }[];

		const byStatus = this.db
			.prepare(
				"SELECT status, COUNT(*) as count FROM receipts GROUP BY status ORDER BY count DESC",
			)
			.all() as unknown as { status: string; count: number }[];

		const byAction = this.db
			.prepare(
				"SELECT action_type, COUNT(*) as count FROM receipts GROUP BY action_type ORDER BY count DESC",
			)
			.all() as unknown as { action_type: string; count: number }[];

		return { total, chains, byRisk, byStatus, byAction };
	}

	/**
	 * Close the database connection.
	 */
	close(): void {
		this.db.close();
	}
}

/**
 * Open (or create) a receipt store at the given path.
 *
 * Use ":memory:" for an in-memory database.
 */
export function openStore(dbPath: string): ReceiptStore {
	return new ReceiptStore(dbPath);
}
