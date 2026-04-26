import { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { makeReceipt } from "../test-utils/receipts.js";
import type { ReceiptStore } from "./store.js";
import { openStore } from "./store.js";

describe("ReceiptStore", () => {
	let store: ReceiptStore;

	beforeEach(() => {
		store = openStore(":memory:");
	});

	afterEach(() => {
		store.close();
	});

	describe("insert and getById", () => {
		it("stores and retrieves a receipt", () => {
			const receipt = makeReceipt({});
			store.insert(receipt, "sha256:abc");

			const retrieved = store.getById(receipt.id);
			expect(retrieved).toEqual(receipt);
		});

		it("returns undefined for missing receipt", () => {
			expect(store.getById("urn:receipt:missing")).toBeUndefined();
		});
	});

	describe("getChain", () => {
		it("returns receipts ordered by sequence", () => {
			store.insert(
				makeReceipt({ id: "urn:receipt:2", sequence: 2 }),
				"sha256:b",
			);
			store.insert(
				makeReceipt({ id: "urn:receipt:1", sequence: 1 }),
				"sha256:a",
			);
			store.insert(
				makeReceipt({ id: "urn:receipt:3", sequence: 3 }),
				"sha256:c",
			);

			const chain = store.getChain("chain_test");

			expect(chain).toHaveLength(3);
			expect(chain[0]?.id).toBe("urn:receipt:1");
			expect(chain[1]?.id).toBe("urn:receipt:2");
			expect(chain[2]?.id).toBe("urn:receipt:3");
		});

		it("returns empty array for unknown chain", () => {
			expect(store.getChain("nonexistent")).toEqual([]);
		});

		it("only returns receipts from the requested chain", () => {
			store.insert(
				makeReceipt({ id: "urn:receipt:a1", chainId: "chain_a" }),
				"sha256:a",
			);
			store.insert(
				makeReceipt({ id: "urn:receipt:b1", chainId: "chain_b" }),
				"sha256:b",
			);

			const chain = store.getChain("chain_a");
			expect(chain).toHaveLength(1);
			expect(chain[0]?.id).toBe("urn:receipt:a1");
		});
	});

	describe("query", () => {
		beforeEach(() => {
			store.insert(
				makeReceipt({
					id: "urn:receipt:1",
					actionType: "filesystem.file.read",
					riskLevel: "low",
					status: "success",
					timestamp: "2026-03-29T10:00:00Z",
				}),
				"sha256:1",
			);
			store.insert(
				makeReceipt({
					id: "urn:receipt:2",
					sequence: 2,
					actionType: "filesystem.file.delete",
					riskLevel: "high",
					status: "success",
					timestamp: "2026-03-29T11:00:00Z",
				}),
				"sha256:2",
			);
			store.insert(
				makeReceipt({
					id: "urn:receipt:3",
					sequence: 3,
					actionType: "system.command.execute",
					riskLevel: "critical",
					status: "failure",
					timestamp: "2026-03-29T12:00:00Z",
				}),
				"sha256:3",
			);
		});

		it("filters by action type", () => {
			const results = store.query({
				actionType: "filesystem.file.read",
			});
			expect(results).toHaveLength(1);
			expect(results[0]?.id).toBe("urn:receipt:1");
		});

		it("filters by risk level", () => {
			const results = store.query({ riskLevel: "critical" });
			expect(results).toHaveLength(1);
			expect(results[0]?.id).toBe("urn:receipt:3");
		});

		it("filters by status", () => {
			const results = store.query({ status: "failure" });
			expect(results).toHaveLength(1);
			expect(results[0]?.id).toBe("urn:receipt:3");
		});

		it("filters by time range", () => {
			const results = store.query({
				after: "2026-03-29T10:30:00Z",
				before: "2026-03-29T11:30:00Z",
			});
			expect(results).toHaveLength(1);
			expect(results[0]?.id).toBe("urn:receipt:2");
		});

		it("combines multiple filters", () => {
			const results = store.query({
				riskLevel: "high",
				status: "success",
			});
			expect(results).toHaveLength(1);
			expect(results[0]?.id).toBe("urn:receipt:2");
		});

		it("respects limit", () => {
			const results = store.query({ limit: 2 });
			expect(results).toHaveLength(2);
		});

		it("returns empty array when no matches", () => {
			const results = store.query({ riskLevel: "medium" });
			expect(results).toEqual([]);
		});

		it("returns all receipts with empty filter", () => {
			const results = store.query({});
			expect(results).toHaveLength(3);
		});

		// Regression: node:sqlite binds JS values by their runtime type, and
		// SQLite's LIMIT requires INTEGER. If `limit` is bound as TEXT (e.g.
		// via String(limit)) it returns zero rows on some Node versions.
		// See https://github.com/agent-receipts/ar/pull/249.
		it("returns rows when limit exceeds row count (LIMIT bound as INTEGER)", () => {
			const results = store.query({ limit: 20 });
			expect(results).toHaveLength(3);
		});

		it("returns rows when limit is combined with filters", () => {
			const results = store.query({
				status: "success",
				limit: 20,
			});
			expect(results).toHaveLength(2);
		});

		it("uses default limit when none provided and returns all rows", () => {
			const results = store.query({});
			expect(results).toHaveLength(3);
		});
	});

	describe("tool_name", () => {
		it("persists tool_name from receipt action", () => {
			const receipt = makeReceipt({});
			receipt.credentialSubject.action.tool_name = "list_issues";
			store.insert(receipt, "sha256:tn1");

			const retrieved = store.getById(receipt.id);
			expect(retrieved?.credentialSubject.action.tool_name).toBe("list_issues");
		});

		it("migrates pre-existing database without tool_name column", () => {
			// Create a DB with the old schema (no tool_name column).
			const oldSchema = `
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
			`;
			const oldDb = new DatabaseSync(":memory:");
			oldDb.exec(oldSchema);

			// Insert a row using the old schema.
			const receipt = makeReceipt({});
			oldDb
				.prepare(
					`INSERT INTO receipts
					(id, chain_id, sequence, action_type, risk_level, status,
					 timestamp, issuer_id, principal_id, receipt_json, receipt_hash,
					 previous_receipt_hash)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				)
				.run(
					receipt.id,
					"chain_test",
					1,
					"filesystem.file.read",
					"low",
					"success",
					"2026-03-29T14:00:00Z",
					"did:agent:test",
					"did:user:test",
					JSON.stringify(receipt),
					"sha256:old",
					null,
				);
			oldDb.close();

			// Opening via ReceiptStore should trigger migration and succeed.
			// Use a file-based DB to test migration on re-open.
			const tmpPath = `:memory:`;
			const migratedStore = openStore(tmpPath);
			const newReceipt = makeReceipt({ id: "urn:receipt:migrated" });
			newReceipt.credentialSubject.action.tool_name = "read_file";
			migratedStore.insert(newReceipt, "sha256:new");

			const retrieved = migratedStore.getById("urn:receipt:migrated");
			expect(retrieved?.credentialSubject.action.tool_name).toBe("read_file");
			migratedStore.close();
		});
	});
});
