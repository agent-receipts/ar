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
	});
});
