import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { classifyToolCall } from "./classify.js";
import { loadTaxonomyConfig } from "./config.js";

describe("loadTaxonomyConfig", () => {
	let tempDir: string;

	beforeEach(() => {
		tempDir = mkdtempSync(join(tmpdir(), "attest-config-"));
	});

	afterEach(() => {
		rmSync(tempDir, { recursive: true });
	});

	function writeConfig(content: string): string {
		const filePath = join(tempDir, "taxonomy.json");
		writeFileSync(filePath, content, "utf-8");
		return filePath;
	}

	it("loads valid mappings from a config file", () => {
		const path = writeConfig(
			JSON.stringify({
				mappings: [
					{ tool_name: "read_file", action_type: "filesystem.file.read" },
					{
						tool_name: "write_file",
						action_type: "filesystem.file.create",
					},
				],
			}),
		);

		const mappings = loadTaxonomyConfig(path);

		expect(mappings).toHaveLength(2);
		expect(mappings[0]).toEqual({
			tool_name: "read_file",
			action_type: "filesystem.file.read",
		});
	});

	it("works with classifyToolCall", () => {
		const path = writeConfig(
			JSON.stringify({
				mappings: [
					{ tool_name: "read_file", action_type: "filesystem.file.read" },
				],
			}),
		);

		const mappings = loadTaxonomyConfig(path);
		const result = classifyToolCall("read_file", mappings);

		expect(result.action_type).toBe("filesystem.file.read");
		expect(result.risk_level).toBe("low");
	});

	it("unmapped tools fall back to unknown", () => {
		const path = writeConfig(JSON.stringify({ mappings: [] }));

		const mappings = loadTaxonomyConfig(path);
		const result = classifyToolCall("some_unknown_tool", mappings);

		expect(result.action_type).toBe("unknown");
		expect(result.risk_level).toBe("medium");
	});

	it("loads an empty mappings array", () => {
		const path = writeConfig(JSON.stringify({ mappings: [] }));

		const mappings = loadTaxonomyConfig(path);
		expect(mappings).toEqual([]);
	});

	it("throws for missing file", () => {
		expect(() => loadTaxonomyConfig("/nonexistent/path.json")).toThrow();
	});

	it("throws for invalid JSON", () => {
		const path = writeConfig("not json");

		expect(() => loadTaxonomyConfig(path)).toThrow();
	});

	it("throws for missing mappings key", () => {
		const path = writeConfig(JSON.stringify({ tools: [] }));

		expect(() => loadTaxonomyConfig(path)).toThrow("Invalid taxonomy config");
	});

	it("throws for duplicate tool_name", () => {
		const path = writeConfig(
			JSON.stringify({
				mappings: [
					{ tool_name: "read_file", action_type: "filesystem.file.read" },
					{ tool_name: "read_file", action_type: "filesystem.file.modify" },
				],
			}),
		);

		expect(() => loadTaxonomyConfig(path)).toThrow(
			"Duplicate taxonomy mapping",
		);
	});

	it("throws for empty string tool_name or action_type", () => {
		const path = writeConfig(
			JSON.stringify({
				mappings: [{ tool_name: "", action_type: "filesystem.file.read" }],
			}),
		);

		expect(() => loadTaxonomyConfig(path)).toThrow("non-empty");
	});

	it("throws for invalid mapping entries", () => {
		const path = writeConfig(
			JSON.stringify({ mappings: [{ tool_name: 123 }] }),
		);

		expect(() => loadTaxonomyConfig(path)).toThrow("Invalid taxonomy mapping");
	});
});
