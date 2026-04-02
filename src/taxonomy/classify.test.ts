import { describe, expect, it } from "vitest";
import { classifyToolCall } from "./classify.js";
import type { TaxonomyMapping } from "./types.js";

const TEST_MAPPINGS: TaxonomyMapping[] = [
	{ tool_name: "read_file", action_type: "filesystem.file.read" },
	{ tool_name: "write_file", action_type: "filesystem.file.create" },
	{ tool_name: "delete_file", action_type: "filesystem.file.delete" },
	{ tool_name: "run_command", action_type: "system.command.execute" },
];

describe("classifyToolCall", () => {
	it("classifies a mapped tool call", () => {
		const result = classifyToolCall("read_file", TEST_MAPPINGS);
		expect(result.action_type).toBe("filesystem.file.read");
		expect(result.risk_level).toBe("low");
	});

	it("returns correct risk level for high-risk actions", () => {
		const result = classifyToolCall("delete_file", TEST_MAPPINGS);
		expect(result.action_type).toBe("filesystem.file.delete");
		expect(result.risk_level).toBe("high");
	});

	it("falls back to unknown for unmapped tool calls", () => {
		const result = classifyToolCall("some_random_tool", TEST_MAPPINGS);
		expect(result.action_type).toBe("unknown");
		expect(result.risk_level).toBe("medium");
	});

	it("falls back to unknown with empty mappings", () => {
		const result = classifyToolCall("read_file", []);
		expect(result.action_type).toBe("unknown");
		expect(result.risk_level).toBe("medium");
	});

	it("handles mapping to an unknown action type gracefully", () => {
		const mappings: TaxonomyMapping[] = [
			{ tool_name: "weird_tool", action_type: "nonexistent.domain.action" },
		];
		const result = classifyToolCall("weird_tool", mappings);
		expect(result.action_type).toBe("unknown");
		expect(result.risk_level).toBe("medium");
	});
});
