import { readFileSync } from "node:fs";
import type { TaxonomyMapping } from "./types.js";

/**
 * Shape of the taxonomy config file (JSON).
 *
 * Example:
 * ```json
 * {
 *   "mappings": [
 *     { "tool_name": "read_file", "action_type": "filesystem.file.read" },
 *     { "tool_name": "write_file", "action_type": "filesystem.file.create" }
 *   ]
 * }
 * ```
 */
export interface TaxonomyConfig {
	mappings: TaxonomyMapping[];
}

/**
 * Load taxonomy mappings from a JSON config file.
 *
 * The file must contain a JSON object with a `mappings` array
 * of `{ tool_name, action_type }` entries.
 *
 * @throws If the file cannot be read or has invalid structure.
 */
export function loadTaxonomyConfig(filePath: string): TaxonomyMapping[] {
	const raw = readFileSync(filePath, "utf-8");
	const parsed: unknown = JSON.parse(raw);

	if (
		typeof parsed !== "object" ||
		parsed === null ||
		!Array.isArray((parsed as TaxonomyConfig).mappings)
	) {
		throw new Error(`Invalid taxonomy config: expected { "mappings": [...] }`);
	}

	const config = parsed as TaxonomyConfig;

	const seen = new Set<string>();

	for (const mapping of config.mappings) {
		if (
			typeof mapping.tool_name !== "string" ||
			typeof mapping.action_type !== "string" ||
			mapping.tool_name === "" ||
			mapping.action_type === ""
		) {
			throw new Error(
				`Invalid taxonomy mapping: each entry must have non-empty "tool_name" and "action_type" strings`,
			);
		}
		if (seen.has(mapping.tool_name)) {
			throw new Error(
				`Duplicate taxonomy mapping for tool_name "${mapping.tool_name}"`,
			);
		}
		seen.add(mapping.tool_name);
	}

	return config.mappings;
}
