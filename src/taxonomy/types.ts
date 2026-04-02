import type { RiskLevel } from "../receipt/types.js";

export interface ActionTypeEntry {
	type: string;
	description: string;
	risk_level: RiskLevel;
}

export interface TaxonomyMapping {
	tool_name: string;
	action_type: string;
}
