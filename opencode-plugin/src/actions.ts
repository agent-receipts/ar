/**
 * Mapping from OpenCode native tool names to Agent Receipts taxonomy action
 * types (sdk/ts `taxonomy/actions.ts`). The resolved type is forwarded to the
 * daemon as `action_type`; the daemon uses it verbatim as `action.type` and
 * derives `risk_level` from the taxonomy. Tools with no mapping are emitted
 * without an `action_type`, and the daemon falls back to a synthetic
 * `"<channel>.<tool>"` type (risk defaults to medium).
 *
 * This is the execd-side, honest-operator placement: the mapping is advisory
 * metadata the agent itself supplies. It is NOT an adversary-resistant
 * classification — a compromised OpenCode could mislabel or omit a call. The
 * daemon re-derives risk from the type rather than trusting an emitter-supplied
 * risk, so mislabelling cannot downgrade risk to evade parameter disclosure.
 */
export const DEFAULT_ACTION_MAP: Readonly<Record<string, string>> = {
	bash: "system.command.execute",
	write: "filesystem.file.create",
	edit: "filesystem.file.modify",
	patch: "filesystem.file.modify",
	apply_patch: "filesystem.file.modify",
	read: "filesystem.file.read",
	glob: "filesystem.file.read",
	grep: "filesystem.file.read",
	list: "filesystem.file.read",
	webfetch: "data.api.read",
};

/**
 * Resolve the taxonomy action type for an OpenCode tool name. `overrides` take
 * precedence over {@link DEFAULT_ACTION_MAP} so callers can extend or correct
 * the defaults via config. Returns `undefined` for unmapped tools, signalling
 * the caller to omit `action_type` and let the daemon fall back.
 */
export function resolveActionType(
	tool: string,
	overrides: Readonly<Record<string, string>> = {},
): string | undefined {
	return overrides[tool] ?? DEFAULT_ACTION_MAP[tool];
}
