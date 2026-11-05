import type { ToolsTable } from '../adapters/types.js';

/*
 * What a saved tools table may hold (specs/123 FR-017, data-model.md). Checked in the handler rather than the
 * schema because each refusal must name the row that broke it, and because which scopes a row may name depends on
 * the API it belongs to — the scopes after any change made in the same request.
 */

export const MAX_TOOL_ROWS = 200;
export const MAX_TOOL_NAME = 128;

// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f]/;

export type ToolsTableResult =
	{ ok: true; tools: ToolsTable } | { ok: false; message: string };

/* A name as an administrator would recognise it in a message, with anything unprintable spelled out. */
function shown(name: string): string {
	return JSON.stringify(name);
}

export function validateToolsTable(
	tools: ToolsTable,
	scopes: readonly string[]
): ToolsTableResult {
	if (tools.rows.length > MAX_TOOL_ROWS) {
		return {
			ok: false,
			message: `a tools table holds at most ${String(MAX_TOOL_ROWS)} tools`
		};
	}
	const seen = new Set<string>();
	for (const { name, scopes: needed } of tools.rows) {
		if (
			name === '' ||
			name.length > MAX_TOOL_NAME ||
			CONTROL.test(name) ||
			name.trim() !== name
		) {
			return {
				ok: false,
				message: `the tool name ${shown(name)} must be 1 to ${String(MAX_TOOL_NAME)} characters, with no control character and no space at either end`
			};
		}
		if (seen.has(name)) {
			return { ok: false, message: `the tool ${shown(name)} is listed twice` };
		}
		seen.add(name);
		if (needed.length === 0) {
			return {
				ok: false,
				message: `the tool ${shown(name)} needs at least one scope`
			};
		}
		if (new Set(needed).size !== needed.length) {
			return {
				ok: false,
				message: `the tool ${shown(name)} names one scope twice`
			};
		}
		const foreign = needed.find((scope) => !scopes.includes(scope));
		if (foreign !== undefined) {
			return {
				ok: false,
				message: `the tool ${shown(name)} needs ${foreign}, which is not one of this API's scopes`
			};
		}
	}
	return {
		ok: true,
		tools: {
			rows: tools.rows.map(({ name, scopes: needed }) => ({
				name,
				scopes: [...needed]
			})),
			otherTools: tools.otherTools,
			withoutMethod: tools.withoutMethod
		}
	};
}

/* The first row a change of the API's scopes would leave needing a scope the API no longer has. */
export function orphanedBy(
	tools: ToolsTable | undefined,
	scopes: readonly string[]
): { tool: string; scope: string } | null {
	for (const row of tools?.rows ?? []) {
		const scope = row.scopes.find((needed) => !scopes.includes(needed));
		if (scope !== undefined) return { tool: row.name, scope };
	}
	return null;
}
