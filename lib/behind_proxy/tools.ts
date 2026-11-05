/*
 * What an API's tools table decides about one request (specs/123 research R6, R13). Pure and import-free: the check
 * and the console's Tools drawer read the same function, so what the drawer says a table does is what it does.
 *
 * The decision rests on the MCP 2026-07-28 request headers, which mirror the JSON-RPC body: `Mcp-Method` names the
 * method and `Mcp-Name` the tool. The proxy never sees the body, so a header is only as true as the server's own
 * check that it matches the body, which that revision makes a MUST and earlier ones never asked for.
 */

export type Choice = 'refuse' | 'token';

export interface ToolRow {
	readonly name: string;
	readonly scopes: readonly string[];
}

export interface ToolsTableView {
	readonly rows: readonly ToolRow[];
	readonly otherTools: Choice;
	readonly withoutMethod: Choice;
}

export type ToolRefusal =
	'bad_mcp_header' | 'old_client' | 'tool_unnamed' | 'tool_not_listed';

export type ToolDecision =
	| { outcome: 'allow' }
	| { outcome: 'refuse'; reason: ToolRefusal }
	| { outcome: 'insufficient'; needed: readonly string[] };

/* The first revision whose servers must refuse a request whose headers and body disagree. */
export const HEADER_VALIDATING_VERSION = '2026-07-28';

const SENTINEL_START = '=?base64?';
const SENTINEL_END = '?=';

// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f]/;

export function hasControlCharacter(value: string): boolean {
	return CONTROL.test(value);
}

/*
 * An `Mcp-Name` as the client meant it. A name a header cannot carry plainly arrives as `=?base64?…?=` (markers
 * lower-case, exactly), and is compared only once decoded. A form that does not decode, or a control character on
 * either side of decoding, is refused rather than matched: a name the table cannot be asked about must not fall
 * through to "any other tool".
 */
export function decodeMcpName(
	raw: string
): { bad: true } | { bad: false; name: string } {
	if (hasControlCharacter(raw)) return { bad: true };
	if (!(raw.startsWith(SENTINEL_START) && raw.endsWith(SENTINEL_END))) {
		return { bad: false, name: raw };
	}
	const encoded = raw.slice(
		SENTINEL_START.length,
		raw.length - SENTINEL_END.length
	);
	if (encoded.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) {
		return { bad: true };
	}
	let name: string;
	try {
		const bytes = Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0));
		name = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
	} catch {
		return { bad: true };
	}
	return hasControlCharacter(name) ? { bad: true } : { bad: false, name };
}

/*
 * A client whose headers the server behind the proxy may never have compared with the body: one that sends no
 * method, or speaks a revision before header validation. The MCP specification asks an intermediary that acts on
 * these headers to reject such traffic rather than trust it, and here the administrator chooses.
 */
export function isOldClient(
	method: string | null,
	protocolVersion: string | null
): boolean {
	if (method === null || protocolVersion === null) return true;
	if (!/^\d{4}-\d{2}-\d{2}$/.test(protocolVersion)) return true;
	return protocolVersion < HEADER_VALIDATING_VERSION;
}

export interface ToolRequest {
	readonly table: ToolsTableView | undefined;
	/* `Mcp-Method` as forwarded, or null. */
	readonly method: string | null;
	/* `Mcp-Name` as forwarded (still encoded), or null. */
	readonly name: string | null;
	/* `MCP-Protocol-Version` as forwarded, or null. */
	readonly protocolVersion: string | null;
	readonly scopes: ReadonlySet<string>;
}

export function decideTool(request: ToolRequest): ToolDecision {
	const { table, method, name, protocolVersion, scopes } = request;
	if (!table || table.rows.length === 0) return { outcome: 'allow' };

	if (method !== null && hasControlCharacter(method)) {
		return { outcome: 'refuse', reason: 'bad_mcp_header' };
	}
	const decoded = name === null ? null : decodeMcpName(name);
	if (decoded?.bad) return { outcome: 'refuse', reason: 'bad_mcp_header' };

	if (isOldClient(method, protocolVersion)) {
		return table.withoutMethod === 'token'
			? { outcome: 'allow' }
			: { outcome: 'refuse', reason: 'old_client' };
	}
	if (method !== 'tools/call') return { outcome: 'allow' };
	if (decoded === null) return { outcome: 'refuse', reason: 'tool_unnamed' };

	const row = table.rows.find((candidate) => candidate.name === decoded.name);
	if (!row) {
		return table.otherTools === 'token'
			? { outcome: 'allow' }
			: { outcome: 'refuse', reason: 'tool_not_listed' };
	}
	return row.scopes.every((scope) => scopes.has(scope))
		? { outcome: 'allow' }
		: { outcome: 'insufficient', needed: row.scopes };
}

/*
 * What a change to the table lets a token do that it could not before, one line each, for the console's
 * confirmation. A narrowing says nothing: it needs no confirmation, only a save.
 */
export function toolWidenings(
	before: ToolsTableView | undefined,
	after: ToolsTableView | undefined
): string[] {
	const was = before?.rows ?? [];
	const now = after?.rows ?? [];
	if (was.length === 0) return [];
	if (now.length === 0) {
		return ['Every tool now needs only a valid token.'];
	}
	const lines: string[] = [];
	const afterOther = after?.otherTools ?? 'refuse';
	for (const row of was) {
		const kept = now.find((candidate) => candidate.name === row.name);
		if (!kept) {
			if (afterOther === 'token') {
				lines.push(`${row.name} now needs only a valid token.`);
			}
			continue;
		}
		const dropped = row.scopes.filter((scope) => !kept.scopes.includes(scope));
		if (dropped.length > 0) {
			lines.push(`${row.name} no longer needs ${dropped.join(', ')}.`);
		}
	}
	if (before?.otherTools !== 'token' && afterOther === 'token') {
		lines.push('Any tool not listed now needs only a valid token.');
	}
	if (before?.withoutMethod !== 'token' && after?.withoutMethod === 'token') {
		lines.push(
			'Clients that do not say which tool they call are now let in with a valid token.'
		);
	}
	return lines;
}
