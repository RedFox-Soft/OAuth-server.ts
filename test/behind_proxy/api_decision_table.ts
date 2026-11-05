import type { ToolsBody } from './api_helpers.ts';

/*
 * One MCP server's tools table and what the check answers for each request against it (specs/123 quickstart §2).
 * Driven through the live check and through the decision the console shows, so the two can never disagree.
 */

export const TABLE: ToolsBody = {
	rows: [
		{ name: 'search_files', scopes: ['files:read'] },
		{ name: 'delete_file', scopes: ['files:write', 'files:delete'] }
	],
	otherTools: 'refuse',
	withoutMethod: 'refuse'
};

export interface Row {
	what: string;
	scopes: string;
	mcpMethod?: string;
	mcpName?: string;
	/* Absent: 2026-07-28. Null: no header at all. */
	protocolVersion?: string | null;
	table?: Partial<ToolsBody>;
	status: number;
	reason: string;
	/* The `scope=` a refusal for a missing scope names. */
	needed?: string;
}

export const ROWS: Row[] = [
	{
		what: 'a listed tool whose one scope the token holds',
		scopes: 'files:read',
		mcpMethod: 'tools/call',
		mcpName: 'search_files',
		status: 200,
		reason: 'allowed'
	},
	{
		what: 'a listed tool one of whose scopes the token lacks',
		scopes: 'files:write',
		mcpMethod: 'tools/call',
		mcpName: 'delete_file',
		status: 403,
		reason: 'insufficient_scope',
		needed: 'files:write files:delete'
	},
	{
		what: 'a listed tool every scope of which the token holds',
		scopes: 'files:write files:delete',
		mcpMethod: 'tools/call',
		mcpName: 'delete_file',
		status: 200,
		reason: 'allowed'
	},
	{
		what: 'listing tools, which names no tool',
		scopes: '',
		mcpMethod: 'tools/list',
		status: 200,
		reason: 'allowed'
	},
	{
		what: 'a tool call that names no tool',
		scopes: '',
		mcpMethod: 'tools/call',
		status: 403,
		reason: 'tool_unnamed'
	},
	{
		what: 'an unlisted tool while any other tool is refused',
		scopes: 'files:read',
		mcpMethod: 'tools/call',
		mcpName: 'rename_file',
		status: 403,
		reason: 'tool_not_listed'
	},
	{
		what: 'an unlisted tool while any other tool needs only a valid token',
		scopes: 'files:read',
		mcpMethod: 'tools/call',
		mcpName: 'rename_file',
		table: { otherTools: 'token' },
		status: 200,
		reason: 'allowed'
	},
	{
		what: 'a client that sends no method',
		scopes: 'files:read',
		status: 403,
		reason: 'old_client'
	},
	{
		what: 'a client speaking a revision before header validation',
		scopes: 'files:read',
		mcpMethod: 'tools/list',
		protocolVersion: '2025-11-25',
		status: 403,
		reason: 'old_client'
	},
	{
		what: 'a client that sends no method while old clients are let in',
		scopes: 'files:read',
		table: { withoutMethod: 'token' },
		status: 200,
		reason: 'allowed'
	},
	{
		what: 'a listed name in another letter case',
		scopes: 'files:read',
		mcpMethod: 'tools/call',
		mcpName: 'Search_Files',
		status: 403,
		reason: 'tool_not_listed'
	},
	{
		what: 'a listed name sent in the Base64 form',
		scopes: 'files:read',
		mcpMethod: 'tools/call',
		mcpName: '=?base64?c2VhcmNoX2ZpbGVz?=',
		status: 200,
		reason: 'allowed'
	},
	{
		what: 'a Base64 form that does not decode',
		scopes: 'files:read',
		mcpMethod: 'tools/call',
		mcpName: '=?base64?!!?=',
		status: 403,
		reason: 'bad_mcp_header'
	},
	{
		what: 'reading a resource, which the table does not cover',
		scopes: 'files:read',
		mcpMethod: 'resources/read',
		mcpName: 'file:///x',
		status: 200,
		reason: 'allowed'
	},
	{
		what: 'anything at all against an empty table',
		scopes: '',
		mcpMethod: 'tools/call',
		mcpName: 'delete_file',
		protocolVersion: null,
		table: { rows: [] },
		status: 200,
		reason: 'allowed'
	}
];

export function tableFor(row: Row): ToolsBody {
	return { ...TABLE, ...row.table };
}
