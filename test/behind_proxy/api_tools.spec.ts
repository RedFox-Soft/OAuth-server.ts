import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.js';
import { decideApiCall } from 'lib/behind_proxy/api_decision.ts';
import { toolWidenings, type ToolsTableView } from 'lib/behind_proxy/tools.ts';
import type { Condition } from 'lib/behind_proxy/conditions.ts';
import { world, type World } from './helpers.ts';
import {
	apiCheck,
	bearer,
	declareApi,
	jwtFor,
	type ApiCheck,
	type ToolsBody
} from './api_helpers.ts';
import { ROWS, TABLE, tableFor, type Row } from './api_decision_table.ts';

/* A table as the console holds it: these rows carry no conditions. */
function viewOf(table: ToolsBody): ToolsTableView {
	return {
		rows: table.rows.map(({ name, scopes }) => ({ name, scopes })),
		otherTools: table.otherTools,
		withoutMethod: table.withoutMethod
	};
}

/* What the console's "Check access" says for a row, in the check's own words: the one decision both ask (specs/131). */
function decidedFor(row: Row): { status: number; reason: string } {
	const table = tableFor(row);
	const decision = decideApiCall(
		{
			tools: {
				rows: table.rows.map(({ name, scopes }) => ({ name, scopes })),
				otherTools: table.otherTools,
				withoutMethod: table.withoutMethod
			}
		},
		{
			token: {
				scopes: new Set(row.scopes.split(' ').filter(Boolean)),
				signedInAt: null,
				signedInWithCode: false
			},
			headers: {
				method: row.mcpMethod ?? null,
				name: row.mcpName ?? null,
				protocolVersion:
					row.protocolVersion === undefined ? '2026-07-28' : row.protocolVersion
			},
			person: null,
			address: null,
			at: Date.now(),
			explain: true
		}
	);
	switch (decision.outcome) {
		case 'allow':
			return { status: 200, reason: 'allowed' };
		case 'insufficient':
			return { status: 403, reason: 'insufficient_scope' };
		case 'refuse':
			return { status: 403, reason: decision.reason };
		case 'sign_in':
		case 'unknown':
			return { status: 0, reason: decision.outcome };
	}
}

/**
 * @proves An MCP server's tools table decides each request by the method and tool the client names: a listed tool
 * needs every scope of its row and a refusal names them all, a request naming no tool needs only a valid token, and
 * a name the table cannot be asked about — another letter case, a malformed form, a header sent twice, a client too old for the server
 * to have checked it — is never mistaken for a listed one. The console's decision and the live check agree on every
 * row.
 */
describe("an API's tools table", () => {
	let w: World;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		w = await world();
	});

	async function send(row: Row, extra: Partial<ApiCheck> = {}) {
		const api = await declareApi(w.cookie, w.acme.id, {
			checkedBy: 'proxy',
			tools: tableFor(row)
		});
		const token = await jwtFor(api, {
			claims: { scope: row.scopes || undefined }
		});
		return apiCheck({
			slug: w.acme.slug,
			identifier: api.identifier,
			authorization: bearer(token),
			...(row.mcpMethod !== undefined ? { mcpMethod: row.mcpMethod } : {}),
			...(row.mcpName !== undefined ? { mcpName: row.mcpName } : {}),
			...(row.protocolVersion !== undefined
				? { protocolVersion: row.protocolVersion }
				: {}),
			...extra
		});
	}

	it.each(ROWS.map((row) => [row.what, row] as const))(
		'%s is decided as the table says, by the check and by the console alike',
		async (_what, row) => {
			const res = await send(row);

			expect({
				status: res.status,
				reason: res.headers.get('x-auth-reason')
			}).toEqual({ status: row.status, reason: row.reason });
			expect(decidedFor(row)).toEqual({
				status: row.status,
				reason: row.reason
			});
			if (row.needed !== undefined) {
				expect(res.headers.get('www-authenticate')).toStartWith(
					`Bearer error="insufficient_scope", scope="${row.needed}", resource_metadata="`
				);
			}
		}
	);

	it('a tool name that differs only in letter case is an unlisted tool', async () => {
		const row: Row = {
			what: 'case',
			scopes: 'files:write files:delete',
			mcpMethod: 'tools/call',
			mcpName: 'DELETE_FILE',
			status: 403,
			reason: 'tool_not_listed'
		};

		const res = await send(row);

		expect(res.headers.get('x-auth-reason')).toBe('tool_not_listed');
	});

	it.each([
		/* Inside the value: HTTP trims whitespace at either end of a header before anyone reads it. */
		['a tab in the method', { mcpMethod: 'tools/\tcall' }],
		['a tab in the tool name', { mcpName: 'search\t_files' }],
		[
			'a line break inside an encoded name',
			{ mcpName: '=?base64?c2VhcmNoCl9maWxlcw==?=' }
		],
		['an encoded name that is not Base64', { mcpName: '=?base64?c2Vh*mNo?=' }],
		['an encoded name that is not UTF-8', { mcpName: '=?base64?/w==?=' }]
	] as [string, Partial<Row>][])(
		'a request with %s is refused',
		async (_what, overrides) => {
			const row: Row = {
				what: 'header',
				scopes: 'files:read',
				mcpMethod: 'tools/call',
				mcpName: 'search_files',
				status: 403,
				reason: 'bad_mcp_header',
				...overrides
			};

			const res = await send(row);

			expect(res.status).toBe(403);
			expect(res.headers.get('x-auth-reason')).toBe('bad_mcp_header');
		}
	);

	it.each([
		['Mcp-Method', {}],
		['Mcp-Name', { otherTools: 'token' }],
		['MCP-Protocol-Version', { withoutMethod: 'token' }]
	] as const)(
		'a request that sends %s twice is refused, never read as some other value',
		async (header, table) => {
			const row: Row = {
				what: 'twice',
				scopes: 'files:read',
				mcpMethod: 'tools/call',
				mcpName: 'delete_file',
				table,
				status: 403,
				reason: 'bad_mcp_header'
			};

			const res = await send(row, { twice: [header] });

			expect(res.status).toBe(403);
			expect(res.headers.get('x-auth-reason')).toBe('bad_mcp_header');
		}
	);

	it.each([['tools/list'], ['tools/call']])(
		'a request whose protocol is older than 2026-07-28 follows the old-clients choice whatever its method: %s',
		async (mcpMethod) => {
			const row: Row = {
				what: 'old',
				scopes: 'files:read',
				mcpMethod,
				mcpName: 'search_files',
				protocolVersion: '2025-06-18',
				status: 403,
				reason: 'old_client'
			};

			const refusedByDefault = await send(row);
			const letIn = await send({
				...row,
				table: { ...TABLE, withoutMethod: 'token' }
			});

			expect(refusedByDefault.headers.get('x-auth-reason')).toBe('old_client');
			expect(letIn.status).toBe(200);
		}
	);

	describe('a change to a saved table', () => {
		it.each([
			[
				'a tool that needs fewer scopes',
				{
					...TABLE,
					rows: [
						TABLE.rows[0],
						{ name: 'delete_file', scopes: ['files:write'] }
					]
				},
				['delete_file no longer needs files:delete.']
			],
			[
				'a row removed while any other tool needs only a valid token',
				{ ...TABLE, rows: [TABLE.rows[0]], otherTools: 'token' as const },
				[
					'delete_file now needs only a valid token.',
					'Any tool not listed now needs only a valid token.'
				]
			],
			[
				'old clients let in',
				{ ...TABLE, withoutMethod: 'token' as const },
				[
					'Clients that do not say which tool they call are now let in with a valid token.'
				]
			],
			[
				'the table emptied',
				{ ...TABLE, rows: [] },
				['Every tool now needs only a valid token.']
			],
			[
				'a tool that needs more scopes, and a row removed while any other tool is refused',
				{
					...TABLE,
					rows: [
						{ name: 'search_files', scopes: ['files:read', 'files:write'] }
					]
				},
				[]
			]
		])('%s is reported as each widening it makes', (_what, after, expected) => {
			expect(toolWidenings(viewOf(TABLE), viewOf(after))).toEqual(expected);
		});
	});

	describe("a change to a tool's conditions", () => {
		const OPS: Condition = { kind: 'group', groupIds: ['ops'] };
		const HOURS: Condition = {
			kind: 'time',
			windows: [{ days: [0, 1, 2, 3, 4], start: 540, end: 1080 }]
		};
		const guarded = (
			conditions: ToolsTableView['rows'][number]['conditions'],
			otherTools: 'refuse' | 'token' = 'refuse',
			timeZone = 'UTC'
		): ToolsTableView => ({
			rows: [
				{
					name: 'delete_files',
					scopes: [],
					...(conditions ? { conditions } : {})
				}
			],
			otherTools,
			withoutMethod: 'refuse',
			access: { conditions: [], timeZone }
		});

		it.each<[string, ToolsTableView, ToolsTableView, string[]]>([
			[
				'a group removed from the tool',
				guarded([OPS, HOURS]),
				guarded([HOURS]),
				[
					'delete_files is no longer limited as strictly by the groups that may call it.'
				]
			],
			[
				'a wider window of hours',
				guarded([HOURS]),
				guarded([
					{
						kind: 'time',
						windows: [{ days: [0, 1, 2, 3, 4, 5, 6], start: 540, end: 1080 }]
					}
				]),
				[
					'delete_files is no longer limited as strictly by the hours it may be called in.'
				]
			],
			[
				'another time zone for a tool with hours',
				guarded([HOURS]),
				guarded([HOURS], 'refuse', 'Asia/Tokyo'),
				[
					'delete_files is no longer limited as strictly by the hours it may be called in.'
				]
			],
			[
				'a guarded tool removed while any other tool needs only a token',
				guarded([OPS], 'token'),
				{
					...guarded([OPS], 'token'),
					rows: [{ name: 'search_files', scopes: ['files:read'] }]
				},
				['delete_files now needs only a valid token.']
			],
			[
				'a condition added to a tool',
				guarded([HOURS]),
				guarded([OPS, HOURS]),
				[]
			],
			[
				'a new tool with a condition',
				guarded([OPS]),
				{
					...guarded([OPS]),
					rows: [
						...guarded([OPS]).rows,
						{ name: 'export_billing', scopes: [], conditions: [OPS] }
					]
				},
				[]
			]
		])(
			'%s is reported as each widening it makes',
			(_what, before, after, expected) => {
				expect(toolWidenings(before, after)).toEqual(expected);
			}
		);
	});
});
