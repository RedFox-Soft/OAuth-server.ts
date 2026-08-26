import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { errorStore, getUserStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import {
	ADMIN_MCP_CLIENT_ID,
	MCP_RESOURCE,
	MCP_ROUTE
} from 'lib/mcp/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.js';

/*
 * US5 — the agent's view of recorded faults.
 *
 * The reads exist to be identical to the console's, which they are by construction: every tool
 * re-dispatches through the same admin route, forwarding the agent's own token, so `assertRole` in the
 * handler *is* the agent's authorization check. What is worth testing is therefore not that the reads
 * work but that the purge is withheld by default and says why — and that a preview stays available
 * either way, because reading the consequence of a deletion is not destructive.
 */
let rpcId = 0;

async function rpc(body: unknown, token: string) {
	const res = await elysia.handle(
		new Request(`http://e.ly${MCP_ROUTE}`, {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				accept: 'application/json, text/event-stream',
				authorization: `Bearer ${token}`
			},
			body: JSON.stringify(body)
		})
	);
	const text = await res.text();
	const isEvent = (res.headers.get('content-type') ?? '').includes(
		'text/event-stream'
	);
	const line = isEvent
		? text.split('\n').find((l) => l.startsWith('data:'))
		: undefined;
	return isEvent
		? line
			? JSON.parse(line.slice('data:'.length).trim())
			: undefined
		: text
			? JSON.parse(text)
			: undefined;
}

function call(name: string, args: Record<string, unknown> = {}) {
	return {
		jsonrpc: '2.0',
		id: ++rpcId,
		method: 'tools/call',
		params: { name, arguments: args }
	};
}

async function agentFor(roles: string[]) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`et-${Math.random()}@x.io`,
		'hash',
		roles
	);
	const at = new AccessToken({
		client: await Client.find(ADMIN_MCP_CLIENT_ID),
		accountId: user._id,
		scope: 'openid'
	});
	at.setAudience(MCP_RESOURCE);
	const token = (await at.save()) as unknown as string;
	const init = await rpc(
		{
			jsonrpc: '2.0',
			id: ++rpcId,
			method: 'initialize',
			params: {
				protocolVersion: '2026-07-28',
				capabilities: {},
				clientInfo: { name: 'test-agent', version: '1.0.0' }
			}
		},
		token
	);
	return { user, token, init };
}

let seq = 0;
const unique = (prefix: string) => `${prefix}-${Date.now()}-${(seq += 1)}`;

async function seedFault(route: string) {
	return errorStore.record(
		{
			fingerprint: unique('fp'),
			errorCode: 'server_error',
			status: 500,
			surface: 'oauth',
			route,
			method: 'POST',
			origin: { file: 'lib/x.ts', line: 1, frame: 'f()' },
			message: 'seeded for the agent',
			record: {
				reference: unique('err'),
				at: new Date(),
				clientId: null,
				actor: null,
				scope: null,
				requestId: null,
				origin: null,
				userAgent: null,
				submittedFields: []
			}
		},
		{ retentionDays: 30, maxGroups: 1000, samplesPerGroup: 10 }
	);
}

/*
 * A read tool returns its payload as JSON in the text content — that is what an agent reads, so it is
 * what this asserts against rather than the structured mirror, which reads do not populate.
 */
function payload(result: unknown): Record<string, unknown> {
	const r = result as { content?: { type: string; text?: string }[] };
	const text = r.content?.find((part) => part.type === 'text')?.text;
	return text ? (JSON.parse(text) as Record<string, unknown>) : {};
}

describe('error store tools over MCP', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		ApplicationConfig['mcp.enabled'] = true;
		ApplicationConfig['errorStore.enabled'] = true;
		await ensureAdminSeed();
	});

	it('publishes the five reads and never the purge', async () => {
		const { token } = await agentFor(['super_admin']);
		const listed = await rpc(
			{ jsonrpc: '2.0', id: ++rpcId, method: 'tools/list', params: {} },
			token
		);
		const names: string[] = (listed.result?.tools ?? []).map(
			(t: { name: string }) => t.name
		);

		for (const tool of [
			'error_list',
			'error_get',
			'error_summary',
			'error_by_reference',
			'error_purge_preview'
		]) {
			expect(names).toContain(tool);
		}
		// FR-031's rule: absence from the published set, not a tool that refuses when called.
		expect(names).not.toContain('error_purge');
	});

	it('lets an agent read what is failing', async () => {
		const { token } = await agentFor(['super_admin']);
		const route = unique('/agent-read');
		await seedFault(route);

		const listed = await rpc(call('error_list', { route }), token);
		expect(payload(listed.result).total).toBe(1);

		const summary = await rpc(call('error_summary'), token);
		expect(typeof payload(summary.result).total).toBe('number');
	});

	it('refuses every error tool for a principal without the privilege', async () => {
		const { token } = await agentFor(['project_admin']);

		for (const tool of ['error_list', 'error_summary', 'error_purge_preview']) {
			const result = await rpc(call(tool), token);
			// Refused exactly as the console refuses the same principal — same handler, same assertRole.
			expect(JSON.stringify(result)).toContain('super_admin');
		}
	});

	describe('the purge', () => {
		/*
		 * Not callable at all, which is the stronger form: a withheld operation is absent from the
		 * published surface rather than registered as a tool that refuses, because a registered tool
		 * appears in `tools/list` however it behaves. The transport therefore answers "not found" — and the
		 * knowledge an operator needs (that it is withheld, and where to do it instead) lives in the server
		 * instructions, asserted below, rather than in this error.
		 */
		it('is not callable at all while withheld', async () => {
			const { token } = await agentFor(['super_admin']);
			const result = await rpc(call('error_purge', { route: '/x' }), token);

			expect(result.error?.message ?? '').toContain('not found');
			expect(result.result).toBeUndefined();
		});

		// Reading the consequence of a deletion is not destructive, so it stays available either way.
		it('still previews what a purge would remove', async () => {
			const { token } = await agentFor(['super_admin']);
			const route = unique('/agent-preview');
			await seedFault(route);

			const result = await rpc(call('error_purge_preview', { route }), token);
			expect(payload(result.result).groups).toBe(1);
			// And nothing went.
			expect((await errorStore.list({ route })).total).toBe(1);
		});

		it('destroys nothing while withheld, however it is asked', async () => {
			const { token } = await agentFor(['super_admin']);
			const route = unique('/agent-insist');
			await seedFault(route);

			await rpc(call('error_purge', { route }), token);
			await rpc(
				call('error_purge', { route, confirmationToken: 'invented' }),
				token
			);

			expect((await errorStore.list({ route })).total).toBe(1);
		});

		it('announces the withheld purge in the server instructions', async () => {
			const { init } = await agentFor(['super_admin']);
			const instructions: string = init.result?.instructions ?? '';

			// So an agent can say where to do it instead, without a tool to discover the absence from.
			expect(instructions.toLowerCase()).toContain('purg');
			expect(instructions).toContain('admin console');
		});
	});

	/*
	 * No credential value can reach an agent through a fault, because none is stored — asserted at this
	 * surface too, since the agent reads the same records by a different path.
	 */
	it('exposes no credential value through a fault', async () => {
		const { token } = await agentFor(['super_admin']);
		const route = unique('/agent-secrets');
		await seedFault(route);

		const listed = await rpc(call('error_list', { route }), token);
		const text = JSON.stringify(listed);

		expect(text).not.toContain('client_secret=');
		expect(text).not.toContain('Bearer ');
	});
});
