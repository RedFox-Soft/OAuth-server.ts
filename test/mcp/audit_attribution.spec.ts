import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	getUserStore,
	adminSessionStore,
	adminAuditStore
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import {
	ADMIN_MCP_CLIENT_ID,
	MCP_RESOURCE,
	MCP_ROUTE
} from 'lib/mcp/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';

/*
 * Agent attribution in the audit trail.
 *
 * The constitution requires an AI agent's action to be attributable to the agent *and* the authorizing
 * principal. The test that matters is not that a field is populated, but that an investigator reading
 * the trail can tell an agent-initiated change from a console one — and can still see which
 * administrator authorized it.
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

async function adminAndToken() {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`attr-${Math.random()}@x.io`,
		'hash',
		['super_admin']
	);
	const at = new AccessToken({
		client: await Client.find(ADMIN_MCP_CLIENT_ID),
		accountId: user._id,
		scope: 'openid'
	});
	at.setAudience(MCP_RESOURCE);
	const token = (await at.save()) as unknown as string;
	await rpc(
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
	return { user, token };
}

async function cookieFor(userId: string) {
	const s = await adminSessionStore.create({
		userId,
		bucketId: ADMIN_BUCKET_ID,
		activeGroupId: UNASSIGNED_GROUP_ID,
		tokens: {},
		ttlSeconds: 60,
		absoluteTtlSeconds: 3600
	});
	return `${ADMIN_SESSION_COOKIE}=${s._id}`;
}

function slug() {
	return `attr-${Math.floor(Math.random() * 1e6)}`;
}

describe('MCP audit attribution', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		ApplicationConfig['mcp.enabled'] = true;
		await ensureAdminSeed();
	});

	it('names the administrator as actor and the agent alongside them', async () => {
		const { user, token } = await adminAndToken();

		await rpc(
			{
				jsonrpc: '2.0',
				id: ++rpcId,
				method: 'tools/call',
				params: {
					name: 'project_create',
					arguments: { name: 'Attributed', slug: slug() }
				}
			},
			token
		);

		const { entries } = await adminAuditStore.list({ actor: user._id });
		expect(entries.length).toBe(1);
		const entry = entries[0];

		// The actor is still the person. The agent is recorded as well, never instead.
		expect(entry.actorId).toBe(user._id);
		expect(entry.actorEmail).toBe(user.email);
		expect(entry.viaClientId).toBe(ADMIN_MCP_CLIENT_ID);
		expect(entry.viaSurface).toBe('mcp');
		expect(entry.action).toBe('project.create');
		expect(entry.targetType).toBe('Project');
	});

	it('records a console action with no surface, so absence means console', async () => {
		const { user } = await adminAndToken();
		const cookie = await cookieFor(user._id);

		const res = await elysia.handle(
			new Request('http://e.ly/admin/api/projects', {
				method: 'POST',
				headers: { 'content-type': 'application/json', cookie },
				body: JSON.stringify({ name: 'Console made', slug: slug() })
			})
		);
		expect(res.status).toBe(201);

		const { entries } = await adminAuditStore.list({ actor: user._id });
		expect(entries.length).toBe(1);
		// Absent rather than set to 'console': that is what makes the entries written before agents
		// existed still correct, with no backfill.
		expect(entries[0].viaSurface ?? null).toBeNull();
		expect(entries[0].viaClientId ?? null).toBeNull();
	});

	it('records the same action, target type and target for either surface', async () => {
		const viaAgent = await adminAndToken();
		await rpc(
			{
				jsonrpc: '2.0',
				id: ++rpcId,
				method: 'tools/call',
				params: {
					name: 'project_create',
					arguments: { name: 'A', slug: slug() }
				}
			},
			viaAgent.token
		);

		const viaConsole = await adminAndToken();
		const cookie = await cookieFor(viaConsole.user._id);
		await elysia.handle(
			new Request('http://e.ly/admin/api/projects', {
				method: 'POST',
				headers: { 'content-type': 'application/json', cookie },
				body: JSON.stringify({ name: 'B', slug: slug() })
			})
		);

		const agentEntry = (
			await adminAuditStore.list({ actor: viaAgent.user._id })
		).entries[0];
		const consoleEntry = (
			await adminAuditStore.list({ actor: viaConsole.user._id })
		).entries[0];

		// Indistinguishable in what was done; distinguishable only in who else was involved.
		expect(agentEntry.action).toBe(consoleEntry.action);
		expect(agentEntry.targetType).toBe(consoleEntry.targetType);
		expect(agentEntry.attributes).toEqual(consoleEntry.attributes);
	});

	it('filters the trail by surface, in both directions', async () => {
		const viaAgent = await adminAndToken();
		await rpc(
			{
				jsonrpc: '2.0',
				id: ++rpcId,
				method: 'tools/call',
				params: {
					name: 'project_create',
					arguments: { name: 'Agent one', slug: slug() }
				}
			},
			viaAgent.token
		);

		const viaConsole = await adminAndToken();
		const cookie = await cookieFor(viaConsole.user._id);
		await elysia.handle(
			new Request('http://e.ly/admin/api/projects', {
				method: 'POST',
				headers: { 'content-type': 'application/json', cookie },
				body: JSON.stringify({ name: 'Console one', slug: slug() })
			})
		);

		const agentOnly = await adminAuditStore.list({ viaSurface: 'mcp' });
		expect(agentOnly.entries.length).toBeGreaterThan(0);
		expect(agentOnly.entries.every((e) => e.viaSurface === 'mcp')).toBe(true);
		expect(agentOnly.entries.some((e) => e.actorId === viaAgent.user._id)).toBe(
			true
		);
		expect(
			agentOnly.entries.some((e) => e.actorId === viaConsole.user._id)
		).toBe(false);

		// 'console' is the absence of the field, not a stored value — the filter has to translate.
		const consoleOnly = await adminAuditStore.list({ viaSurface: 'console' });
		expect(
			consoleOnly.entries.some((e) => e.actorId === viaConsole.user._id)
		).toBe(true);
		expect(
			consoleOnly.entries.some((e) => e.actorId === viaAgent.user._id)
		).toBe(false);
	});

	it('filters by the acting agent', async () => {
		const { user, token } = await adminAndToken();
		await rpc(
			{
				jsonrpc: '2.0',
				id: ++rpcId,
				method: 'tools/call',
				params: {
					name: 'project_create',
					arguments: { name: 'By agent', slug: slug() }
				}
			},
			token
		);

		const byAgent = await adminAuditStore.list({
			viaClientId: ADMIN_MCP_CLIENT_ID
		});
		expect(byAgent.entries.some((e) => e.actorId === user._id)).toBe(true);

		const byOther = await adminAuditStore.list({
			viaClientId: 'some-other-agent'
		});
		expect(byOther.entries.some((e) => e.actorId === user._id)).toBe(false);
	});

	it('refuses a mistyped filter rather than answering the unfiltered trail', async () => {
		const { user } = await adminAndToken();
		const cookie = await cookieFor(user._id);

		const res = await elysia.handle(
			new Request('http://e.ly/admin/api/audit?viaSurfce=mcp', {
				headers: { cookie }
			})
		);

		// The one surface whose purpose is to be trusted about what happened must not answer a
		// narrower question with a broader answer.
		expect(res.status).toBe(422);
		/*
		 * Which layer refuses it is not the point and is not asserted: an undeclared query parameter is
		 * caught by request validation here, and by the route's own raw-URL check when validation lets one
		 * through. What must hold is that a narrower question is never answered with a broader answer, and
		 * that the refusal names the parameter so an operator can fix their filter.
		 */
		const body = JSON.stringify(await res.json());
		expect(body).toContain('viaSurfce');
	});
});
