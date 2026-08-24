import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	getUserStore,
	getProjectStore,
	getBucketStore,
	adminSessionStore
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import {
	ADMIN_MCP_CLIENT_ID,
	MCP_RESOURCE,
	MCP_ROUTE
} from 'lib/mcp/consts.ts';
import { mcpCatalogue, pathArgName } from 'lib/mcp/catalogue.ts';
import { ApplicationConfig } from 'lib/configs/application.js';

/*
 * SC-002 / FR-025: an operator reading the agent's answer and the console side by side sees the same
 * facts.
 *
 * Asserted as an equality between the two surfaces rather than against a fixture, because a fixture only
 * records what the fields were on the day it was written. Driven from the catalogue, so a read published
 * later is compared without anyone extending this file — which is the same reason the secrecy sweep is
 * built that way.
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

async function principal() {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`par-${Math.random()}@x.io`,
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
	const session = await adminSessionStore.create({
		userId: user._id,
		bucketId: ADMIN_BUCKET_ID,
		tokens: {},
		ttlSeconds: 60,
		absoluteTtlSeconds: 3600
	});
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
	return { user, token, cookie: `${ADMIN_SESSION_COOKIE}=${session._id}` };
}

/* Fields that legitimately differ between two calls, so comparing them would only produce flakes. */
const VOLATILE = new Set(['updatedAt', 'createdAt']);

/*
 * The one field that SHOULD differ, and the only one: `whoami` names the acting agent, and there is no
 * agent on the console path. Asserted separately below rather than added to VOLATILE, because "these two
 * answers differ in exactly this way for exactly this reason" is a stronger statement than ignoring it.
 */
const AGENT_ONLY = 'viaClientId';

function stripVolatile(value: unknown): unknown {
	if (Array.isArray(value)) return value.map(stripVolatile);
	if (value && typeof value === 'object') {
		return Object.fromEntries(
			Object.entries(value as Record<string, unknown>)
				.filter(([k]) => !VOLATILE.has(k))
				.map(([k, v]) => [k, stripVolatile(v)])
		);
	}
	return value;
}

describe('agent answers match the console, field for field', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		ApplicationConfig['mcp.enabled'] = true;
		await ensureAdminSeed();
	});

	it('returns identical payloads for every read the catalogue publishes', async () => {
		const { token, cookie, user } = await principal();

		// Enough state that a read returning an empty collection cannot pass vacuously.
		const project = await getProjectStore().create({
			name: 'Parity',
			slug: `par-${Math.floor(Math.random() * 1e6)}`,
			managedBy: [user._id]
		});
		const bucket = await getBucketStore().create({ name: 'Parity bucket' });
		const created = await rpc(
			{
				jsonrpc: '2.0',
				id: ++rpcId,
				method: 'tools/call',
				params: {
					name: 'client_create',
					arguments: {
						id: project._id,
						clientName: 'Parity',
						grantTypes: ['authorization_code'],
						redirectUris: ['https://p.example.com/cb'],
						tokenEndpointAuthMethod: 'none'
					}
				}
			},
			token
		);
		const clientId = (
			created.result?.structuredContent?.result as { clientId: string }
		).clientId;
		const endUser = await getUserStore(bucket._id).create(
			`member-${Math.random()}@x.io`,
			'hash',
			[]
		);

		const ARGS: Record<string, Record<string, string>> = {
			project_get: { id: project._id },
			client_list: { id: project._id },
			client_get: { id: project._id, clientId },
			bucket_get: { id: bucket._id },
			bucket_user_list: { id: bucket._id },
			federation_provider_list: { id: bucket._id },
			federation_identity_list: { id: bucket._id, uid: endUser._id }
		};

		let compared = 0;

		for (const tool of mcpCatalogue.filter((t) => t.consequence === 'read')) {
			const args = ARGS[tool.tool] ?? {};
			if (
				tool.pathParams.some((p) => args[pathArgName(tool, p)] === undefined)
			) {
				continue;
			}

			// The same operation, over the console.
			let path = tool.path;
			for (const param of tool.pathParams) {
				path = path.replace(
					`:${param}`,
					encodeURIComponent(args[pathArgName(tool, param)])
				);
			}
			const httpRes = await elysia.handle(
				new Request(`http://e.ly${path}`, { headers: { cookie } })
			);
			expect(httpRes.status, `${tool.tool} failed over the console`).toBe(200);
			const viaConsole = await httpRes.json();

			const agentResponse = await rpc(
				{
					jsonrpc: '2.0',
					id: ++rpcId,
					method: 'tools/call',
					params: { name: tool.tool, arguments: args }
				},
				token
			);
			expect(
				agentResponse.result?.isError,
				`${tool.tool} errored over MCP`
			).not.toBe(true);
			const viaAgent = agentResponse.result?.structuredContent?.result;

			const agentPayload = stripVolatile(viaAgent) as Record<string, unknown>;
			const consolePayload = stripVolatile(viaConsole) as Record<
				string,
				unknown
			>;

			let comparable = agentPayload;
			if (tool.tool === 'whoami') {
				expect(agentPayload[AGENT_ONLY]).toBe(ADMIN_MCP_CLIENT_ID);
				expect(consolePayload[AGENT_ONLY]).toBeUndefined();
				// Rebuilt without the field rather than deleted from it: the payload is the assertion's
				// subject, and mutating it would make a later failure harder to read.
				comparable = Object.fromEntries(
					Object.entries(agentPayload).filter(([k]) => k !== AGENT_ONLY)
				);
			}

			expect(
				comparable,
				`${tool.tool} answered differently over the two surfaces`
			).toEqual(consolePayload);
			compared += 1;
		}

		// Guards the loop itself: a `continue` that silently skipped everything would otherwise pass.
		expect(compared).toBeGreaterThanOrEqual(12);
	});

	it('reports the same refusal for the same forbidden read', async () => {
		// The comparison has to hold for failures too, or an agent could be told "not found" where the
		// console says "forbidden" and an operator would chase the wrong thing.
		const user = await getUserStore(ADMIN_BUCKET_ID).create(
			`par-scoped-${Math.random()}@x.io`,
			'hash',
			['project_admin']
		);
		const at = new AccessToken({
			client: await Client.find(ADMIN_MCP_CLIENT_ID),
			accountId: user._id,
			scope: 'openid'
		});
		at.setAudience(MCP_RESOURCE);
		const token = (await at.save()) as unknown as string;
		const session = await adminSessionStore.create({
			userId: user._id,
			bucketId: ADMIN_BUCKET_ID,
			tokens: {},
			ttlSeconds: 60,
			absoluteTtlSeconds: 3600
		});
		const cookie = `${ADMIN_SESSION_COOKIE}=${session._id}`;

		const theirs = await getProjectStore().create({
			name: 'Not theirs',
			slug: `nt-${Math.floor(Math.random() * 1e6)}`,
			managedBy: []
		});

		const httpRes = await elysia.handle(
			new Request(`http://e.ly/admin/api/projects/${theirs._id}`, {
				headers: { cookie }
			})
		);
		const consoleBody = (await httpRes.json()) as { message?: string };

		const agentResponse = await rpc(
			{
				jsonrpc: '2.0',
				id: ++rpcId,
				method: 'tools/call',
				params: { name: 'project_get', arguments: { id: theirs._id } }
			},
			token
		);

		expect(httpRes.status).toBe(403);
		expect(agentResponse.result?.isError).toBe(true);
		expect(agentResponse.result?.structuredContent?.reason).toBe('forbidden');
		// The handler's own words reach the agent, not a rewritten summary.
		expect(agentResponse.result?.structuredContent?.message).toBe(
			consoleBody.message
		);
	});
});
