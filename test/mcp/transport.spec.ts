import { describe, it, expect, beforeAll, beforeEach, mock } from 'bun:test';

import bootstrap from '../test_helper.js';
import { eventBus } from 'lib/event_bus.js';
import { elysia } from 'lib/index.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getUserStore, getProjectStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import {
	ADMIN_MCP_CLIENT_ID,
	MCP_RESOURCE,
	MCP_METADATA_ROUTE,
	MCP_ROUTE
} from 'lib/mcp/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.js';

/*
 * End-to-end proof that the surface actually serves: a real MCP client protocol exchange over the real
 * mounted route, authenticated with a real audience-bound access token, reaching the real admin routes.
 *
 * Integration-first per Principle V: the assertions here are about what an agent observes, not about
 * the internals that produce it.
 */

let rpcId = 0;

async function mcp(
	method: string,
	params: Record<string, unknown> | undefined,
	token?: string
) {
	const res = await elysia.handle(
		new Request(`http://e.ly${MCP_ROUTE}`, {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				accept: 'application/json, text/event-stream',
				...(token ? { authorization: `Bearer ${token}` } : {})
			},
			body: JSON.stringify({
				jsonrpc: '2.0',
				id: ++rpcId,
				method,
				...(params ? { params } : {})
			})
		})
	);
	const text = await res.text();
	/*
	 * Streamable HTTP answers a single request either as JSON or as one SSE event, depending on what the
	 * client accepted — and the SSE form arrives as `event: message\ndata: {...}`. The test cares about
	 * the JSON-RPC payload either way, so unwrap the event when that is what came back.
	 */
	const isEventStream = (res.headers.get('content-type') ?? '').includes(
		'text/event-stream'
	);
	let payload;
	if (isEventStream) {
		const line = text.split('\n').find((l) => l.startsWith('data:'));
		payload = line ? JSON.parse(line.slice('data:'.length).trim()) : undefined;
	} else {
		payload = text ? JSON.parse(text) : undefined;
	}
	return { status: res.status, headers: res.headers, payload };
}

/* An access token of exactly the shape the token endpoint mints for `resource=<issuer>/mcp`. */
async function tokenFor(
	roles: string[],
	overrides: Record<string, unknown> = {}
) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`mcp-${roles.join('-')}-${Math.random()}@x.io`,
		'hash',
		roles
	);
	const at = new AccessToken({
		client: await Client.find(ADMIN_MCP_CLIENT_ID),
		accountId: user._id,
		scope: 'openid',
		...overrides
	});
	at.setAudience(MCP_RESOURCE);
	const value = await at.save();
	return { token: value as unknown as string, user };
}

describe('MCP transport', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		ApplicationConfig['mcp.enabled'] = true;
		await ensureAdminSeed();
	});

	it('publishes RFC 9728 protected resource metadata at the path-aware well-known URL', async () => {
		const res = await elysia.handle(
			new Request(`http://e.ly${MCP_METADATA_ROUTE}`)
		);
		expect(res.status).toBe(200);
		const doc = await res.json();
		expect(doc.resource).toBe(MCP_RESOURCE);
		expect(doc.authorization_servers).toBeArray();
		expect(doc.authorization_servers.length).toBeGreaterThan(0);
	});

	it('refuses an unauthenticated call with a 401 naming where to get a token', async () => {
		const { status, headers, payload } = await mcp('tools/list', {});
		expect(status).toBe(401);
		const challenge = headers.get('www-authenticate') ?? '';
		expect(challenge).toContain('Bearer');
		expect(challenge).toContain('resource_metadata=');
		// Nothing about instance state, and no hint which check failed.
		expect(JSON.stringify(payload)).not.toContain('audience');
		// The body an MCP client can actually read, not a framework validation report.
		expect(payload.jsonrpc).toBe('2.0');
		expect(payload.error?.code).toBe(-32001);
	});

	/*
	 * A missing `authorization` is refused by the route's header schema, so the refusal starts life as
	 * a validation error and reaches the challenge only because the shared error handler hands `/mcp`
	 * validation down to this app's own onError. Both halves of that are asserted: the reason lands on
	 * the MCP channel, and nothing lands on the generic one — the handler's `mapErrorCode` has no
	 * `/mcp` entry, so an emit on the way past would file every credential-less call as a fault.
	 */
	it('reports a credential-less call on the MCP channel and not as a server_error', async () => {
		const refused = mock();
		const faults = mock();
		eventBus.on('mcp.auth.error', refused);
		eventBus.on('server_error', faults);

		try {
			const { status } = await mcp('tools/list', {});
			expect(status).toBe(401);
			expect(refused).toHaveBeenCalledTimes(1);
			expect(refused.mock.calls[0]?.[0]).toEqual({ reason: 'no_credential' });
			expect(faults).not.toHaveBeenCalled();
		} finally {
			eventBus.off('mcp.auth.error', refused);
			eventBus.off('server_error', faults);
		}
	});

	it('refuses a token minted for another audience', async () => {
		const user = await getUserStore(ADMIN_BUCKET_ID).create(
			`other-aud-${Math.random()}@x.io`,
			'hash',
			['super_admin']
		);
		const at = new AccessToken({
			client: await Client.find(ADMIN_MCP_CLIENT_ID),
			accountId: user._id,
			scope: 'openid'
		});
		at.setAudience('https://somewhere.else.example/api');
		const token = (await at.save()) as unknown as string;

		const { status } = await mcp('tools/list', {}, token);
		expect(status).toBe(401);
	});

	it('refuses a token with no audience at all', async () => {
		const user = await getUserStore(ADMIN_BUCKET_ID).create(
			`no-aud-${Math.random()}@x.io`,
			'hash',
			['super_admin']
		);
		const at = new AccessToken({
			client: await Client.find(ADMIN_MCP_CLIENT_ID),
			accountId: user._id,
			scope: 'openid'
		});
		const token = (await at.save()) as unknown as string;

		const { status } = await mcp('tools/list', {}, token);
		expect(status).toBe(401);
	});

	it('completes an initialize handshake for an authorized administrator', async () => {
		const { token } = await tokenFor(['super_admin']);
		const { status, payload } = await mcp(
			'initialize',
			{
				protocolVersion: '2026-07-28',
				capabilities: {},
				clientInfo: { name: 'test-agent', version: '1.0.0' }
			},
			token
		);
		expect(status).toBe(200);
		expect(payload.result?.serverInfo?.name).toBe('oauth-server-admin');
		// The withheld operations are announced up front rather than discovered by guessing.
		expect(payload.result?.instructions).toContain('admin console');
	});

	it('lists the read tools and withholds the container deletions', async () => {
		const { token } = await tokenFor(['super_admin']);
		await mcp(
			'initialize',
			{
				protocolVersion: '2026-07-28',
				capabilities: {},
				clientInfo: { name: 'test-agent', version: '1.0.0' }
			},
			token
		);
		const { status, payload } = await mcp('tools/list', {}, token);
		expect(status).toBe(200);

		const names: string[] = (payload.result?.tools ?? []).map(
			(t: { name: string }) => t.name
		);
		expect(names).toContain('project_list');
		expect(names).toContain('whoami');
		expect(names).toContain('audit_list');

		// FR-031: absent from the published surface, not merely refused when called.
		expect(names).not.toContain('project_delete');
		expect(names).not.toContain('bucket_delete');
	});

	it('answers whoami from the real admin route, as the authorizing administrator', async () => {
		const { token, user } = await tokenFor(['super_admin']);
		await mcp(
			'initialize',
			{
				protocolVersion: '2026-07-28',
				capabilities: {},
				clientInfo: { name: 'test-agent', version: '1.0.0' }
			},
			token
		);
		const { status, payload } = await mcp(
			'tools/call',
			{ name: 'whoami', arguments: {} },
			token
		);
		expect(status).toBe(200);
		expect(payload.result?.isError).not.toBe(true);

		const structured = payload.result?.structuredContent?.result;
		expect(structured?.userId).toBe(user._id);
		expect(structured?.roles).toContain('super_admin');
		// The agent is recorded as the acting client, distinct from the administrator.
		expect(structured?.viaClientId).toBe(ADMIN_MCP_CLIENT_ID);
	});

	it('scopes a read to what the administrator may see', async () => {
		const { token } = await tokenFor(['project_admin']);
		await getProjectStore().create({
			name: 'Not theirs',
			slug: `nt-${Math.floor(Math.random() * 1e6)}`,
			managedBy: []
		});
		await mcp(
			'initialize',
			{
				protocolVersion: '2026-07-28',
				capabilities: {},
				clientInfo: { name: 'test-agent', version: '1.0.0' }
			},
			token
		);
		const { payload } = await mcp(
			'tools/call',
			{ name: 'project_list', arguments: {} },
			token
		);
		const projects = payload.result?.structuredContent?.result ?? [];
		// A project_admin manages none of them, so the list is empty even though projects exist.
		expect(projects).toEqual([]);
	});

	it('refuses a super-admin-gated read to a non-super-administrator, as forbidden', async () => {
		const { token } = await tokenFor(['project_admin']);
		await mcp(
			'initialize',
			{
				protocolVersion: '2026-07-28',
				capabilities: {},
				clientInfo: { name: 'test-agent', version: '1.0.0' }
			},
			token
		);
		const { payload } = await mcp(
			'tools/call',
			{ name: 'admin_list', arguments: {} },
			token
		);
		expect(payload.result?.isError).toBe(true);
		expect(payload.result?.structuredContent?.reason).toBe('forbidden');
	});

	it('is absent entirely when the capability is switched off', async () => {
		const { token } = await tokenFor(['super_admin']);
		ApplicationConfig['mcp.enabled'] = false;

		const { status } = await mcp('tools/list', {}, token);
		expect(status).toBe(404);

		const meta = await elysia.handle(
			new Request(`http://e.ly${MCP_METADATA_ROUTE}`)
		);
		expect(meta.status).toBe(404);
	});
});
