import { describe, it, expect, beforeAll, beforeEach, mock } from 'bun:test';

import bootstrap from '../test_helper.js';
import { eventBus, type ServerListener } from 'lib/event_bus.js';
import { elysia } from 'lib/index.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getProjectStore } from 'lib/adapters/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import {
	ADMIN_MCP_CLIENT_ID,
	MCP_RESOURCE,
	MCP_METADATA_ROUTE,
	MCP_ROUTE
} from 'lib/mcp/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { createAdministrator, type AdminKind } from '../administrators.ts';
import { Type } from '@sinclair/typebox';
import { present, shaped } from '../shape.ts';
import { postMcp } from './rpc.ts';

/*
 * End-to-end proof that the surface actually serves: a real MCP client protocol exchange over the real
 * mounted route, authenticated with a real audience-bound access token, reaching the real admin routes.
 *
 * Integration-first per Principle V: the assertions here are about what an agent observes, not about
 * the internals that produce it.
 */

let rpcId = 0;

/* One JSON-RPC request; `payload` is the checked message, absent when the answer carried none. */
async function mcp(
	method: string,
	params: Record<string, unknown> | undefined,
	token?: string
) {
	const { status, message } = await postMcp(
		{
			jsonrpc: '2.0',
			id: ++rpcId,
			method,
			...(params ? { params } : {})
		},
		token
	);
	return { status, payload: message };
}

/*
 * A tools/list POST read as plain HTTP, for what is not a JSON-RPC message: the challenge header an
 * agent acts on, and the status of a surface that is switched off.
 */
async function rawToolsList(token?: string) {
	return elysia.handle(
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
				method: 'tools/list',
				params: {}
			})
		})
	);
}

/* An access token of exactly the shape the token endpoint mints for `resource=<issuer>/mcp`. */
async function tokenFor(
	kind: AdminKind,
	overrides: Record<string, unknown> = {}
) {
	const user = await createAdministrator(
		kind,
		`mcp-${kind}-${Math.random()}@x.io`
	);
	const at = new AccessToken({
		client: await Client.find(ADMIN_MCP_CLIENT_ID),
		accountId: user._id,
		scope: 'openid',
		...overrides
	});
	at.setAudience(MCP_RESOURCE);
	return { token: await at.save(), user };
}

/**
 * @proves The agent surface is discoverable, refuses an unauthenticated or wrongly-audienced
 * call recoverably, scopes every read to the authorizing administrator, and is absent when
 * switched off.
 */
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
		const doc = shaped(
			Type.Object({
				resource: Type.String(),
				authorization_servers: Type.Array(Type.String())
			}),
			await res.json()
		);
		expect(doc.resource).toBe(MCP_RESOURCE);
		expect(doc.authorization_servers.length).toBeGreaterThan(0);
	});

	it('refuses an unauthenticated call with a 401 naming where to get a token', async () => {
		const { status, payload } = await mcp('tools/list', {});
		expect(status).toBe(401);
		const challenge =
			(await rawToolsList()).headers.get('www-authenticate') ?? '';
		expect(challenge).toContain('Bearer');
		expect(challenge).toContain('resource_metadata=');
		// Nothing about instance state, and no hint which check failed.
		expect(JSON.stringify(payload)).not.toContain('audience');
		// The body an MCP client can actually read, not a framework validation report.
		const message = present(payload, 'a JSON-RPC message');
		expect(message.jsonrpc).toBe('2.0');
		expect(message.error?.code).toBe(-32001);
	});

	/*
	 * A missing `authorization` is refused by the route's header schema, so the refusal starts life as
	 * a validation error and reaches the challenge only because the shared error handler hands `/mcp`
	 * validation down to this app's own onError. Both halves of that are asserted: the reason lands on
	 * the MCP channel, and nothing lands on the generic one — the handler's `mapErrorCode` has no
	 * `/mcp` entry, so an emit on the way past would file every credential-less call as a fault.
	 */
	it('reports a credential-less call on the MCP channel and not as a server_error', async () => {
		const refused = mock<ServerListener<'mcp.auth.error'>>();
		const faults = mock<ServerListener<'server_error'>>();
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
		const user = await createAdministrator(
			'super',
			`other-aud-${Math.random()}@x.io`
		);
		const at = new AccessToken({
			client: await Client.find(ADMIN_MCP_CLIENT_ID),
			accountId: user._id,
			scope: 'openid'
		});
		at.setAudience('https://somewhere.else.example/api');
		const token = await at.save();

		const { status } = await mcp('tools/list', {}, token);
		expect(status).toBe(401);
	});

	it('refuses a token with no audience at all', async () => {
		const user = await createAdministrator(
			'super',
			`no-aud-${Math.random()}@x.io`
		);
		const at = new AccessToken({
			client: await Client.find(ADMIN_MCP_CLIENT_ID),
			accountId: user._id,
			scope: 'openid'
		});
		const token = await at.save();

		const { status } = await mcp('tools/list', {}, token);
		expect(status).toBe(401);
	});

	it('completes an initialize handshake for an authorized administrator', async () => {
		const { token } = await tokenFor('super');
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
		expect(payload?.result?.serverInfo?.name).toBe('oauth-server-admin');
		// The withheld operations are announced up front rather than discovered by guessing.
		expect(payload?.result?.instructions).toContain('admin console');
	});

	it('lists the read tools and withholds the container deletions', async () => {
		const { token } = await tokenFor('super');
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

		const names = (payload?.result?.tools ?? []).map((t) => t.name);
		expect(names).toContain('project_list');
		expect(names).toContain('whoami');
		expect(names).toContain('audit_list');

		// FR-031: absent from the published surface, not merely refused when called.
		expect(names).not.toContain('project_delete');
		expect(names).not.toContain('bucket_delete');
	});

	it('answers whoami from the real admin route, as the authorizing administrator', async () => {
		const { token, user } = await tokenFor('super');
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
		expect(payload?.result?.isError).not.toBe(true);

		const structured = shaped(
			Type.Object({
				userId: Type.String(),
				superAdmin: Type.Boolean(),
				viaClientId: Type.String()
			}),
			payload?.result?.structuredContent?.result
		);
		expect(structured.userId).toBe(user._id);
		expect(structured.superAdmin).toBe(true);
		// The agent is recorded as the acting client, distinct from the administrator.
		expect(structured.viaClientId).toBe(ADMIN_MCP_CLIENT_ID);
	});

	it('scopes a read to what the administrator may see', async () => {
		const { token } = await tokenFor('plain');
		await getProjectStore().create({
			name: 'Not theirs',
			slug: `nt-${Math.floor(Math.random() * 1e6)}`,
			ownerGroupId: UNASSIGNED_GROUP_ID
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
		// Required, not defaulted: a refused or empty-handed call must not pass as an empty list.
		const projects = present(
			payload?.result?.structuredContent?.result,
			'the project list'
		);
		// A project administrator manages none of them, so the list is empty even though projects exist.
		expect(projects).toEqual([]);
	});

	it('refuses a super-admin-gated read to a non-super-administrator, as forbidden', async () => {
		const { token } = await tokenFor('plain');
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
		expect(payload?.result?.isError).toBe(true);
		expect(payload?.result?.structuredContent?.reason).toBe('forbidden');
	});

	it('is absent entirely when the capability is switched off', async () => {
		const { token } = await tokenFor('super');
		ApplicationConfig['mcp.enabled'] = false;

		// Not a JSON-RPC answer at all: the route is not there.
		const { status } = await rawToolsList(token);
		expect(status).toBe(404);

		const meta = await elysia.handle(
			new Request(`http://e.ly${MCP_METADATA_ROUTE}`)
		);
		expect(meta.status).toBe(404);
	});
});
