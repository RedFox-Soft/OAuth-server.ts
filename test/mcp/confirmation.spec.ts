import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	getUserStore,
	getProjectStore,
	adminAuditStore,
	mcpConfirmationStore
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import {
	ADMIN_MCP_CLIENT_ID,
	MCP_RESOURCE,
	MCP_ROUTE
} from 'lib/mcp/consts.ts';
import { mcpCatalogue } from 'lib/mcp/catalogue.ts';
import { ApplicationConfig } from 'lib/configs/application.js';

/*
 * The two-step gate on high-consequence operations.
 *
 * The property under test is that nothing high-consequence can be made to happen in one instruction —
 * because the whole reason the gate lives on the server, rather than as a prompt in the agent's own
 * interface, is that a client-side confirmation is not a control this server can rely on.
 */

let rpcId = 0;

async function rpc(body: unknown, token?: string) {
	const res = await elysia.handle(
		new Request(`http://e.ly${MCP_ROUTE}`, {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				accept: 'application/json, text/event-stream',
				...(token ? { authorization: `Bearer ${token}` } : {})
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
	const payload = isEvent
		? line
			? JSON.parse(line.slice('data:'.length).trim())
			: undefined
		: text
			? JSON.parse(text)
			: undefined;
	return { status: res.status, payload };
}

async function tokenFor(roles: string[]) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`conf-${roles.join('-')}-${Math.random()}@x.io`,
		'hash',
		roles
	);
	const at = new AccessToken({
		client: await Client.find(ADMIN_MCP_CLIENT_ID),
		accountId: user._id,
		scope: 'openid'
	});
	at.setAudience(MCP_RESOURCE);
	return { token: (await at.save()) as unknown as string, user };
}

async function session(roles: string[]) {
	const { token, user } = await tokenFor(roles);
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
	return { token, user };
}

function call(name: string, args: Record<string, unknown>) {
	return {
		jsonrpc: '2.0',
		id: ++rpcId,
		method: 'tools/call',
		params: { name, arguments: args }
	};
}

/* A project with one client in it, which is a legitimate target for client_delete. */
async function projectWithClient(token: string) {
	const project = await getProjectStore().create({
		name: 'Conf',
		slug: `conf-${Math.floor(Math.random() * 1e6)}`,
		ownerGroupId: UNASSIGNED_GROUP_ID
	});
	const created = await rpc(
		call('client_create', {
			id: project._id,
			clientName: 'Billing',
			grantTypes: ['authorization_code'],
			redirectUris: ['https://b.example.com/cb'],
			tokenEndpointAuthMethod: 'none'
		}),
		token
	);
	const body = created.payload.result?.structuredContent?.result as {
		clientId: string;
	};
	return { project, clientId: body.clientId };
}

describe('MCP confirmation gate', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		ApplicationConfig['mcp.enabled'] = true;
		await ensureAdminSeed();
	});

	it('classifies thirteen tools as high-consequence and declares the argument on each', () => {
		const high = mcpCatalogue.filter((t) => t.consequence === 'high');
		expect(high.length).toBe(13);
	});

	it('describes instead of acting, and changes nothing', async () => {
		const { token } = await session(['super_admin']);
		const { project, clientId } = await projectWithClient(token);

		const described = await rpc(
			call('client_delete', { id: project._id, clientId }),
			token
		);
		const structured = described.payload.result?.structuredContent;

		expect(described.payload.result?.isError).not.toBe(true);
		expect(structured?.status).toBe('confirmation_required');
		expect(structured?.confirmationToken).toBeString();
		expect(structured?.target).toContain(clientId);

		// Nothing happened: the client is still there.
		const still = await rpc(
			call('client_get', { id: project._id, clientId }),
			token
		);
		expect(still.payload.result?.isError).not.toBe(true);
	});

	it('writes no audit entry for the description', async () => {
		const { token, user } = await session(['super_admin']);
		const { project, clientId } = await projectWithClient(token);

		const before = await adminAuditStore.list({ actor: user._id });
		await rpc(call('client_delete', { id: project._id, clientId }), token);
		const after = await adminAuditStore.list({ actor: user._id });

		// The trail records actions applied. A step that deliberately applies nothing must not appear in
		// it, or a reader cannot tell a described deletion from a performed one.
		expect(after.total).toBe(before.total);
	});

	it('performs the operation when the token is presented back', async () => {
		const { token } = await session(['super_admin']);
		const { project, clientId } = await projectWithClient(token);

		const described = await rpc(
			call('client_delete', { id: project._id, clientId }),
			token
		);
		const confirmationToken =
			described.payload.result?.structuredContent?.confirmationToken;

		const performed = await rpc(
			call('client_delete', { id: project._id, clientId, confirmationToken }),
			token
		);
		expect(performed.payload.result?.isError).not.toBe(true);

		const gone = await rpc(
			call('client_get', { id: project._id, clientId }),
			token
		);
		expect(gone.payload.result?.isError).toBe(true);
	});

	it('refuses a replayed confirmation', async () => {
		const { token } = await session(['super_admin']);
		const { project, clientId } = await projectWithClient(token);

		const described = await rpc(
			call('client_delete', { id: project._id, clientId }),
			token
		);
		const confirmationToken =
			described.payload.result?.structuredContent?.confirmationToken;

		await rpc(
			call('client_delete', { id: project._id, clientId, confirmationToken }),
			token
		);
		const replayed = await rpc(
			call('client_delete', { id: project._id, clientId, confirmationToken }),
			token
		);

		expect(replayed.payload.result?.isError).toBe(true);
		expect(replayed.payload.result?.structuredContent?.failure).toBe(
			'unknown_or_spent'
		);
	});

	it('refuses a confirmation aimed at a different target', async () => {
		const { token } = await session(['super_admin']);
		const first = await projectWithClient(token);
		const second = await projectWithClient(token);

		const described = await rpc(
			call('client_delete', {
				id: first.project._id,
				clientId: first.clientId
			}),
			token
		);
		const confirmationToken =
			described.payload.result?.structuredContent?.confirmationToken;

		const misaimed = await rpc(
			call('client_delete', {
				id: second.project._id,
				clientId: second.clientId,
				confirmationToken
			}),
			token
		);

		expect(misaimed.payload.result?.isError).toBe(true);
		expect(misaimed.payload.result?.structuredContent?.failure).toBe(
			'wrong_target'
		);

		// And the second client still exists — the misaimed confirmation performed nothing.
		const still = await rpc(
			call('client_get', {
				id: second.project._id,
				clientId: second.clientId
			}),
			token
		);
		expect(still.payload.result?.isError).not.toBe(true);
	});

	it('refuses a confirmation issued for a different operation', async () => {
		const { token } = await session(['super_admin']);
		const { project, clientId } = await projectWithClient(token);

		const described = await rpc(
			call('client_delete', { id: project._id, clientId }),
			token
		);
		const confirmationToken =
			described.payload.result?.structuredContent?.confirmationToken;

		const wrongTool = await rpc(
			call('client_secret_rotate', {
				id: project._id,
				clientId,
				confirmationToken
			}),
			token
		);

		expect(wrongTool.payload.result?.isError).toBe(true);
		expect(wrongTool.payload.result?.structuredContent?.failure).toBe(
			'wrong_tool'
		);
	});

	it('refuses a confirmation issued to a different administrator', async () => {
		const alice = await session(['super_admin']);
		const bob = await session(['super_admin']);
		const { project, clientId } = await projectWithClient(alice.token);

		const described = await rpc(
			call('client_delete', { id: project._id, clientId }),
			alice.token
		);
		const confirmationToken =
			described.payload.result?.structuredContent?.confirmationToken;

		const byBob = await rpc(
			call('client_delete', { id: project._id, clientId, confirmationToken }),
			bob.token
		);

		expect(byBob.payload.result?.isError).toBe(true);
		expect(byBob.payload.result?.structuredContent?.failure).toBe(
			'wrong_principal'
		);
	});

	it('refuses when the parameters changed after the description', async () => {
		const { token } = await session(['super_admin']);
		const bucket = await rpc(
			call('bucket_create', { name: 'Conf bucket' }),
			token
		);
		const bucketId = (
			bucket.payload.result?.structuredContent?.result as { _id: string }
		)._id;
		const created = await rpc(
			call('bucket_user_create', {
				id: bucketId,
				email: `u-${Math.random()}@x.io`,
				password: 'correct horse battery staple'
			}),
			token
		);
		const uid = (
			created.payload.result?.structuredContent?.result as { _id: string }
		)._id;

		const described = await rpc(
			call('bucket_user_password_reset', {
				id: bucketId,
				uid,
				password: 'first proposed password'
			}),
			token
		);
		const confirmationToken =
			described.payload.result?.structuredContent?.confirmationToken;

		// Same tool, same target, different payload. This is the case a target-only binding would miss.
		const swapped = await rpc(
			call('bucket_user_password_reset', {
				id: bucketId,
				uid,
				password: 'something else entirely',
				confirmationToken
			}),
			token
		);

		expect(swapped.payload.result?.isError).toBe(true);
		expect(swapped.payload.result?.structuredContent?.failure).toBe(
			'arguments_changed'
		);
	});

	it('refuses a confirmation offered to an ordinary tool', async () => {
		const { token } = await session(['super_admin']);
		const refused = await rpc(
			call('project_create', {
				name: 'X',
				slug: `x-${Math.floor(Math.random() * 1e6)}`,
				confirmationToken: 'anything'
			}),
			token
		);
		/*
		 * Refused by the input schema, before the handler runs: an ordinary tool does not declare
		 * `confirmationToken`, and every tool schema is `additionalProperties: false`. That is stronger
		 * than a handler check — the operation cannot even be attempted — so the assertion is on the
		 * refusal, not on which layer produced it.
		 */
		expect(refused.payload.result?.isError).toBe(true);
		const text = refused.payload.result?.content?.[0]?.text ?? '';
		expect(text).toContain('project_create');
		expect(text).toContain('additional properties');
	});

	it('issues no confirmation to a caller who lacks the role', async () => {
		const { token } = await session(['project_admin']);
		const before = await mcpConfirmationStore.count();

		const refused = await rpc(call('jwks_generate', { alg: 'RS256' }), token);

		expect(refused.payload.result?.isError).toBe(true);
		expect(refused.payload.result?.structuredContent?.reason).toBe('forbidden');
		// No token handed out for an operation that could never be performed.
		expect(await mcpConfirmationStore.count()).toBe(before);
	});
});
