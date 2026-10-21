import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../../test_helper.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminAuditStore,
	getOutsideAuthorizationServerStore
} from 'lib/adapters/index.ts';
import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { outsideServerId } from 'lib/assertions/outside_server_id.ts';
import { ADMIN_MCP_CLIENT_ID, MCP_RESOURCE } from 'lib/mcp/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { shaped } from 'test/shape.js';
import { createAdministrator } from '../../administrators.ts';
import { sessionFor } from '../../admin_session.ts';
import {
	adminCookie,
	defaultBucket
} from '../../end_user_lifecycle/fixtures.ts';
import {
	defaultBucketWith,
	upstreamProvider
} from '../../global_token_revocation/helpers.ts';
import { admin } from '../../provisioning/helpers.ts';
import { rpc } from '../../mcp/rpc.ts';

const BASE = `/admin/api/projects/${DEFAULT_BUCKET_ID}`;

let rpcId = 0;

function call(name: string, args: Record<string, unknown>) {
	return {
		jsonrpc: '2.0',
		id: ++rpcId,
		method: 'tools/call',
		params: { name, arguments: args }
	};
}

async function agentToken(): Promise<{ token: string; userId: string }> {
	const user = await createAdministrator(
		'super',
		`parity-${Math.random()}@x.io`
	);
	const at = new AccessToken({
		client: await Client.find(ADMIN_MCP_CLIENT_ID),
		accountId: user._id,
		scope: 'openid'
	});
	at.setAudience(MCP_RESOURCE);
	const token = await at.save();
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
	return { token, userId: user._id };
}

function connectionBody(issuer: string) {
	return {
		issuer,
		displayName: 'Tickets',
		applications: [{ clientId: 'globex-agent', externalClientId: 'f53f191f' }],
		rules: [
			{
				appliesTo: 'everyone',
				apis: [{ identifier: 'https://mcp.tickets.example/', scopes: ['read'] }]
			}
		]
	};
}

const Stored = Type.Object({
	clients: Type.Array(Type.Unknown()),
	rules: Type.Array(Type.Unknown()),
	includeEmail: Type.Boolean()
});

/**
 * @proves An agent trusts a provider's assertions and connects outside authorization servers exactly as an
 * administrator does in the console — the same stored result, recorded in the trail under the administrator
 * and the agent — but only after confirming each, and nobody without the project's edit right can do either.
 */
describe('setting up enterprise-managed authorization through the console and an agent', () => {
	let cookie: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await defaultBucket();
		cookie = await adminCookie();
	});

	beforeEach(async () => {
		ApplicationConfig['mcp.enabled'] = true;
		await ensureAdminSeed();
		await defaultBucketWith([
			upstreamProvider('corp', 'https://corp.idp.test', {
				acceptsGlobalTokenRevocation: undefined
			})
		]);
	});

	it('records trusting a provider for assertions in the trail, naming the field', async () => {
		const res = await admin('PATCH', `${BASE}/federation/corp`, cookie, {
			acceptsIdentityAssertions: true
		});

		expect(res.status).toBe(200);
		const { entries } = await adminAuditStore.list({});
		expect(
			entries.find(
				(entry) =>
					entry.action === 'federation.provider.update' &&
					(entry.attributes ?? []).includes('acceptsIdentityAssertions')
			)
		).toBeDefined();
	});

	it('refuses to trust a second provider with the same issuer', async () => {
		await defaultBucketWith([
			upstreamProvider('corp', 'https://corp.idp.test', {
				acceptsGlobalTokenRevocation: undefined,
				acceptsIdentityAssertions: true
			}),
			upstreamProvider('corp-again', 'https://corp.idp.test', {
				acceptsGlobalTokenRevocation: undefined
			})
		]);

		const res = await admin('PATCH', `${BASE}/federation/corp-again`, cookie, {
			acceptsIdentityAssertions: true
		});

		expect(res.status).toBe(409);
	});

	it('asks an agent to confirm trusting a provider for assertions, then applies it', async () => {
		const { token } = await agentToken();
		const args = {
			id: DEFAULT_BUCKET_ID,
			providerId: 'corp',
			acceptsIdentityAssertions: true
		};

		const described = await rpc(
			call('federation_provider_update', args),
			token
		);
		const confirmationToken =
			described.result?.structuredContent?.confirmationToken;
		expect(described.result?.structuredContent?.status).toBe(
			'confirmation_required'
		);
		const applied = await rpc(
			call('federation_provider_update', { ...args, confirmationToken }),
			token
		);

		expect(applied.result?.isError).not.toBe(true);
	});

	it('stores what an agent connects exactly as what the console connects, under the administrator and the agent', async () => {
		const { token, userId } = await agentToken();
		await admin(
			'POST',
			`${BASE}/outside-authorization-servers`,
			cookie,
			connectionBody('https://as.console.example')
		);

		const args = {
			id: DEFAULT_BUCKET_ID,
			...connectionBody('https://as.agent.example')
		};
		const described = await rpc(
			call('outside_authorization_server_create', args),
			token
		);
		const confirmationToken =
			described.result?.structuredContent?.confirmationToken;
		await rpc(
			call('outside_authorization_server_create', {
				...args,
				confirmationToken
			}),
			token
		);

		const store = getOutsideAuthorizationServerStore();
		const viaConsole = shaped(
			Stored,
			await store.find(
				outsideServerId(DEFAULT_BUCKET_ID, 'https://as.console.example')
			)
		);
		const viaAgent = shaped(
			Stored,
			await store.find(
				outsideServerId(DEFAULT_BUCKET_ID, 'https://as.agent.example')
			)
		);
		const { clients, rules, includeEmail } = viaConsole;
		expect({
			clients: viaAgent.clients,
			rules: viaAgent.rules,
			includeEmail: viaAgent.includeEmail
		}).toEqual({ clients, rules, includeEmail });
		const { entries } = await adminAuditStore.list({ actor: userId });
		expect(
			entries.find((entry) => entry.action === 'outside.server.create')
				?.viaClientId
		).toBe(ADMIN_MCP_CLIENT_ID);
	});

	it('refuses an administrator without the project to connect an outside server, and stores nothing', async () => {
		const stranger = await createAdministrator('plain');
		const strangerCookie = `${ADMIN_SESSION_COOKIE}=${(await sessionFor(stranger))._id}`;

		const res = await admin(
			'POST',
			`${BASE}/outside-authorization-servers`,
			strangerCookie,
			connectionBody('https://as.stranger.example')
		);

		expect([403, 404]).toContain(res.status);
		expect(
			await getOutsideAuthorizationServerStore().find(
				outsideServerId(DEFAULT_BUCKET_ID, 'https://as.stranger.example')
			)
		).toBeNull();
	});
});
