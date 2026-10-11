import {
	describe,
	it,
	expect,
	beforeAll,
	beforeEach,
	afterEach
} from 'bun:test';

import bootstrap from '../test_helper.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	getBucketStore,
	adminAuditStore,
	getUserStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { ADMIN_MCP_CLIENT_ID, MCP_RESOURCE } from 'lib/mcp/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { mock } from '../fetch_mock.ts';
import { idpStub } from '../federation/idp_stub.ts';
import { shaped } from 'test/shape.js';
import { Type } from '@sinclair/typebox';
import { createAdministrator } from '../administrators.ts';
import { call, rpc } from './rpc.ts';

let rpcId = 0;

async function agentSession() {
	const user = await createAdministrator(
		'super',
		`console-providers-${Math.random()}@x.io`
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
	return { user, token };
}

function resultOf(response: { result?: { structuredContent?: unknown } }) {
	return shaped(
		Type.Record(Type.String(), Type.Unknown()),
		response.result?.structuredContent ?? {}
	);
}

const provider = (issuer: string, id: string) => ({
	id,
	displayName: 'Corp SSO',
	issuer,
	clientId: 'upstream-client',
	clientSecret: 'upstream-secret'
});

async function consoleProviders() {
	return (await getBucketStore().find(ADMIN_BUCKET_ID))?.federation ?? [];
}

/**
 * @proves An agent changes the console's own identity providers only by confirming each change, because
 * those providers decide who can sign in to the console, while the same change on an ordinary bucket
 * takes one call; and an agent can never turn password sign-in to the console off.
 */
describe("an agent and the console's identity providers", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		ApplicationConfig['mcp.enabled'] = true;
		resetAdminMemoryStores();
		await ensureAdminSeed();
	});

	afterEach(async () => {
		mock.restore();
		await getBucketStore().update(ADMIN_BUCKET_ID, {
			federation: [],
			passwordLogin: true
		});
	});

	it('a provider write on the Administrators bucket takes effect only on the confirmed second call', async () => {
		const { token } = await agentSession();
		const idp = await idpStub('https://idp-agent-console.test');
		idp.expectDiscovery();
		const args = {
			bucketId: ADMIN_BUCKET_ID,
			...provider(idp.origin, 'corp-sso')
		};

		const first = resultOf(
			await rpc(call('federation_provider_create', args), token)
		);
		expect(first.status).toBe('confirmation_required');
		expect(await consoleProviders()).toEqual([]);

		const second = await rpc(
			call('federation_provider_create', {
				...args,
				confirmationToken: first.confirmationToken
			}),
			token
		);
		expect(second.result?.isError ?? false).toBe(false);
		expect((await consoleProviders()).map((p) => p.id)).toEqual(['corp-sso']);
		const { entries } = await adminAuditStore.list({
			action: 'federation.provider.create',
			targetId: ADMIN_BUCKET_ID
		});
		expect(entries.map((entry) => entry.viaClientId)).toContain(
			ADMIN_MCP_CLIENT_ID
		);
	});

	it('the same write on an ordinary bucket takes effect in one call', async () => {
		const { token } = await agentSession();
		const idp = await idpStub('https://idp-agent-ordinary.test');
		idp.expectDiscovery();
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: `ordinary-${Math.random()}`,
			slug: `o-${Math.random().toString(36).slice(2, 10)}`
		});

		const response = await rpc(
			call('federation_provider_create', {
				bucketId: bucket._id,
				...provider(idp.origin, 'acme-sso')
			}),
			token
		);

		expect(response.result?.isError ?? false).toBe(false);
		expect(
			(await getBucketStore().find(bucket._id))?.federation.map((p) => p.id)
		).toEqual(['acme-sso']);
	});

	it('a confirmation issued for the Administrators bucket changes nothing elsewhere', async () => {
		const { token } = await agentSession();
		const idp = await idpStub('https://idp-agent-elsewhere.test');
		idp.expectDiscovery();
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: `elsewhere-${Math.random()}`,
			slug: `e-${Math.random().toString(36).slice(2, 10)}`
		});
		const first = resultOf(
			await rpc(
				call('federation_provider_create', {
					bucketId: ADMIN_BUCKET_ID,
					...provider(idp.origin, 'corp-sso')
				}),
				token
			)
		);

		const spent = await rpc(
			call('federation_provider_create', {
				bucketId: bucket._id,
				...provider(idp.origin, 'corp-sso'),
				confirmationToken: first.confirmationToken
			}),
			token
		);

		expect(spent.result?.isError).toBe(true);
		expect((await getBucketStore().find(bucket._id))?.federation).toEqual([]);
	});

	/*
	 * Everything a person would need is in place — an enabled provider, the administrator linked there —
	 * so what refuses it is that an agent's request never signed in through a provider.
	 */
	it('an agent cannot turn password sign-in to the console off', async () => {
		const { token, user } = await agentSession();
		await getBucketStore().update(ADMIN_BUCKET_ID, {
			federation: [
				{
					...provider('https://idp-agent-off.test', 'corp-sso'),
					enabled: true,
					scopes: ['openid', 'email'],
					emailTrusted: true,
					provisioning: 'existing_only',
					allowedEmailDomains: [],
					emailClaim: 'email'
				}
			]
		});
		await getUserStore(ADMIN_BUCKET_ID).update(user._id, {
			federated: [
				{ providerId: 'corp-sso', sub: 'agent-owner', linkedAt: new Date() }
			]
		});

		const response = await rpc(
			call('bucket_update', { id: ADMIN_BUCKET_ID, passwordLogin: false }),
			token
		);

		expect(response.result?.isError).toBe(true);
		expect((await getBucketStore().find(ADMIN_BUCKET_ID))?.passwordLogin).toBe(
			true
		);
	});
});
