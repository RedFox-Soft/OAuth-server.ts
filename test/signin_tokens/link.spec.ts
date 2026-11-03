import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	mock
} from 'bun:test';

import bootstrap from '../test_helper.js';
import { assertNoPendingInterceptors } from '../fetch_mock.js';
import { adminAuditStore, getBucketStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import type { ConnectedService } from 'lib/connected_services/types.ts';
import type { FederationProvider } from 'lib/federation/types.ts';
import { ADMIN_MCP_CLIENT_ID, MCP_RESOURCE } from 'lib/mcp/consts.ts';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { present } from '../shape.js';
import { TEST_KEYRING } from '../sealing/fixtures.ts';
import { createAdministrator } from '../administrators.ts';
import { cookieFor } from '../admin/ownership_fixtures.ts';
import { postMcp } from '../mcp/rpc.ts';
import { defaultBucket } from '../connected_apps/helpers.ts';
import { admin } from '../connected_services/harness.ts';
import { provider as federationProvider } from '../federation/harness.ts';

const SERVICES = `/admin/api/projects/${DEFAULT_BUCKET_ID}/connected-services`;
const ISSUER = 'https://idp-link.test';
const MICROSOFT = (tenant: string) =>
	`https://login.microsoftonline.com/${tenant}/v2.0`;

function service(
	id: string,
	fields: Partial<ConnectedService> = {}
): ConnectedService {
	return {
		id,
		kind: 'oidc',
		issuer: ISSUER,
		clientId: 'stub-client',
		clientSecret: 'stub-secret',
		scopes: ['files.read'],
		displayName: `Service ${id}`,
		createdAt: '',
		updatedAt: '',
		...fields
	};
}

function signIn(
	id: string,
	fields: Partial<FederationProvider> = {}
): FederationProvider {
	return federationProvider(ISSUER, {
		id,
		displayName: `Sign-in ${id}`,
		...fields
	});
}

async function project(
	providers: FederationProvider[],
	services: ConnectedService[]
): Promise<void> {
	await defaultBucket();
	await getBucketStore().update(DEFAULT_BUCKET_ID, {
		federation: providers,
		connectedServices: services
	});
}

async function stored(id: string): Promise<ConnectedService | undefined> {
	const bucket = present(
		await getBucketStore().find(DEFAULT_BUCKET_ID),
		'the project'
	);
	return bucket.connectedServices?.find((entry) => entry.id === id);
}

/**
 * @proves An administrator links a sign-in provider to a connected service only when both are the same provider with
 * the same registration and a keyring is in use, the link is audited and shown on both, and no later edit of the
 * provider can leave a link its tokens could not honour.
 */
describe('linking a sign-in provider to a connected service', () => {
	let cookie: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'signin_tokens' });
		cookie = await cookieFor(await createAdministrator('super'));
	});

	beforeEach(() => {
		resetKeyringForTests(TEST_KEYRING);
	});

	afterEach(() => {
		assertNoPendingInterceptors();
		mock.restore();
	});

	it('links a matching sign-in provider, shows the link on both and records it', async () => {
		await project([signIn('sso')], [service('files')]);

		const linked = await admin(cookie, 'PATCH', `${SERVICES}/files`, {
			signInProviderId: 'sso'
		});
		const provider = await admin(
			cookie,
			'GET',
			`/admin/api/projects/${DEFAULT_BUCKET_ID}/federation/sso`
		);

		expect(linked.status).toBe(200);
		expect(linked.json.signInProvider).toEqual({
			id: 'sso',
			displayName: 'Sign-in sso'
		});
		expect(provider.json.keepsTokensFor).toEqual({
			serviceId: 'files',
			displayName: 'Service files'
		});
		const { entries } = await adminAuditStore.list({
			targetId: DEFAULT_BUCKET_ID
		});
		expect(
			entries.find(
				(entry) =>
					entry.action === 'connected.service.update' &&
					entry.signInProviderId === 'sso'
			)
		).toBeDefined();
	});

	it('refuses a sign-in provider at another provider', async () => {
		await project(
			[signIn('elsewhere', { issuer: 'https://other-idp.test' })],
			[service('files')]
		);

		const answer = await admin(cookie, 'PATCH', `${SERVICES}/files`, {
			signInProviderId: 'elsewhere'
		});

		expect(answer.status).toBe(409);
		expect(answer.json.code).toBe('sign_in_provider_mismatch');
		expect((await stored('files'))?.signInProviderId).toBeUndefined();
	});

	it('refuses a sign-in provider with another client id', async () => {
		await project(
			[signIn('sso', { clientId: 'another-client' })],
			[service('files')]
		);

		const answer = await admin(cookie, 'PATCH', `${SERVICES}/files`, {
			signInProviderId: 'sso'
		});

		expect(answer.status).toBe(409);
		expect(answer.json.code).toBe('sign_in_provider_mismatch');
	});

	it('refuses a Microsoft sign-in provider admitting another tenant', async () => {
		await project(
			[
				federationProvider(MICROSOFT('organizations'), {
					id: 'ms',
					clientId: 'ms-client',
					tenant: 'organizations'
				})
			],
			[
				service('mail', {
					kind: 'catalogue',
					catalogueId: 'microsoft',
					issuer: undefined,
					tenant: 'contoso.example',
					clientId: 'ms-client'
				})
			]
		);

		const answer = await admin(cookie, 'PATCH', `${SERVICES}/mail`, {
			signInProviderId: 'ms'
		});

		expect(answer.status).toBe(409);
		expect(answer.json.code).toBe('sign_in_provider_mismatch');
	});

	it('refuses to link without a keyring, as declaring a service does', async () => {
		await project([signIn('sso')], [service('files')]);
		resetKeyringForTests(null);

		const answer = await admin(cookie, 'PATCH', `${SERVICES}/files`, {
			signInProviderId: 'sso'
		});

		expect(answer.status).toBe(409);
		expect(answer.json.code).toBe('keyring_required');
	});

	it('refuses a sign-in provider that already keeps tokens for another service', async () => {
		await project(
			[signIn('sso')],
			[service('files', { signInProviderId: 'sso' }), service('more')]
		);

		const answer = await admin(cookie, 'PATCH', `${SERVICES}/more`, {
			signInProviderId: 'sso'
		});

		expect(answer.status).toBe(409);
		expect(answer.json.code).toBe('sign_in_provider_taken');
	});

	it('refuses to link Slack, whose tokens never come from a sign-in', async () => {
		await project(
			[signIn('sso')],
			[
				service('chat', {
					kind: 'catalogue',
					catalogueId: 'slack',
					issuer: undefined
				})
			]
		);

		const answer = await admin(cookie, 'PATCH', `${SERVICES}/chat`, {
			signInProviderId: 'sso'
		});

		expect(answer.status).toBe(409);
		expect(answer.json.code).toBe('sign_in_provider_unlinkable');
	});

	it('removes the link when asked, and lists the providers that could be linked', async () => {
		await project(
			[
				signIn('sso'),
				signIn('elsewhere', { issuer: 'https://other-idp.test' })
			],
			[service('files', { signInProviderId: 'sso' })]
		);

		const answer = await admin(cookie, 'PATCH', `${SERVICES}/files`, {
			signInProviderId: null
		});

		expect(answer.status).toBe(200);
		expect(answer.json.signInProvider).toBeUndefined();
		expect(answer.json.linkableSignInProviders).toEqual([
			{ id: 'sso', displayName: 'Sign-in sso' }
		]);
		expect((await stored('files'))?.signInProviderId).toBeUndefined();
	});

	it('refuses an edit of a linked provider’s client id, naming the service', async () => {
		await project(
			[signIn('sso')],
			[service('files', { signInProviderId: 'sso' })]
		);

		const answer = await admin(
			cookie,
			'PATCH',
			`/admin/api/projects/${DEFAULT_BUCKET_ID}/federation/sso`,
			{ clientId: 'replaced-client' }
		);

		expect(answer.status).toBe(409);
		expect(answer.json.code).toBe('linked_to_service');
		expect(String(answer.json.message)).toContain('Service files');
	});

	it('removes the link with a deleted provider, says so in the trail and keeps the service', async () => {
		await project(
			[signIn('sso'), signIn('spare', { issuer: 'https://spare-idp.test' })],
			[service('files', { signInProviderId: 'sso' })]
		);

		const answer = await admin(
			cookie,
			'DELETE',
			`/admin/api/projects/${DEFAULT_BUCKET_ID}/federation/sso`
		);

		expect(answer.status).toBe(200);
		const kept = await stored('files');
		expect(kept).toBeDefined();
		expect(kept?.signInProviderId).toBeUndefined();
		const { entries } = await adminAuditStore.list({
			targetId: DEFAULT_BUCKET_ID
		});
		expect(
			entries.find(
				(entry) =>
					entry.action === 'federation.provider.delete' &&
					entry.unlinked === 'files'
			)
		).toBeDefined();
	});

	it('offers no link in the administrators’ project', async () => {
		const answer = await admin(
			cookie,
			'PATCH',
			`/admin/api/projects/${ADMIN_BUCKET_ID}/connected-services/any`,
			{ signInProviderId: 'sso' }
		);

		expect(answer.status).toBeGreaterThanOrEqual(400);
		expect(answer.status).not.toBe(200);
	});

	it('is the same for an agent through the MCP endpoint', async () => {
		await project([signIn('sso')], [service('files')]);
		ApplicationConfig['mcp.enabled'] = true;
		await ensureAdminSeed();
		const operator = await createAdministrator('super');
		const at = new AccessToken({
			client: await Client.find(ADMIN_MCP_CLIENT_ID),
			accountId: operator._id,
			scope: 'openid'
		});
		at.setAudience(MCP_RESOURCE);
		const token = await at.save();
		await postMcp(
			{
				jsonrpc: '2.0',
				id: 1,
				method: 'initialize',
				params: {
					protocolVersion: '2026-07-28',
					capabilities: {},
					clientInfo: { name: 'test-agent', version: '1.0.0' }
				}
			},
			token
		);

		await postMcp(
			{
				jsonrpc: '2.0',
				id: 2,
				method: 'tools/call',
				params: {
					name: 'connected_service_update',
					arguments: {
						id: DEFAULT_BUCKET_ID,
						serviceId: 'files',
						signInProviderId: 'sso'
					}
				}
			},
			token
		);

		expect((await stored('files'))?.signInProviderId).toBe('sso');
	});
});
