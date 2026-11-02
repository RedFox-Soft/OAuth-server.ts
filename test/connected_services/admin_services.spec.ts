import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it
} from 'bun:test';

import bootstrap from '../test_helper.ts';
import { assertNoPendingInterceptors } from '../fetch_mock.js';
import { adminAuditStore, getBucketStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import { SECRET_MASK } from 'lib/federation/consts.ts';
import { forgetAllDiscovery } from 'lib/federation/discovery.ts';
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { SEALED_PREFIX } from 'lib/sealing/seal.ts';
import { TEST_KEYRING } from '../sealing/fixtures.ts';
import { admin, projectAdministrator } from './harness.ts';
import { oidcStub } from './stubs.ts';
import { createAdministrator } from '../administrators.ts';
import { cookieFor } from '../admin/ownership_fixtures.ts';

const github = {
	kind: 'catalogue',
	catalogueId: 'github',
	clientId: 'Ov23liProjectApp',
	clientSecret: 'project-github-secret'
};

/**
 * @proves A project administrator declares the services the project's people may connect, with the project's own
 * registration at each provider, and the registration's secret is sealed and never read back.
 */
describe('declaring a connected service', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});
	beforeEach(() => {
		forgetAllDiscovery();
	});
	afterEach(() => {
		resetKeyringForTests(TEST_KEYRING);
		assertNoPendingInterceptors();
	});

	it('stores the service with its secret sealed, and every read masks it', async () => {
		const { cookie, bucket } = await projectAdministrator();
		const path = `/admin/api/projects/${bucket._id}/connected-services`;

		const created = await admin(cookie, 'POST', path, github);
		const listed = await admin(cookie, 'GET', path);

		expect(created.status).toBe(201);
		expect(created.json.clientSecret).toBe(SECRET_MASK);
		const services = listed.json.services as Record<string, unknown>[];
		expect(services.map((s) => s.clientSecret)).toEqual([SECRET_MASK]);
		const raw = await getBucketStore().find(bucket._id);
		// Read through the decorated store the secret opens; the pass's scan sees what is stored.
		expect(raw?.connectedServices?.[0].clientSecret).toBe(
			'project-github-secret'
		);
		const { getSealingStore } = await import('lib/adapters/index.ts');
		const stored = (
			await getSealingStore().scan('connectedServiceSecret')
		).find(
			(leaf) =>
				leaf.target.kind === 'connectedServiceSecret' &&
				leaf.target.bucketId === bucket._id
		);
		expect(String(stored?.value).startsWith(SEALED_PREFIX)).toBe(true);
	});

	it('records the creation in the audit trail, naming the fields and never the secret', async () => {
		const { cookie, bucket } = await projectAdministrator();

		await admin(
			cookie,
			'POST',
			`/admin/api/projects/${bucket._id}/connected-services`,
			github
		);

		const { entries } = await adminAuditStore.list({ targetId: bucket._id });
		const entry = entries.find((e) => e.action === 'connected.service.create');
		expect(entry?.attributes).toContain('clientSecret');
		expect(JSON.stringify(entry)).not.toContain('project-github-secret');
	});

	it('declares a catalogue service with only the values that differ between deployments', async () => {
		const { cookie, bucket } = await projectAdministrator();

		const created = await admin(
			cookie,
			'POST',
			`/admin/api/projects/${bucket._id}/connected-services`,
			github
		);

		expect(created.json).toMatchObject({
			kind: 'catalogue',
			catalogueId: 'github',
			displayName: 'GitHub',
			scopes: ['read:user'],
			callbackUri: expect.stringMatching(
				/\/account\/services\/callback$/
			) as unknown
		});
	});

	it('takes an OpenID Connect service from its discovery document', async () => {
		const { cookie, bucket } = await projectAdministrator();
		const idp = await oidcStub('https://idp-connected-declare.test', {
			clientId: 'c'
		});
		idp.expectDiscovery();

		const created = await admin(
			cookie,
			'POST',
			`/admin/api/projects/${bucket._id}/connected-services`,
			{
				kind: 'oidc',
				issuer: idp.issuer,
				clientId: 'c',
				clientSecret: 's',
				scopes: ['openid', 'calendar'],
				displayName: 'Acme Calendar'
			}
		);

		expect(created.status).toBe(201);
		expect(created.json.issuer).toBe(idp.issuer);
	});

	it('refuses a plain OAuth 2.0 service that says nothing about who the account is', async () => {
		const { cookie, bucket } = await projectAdministrator();

		const refused = await admin(
			cookie,
			'POST',
			`/admin/api/projects/${bucket._id}/connected-services`,
			{
				kind: 'oauth2',
				authorizationEndpoint: 'https://notes.example.com/oauth/authorize',
				tokenEndpoint: 'https://notes.example.com/oauth/token',
				clientId: 'c',
				clientSecret: 's',
				scopes: [],
				displayName: 'Notes'
			}
		);

		expect(refused.status).toBe(400);
		expect(refused.json.field).toBe('identity');
		expect(
			(await getBucketStore().find(bucket._id))?.connectedServices
		).toBeUndefined();
	});

	it('refuses to change the client id of a service', async () => {
		const { cookie, bucket } = await projectAdministrator();
		const created = await admin(
			cookie,
			'POST',
			`/admin/api/projects/${bucket._id}/connected-services`,
			github
		);

		const refused = await admin(
			cookie,
			'PATCH',
			`/admin/api/projects/${bucket._id}/connected-services/${String(created.json.id)}`,
			{ clientId: 'another-registration' }
		);

		expect(refused.status).toBe(400);
		expect(refused.json.field).toBe('clientId');
	});

	it('refuses declaring a service while no keyring is in use, and stores nothing', async () => {
		const { cookie, bucket } = await projectAdministrator();
		resetKeyringForTests(null);

		const refused = await admin(
			cookie,
			'POST',
			`/admin/api/projects/${bucket._id}/connected-services`,
			github
		);

		expect(refused.status).toBe(409);
		expect(refused.json.code).toBe('keyring_required');
		expect(
			(await getBucketStore().find(bucket._id))?.connectedServices
		).toBeUndefined();
	});

	it('refuses an endpoint that is not https', async () => {
		const { cookie, bucket } = await projectAdministrator();

		const refused = await admin(
			cookie,
			'POST',
			`/admin/api/projects/${bucket._id}/connected-services`,
			{
				kind: 'oauth2',
				authorizationEndpoint: 'http://notes.example.com/oauth/authorize',
				tokenEndpoint: 'https://notes.example.com/oauth/token',
				identity: { source: 'token', idPath: 'user.id' },
				clientId: 'c',
				clientSecret: 's',
				scopes: [],
				displayName: 'Notes'
			}
		);

		expect(refused.status).toBe(400);
		expect(refused.json.field).toBe('authorizationEndpoint');
	});

	it('refuses an endpoint at a private address', async () => {
		const { cookie, bucket } = await projectAdministrator();

		const refused = await admin(
			cookie,
			'POST',
			`/admin/api/projects/${bucket._id}/connected-services`,
			{
				kind: 'oauth2',
				authorizationEndpoint: 'https://notes.example.com/oauth/authorize',
				tokenEndpoint: 'https://10.0.0.7/oauth/token',
				identity: { source: 'token', idPath: 'user.id' },
				clientId: 'c',
				clientSecret: 's',
				scopes: [],
				displayName: 'Notes'
			}
		);

		expect(refused.status).toBe(400);
		expect(refused.json.field).toBe('tokenEndpoint');
	});

	it('refuses a submitted mask as the secret of a new service', async () => {
		const { cookie, bucket } = await projectAdministrator();

		const refused = await admin(
			cookie,
			'POST',
			`/admin/api/projects/${bucket._id}/connected-services`,
			{
				...github,
				clientSecret: SECRET_MASK
			}
		);

		expect(refused.status).toBe(400);
		expect(refused.json.field).toBe('clientSecret');
	});

	it('refuses a connected service in the Administrators project', async () => {
		const cookie = await cookieFor(await createAdministrator('super'));

		const refused = await admin(
			cookie,
			'POST',
			`/admin/api/projects/${ADMIN_BUCKET_ID}/connected-services`,
			github
		);

		expect(refused.status).toBe(403);
	});
});
