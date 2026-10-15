import { describe, it, expect, beforeAll } from 'bun:test';

import bootstrap, {
	agent,
	bindClientToBucket,
	getHeader,
	seedBucket,
	type Setup
} from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getProtectedResourceStore } from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { ROOT_NAMESPACE } from 'lib/resources/namespace.ts';

/*
 * Skipping the consent screen is a tenant's decision about its own users, not about anyone else's. An
 * application of the default bucket reaches another bucket's sign-in when it names a resource that
 * bucket declared, and honouring its `consent.require: false` there would hand whoever registered it
 * the claims of that bucket's users with a session — with `prompt=none`, without a page ever being
 * shown.
 */

const TENANT_BUCKET = 'waiver-tenant';
const TENANT_RESOURCE = 'https://api.waiver-tenant.example/';

async function authorizeSilently(
	clientId: string,
	redirectUri: string,
	cookie: string,
	resource?: string
) {
	const auth = new AuthorizationRequest({
		client_id: clientId,
		redirect_uri: redirectUri,
		scope: 'openid email',
		prompt: 'none'
	});
	const { response } = await agent.auth.get({
		query: { ...auth.params, ...(resource ? { resource: [resource] } : {}) },
		headers: { cookie }
	});
	return new URL(getHeader(response, 'location'));
}

/**
 * @proves A client that skips consent does so only for users of the bucket it belongs to, and asks
 * the users of any other bucket it signs into.
 */
describe('a client that skips consent, signing into a bucket', () => {
	let setup: Setup;
	let cookie: string;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url);
		await ensureAdminSeed();
		await seedBucket({
			bucketId: TENANT_BUCKET,
			clientId: 'tenant-app',
			accountId: 'tenant-user'
		});
		await bindClientToBucket('default-app', DEFAULT_BUCKET_ID);
		await getProtectedResourceStore().create({
			namespace: ROOT_NAMESPACE,
			identifier: TENANT_RESOURCE,
			bucketId: TENANT_BUCKET,
			name: 'Tenant API',
			scopes: ['api:read']
		});
		cookie = await setup.login({
			accountId: 'tenant-user',
			bucketId: TENANT_BUCKET,
			scope: 'openid'
		});
	});

	it('asks for consent in a bucket it does not belong to', async () => {
		const callback = await authorizeSilently(
			'default-app',
			'https://default.example.com/cb',
			cookie,
			TENANT_RESOURCE
		);

		expect(callback.searchParams.get('error')).toBe('consent_required');
		expect(callback.searchParams.get('code')).toBeNull();
	});

	/* The same request in every respect but whose application it is. */

	it('skips consent in the bucket it belongs to', async () => {
		const callback = await authorizeSilently(
			'tenant-app',
			'https://tenant.example.com/cb',
			cookie,
			TENANT_RESOURCE
		);

		expect(callback.searchParams.get('error')).toBeNull();
		expect(callback.searchParams.get('code')).toBeTruthy();
	});
});
