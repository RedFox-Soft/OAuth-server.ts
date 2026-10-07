import { describe, it, expect, beforeAll } from 'bun:test';

import bootstrap, { agent, getHeader } from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { getUserStore, resetAdminMemoryStores } from 'lib/adapters/index.ts';
import { decode as decodeJWT } from 'lib/helpers/jwt.ts';
import { idTokenOf } from '../acr/response.ts';
import { idpStub } from './idp_stub.ts';
import { provider, seedBucket, walk } from './harness.ts';
import { present } from 'test/shape.js';

const CLIENT = 'fed-amr-app';

/**
 * @proves A relying party is told of no authentication method after a sign-in through an upstream
 * provider — this server observed none of its own, and it does not repeat the provider's.
 */
describe('authentication methods after a federated sign-in', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'amr' });
		resetAdminMemoryStores();
	});

	it('carries no amr even when the upstream assertion names methods', async () => {
		const idp = await idpStub('https://idp-amr.test');
		const bucketId = await seedBucket(CLIENT, {
			federation: [provider(idp.origin)]
		});
		const store = getUserStore(bucketId);
		const account = await store.create(
			'amr@acme.test',
			'irrelevant-hash',
			true
		);
		await store.update(account._id, {
			federated: [
				{
					providerId: 'acme-sso',
					sub: 'upstream-subject-1',
					linkedAt: new Date()
				}
			]
		});
		idp.expectDiscovery();
		const auth = new AuthorizationRequest({
			client_id: CLIENT,
			scope: 'openid'
		});
		const { response } = await agent.auth.get({ query: auth.params });
		const cookie = present(
			response.headers.get('set-cookie'),
			'an interaction cookie'
		);
		const uid = getHeader(response, 'location').split('/')[2];

		const { complete } = await walk(uid, cookie, {
			idp,
			claims: { email: 'amr@acme.test', amr: ['hwk', 'mfa'] }
		});

		const code = present(
			new URL(
				present(complete?.location, 'a redirect'),
				'http://e.ly'
			).searchParams.get('code'),
			'an authorization code'
		);
		const { payload } = decodeJWT(idTokenOf(await auth.getToken(code)));
		expect(payload).not.toHaveProperty('amr');
	});
});
