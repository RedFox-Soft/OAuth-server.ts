import { afterAll, beforeAll, describe, expect, it } from 'bun:test';

import bootstrap, {
	agent,
	clearSeededBuckets,
	seedBucket,
	type Setup
} from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';

/**
 * @proves An end user signed in to one user bucket is asked to sign in when they reach an
 * application of another, rather than being refused with an internal fault.
 */
describe('a browser signed in to one bucket reaching another', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url);
		await seedBucket({
			bucketId: 'acme',
			clientId: 'acme-app',
			accountId: 'bob'
		});
	});

	afterAll(async () => {
		await clearSeededBuckets();
	});

	async function requestForOtherBucket(cookie: string) {
		const auth = new AuthorizationRequest({
			client_id: 'acme-app',
			scope: 'openid',
			redirect_uri: 'https://acme.example.com/cb'
		});

		const { response } = await agent.auth.get({
			query: auth.params,
			headers: { cookie }
		});

		return response;
	}

	/*
	 * Asserted against the delivered outcome rather than the HTTP status, because the status is not
	 * where this fault shows: the shared error handler delivers an authorization failure through the
	 * response mode, so the defect arrives as a 303 carrying `error=server_error` and a status check
	 * passes while the end user is stranded.
	 */
	it('produces no internal error when the browser holds a sign-in in another bucket', async () => {
		const cookie = await setup.login({ accountId: 'ana' });

		const response = await requestForOtherBucket(cookie);

		expect(response.status).toBeLessThan(500);
		expect(response.headers.get('location') ?? '').not.toContain(
			'error=server_error'
		);
	});

	it('asks the end user to sign in when the browser holds a sign-in in another bucket', async () => {
		const cookie = await setup.login({ accountId: 'ana' });

		const response = await requestForOtherBucket(cookie);

		expect(response.status).toBe(303);
		expect(response.headers.get('location')).toContain('/ui/');
	});
});
