import { afterAll, beforeAll, describe, expect, it } from 'bun:test';

import bootstrap, {
	agent,
	clearSeededBuckets,
	seedBucket,
	type Setup
} from '../test_helper.js';
import { getUserStore } from 'lib/adapters/index.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';

const PASSWORD = 'sup3rsecret';

/**
 * @proves Signing in as a person of a second user bucket completes, rather than being gated behind a
 * demand to end every sign-in the browser holds.
 */
describe('signing in to a second bucket while a sign-in is already held', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url);
		await seedBucket({
			bucketId: 'acme',
			clientId: 'acme-app',
			accountId: 'bob'
		});
		await getUserStore('acme').create(
			'bob@acme.example.com',
			await Bun.password.hash(PASSWORD)
		);
	});

	afterAll(async () => {
		await clearSeededBuckets();
	});

	it('completes the sign-in rather than demanding a sign-out first', async () => {
		// A sign-in already held, in the default bucket, as somebody else entirely.
		const held = await setup.login({ accountId: 'ana' });

		const auth = new AuthorizationRequest({
			client_id: 'acme-app',
			scope: 'openid',
			redirect_uri: 'https://acme.example.com/cb'
		});
		const { response: prompt } = await agent.auth.get({
			query: auth.params,
			headers: { cookie: held }
		});

		expect(prompt.status).toBe(303);
		const location = prompt.headers.get('location') ?? '';
		expect(location).toContain('/ui/');

		const [, , uid] = location.split('/');
		const interactionCookie = prompt.headers.get('set-cookie') ?? '';

		const { response } = await agent.ui[uid].login.post(
			{ username: 'bob@acme.example.com', password: PASSWORD },
			{ headers: { cookie: `${held}; ${interactionCookie}` } }
		);

		/*
		 * Asserted on where the end user is sent, not merely on the absence of an error. The sign-out
		 * confirmation is rendered with 200 and no error at all, so a case checking only "did not fail"
		 * would pass while the end user sat in front of a page asking whether to end every session they
		 * hold. A 303 back toward the application is the outcome that distinguishes the two.
		 */
		expect(response.status).toBe(303);
		expect(response.headers.get('location') ?? '').not.toContain('error=');
	});
});
