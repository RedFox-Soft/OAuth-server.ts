import { describe, it, beforeAll, expect, jest } from 'bun:test';

import { elysia } from 'lib/index.ts';
import { createEndUser } from 'lib/end_users/service.ts';
import nanoid from 'lib/helpers/nanoid.js';
import bootstrap, { agent, getHeader } from '../test_helper.js';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { defaultBucket } from './fixtures.ts';

/* Each attempt costs an argon2 verification. */
jest.setTimeout(20_000);

async function signInWithPassword(email: string, password: string) {
	const auth = new AuthorizationRequest({
		client_id: 'client',
		scope: 'openid'
	});
	const { response } = await agent.auth.get({ query: auth.params });
	const uid = getHeader(response, 'location').split('/')[2];
	const cookie = response.headers.get('set-cookie');
	if (!cookie) throw new Error('expected an interaction cookie from /auth');
	const res = await elysia.handle(
		new Request(`http://e.ly/ui/${uid}/login`, {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
				cookie
			},
			body: new URLSearchParams({ username: email, password }).toString(),
			redirect: 'manual'
		})
	);
	return res.text();
}

/**
 * @proves An account created without a password cannot be opened with any password (spec 069,
 * FR-012).
 */
describe('a user created without a password', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	for (const password of ['password', 'seeded', 'correct horse battery']) {
		it(`refuses a password sign-in with "${password}"`, async () => {
			const email = `passwordless-${nanoid()}@x.io`;
			await createEndUser(
				await defaultBucket(),
				{ kind: 'admin' },
				{ id: nanoid(), email },
				async () => {}
			);

			const page = await signInWithPassword(email, password);

			expect(page).toContain('Invalid username or password');
		});
	}
});
