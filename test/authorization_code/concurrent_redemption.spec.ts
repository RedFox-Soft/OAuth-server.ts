import { describe, it, beforeAll, expect } from 'bun:test';

import bootstrap, {
	agent,
	redirectParameter,
	type Setup
} from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';

/*
 * A code is single use under concurrency, not only in sequence. The check that a code was spent read
 * a copy fetched earlier in the same request, and the write that spends it was unconditional, so two
 * redemptions arriving together both saw it unspent and both received tokens — and the rule that a
 * second use revokes the grant never fired, because neither request was the second.
 */

/**
 * @proves An authorization code redeemed by several requests at once yields tokens to exactly one
 * of them.
 */
describe('an authorization code redeemed concurrently', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'authorization_code' });
	});

	it('issues tokens to exactly one of the redemptions', async () => {
		const cookie = await setup.login();
		const auth = new AuthorizationRequest({
			client_id: 'client',
			scope: 'openid',
			redirect_uri: 'https://client.example.com/cb'
		});
		const { response } = await agent.auth.get({
			query: auth.params,
			headers: { cookie }
		});
		const code = redirectParameter(response, 'code');

		const results = await Promise.all(
			Array.from({ length: 5 }, () => auth.getToken(code))
		);

		const issued = results.filter(({ response }) => response.status === 200);
		expect(issued).toHaveLength(1);
	});
});
