import {
	describe,
	it,
	beforeAll,
	beforeEach,
	afterEach,
	expect,
	mock,
	spyOn
} from 'bun:test';

import { addons } from 'lib/addon/index.js';
import bootstrap, {
	agent,
	redirectParameter,
	type Setup
} from '../test_helper.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';

/*
 * A rotating refresh token is single use under concurrency, not only in sequence. Rotation read the
 * token, checked it unspent, and marked it spent with an unconditional write, so several refreshes
 * arriving together — the token's holder racing whoever stole it — each rotated it into a chain of its
 * own, and the reuse rule that revokes the grant never fired because none of them was the second use.
 */

/**
 * @proves A rotating refresh token presented by several requests at once is rotated for at most one
 * of them.
 */
describe('a rotating refresh token presented concurrently', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'refresh' });
	});

	beforeEach(() => {
		spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(false);
		addons.override({ rotateRefreshToken: () => true });
	});

	afterEach(() => {
		mock.restore();
	});

	it('issues a new refresh token to at most one of the requests', async () => {
		const authReq = new AuthorizationRequest({
			client_id: 'client',
			scope: 'openid offline_access',
			prompt: 'consent',
			redirect_uri: 'https://client.example.com/cb'
		});
		const cookie = await setup.login({ scope: 'openid offline_access' });
		const auth = await agent.auth.get({
			query: authReq.params,
			headers: { cookie }
		});
		const { data } = await authReq.getToken(
			redirectParameter(auth.response, 'code')
		);
		const refreshToken = data?.refresh_token;
		if (!refreshToken) throw new Error('expected a refresh token');

		const results = await Promise.all(
			Array.from({ length: 5 }, () =>
				agent.token.post(
					{ refresh_token: refreshToken, grant_type: 'refresh_token' },
					{ headers: AuthorizationRequest.basicAuthHeader('client', 'secret') }
				)
			)
		);

		expect(
			results.filter(({ data }) => data?.refresh_token).length
		).toBeLessThanOrEqual(1);
	});
});
