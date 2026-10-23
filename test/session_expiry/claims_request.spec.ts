import { describe, it, beforeAll, afterEach, expect } from 'bun:test';
import { nanoid } from 'nanoid';

import bootstrap, {
	agent,
	redirectParameter,
	setSeedClaims,
	type Setup
} from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { present } from 'test/shape.js';
import { expiryOf } from './expiry.ts';

/**
 * @proves No `session_expiry` but the server's own ever reaches a relying party: not one an account record
 * held from before the name was reserved, and not one a claims request asks for.
 */
describe('a session_expiry the server did not compute', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'session_expiry' });
	});

	afterEach(() => {
		setSeedClaims(undefined);
	});

	async function tokensFor(claims: {
		id_token?: Record<string, unknown>;
		userinfo?: Record<string, unknown>;
	}) {
		const cookie = await setup.login({ scope: 'openid', accountId: nanoid() });
		const auth = new AuthorizationRequest({
			client_id: 'amr-app',
			scope: 'openid',
			claims
		});
		const { response } = await agent.auth.get({
			query: auth.params,
			headers: { cookie }
		});
		return auth.getToken(redirectParameter(response, 'code'));
	}

	it('never reaches userinfo from an account record that holds one, even when the claims request names it', async () => {
		setSeedClaims({ session_expiry: 1 });
		const { data } = await tokensFor({ userinfo: { session_expiry: null } });

		const info = await agent.userinfo.get({
			headers: {
				authorization: `Bearer ${present(data?.access_token, 'an access token')}`
			}
		});

		expect(info.response.status).toBe(200);
		expect(
			(info.data as Record<string, unknown>).session_expiry
		).toBeUndefined();
	});

	it('the ID token carries the server’s session_expiry even when the claims request asks for a value', async () => {
		const token = await tokensFor({
			id_token: { session_expiry: { value: 1 } }
		});

		const { iat, sessionExpiry } = expiryOf(token);
		expect(sessionExpiry).toBeGreaterThanOrEqual(iat + 300);
	});
});
