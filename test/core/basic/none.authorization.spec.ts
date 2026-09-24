import { describe, it, beforeAll, expect } from 'bun:test';

import bootstrap, { agent, formAgent, type Setup } from '../../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';

/**
 * @proves A response_type=none request returns state and nothing else, over both HTTP verbs.
 */
describe('/auth response_type=none', () => {
	let setup: Setup;
	let cookie: string | undefined = undefined;
	beforeAll(async function () {
		setup = await bootstrap(import.meta.url);
		cookie = await setup.login();
	});

	['get', 'post'].forEach((verb) => {
		async function authRequest(auth: AuthorizationRequest) {
			const headers = { cookie };
			return verb === 'get'
				? agent.auth.get({ query: auth.params, headers })
				: formAgent.auth.post(auth.params, { headers });
		}

		it(`${verb} responds with a state in search`, async function () {
			const auth = new AuthorizationRequest({
				response_type: 'none',
				scope: 'openid'
			});

			const { response } = await authRequest(auth);
			expect(response.status).toBe(303);
			auth.validatePresence(response, ['state']);
			auth.validateState(response);
			auth.validateClientLocation(response);
		});
	});
});
