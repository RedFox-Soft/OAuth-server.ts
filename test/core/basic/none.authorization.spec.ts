import { describe, it, beforeAll, expect, spyOn } from 'bun:test';

import bootstrap, { agent } from '../../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { provider } from 'lib/provider.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';

describe('/auth response_type=none', () => {
	let setup = null;
	let cookie: string | undefined = undefined;
	beforeAll(async function () {
		setup = await bootstrap(import.meta.url)();
		cookie = await setup.login();
	});

	['get', 'post'].forEach((verb) => {
		async function authRequest(auth: AuthorizationRequest) {
			if (verb === 'get') {
				return agent.auth.get({
					query: auth.params,
					headers: {
						cookie
					}
				});
			} else if (verb === 'post') {
				return agent.auth.post(
					new URLSearchParams(Object.entries(auth.params)).toString(),
					{
						headers: {
							cookie
						}
					}
				);
			}
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

		it(`${verb} populates ctx.oidc.entities`, async function () {
			const spy = spyOn(OIDCContext.prototype, 'entity');
			const auth = new AuthorizationRequest({
				response_type: 'none',
				scope: 'openid'
			});

			const { response } = await authRequest(auth);
			expect(response.status).toBe(303);
			const entities = spy.mock.calls.map((call) => call[0]);
			expect(['Client', 'Grant', 'Account', 'Session']).toEqual(
				expect.arrayContaining(entities)
			);
		});
	});
});
