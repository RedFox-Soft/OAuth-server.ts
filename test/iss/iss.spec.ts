import { describe, it, beforeAll, expect } from 'bun:test';
import bootstrap, { agent, type Setup } from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';

/**
 * @proves Every authorization response and error carries iss, so a client can detect a mix-up
 * attack.
 */
describe('OAuth 2.0 Authorization Server Issuer Identification', () => {
	let setup: Setup;
	beforeAll(async function () {
		setup = await bootstrap(import.meta.url);
	});

	it('discovery advertises authorization_response_iss_parameter_supported', async function () {
		const { data, status } =
			await agent['.well-known']['openid-configuration'].get();
		expect(status).toBe(200);
		expect(data).toHaveProperty(
			'authorization_response_iss_parameter_supported',
			true
		);
	});

	describe('OAuth 2.0 Authorization Server Issuer Identifier in Authorization Response', async () => {
		let cookie: string;
		beforeAll(async function () {
			cookie = await setup.login();
		});

		it('the authorization response carries iss', async function () {
			const auth = new AuthorizationRequest({ scope: 'openid' });
			const { status, response } = await agent.auth.get({
				query: auth.params,
				headers: { cookie }
			});
			expect(status).toBe(303);
			auth.validatePresence(response, ['iss'], false);
			auth.validateClientLocation(response);
			auth.validateIss(response);
		});

		it('carries iss in the response to response_type=none', async function () {
			const auth = new AuthorizationRequest({
				response_type: 'none',
				scope: 'openid'
			});
			const { status, response } = await agent.auth.get({
				query: auth.params,
				headers: { cookie }
			});
			expect(status).toBe(303);
			auth.validatePresence(response, ['state', 'iss'], false);
			auth.validateClientLocation(response);
			auth.validateIss(response);
		});

		it('carries iss inside the JARM response', async function () {
			const auth = new AuthorizationRequest({
				response_mode: 'jwt',
				scope: 'openid'
			});
			const { status, response } = await agent.auth.get({
				query: auth.params,
				headers: { cookie }
			});

			expect(status).toBe(303);
			auth.validatePresence(response, ['response']);
			auth.validateClientLocation(response);
		});

		it('carries iss on an error response', async function () {
			const auth = new AuthorizationRequest({
				scope: 'openid profile'
			});
			const { status, response } = await agent.auth.get({
				query: auth.params,
				headers: { cookie }
			});
			expect(status).toBe(303);
			auth.validatePresence(response, ['error', 'iss'], false);
			auth.validateClientLocation(response);
			auth.validateIss(response);
		});

		it('carries iss on an error response to response_type=none', async function () {
			const auth = new AuthorizationRequest({
				response_type: 'none',
				scope: 'openid profile'
			});
			const { status, response } = await agent.auth.get({
				query: auth.params,
				headers: { cookie }
			});
			expect(status).toBe(303);
			auth.validatePresence(response, ['error', 'iss'], false);
			auth.validateClientLocation(response);
			auth.validateIss(response);
		});

		it('carries iss on a JARM error response', async function () {
			const auth = new AuthorizationRequest({
				response_mode: 'jwt',
				scope: 'openid profile'
			});
			const { status, response } = await agent.auth.get({
				query: auth.params,
				headers: { cookie }
			});
			expect(status).toBe(303);
			auth.validatePresence(response, ['response']);
			auth.validateClientLocation(response);
		});
	});
});
