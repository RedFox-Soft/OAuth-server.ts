import { describe, it, beforeAll, expect } from 'bun:test';
import bootstrap, { agent } from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';

describe('OAuth 2.0 Authorization Server Issuer Identification', () => {
	let setup;
	beforeAll(async function () {
		setup = await bootstrap(import.meta.url)();
	});

	it('enriched discovery shows the url now', async function () {
		const { data, status } =
			await agent['.well-known']['openid-configuration'].get();
		expect(status).toBe(200);
		expect(data).toHaveProperty(
			'authorization_response_iss_parameter_supported',
			true
		);
	});

	describe('OAuth 2.0 Authorization Server Issuer Identifier in Authorization Response', async () => {
		let cookie;
		beforeAll(async function () {
			cookie = await setup.login();
		});

		it('response_type=code', async function () {
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

		it('response_type=none', async function () {
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

		it('response_mode=jwt', async function () {
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

		it('error with regular response modes', async function () {
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

		it('error with response_type none', async function () {
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

		it('error with response_mode=jwt', async function () {
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
