import * as url from 'node:url';
import { describe, it, beforeAll, expect, mock } from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import { decode } from '../../lib/helpers/jwt.ts';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { ISSUER } from 'lib/configs/env.js';
import { provider } from 'lib/provider.js';

describe('configuration features.jwtResponseModes', () => {
	let setup = null;
	beforeAll(async function () {
		setup = await bootstrap(import.meta.url)();
	});

	describe('discovery', () => {
		it('extends the well known config', async function () {
			const { data } = await agent['.well-known']['openid-configuration'].get();

			expect(data).toHaveProperty('authorization_signing_alg_values_supported');
			expect(data).toHaveProperty(
				'authorization_encryption_alg_values_supported'
			);
			expect(data).toHaveProperty(
				'authorization_encryption_enc_values_supported'
			);
			expect(data.response_modes_supported).toContain('jwt');
			expect(data.response_modes_supported).toContain('query.jwt');
			expect(data.response_modes_supported).toContain('form_post.jwt');
		});
	});

	describe('response_mode=jwt', () => {
		it('defaults to query for code response type', async function () {
			const auth = new AuthorizationRequest({
				response_mode: 'jwt',
				scope: 'openid'
			});
			const cookie = await setup.login();
			const { status, response } = await agent.auth.get({
				query: auth.params,
				headers: {
					cookie
				}
			});
			expect(status).toBe(303);
			auth.validatePresence(response, ['response']);
			auth.validateClientLocation(response);
			const location = response.headers.get('location');
			const {
				query: { response: jwt }
			} = url.parse(location, true);
			const { payload } = decode(jwt);
			expect(payload).toHaveProperty('code');
			expect(payload.exp).toBeNumber();
			expect(payload.aud).toBe('client');
			expect(payload).not.toHaveProperty('scope');
			expect(payload.state).toBe(auth.params.state);
			expect(payload.iss).toBe(ISSUER);
		});

		it('defaults to query for none response type', async function () {
			const auth = new AuthorizationRequest({
				response_type: 'none',
				response_mode: 'jwt',
				scope: 'openid'
			});

			const cookie = await setup.login();
			const { status, response } = await agent.auth.get({
				query: auth.params,
				headers: {
					cookie
				}
			});
			expect(status).toBe(303);
			auth.validatePresence(response, ['response']);
			auth.validateClientLocation(response);
			const location = response.headers.get('location');
			const {
				query: { response: jwt }
			} = url.parse(location, true);
			const { payload } = decode(jwt);
			expect(payload).toContainAllKeys(['exp', 'aud', 'state', 'iss']);
		});

		describe('when secret is expired', () => {
			it('defaults to fragment for implicit and hybrid response types', async function () {
				const auth = new AuthorizationRequest({
					client_id: 'client-expired',
					response_mode: 'jwt',
					scope: 'openid'
				});

				const cookie = await setup.login();
				const { status, response } = await agent.auth.get({
					query: auth.params,
					headers: {
						cookie
					}
				});
				expect(status).toBe(303);
				auth.validateClientLocation(response);
				auth.validateError(response, 'invalid_client');
				auth.validateErrorDescription(
					response,
					'client secret is expired, cannot issue a JWT Authorization response'
				);
			});

			it('defaults to query for code response type', async function () {
				const auth = new AuthorizationRequest({
					response_mode: 'jwt',
					scope: 'openid',
					client_id: 'client-expired'
				});

				const cookie = await setup.login();
				const { status, response } = await agent.auth.get({
					query: auth.params,
					headers: {
						cookie
					}
				});
				expect(status).toBe(303);
				auth.validateClientLocation(response);
				auth.validateError(response, 'invalid_client');
				auth.validateErrorDescription(
					response,
					'client secret is expired, cannot issue a JWT Authorization response'
				);
			});

			it('defaults to query for none response type', async function () {
				const auth = new AuthorizationRequest({
					response_type: 'none',
					response_mode: 'jwt',
					scope: 'openid',
					client_id: 'client-expired'
				});

				const cookie = await setup.login();
				const { status, response } = await agent.auth.get({
					query: auth.params,
					headers: {
						cookie
					}
				});
				expect(status).toBe(303);
				auth.validateClientLocation(response);
				auth.validateError(response, 'invalid_client');
				auth.validateErrorDescription(
					response,
					'client secret is expired, cannot issue a JWT Authorization response'
				);
			});
		});
	});

	describe('response_mode=query.jwt', () => {
		it('uses the query part when expired', async function () {
			const auth = new AuthorizationRequest({
				response_mode: 'query.jwt',
				scope: 'openid',
				client_id: 'client-expired'
			});

			const cookie = await setup.login();
			const { status, response } = await agent.auth.get({
				query: auth.params,
				headers: {
					cookie
				}
			});
			expect(status).toBe(303);
			auth.validateClientLocation(response);
			auth.validateError(response, 'invalid_client');
			auth.validateErrorDescription(
				response,
				'client secret is expired, cannot issue a JWT Authorization response'
			);
		});

		it('is allowed for code response type', async function () {
			const auth = new AuthorizationRequest({
				response_mode: 'query.jwt',
				scope: 'openid'
			});

			const cookie = await setup.login();
			const { status, response } = await agent.auth.get({
				query: auth.params,
				headers: {
					cookie
				}
			});
			expect(status).toBe(303);
			auth.validatePresence(response, ['response']);
			auth.validateClientLocation(response);
			const location = response.headers.get('location');
			const {
				query: { response: jwt }
			} = url.parse(location, true);
			const { payload } = decode(jwt);
			expect(payload).toHaveProperty('code');
			expect(payload.exp).toBeNumber();
			expect(payload.aud).toBe('client');
			expect(payload).not.toHaveProperty('scope');
			expect(payload.state).toBe(auth.params.state);
			expect(payload.iss).toBe(ISSUER);
		});

		it('is allowed for none response type', async function () {
			const auth = new AuthorizationRequest({
				response_type: 'none',
				response_mode: 'query.jwt',
				scope: 'openid'
			});

			const cookie = await setup.login();
			const { status, response } = await agent.auth.get({
				query: auth.params,
				headers: {
					cookie
				}
			});
			expect(status).toBe(303);
			auth.validatePresence(response, ['response']);
			auth.validateClientLocation(response);
			const location = response.headers.get('location');
			const {
				query: { response: jwt }
			} = url.parse(location, true);
			const { payload } = decode(jwt);
			expect(payload).toContainAllKeys(['exp', 'aud', 'state', 'iss']);
		});
	});

	Object.entries({
		'query.jwt': 303,
		'form_post.jwt': 400
	}).forEach(([mode, errStatus]) => {
		describe(`${mode} err handling`, () => {
			it(`responds with a ${errStatus}`, async function () {
				const auth = new AuthorizationRequest({
					prompt: 'none',
					response_mode: mode,
					scope: 'openid'
				});

				const spy = mock();
				provider.once('authorization.error', spy);

				const { status } = await agent.auth.get({
					query: auth.params
				});
				expect(status).toBe(errStatus);
				expect(spy).toBeCalled();
			});

			it('handles expired secrets', async function () {
				const spy = mock();
				provider.once('authorization.error', spy);

				const auth = new AuthorizationRequest({
					response_mode: mode,
					scope: 'openid',
					client_id: 'client-expired'
				});
				const { status } = await agent.auth.get({
					query: auth.params
				});
				expect(status).toBe(errStatus);
				expect(spy).toBeCalled();
				expect(spy.mock.calls[0][0]).toHaveProperty('error', 'invalid_client');
				expect(spy.mock.calls[0][0]).toHaveProperty(
					'error_description',
					'client secret is expired, cannot issue a JWT Authorization response'
				);
			});
		});
	});
});
