import * as crypto from 'node:crypto';

import { SignJWT } from 'jose';
import { describe, it, expect, mock } from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import epochTime from '../../lib/helpers/epoch_time.js';

import { keypair } from './fapi2.config.js';
import { ISSUER } from 'lib/configs/env.js';
import { provider } from 'lib/provider.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import nanoid from 'lib/helpers/nanoid.js';

describe('FAPI 2.0 Final behaviours', async () => {
	const setup = await bootstrap(import.meta.url, { config: 'fapi2' })();

	describe('FAPI 2.0 Final Mode Authorization Request', () => {
		it('requires pkjwt audience to be the issuer identifier', async function () {
			const spy = mock();
			provider.on('pushed_authorization_request.error', spy);

			const res = await agent.par.post({
				scope: 'openid',
				client_id: 'client',
				response_type: 'code',
				client_assertion_type:
					'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
				client_assertion: await new SignJWT({
					jti: crypto.randomUUID(),
					sub: 'client',
					iss: 'client',
					aud: ISSUER + '/token',
					exp: epochTime() + 60,
					nbf: epochTime()
				})
					.setProtectedHeader({ alg: 'ES256' })
					.sign(keypair.privateKey),
				code_challenge_method: 'S256',
				code_challenge: crypto.hash('sha256', 'foo', 'base64url')
			});
			expect(res.status).toBe(401);
			expect(res.error.value).toEqual({
				error: 'invalid_client',
				error_description: 'client authentication failed'
			});

			expect(spy.mock.calls[0][0].error_detail).toBe(
				'audience (aud) must equal the issuer identifier url'
			);
		});
	});

	describe('Request Object', () => {
		it('still works', async function () {
			const request = await new SignJWT({
				client_id: 'client',
				iss: 'client',
				scope: 'openid',
				response_type: 'code',
				redirect_uri: 'https://client.example.com/cb',
				aud: ISSUER,
				exp: epochTime() + 60,
				nbf: epochTime(),
				code_challenge_method: 'S256',
				code_challenge: crypto.hash('sha256', 'foo', 'base64url')
			})
				.setJti(nanoid())
				.setProtectedHeader({ alg: 'ES256' })
				.sign(keypair.privateKey);

			const auth = new AuthorizationRequest({
				request,
				scope: 'openid',
				client_id: 'client'
			});

			const cookie = await setup.login();
			const res = await agent.auth.get({
				query: auth.params,
				headers: { cookie }
			});
			expect(res.status).toBe(303);
			auth.validatePresence(res, ['code']);
			auth.validateClientLocation(res);
		});

		it('requires exp to be provided in the Request Object', async function () {
			const request = await new SignJWT({
				aud: ISSUER,
				code_challenge_method: 'S256',
				code_challenge: crypto.hash('sha256', 'foo', 'base64url'),
				// exp: epochTime() + 60,
				nbf: epochTime(),
				iss: 'client',
				client_id: 'client',
				scope: 'openid',
				response_type: 'code'
			})
				.setJti(nanoid())
				.setProtectedHeader({ alg: 'ES256' })
				.sign(keypair.privateKey);

			const auth = new AuthorizationRequest({
				request,
				scope: 'openid',
				client_id: 'client'
			});
			const cookie = await setup.login();
			const res = await agent.auth.get({
				query: auth.params,
				headers: { cookie }
			});
			expect(res.status).toBe(303);
			auth.validatePresence(res, ['error', 'error_description', 'state']);
			auth.validateClientLocation(res);
			auth.validateError(res, 'invalid_request');
			auth.validateErrorDescription(res, "Property 'exp' is missing");
		});

		it('requires nbf to be provided in the Request Object', async function () {
			const request = await new SignJWT({
				aud: ISSUER,
				code_challenge_method: 'S256',
				code_challenge: crypto.hash('sha256', 'foo', 'base64url'),
				exp: epochTime() + 60,
				// nbf: epochTime(),
				client_id: 'client',
				scope: 'openid',
				iss: 'client',
				response_type: 'code'
			})
				.setJti(nanoid())
				.setProtectedHeader({ alg: 'ES256' })
				.sign(keypair.privateKey);

			const auth = new AuthorizationRequest({
				request,
				scope: 'openid',
				client_id: 'client'
			});
			const cookie = await setup.login();

			const res = await agent.auth.get({
				query: auth.params,
				headers: { cookie }
			});
			expect(res.status).toBe(303);
			auth.validatePresence(res, ['error', 'error_description', 'state']);
			auth.validateClientLocation(res);
			auth.validateError(res, 'invalid_request_object');
			auth.validateErrorDescription(
				res,
				"Request Object is missing the 'nbf' claim"
			);
		});

		it('requires nbf to be no more than 3600 from exp', async function () {
			const request = await new SignJWT({
				exp: epochTime() + 60,
				nbf: epochTime() - 3600,
				aud: ISSUER,
				code_challenge_method: 'S256',
				code_challenge: crypto.hash('sha256', 'foo', 'base64url'),
				client_id: 'client',
				scope: 'openid',
				iss: 'client',
				response_type: 'code'
			})
				.setJti(nanoid())
				.setProtectedHeader({ alg: 'ES256' })
				.sign(keypair.privateKey);

			const auth = new AuthorizationRequest({
				request,
				scope: 'openid',
				client_id: 'client'
			});
			const cookie = await setup.login();

			const res = await agent.auth.get({
				query: auth.params,
				headers: { cookie }
			});
			expect(res.status).toBe(303);
			auth.validatePresence(res, ['error', 'error_description', 'state']);
			auth.validateClientLocation(res);
			auth.validateError(res, 'invalid_request_object');
			auth.validateErrorDescription(
				res,
				"Request Object 'exp' claim too far from 'nbf' claim"
			);
		});
	});
});
