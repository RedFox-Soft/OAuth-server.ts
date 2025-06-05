import { SignJWT, decodeJwt } from 'jose';
import crypto from 'node:crypto';

import bootstrap from '../test_helper.js';
import epochTime from '../../lib/helpers/epoch_time.ts';

import { keypair } from './fapi-final.config.js';
import { parse } from 'node:url';
import { expect } from 'chai';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { ISSUER } from 'lib/configs/env.js';

describe('Financial-grade API Security Profile 1.0 - Part 2: Advanced (FINAL) behaviours', () => {
	before(bootstrap(import.meta.url, { config: 'fapi-final' }));

	describe('FAPI 1.0 Final Authorization Request', () => {
		beforeEach(function () {
			return this.login();
		});

		it('requires jwt response mode to be used when id token is not issued by authorization endpoint', function () {
			const auth = new AuthorizationRequest({
				scope: 'openid',
				client_id: 'client',
				response_type: 'code',
				nonce: 'foo'
			});

			return this.wrap({
				agent: this.agent,
				route: '/auth',
				verb: 'get',
				auth
			})
				.expect(303)
				.expect(auth.validateClientLocation)
				.expect(auth.validateError('invalid_request'))
				.expect(
					auth.validateErrorDescription(
						'requested response_mode is not allowed for this client or request'
					)
				);
		});

		it('requires jwt response mode to be used when id token is not issued by authorization endpoint (JAR)', async function () {
			const request = await new SignJWT({
				scope: 'openid',
				client_id: 'client',
				response_type: 'code',
				nonce: 'foo',
				iss: 'client',
				aud: ISSUER,
				exp: epochTime() + 60,
				nbf: epochTime()
			})
				.setProtectedHeader({ alg: 'ES256' })
				.sign(keypair.privateKey);

			const auth = new AuthorizationRequest({
				request,
				state: undefined
			});

			return this.wrap({
				agent: this.agent,
				route: '/auth',
				verb: 'get',
				auth
			})
				.expect(303)
				.expect(auth.validateClientLocation)
				.expect(auth.validateError('invalid_request'))
				.expect(
					auth.validateErrorDescription(
						'requested response_mode is not allowed for this client or request'
					)
				);
		});
	});

	describe('Request Object', () => {
		beforeEach(function () {
			return this.login();
		});
		afterEach(function () {
			return this.logout();
		});

		it('still works', async function () {
			const code_verifier = crypto.randomBytes(32).toString('base64url');
			const code_challenge = crypto
				.createHash('sha256')
				.update(code_verifier)
				.digest('base64url');

			const request = await new SignJWT({
				client_id: 'client',
				iss: 'client',
				scope: 'openid',
				response_type: 'code',
				response_mode: 'jwt',
				code_challenge_method: 'S256',
				code_challenge,
				nonce: 'foo',
				redirect_uri: 'https://client.example.com/cb',
				aud: ISSUER,
				state: 'foo',
				exp: epochTime() + 60,
				nbf: epochTime()
			})
				.setProtectedHeader({ alg: 'ES256' })
				.sign(keypair.privateKey);

			const auth = new this.AuthorizationRequest({
				request,
				scope: 'openid',
				client_id: 'client',
				state: 'foo'
			});

			return this.wrap({
				agent: this.agent,
				route: '/auth',
				verb: 'get',
				auth
			})
				.expect(303)
				.expect((res) => {
					const { response } = parse(res.headers.location, true).query;
					const jwt = decodeJwt(response);
					expect(jwt).to.have.property('code');
					expect(jwt).to.have.property('state', 'foo');
					expect(jwt).to.have.property('aud', 'client');
				})
				.expect(auth.validateClientLocation);
		});

		it('requires exp to be provided in the Request Object', async function () {
			const request = await new SignJWT({
				aud: this.provider.issuer,
				// exp: epochTime() + 60,
				nbf: epochTime(),
				iss: 'client',
				client_id: 'client',
				scope: 'openid',
				response_type: 'code',
				nonce: 'foo'
			})
				.setProtectedHeader({ alg: 'ES256' })
				.sign(keypair.privateKey);

			const auth = new AuthorizationRequest({
				request,
				scope: 'openid',
				client_id: 'client',
				response_type: 'code',
				nonce: 'foo'
			});

			return this.wrap({
				agent: this.agent,
				route: '/auth',
				verb: 'get',
				auth
			})
				.expect(303)
				.expect(auth.validatePresence(['error', 'error_description', 'state']))
				.expect(auth.validateClientLocation)
				.expect(auth.validateError('invalid_request_object'))
				.expect(
					auth.validateErrorDescription(
						"Request Object is missing the 'exp' claim"
					)
				);
		});

		it('requires nbf to be provided in the Request Object', async function () {
			const request = await new SignJWT({
				aud: ISSUER,
				exp: epochTime() + 60,
				// nbf: epochTime(),
				client_id: 'client',
				scope: 'openid',
				iss: 'client',
				response_type: 'code',
				nonce: 'foo'
			})
				.setProtectedHeader({ alg: 'ES256' })
				.sign(keypair.privateKey);

			const auth = new AuthorizationRequest({
				request,
				scope: 'openid',
				client_id: 'client',
				response_type: 'code',
				nonce: 'foo'
			});

			return this.wrap({
				agent: this.agent,
				route: '/auth',
				verb: 'get',
				auth
			})
				.expect(303)
				.expect(auth.validatePresence(['error', 'error_description', 'state']))
				.expect(auth.validateClientLocation)
				.expect(auth.validateError('invalid_request_object'))
				.expect(
					auth.validateErrorDescription(
						"Request Object is missing the 'nbf' claim"
					)
				);
		});

		it('requires nbf to be no more than 3600 from exp', async function () {
			const request = await new SignJWT({
				exp: epochTime() + 60,
				nbf: epochTime() - 3600,
				aud: ISSUER,
				client_id: 'client',
				scope: 'openid',
				iss: 'client',
				response_type: 'code',
				nonce: 'foo'
			})
				.setProtectedHeader({ alg: 'ES256' })
				.sign(keypair.privateKey);

			const auth = new AuthorizationRequest({
				request,
				scope: 'openid',
				client_id: 'client',
				response_type: 'code',
				nonce: 'foo'
			});

			return this.wrap({
				agent: this.agent,
				route: '/auth',
				verb: 'get',
				auth
			})
				.expect(303)
				.expect(auth.validatePresence(['error', 'error_description', 'state']))
				.expect(auth.validateClientLocation)
				.expect(auth.validateError('invalid_request_object'))
				.expect(
					auth.validateErrorDescription(
						"Request Object 'exp' claim too far from 'nbf' claim"
					)
				);
		});
	});
});
