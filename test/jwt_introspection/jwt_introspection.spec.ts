import { describe, it, beforeAll, afterEach, expect, setSystemTime } from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import * as JWT from '../../lib/helpers/jwt.ts';
import { provider } from 'lib/provider.js';
import { ISSUER } from 'lib/configs/env.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ApplicationConfig } from 'lib/configs/application.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';

describe('jwtIntrospection features', () => {
	let setup = null;
	beforeAll(async () => {
		setup = await bootstrap(import.meta.url)();
	});

	afterEach(() => setSystemTime());

	describe('enriched discovery', () => {
		it('shows the url now', async () => {
			const { data } = await agent['.well-known']['openid-configuration'].get();
			expect(data).toHaveProperty('introspection_signing_alg_values_supported');
		});
	});

	describe('JWT Response for OAuth Token Introspection', () => {
		beforeAll(function () {
			return setup.login({ accountId: 'accountId' });
		});

		it('can only be enabled with introspection', () => {
			const original = ApplicationConfig['introspection.enabled'];
			ApplicationConfig['introspection.enabled'] = false;
			try {
				expect(() => provider.init({})).toThrow(
					'jwtIntrospection is only available in conjuction with introspection'
				);
			} finally {
				ApplicationConfig['introspection.enabled'] = original;
			}
		});

		it('returns the response as json when not negotiated to be a JWT', async () => {
			const now = Date.now();
			setSystemTime(now);
			const at = new AccessToken({
				accountId: 'accountId',
				grantId: setup.getGrantId(),
				client: await Client.find('client-signed'),
				scope: 'openid'
			});

			const token = await at.save();
			const jsonRes = await agent.token.introspect.post(
				{ token },
				{
					headers: AuthorizationRequest.basicAuthHeader(
						'client-signed',
						'secret'
					)
				}
			);
			expect(jsonRes.status).toBe(200);
			expect(jsonRes.response.headers.get('content-type')).toContain(
				'application/json'
			);
			const json = jsonRes.data;
			const iat = json.iat;

			setSystemTime(now + 10 * 1000);

			const jwtRes = await agent.token.introspect.post(
				{ token },
				{
					headers: {
						...AuthorizationRequest.basicAuthHeader('client-signed', 'secret'),
						accept: 'application/token-introspection+jwt'
					}
				}
			);
			expect(jwtRes.status).toBe(200);
			expect(jwtRes.response.headers.get('content-type')).toBe(
				'application/token-introspection+jwt; charset=utf-8'
			);
			const {
				payload: { iat: jwtIat, iss, aud, token_introspection },
				header
			} = JWT.decode(jwtRes.data);
			expect(iss).toEqual(ISSUER);
			expect(aud).toEqual('client-signed');
			expect(token_introspection).toEqual(json);
			expect(jwtIat).toEqual(iat + 10);
			expect(header).toHaveProperty('typ', 'token-introspection+jwt');
		});

		it('returns the response as jwt (active: false)', async () => {
			const now = Date.now();
			setSystemTime(now);

			const jwtRes = await agent.token.introspect.post(
				{ token: 'foobar' },
				{
					headers: {
						...AuthorizationRequest.basicAuthHeader('client-signed', 'secret'),
						accept: 'application/token-introspection+jwt'
					}
				}
			);
			expect(jwtRes.status).toBe(200);
			expect(jwtRes.response.headers.get('content-type')).toBe(
				'application/token-introspection+jwt; charset=utf-8'
			);
			const {
				payload: { iat: jwtIat, iss, aud, token_introspection },
				header
			} = JWT.decode(jwtRes.data);
			expect(iss).toEqual(ISSUER);
			expect(aud).toEqual('client-signed');
			expect(token_introspection).toEqual({ active: false });
			expect(jwtIat).toEqual(Math.floor(now / 1000));
			expect(header).toHaveProperty('typ', 'token-introspection+jwt');
		});

		it('errors when secret is expired for HMAC alg', async () => {
			const at = new AccessToken({
				accountId: 'accountId',
				grantId: setup.getGrantId(),
				client: await Client.find('client-HS-expired'),
				scope: 'openid'
			});

			const token = await at.save();

			const res = await agent.token.introspect.post(
				{ client_id: 'client-HS-expired', token },
				{ headers: { accept: 'application/token-introspection+jwt' } }
			);
			expect(res.status).toBe(400);
			expect(res.response.headers.get('content-type')).toContain(
				'application/json'
			);
			expect(res.error.value).toEqual({
				error: 'invalid_client',
				error_description:
					'client secret is expired - cannot respond with HS256 JWT Introspection response'
			});
		});

		it('non-authenticated without accept: application/token-introspection+jwt fails', async () => {
			const at = new AccessToken({
				accountId: 'accountId',
				grantId: setup.getGrantId(),
				client: await Client.find('client-encrypted'),
				scope: 'openid'
			});

			const token = await at.save();
			const failRes = await agent.token.introspect.post({
				client_id: 'client-encrypted',
				token
			});
			expect(failRes.status).toBe(400);
			expect(failRes.response.headers.get('content-type')).toContain(
				'application/json'
			);
			expect(failRes.error.value).toEqual({
				error: 'invalid_request',
				error_description:
					'introspection must be requested with Accept: application/token-introspection+jwt for this client'
			});

			const okRes = await agent.token.introspect.post(
				{ client_id: 'client-encrypted', token },
				{ headers: { accept: 'application/token-introspection+jwt' } }
			);
			expect(okRes.status).toBe(200);
			expect(okRes.response.headers.get('content-type')).toBe(
				'application/token-introspection+jwt; charset=utf-8'
			);
			const header = JWT.header(okRes.data);
			expect(header).toHaveProperty('alg', 'A128KW');
			expect(header).toHaveProperty('enc', 'A128CBC-HS256');
		});
	});
});
