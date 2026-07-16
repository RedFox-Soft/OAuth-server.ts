import {
	describe,
	it,
	beforeAll,
	afterAll,
	afterEach,
	expect,
	mock,
	spyOn
} from 'bun:test';

import bootstrap, { agent, getHeader } from '../test_helper.js';
import { ISSUER } from 'lib/configs/env.js';
import { provider } from 'lib/provider.js';
import { Client } from 'lib/models/client.js';
import { ApplicationConfig } from 'lib/configs/application.js';
import { InitialAccessToken } from 'lib/models/initial_access_token.js';
import { RegistrationAccessToken } from 'lib/models/registration_access_token.js';
import { TestAdapter } from 'test/models.js';

const json = { 'content-type': 'application/json' };
const bearer = (token) => ({ authorization: `Bearer ${token}` });

function bodyOf(res) {
	return res.error?.value ?? res.data;
}

function expectFail(res, code, error, error_description) {
	expect(res.status).toBe(code);
	expect(bodyOf(res)).toHaveProperty('error', error);
	expect(bodyOf(res)).toHaveProperty('error_description', error_description);

	const wwwAuth = res.headers?.get?.('www-authenticate');
	if (code === 401) {
		expect(wwwAuth).toContain(`Bearer realm="${ISSUER}"`);
		expect(wwwAuth).toContain(`error="${error}"`);
	} else if (error_description === 'no access token provided') {
		expect(wwwAuth).toContain(`Bearer realm="${ISSUER}"`);
		expect(wwwAuth).not.toContain('error=');
	}
}

function reg(metadata = {}, headers = {}) {
	return agent.reg.post(
		{ redirect_uris: ['https://client.example.com/cb'], ...metadata },
		{ headers: { ...json, ...headers } }
	);
}

describe('registration features', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	afterEach(() => {
		mock.restore();
		provider.removeAllListeners('registration_create.success');
		provider.removeAllListeners('registration_access_token.destroyed');
	});

	describe('POST /reg', () => {
		it('generates the id, secret that does not expire and reg access token and returns the defaulted values', async () => {
			const { status, data } = await reg();
			if (!data) throw new Error('expected response data');
			expect(status).toBe(201);
			expect(data).toHaveProperty('client_id');
			expect(data).toHaveProperty('client_secret');
			expect(data).toHaveProperty('registration_access_token');
			expect(data).toHaveProperty('client_secret_expires_at', 0);
			expect(data).toHaveProperty('application_type', 'web');
			expect(data).toHaveProperty('id_token_signed_response_alg', 'RS256');
			expect(data).toHaveProperty(
				'token_endpoint_auth_method',
				'client_secret_basic'
			);
			expect(data).toHaveProperty('require_auth_time', false);
			expect(data.grant_types).toEqual(['authorization_code']);
			expect(data.response_types).toEqual(['code']);
			expect(data).toHaveProperty(
				'registration_client_uri',
				`${ISSUER}/reg/${data.client_id}`
			);
		});

		it('populates the Client and RegistrationAccessToken (issues both)', async () => {
			const { status, data } = await reg();
			expect(status).toBe(201);
			expect(data).toHaveProperty('client_id');
			expect(data).toHaveProperty('registration_access_token');
		});

		describe('when issueRegistrationAccessToken is false', () => {
			beforeAll(() => {
				ApplicationConfig['registration.issueRegistrationAccessToken'] = false;
			});
			afterAll(() => {
				ApplicationConfig['registration.issueRegistrationAccessToken'] = true;
			});

			it('omits issuing a registration access token and does not return registration_client_uri', async () => {
				const { status, data } = await reg();
				expect(status).toBe(201);
				expect(data).not.toHaveProperty('registration_client_uri');
				expect(data).not.toHaveProperty('registration_access_token');
			});
		});

		describe('when issueRegistrationAccessToken is a function returning false', () => {
			beforeAll(() => {
				ApplicationConfig['registration.issueRegistrationAccessToken'] = () =>
					false;
			});
			afterAll(() => {
				ApplicationConfig['registration.issueRegistrationAccessToken'] = true;
			});
			it('omits issuing a registration access token and does not return registration_client_uri', async () => {
				const { status, data } = await reg();
				expect(status).toBe(201);
				expect(data).not.toHaveProperty('registration_client_uri');
				expect(data).not.toHaveProperty('registration_access_token');
			});
		});

		describe('when issueRegistrationAccessToken is a function returning true', () => {
			beforeAll(() => {
				ApplicationConfig['registration.issueRegistrationAccessToken'] = () =>
					true;
			});
			afterAll(() => {
				ApplicationConfig['registration.issueRegistrationAccessToken'] = true;
			});
			it('issues a registration access token and does return registration_client_uri', async () => {
				const { status, data } = await reg();
				expect(status).toBe(201);
				expect(data).toHaveProperty('registration_client_uri');
				expect(data).toHaveProperty('registration_access_token');
			});
		});

		describe('when issueRegistrationAccessToken is true', () => {
			beforeAll(() => {
				ApplicationConfig['registration.issueRegistrationAccessToken'] = true;
			});
			it('issues a registration access token and does return registration_client_uri', async () => {
				const { status, data } = await reg();
				expect(status).toBe(201);
				expect(data).toHaveProperty('registration_client_uri');
				expect(data).toHaveProperty('registration_access_token');
			});
		});

		it('omits the client_secret generation when it is not needed', async () => {
			const { status, data } = await reg({
				token_endpoint_auth_method: 'none',
				response_types: ['code'],
				grant_types: ['authorization_code']
			});
			expect(status).toBe(201);
			expect(data).not.toHaveProperty('client_secret');
			expect(data).not.toHaveProperty('client_secret_expires_at');
		});

		it('omits the client_secret generation when it is not needed and in doing so ignores provided client_secret and client_secret_expires_at', async () => {
			const { data } = await reg({
				token_endpoint_auth_method: 'none',
				response_types: ['code'],
				grant_types: ['authorization_code'],
				client_secret: 'foo',
				client_secret_expires_at: 123
			});
			if (!data) throw new Error('expected response data');
			expect(data).not.toHaveProperty('client_secret');
			expect(data).not.toHaveProperty('client_secret_expires_at');

			const client = await Client.find(data.client_id);
			expect(client).not.toHaveProperty('clientSecret');
			expect(client).not.toHaveProperty('clientSecretExpiresAt');
		});

		it('issues the client_secret when needed for sig', async () => {
			const { status, data } = await reg({
				token_endpoint_auth_method: 'none',
				response_types: ['code'],
				grant_types: ['authorization_code'],
				id_token_signed_response_alg: 'HS256'
			});
			expect(status).toBe(201);
			expect(data).toHaveProperty('client_secret');
			expect(data).toHaveProperty('client_secret_expires_at');
		});

		it('issues the client_secret when needed for auth', async () => {
			const { status, data } = await reg({
				token_endpoint_auth_method: 'client_secret_jwt',
				response_types: ['code'],
				grant_types: ['authorization_code']
			});
			expect(status).toBe(201);
			expect(data).toHaveProperty('client_secret');
			expect(data).toHaveProperty('client_secret_expires_at');
		});

		it('returns token-endpoint-like cache headers', async () => {
			const res = await reg();
			expect(getHeader(res.response, 'cache-control')).toBe('no-store');
		});

		it('stores the client and emits an event', async () => {
			const spy = mock();
			provider.once('registration_create.success', spy);
			const adapter = TestAdapter.for('Client');
			const upsert = spyOn(adapter, 'upsert');

			const { status } = await reg();
			expect(status).toBe(201);
			expect(upsert).toHaveBeenCalledTimes(1);
			expect(spy).toHaveBeenCalledTimes(1);
			// coverage-adapted: the port's validated client is a plain object (no `Client`
			// class), so assert the emitted args' shape instead of constructor.name.
			expect(spy.mock.calls[0][0]).toHaveProperty('oidc');
			expect(spy.mock.calls[0][1]).toHaveProperty('clientId');
		});

		it('uses the adapter to find stored clients', async () => {
			const adapter = TestAdapter.for('Client');
			// coverage-adapted: this port validates on read and keeps base metadata in
			// canonical camelCase, so seed the stored record in that shape.
			adapter.store.set('Client:foobar', {
				clientId: 'foobar',
				clientSecret: 'foobarbaz',
				redirectUris: ['https://client.example.com/cb']
			});

			const client = await Client.find('foobar');
			expect(client).toBeTruthy();
		});

		it('validates the parameters to be valid and responds with errors', async () => {
			// spec-authoritative: this port validates canonical camelCase metadata, so the
			// message is the port's ('grantTypes …') rather than the legacy snake wording.
			const res = await reg({ grant_types: ['this is clearly wrong'] });
			expectFail(
				res,
				400,
				'invalid_client_metadata',
				"grantTypes must contain 'authorization_code' when code is amongst responseTypes"
			);
		});

		it('validates the parameters to be valid and responds with redirect_uri errors', async () => {
			// spec-authoritative: canonical camelCase message from this port's schema.
			const res = await agent.reg.post({}, { headers: json });
			expectFail(
				res,
				400,
				'invalid_redirect_uri',
				'redirectUris must contain members'
			);
		});

		it('only accepts application/json POSTs', async () => {
			const res = await agent.reg.post('redirect_uris=x', {
				headers: { 'content-type': 'application/x-www-form-urlencoded' }
			});
			expect(res.status).toBe(400);
			expect(bodyOf(res)).toEqual({
				error: 'invalid_request',
				error_description:
					'only application/json content-type bodies are supported on POST /reg'
			});
		});

		describe('initial access tokens', () => {
			describe('fix string one', () => {
				beforeAll(() => {
					ApplicationConfig['registration.initialAccessToken'] = 'foobar';
				});
				afterAll(() => {
					ApplicationConfig['registration.initialAccessToken'] = false;
				});

				it('fails reg calls with the access tokens in application/json body', async () => {
					const res = await reg({ access_token: 'foobar' });
					expect(res.status).toBe(400);
					expect(bodyOf(res)).toEqual({
						error: 'invalid_request',
						error_description: 'no access token provided'
					});
				});

				it('allows reg calls with the access tokens as a Bearer token [header]', async () => {
					const res = await reg({}, bearer('foobar'));
					expect(res.status).toBe(201);
				});

				it('rejects calls with bad access token', async () => {
					const res = await reg({}, bearer('foobarbaz'));
					expectFail(res, 401, 'invalid_token', 'invalid token provided');
				});
			});

			describe('using a model', () => {
				let token;
				beforeAll(async () => {
					ApplicationConfig['registration.initialAccessToken'] = true;
					token = await new InitialAccessToken({}).save();
				});
				afterAll(() => {
					ApplicationConfig['registration.initialAccessToken'] = false;
				});

				it('allows the developers to insert new tokens with no expiration', async () => {
					const v = await new InitialAccessToken().save();
					const stored = TestAdapter.for('InitialAccessToken').syncFind(v);
					expect(stored).not.toHaveProperty('exp');
				});

				it('allows the developers to insert new tokens with expiration', async () => {
					const v = await new InitialAccessToken({
						expiresIn: 24 * 60 * 60
					}).save();
					const stored = TestAdapter.for('InitialAccessToken').syncFind(v);
					expect(stored).toHaveProperty('exp');
				});

				it('fails reg calls with the access tokens in application/json body', async () => {
					const res = await reg({ access_token: token });
					expect(res.status).toBe(400);
					expect(bodyOf(res)).toEqual({
						error: 'invalid_request',
						error_description: 'no access token provided'
					});
				});

				it('allows reg calls with the access tokens as a Bearer token [header]', async () => {
					const res = await reg({}, bearer(token));
					expect(res.status).toBe(201);
				});

				it('accepts a valid InitialAccessToken (entity populated → 201)', async () => {
					const res = await reg({}, bearer(token));
					expect(res.status).toBe(201);
				});

				it('rejects calls with bad access token', async () => {
					const res = await reg({}, bearer('foobarbaz'));
					expectFail(res, 401, 'invalid_token', 'invalid token provided');
				});

				it('rejects calls with not found access token', async () => {
					const res = await reg(
						{},
						bearer('Loremipsumdolorsitametconsecteturadipisicingelitsed')
					);
					expectFail(res, 401, 'invalid_token', 'invalid token provided');
				});

				it('rejects calls with manipulated access token', async () => {
					const res = await reg({}, bearer(token.slice(0, -1)));
					expectFail(res, 401, 'invalid_token', 'invalid token provided');
				});
			});
		});
	});

	describe('GET /reg/:clientId', () => {
		let clientId;
		let token;
		beforeAll(async () => {
			const { data } = await reg();
			if (!data) throw new Error('expected response data');
			clientId = data.client_id;
			token = data.registration_access_token;
		});

		it('returns all available nonsecret metadata', async () => {
			const res = await agent.reg({ clientId }).get({ headers: bearer(token) });
			expect(res.status).toBe(200);
			expect(getHeader(res.response, 'content-type')).toMatch(/application\/json/);
			expect(res.data).toHaveProperty('client_id');
			expect(res.data).toHaveProperty('client_secret');
			expect(res.data).toHaveProperty('registration_access_token');
			expect(res.data).toHaveProperty('client_secret_expires_at', 0);
			expect(res.data).toHaveProperty('application_type', 'web');
			expect(res.data).toHaveProperty('id_token_signed_response_alg', 'RS256');
			expect(res.data).toHaveProperty(
				'token_endpoint_auth_method',
				'client_secret_basic'
			);
			expect(res.data).toHaveProperty('require_auth_time', false);
			if (!res.data) throw new Error('expected response data');
			expect(res.data.grant_types).toEqual(['authorization_code']);
			expect(res.data.response_types).toEqual(['code']);
			expect(res.data).toHaveProperty(
				'registration_client_uri',
				`${ISSUER}/reg/${res.data.client_id}`
			);
		});

		it('returns token-endpoint-like cache headers', async () => {
			const res = await agent.reg({ clientId }).get({ headers: bearer(token) });
			expect(getHeader(res.response, 'cache-control')).toBe('no-store');
		});

		it('validates client is a valid client', async () => {
			const res = await agent
				.reg({ clientId: 'thisDOesnotCompute' })
				.get({ headers: bearer('wahtever') });
			expectFail(res, 401, 'invalid_token', 'invalid token provided');
		});

		it('validates auth presence', async () => {
			const res = await agent.reg({ clientId }).get();
			expectFail(res, 400, 'invalid_request', 'no access token provided');
		});

		it('validates auth', async () => {
			const res = await agent
				.reg({ clientId })
				.get({ headers: bearer('invalidtoken') });
			expectFail(res, 401, 'invalid_token', 'invalid token provided');
		});

		it('validates auth (notfoundtoken)', async () => {
			const res = await agent.reg({ clientId }).get({
				headers: bearer('Loremipsumdolorsitametconsecteturadipisicingelitsed')
			});
			expectFail(res, 401, 'invalid_token', 'invalid token provided');
		});

		it('accepts query', async () => {
			const res = await agent
				.reg({ clientId })
				.get({ query: { access_token: token } });
			expect(res.status).toBe(200);
		});

		it('accepts header', async () => {
			const res = await agent.reg({ clientId }).get({ headers: bearer(token) });
			expect(res.status).toBe(200);
		});

		it('invalidates registration_access_token if used on the wrong client', async () => {
			const spy = mock();
			provider.once('registration_access_token.destroyed', spy);

			const res = await agent
				.reg({ clientId: 'foobar' })
				.get({ headers: bearer(token) });
			expect(getHeader(res.response, 'cache-control')).toBe('no-store');
			expectFail(res, 401, 'invalid_token', 'invalid token provided');
			expect(spy).toHaveBeenCalledTimes(1);
			expect(spy.mock.calls[0][0].payload.clientId).toBe(clientId);
		});

		it('cannot read non-dynamic clients', async () => {
			const rat = new RegistrationAccessToken({ clientId: 'client' });
			const bearerToken = await rat.save();
			const res = await agent
				.reg({ clientId: 'client' })
				.get({ headers: bearer(bearerToken) });
			expectFail(
				res,
				403,
				'invalid_request',
				'client does not have permission to read its record'
			);
		});
	});
});
