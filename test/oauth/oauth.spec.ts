import { parse as parseUrl } from 'node:url';

import {
	describe,
	it,
	beforeAll,
	beforeEach,
	afterEach,
	expect,
	spyOn,
	mock
} from 'bun:test';
import snakeCase from 'lodash/snakeCase.js';

import bootstrap, {
	agent,
	jsonToFormUrlEncoded,
	type Setup
} from '../test_helper.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { provider } from 'lib/provider.js';
import { Client } from 'lib/models/client.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { TestAdapter } from 'test/models.js';

function getAuth(auth, cookie?) {
	return agent.auth.get({ query: auth.params, headers: { cookie } });
}

function codeFromResponse(response: Response) {
	const location = response.headers.get('location');
	const {
		query: { code }
	} = parseUrl(location, true);
	return code as string;
}

describe('requests without the openid scope', () => {
	let setup: Setup;
	beforeAll(async () => {
		setup = await bootstrap(import.meta.url);
	});

	beforeEach(function () {
		// consent skip: never require an interaction prompt for these flows.
		// Re-applied every test because afterEach's mock.restore() clears it.
		spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(false);
	});

	afterEach(function () {
		provider.removeAllListeners();
		mock.restore();
	});

	describe('openid scope gated parameters', () => {
		// Each value must be well-formed enough to clear the TypeBox query-schema
		// validation so the request actually reaches the openid-scope gate under
		// test. `max_age` must be numeric; `claims` must be an object/ObjectString.
		const gatedValues = {
			acr_values: 'foo',
			claims: { id_token: { email: null } },
			claims_locales: 'foo',
			id_token_hint: 'foo',
			max_age: 300,
			nonce: 'foo'
		};
		Object.keys(gatedValues).forEach((param) => {
			it(`${param} can only be used when openid is amongst the requested scopes`, async function () {
				const auth = new AuthorizationRequest({
					[param]: gatedValues[param]
				});

				const { response } = await getAuth(auth);

				expect(response.status).toBe(303);
				// notice state is not expected
				auth.validatePresence(response, [
					'error',
					'error_description',
					'state'
				]);
				auth.validateClientLocation(response);
				auth.validateError(response, 'invalid_request');
				auth.validateErrorDescription(
					response,
					`openid scope must be requested when using the ${param} parameter`
				);
			});
		});

		Object.entries({
			defaultAcrValues: ['foo'],
			defaultMaxAge: 300,
			requireAuthTime: true
		}).forEach(([clientProperty, value]) => {
			it(`must be provided when client is configured with ${snakeCase(clientProperty)}`, async function () {
				const auth = new AuthorizationRequest({ client_id: 'client' });

				const client = await Client.find('client');
				client[clientProperty] = value;

				let response;
				try {
					({ response } = await getAuth(auth));
				} finally {
					delete client[clientProperty];
				}

				expect(response.status).toBe(303);
				// notice state is not expected
				auth.validatePresence(response, [
					'error',
					'error_description',
					'state'
				]);
				auth.validateClientLocation(response);
				auth.validateError(response, 'invalid_request');
				auth.validateErrorDescription(
					response,
					`openid scope must be requested for clients with ${snakeCase(clientProperty)}`
				);
			});
		});
	});

	describe('response_types and flows that work when scope parameter is missing openid scope', () => {
		const scope = 'api:read';

		describe('when scope is e.g. missing openid (api:read)', () => {
			let cookie: string;
			beforeAll(async function () {
				cookie = await setup.login({
					scope: [scope, 'offline_access'].join(' ')
				});
			});

			describe('response_type=code', () => {
				it('gets a code from the authorization endpoint', async function () {
					const auth = new AuthorizationRequest({ scope });

					const spy = mock();
					provider.on('authorization_code.saved', spy);

					const { response } = await getAuth(auth, cookie);

					expect(response.status).toBe(303);
					auth.validateClientLocation(response);
					auth.validatePresence(response, ['code', 'state']);

					expect(spy).toHaveBeenCalledTimes(1);
					expect(spy.mock.calls[0][0].payload).toHaveProperty('scope', scope);
				});

				describe('authorization code exchange', () => {
					let auth;
					let code;
					beforeEach(async function () {
						auth = new AuthorizationRequest({ scope });

						const { response } = await getAuth(auth, cookie);
						expect(response.status).toBe(303);
						auth.validateClientLocation(response);
						auth.validatePresence(response, ['code', 'state']);
						code = codeFromResponse(response);
					});

					it('gets an access token', async function () {
						const spy = mock();
						provider.on('access_token.saved', spy);
						provider.on('access_token.issued', spy);

						const { data, status } = await auth.getToken(code);
						expect(status).toBe(200);
						expect(data).toHaveProperty('access_token');
						expect(data).not.toHaveProperty('id_token');

						expect(spy).toHaveBeenCalledTimes(1);
						expect(spy.mock.calls[0][0].payload).toHaveProperty('scope', scope);
					});

					it('gets an access token and a refresh token', async function () {
						const adapter = TestAdapter.for('AuthorizationCode');
						const jti = setup.getTokenJti(code);

						const refreshScope = `${scope || ''} offline_access`.trim();

						adapter.syncUpdate(jti, {
							scope: refreshScope
						});

						const spy = mock();
						provider.on('access_token.saved', spy);
						provider.on('access_token.issued', spy);
						provider.on('refresh_token.saved', spy);

						const { data, status } = await auth.getToken(code);
						expect(status).toBe(200);
						expect(data).toHaveProperty('access_token');
						expect(data).toHaveProperty('refresh_token');
						expect(data).not.toHaveProperty('id_token');

						expect(spy).toHaveBeenCalledTimes(2);
						expect(spy.mock.calls[0][0].payload).toHaveProperty(
							'scope',
							refreshScope
						);
						expect(spy.mock.calls[1][0].payload).toHaveProperty(
							'scope',
							refreshScope
						);
					});
				});

				describe('refresh token exchange', () => {
					const refreshScope = `${scope || ''} offline_access`.trim();
					let rt;

					beforeAll(async function () {
						cookie = await setup.login({
							scope: [scope, 'offline_access'].join(' ')
						});
					});

					beforeEach(async function () {
						const auth = new AuthorizationRequest({
							scope: refreshScope,
							prompt: 'consent'
						});

						const { response } = await getAuth(auth, cookie);
						expect(response.status).toBe(303);
						auth.validateClientLocation(response);
						auth.validatePresence(response, ['code', 'state']);
						const code = codeFromResponse(response);

						const { data } = await auth.getToken(code);
						if (!data) throw new Error('expected response data');
						rt = data.refresh_token;
					});

					it('gets an access token and a refresh token', async function () {
						const spy = mock();
						provider.on('access_token.saved', spy);
						provider.on('access_token.issued', spy);
						provider.on('refresh_token.saved', spy);

						const { data, status } = await agent.token.post({
							client_id: 'client',
							grant_type: 'refresh_token',
							refresh_token: rt
						});
						expect(status).toBe(200);
						expect(data).toHaveProperty('access_token');
						expect(data).toHaveProperty('refresh_token');
						expect(data).not.toHaveProperty('id_token');

						expect(spy).toHaveBeenCalledTimes(2);
						expect(spy.mock.calls[0][0].payload).toHaveProperty(
							'scope',
							refreshScope
						);
						expect(spy.mock.calls[1][0].payload).toHaveProperty(
							'scope',
							refreshScope
						);
					});
				});
			});

			describe('response_type=none', () => {
				it('gets nothing from the authorization endpoint', async function () {
					const auth = new AuthorizationRequest({
						response_type: 'none',
						scope
					});

					const spy = mock();
					provider.on('authorization.success', spy);

					const { response } = await getAuth(auth, cookie);

					expect(response.status).toBe(303);
					auth.validateClientLocation(response);
					auth.validatePresence(response, ['state']);

					expect(spy).toHaveBeenCalledTimes(1);
					expect(spy.mock.calls[0][0].oidc.params).toHaveProperty(
						'scope',
						scope
					);
				});
			});
		});

		describe('device flow', () => {
			beforeAll(async function () {
				await setup.login({ scope: [scope, 'offline_access'].join(' ') });
			});

			it('accepts the device authorization request', async function () {
				const spy = mock();
				provider.on('device_code.saved', spy);

				const { status } = await agent.device.auth.post(
					jsonToFormUrlEncoded({
						client_id: 'client',
						scope
					}),
					{
						headers: {
							'content-type': 'application/x-www-form-urlencoded'
						}
					}
				);

				expect(status).toBe(200);
				expect(spy).toHaveBeenCalledTimes(1);
				if (scope) {
					expect(spy.mock.calls[0][0].payload.params).toHaveProperty(
						'scope',
						scope
					);
				} else {
					expect(spy.mock.calls[0][0].payload.params).not.toHaveProperty(
						'scope'
					);
				}
			});

			describe('urn:ietf:params:oauth:grant-type:device_code', () => {
				let jti;
				let code;
				beforeEach(async function () {
					provider.on('device_code.saved', (token) => {
						jti = token.jti;
					});

					const { data, status } = await agent.device.auth.post(
						jsonToFormUrlEncoded({
							client_id: 'client',
							scope
						}),
						{
							headers: {
								'content-type': 'application/x-www-form-urlencoded'
							}
						}
					);
					if (!data) throw new Error('expected response data');
					expect(status).toBe(200);
					code = data.device_code;

					TestAdapter.for('DeviceCode').syncUpdate(jti, {
						scope,
						accountId: setup.getAccountId(),
						grantId: setup.getGrantId('client'),
						clientId: 'client'
					});
				});

				// SKIP: blocked by a lib bug in lib/actions/grants/device_code.ts.
				// It assigns the issued token's scope via `at.scope = ...` (and
				// `at.claims = ...`), but AccessToken has no `scope`/`claims` setter,
				// so the value lands on a throw-away instance own-property and never
				// reaches `at.payload.scope`. The authorization_code handler correctly
				// uses `at.payload.scope = ...`. The token *response* still shows the
				// scope (it falls back to `code.payload.scope`), but the persisted /
				// emitted AccessToken payload lacks it, so this assertion fails.
				// Fix: change device_code.ts lines ~152/154/155 to set
				// `at.payload.scope` / `at.payload.claims` (mirror authorization_code.ts).
				it('gets an access token', async function () {
					const spy = mock();
					provider.on('access_token.saved', spy);
					provider.on('access_token.issued', spy);

					const { data, status } = await agent.token.post({
						client_id: 'client',
						grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
						device_code: code
					});
					expect(status).toBe(200);
					expect(data).toHaveProperty('access_token');
					expect(data).not.toHaveProperty('id_token');

					expect(spy).toHaveBeenCalledTimes(1);
					expect(spy.mock.calls[0][0].payload).toHaveProperty('scope', scope);
				});

				// SKIP: same lib bug as above (device_code.ts uses `at.scope`/
				// `code.scope` rather than `.payload.scope`); the RefreshToken is also
				// built with `scope: code.scope` where `code.scope` is undefined (no
				// getter), so the emitted refresh_token payload scope is wrong too.
				it('gets an access and a refresh_token', async function () {
					const refreshScope = `${scope || ''} offline_access`.trim();
					const spy = mock();
					provider.on('access_token.saved', spy);
					provider.on('access_token.issued', spy);
					provider.on('refresh_token.saved', spy);

					TestAdapter.for('DeviceCode').syncUpdate(jti, {
						scope: refreshScope
					});

					const { data, status } = await agent.token.post({
						client_id: 'client',
						grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
						device_code: code
					});
					expect(status).toBe(200);
					expect(data).toHaveProperty('access_token');
					expect(data).toHaveProperty('refresh_token');
					expect(data).not.toHaveProperty('id_token');

					expect(spy).toHaveBeenCalledTimes(2);
					expect(spy.mock.calls[0][0].payload).toHaveProperty(
						'scope',
						refreshScope
					);
					expect(spy.mock.calls[1][0].payload).toHaveProperty(
						'scope',
						refreshScope
					);
				});
			});
		});
	});
});
