import {
	describe,
	it,
	expect,
	beforeAll,
	afterEach,
	spyOn,
	mock
} from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import { ISSUER } from 'lib/configs/env.js';
import { provider } from 'lib/provider.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { RefreshToken } from 'lib/models/refresh_token.js';
import { Client } from 'lib/models/client.js';
import { AuthorizationCode } from 'lib/models/authorization_code.js';
import { AccessToken } from 'lib/models/access_token.js';

describe('introspection features', () => {
	let setup = null;
	beforeAll(async function () {
		setup = await bootstrap(import.meta.url)();
	});
	afterEach(function () {
		mock.restore();
	});

	describe('enriched discovery', () => {
		it('shows the url now', async function () {
			const { data } = await agent['.well-known']['openid-configuration'].get();

			expect(data).toHaveProperty(
				'introspection_endpoint',
				`${ISSUER}/token/introspect`
			);
			expect(data).not.toHaveProperty(
				'introspection_signing_alg_values_supported'
			);
		});
	});

	describe('/token/introspection', () => {
		beforeAll(function () {
			return setup.login({ accountId: 'accountId' });
		});
		it('returns the properties for access token [no hint]', async function () {
			const at = new AccessToken({
				accountId: 'accountId',
				grantId: setup.getGrantId(),
				client: await Client.find('client'),
				scope: 'scope',
				aud: 'urn:example:foo'
			});

			const token = await at.save();
			const { data, status } = await agent.token.introspect.post(
				{ token },
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(data).toContainKeys([
				'client_id',
				'scope',
				'sub',
				'iss',
				'iat',
				'exp',
				'token_type',
				'aud'
			]);
			expect(data.sub).toBe('accountId');
			expect(data.token_type).toBe('Bearer');
			expect(data.iss).toBe(ISSUER);
			expect(data.aud).toBe('urn:example:foo');
		});

		it('returns the properties for access token [correct hint]', async function () {
			const at = new AccessToken({
				accountId: 'accountId',
				grantId: setup.getGrantId(),
				client: await Client.find('client'),
				scope: 'scope'
			});

			const token = await at.save();
			const { data, status } = await agent.token.introspect.post(
				{ token, token_type_hint: 'access_token' },
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);

			expect(data).toContainKeys(['client_id', 'scope', 'sub']);
			expect(data.sub).toBe('accountId');
		});

		it('returns the properties for access token [wrong hint]', async function () {
			const at = new AccessToken({
				accountId: 'accountId',
				grantId: setup.getGrantId(),
				client: await Client.find('client'),
				scope: 'scope'
			});

			const token = await at.save();
			const { data, status } = await agent.token.introspect.post(
				{ token, token_type_hint: 'refresh_token' },
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);

			expect(data).toContainKeys(['client_id', 'scope', 'sub']);
			expect(data.sub).toBe('accountId');
		});

		it('returns the properties for access token [unrecognized hint]', async function () {
			const at = new AccessToken({
				accountId: 'accountId',
				grantId: setup.getGrantId(),
				client: await Client.find('client'),
				scope: 'scope'
			});

			const token = await at.save();
			const { data, status } = await agent.token.introspect.post(
				{ token, token_type_hint: 'foobar' },
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);

			expect(data).toContainKeys(['client_id', 'scope', 'sub']);
			expect(data.sub).toBe('accountId');
		});

		it('returns the properties for refresh token [no hint]', async function () {
			const rt = new RefreshToken({
				accountId: 'accountId',
				grantId: setup.getGrantId(),
				client: await Client.find('client'),
				scope: 'scope'
			});

			const token = await rt.save();
			const { data, status } = await agent.token.introspect.post(
				{ token },
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(data).toContainKeys(['client_id', 'scope', 'sub']);
		});

		it('returns the properties for refresh token [correct hint]', async function () {
			const rt = new RefreshToken({
				accountId: 'accountId',
				grantId: setup.getGrantId(),
				client: await Client.find('client'),
				scope: 'scope'
			});

			const token = await rt.save();
			const { data, status } = await agent.token.introspect.post(
				{ token, token_type_hint: 'refresh_token' },
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(data).toContainKeys(['client_id', 'scope', 'sub']);
		});

		it('returns the properties for refresh token [wrong hint]', async function () {
			const rt = new RefreshToken({
				accountId: 'accountId',
				grantId: setup.getGrantId(),
				client: await Client.find('client'),
				scope: 'scope'
			});

			const token = await rt.save();
			const { data, status } = await agent.token.introspect.post(
				{ token, token_type_hint: 'client_credentials' },
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(data).toContainKeys(['client_id', 'scope', 'sub']);
		});

		it('returns the properties for refresh token [unrecognized hint]', async function () {
			const rt = new RefreshToken({
				accountId: 'accountId',
				grantId: setup.getGrantId(),
				client: await Client.find('client'),
				scope: 'scope'
			});

			const token = await rt.save();
			const { data, status } = await agent.token.introspect.post(
				{ token, token_type_hint: 'foobar' },
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(data).toContainKeys(['client_id', 'scope', 'sub']);
		});

		it('returns the properties for client credentials token [no hint]', async function () {
			const rt = new provider.ClientCredentials({
				client: await Client.find('client')
			});

			const token = await rt.save();
			const { data, status } = await agent.token.introspect.post(
				{ token },
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(data).toContainKey('client_id');
		});

		it('returns the properties for client credentials token [correct hint]', async function () {
			const rt = new provider.ClientCredentials({
				client: await Client.find('client')
			});

			const token = await rt.save();
			const { data, status } = await agent.token.introspect.post(
				{ token, token_type_hint: 'client_credentials' },
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(data).toContainKey('client_id');
		});

		it('returns the properties for client credentials token [wrong hint]', async function () {
			const rt = new provider.ClientCredentials({
				client: await Client.find('client')
			});

			const token = await rt.save();
			const { data, status } = await agent.token.introspect.post(
				{ token, token_type_hint: 'access_token' },
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(data).toContainKey('client_id');
		});

		it('returns the properties for client credentials token [unrecognized hint]', async function () {
			const rt = new provider.ClientCredentials({
				client: await Client.find('client')
			});

			const token = await rt.save();
			const { data, status } = await agent.token.introspect.post(
				{ token, token_type_hint: 'foobar' },
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(data).toContainKey('client_id');
		});

		it('can be called by pairwise clients', async function () {
			const rt = new RefreshToken({
				accountId: 'accountId',
				grantId: setup.getGrantId('client-pairwise'),
				clientId: 'client-pairwise',
				scope: 'scope'
			});

			const token = await rt.save();
			const { data, status } = await agent.token.introspect.post(
				{ token },
				{
					headers: AuthorizationRequest.basicAuthHeader(
						'client-pairwise',
						'secret'
					)
				}
			);
			expect(status).toBe(200);
			expect(data).toContainKeys(['client_id', 'scope', 'sub']);
			expect(data.sub).not.toBe('accountId');
		});

		it('can be called by RS clients and uses the original subject_type', async function () {
			const rt = new RefreshToken({
				accountId: 'accountId',
				grantId: setup.getGrantId('client-pairwise'),
				clientId: 'client-pairwise',
				scope: 'scope'
			});

			const token = await rt.save();
			const { data, status } = await agent.token.introspect.post(
				{ token },
				{
					headers: AuthorizationRequest.basicAuthHeader(
						'client-pairwise',
						'secret'
					)
				}
			);
			expect(status).toBe(200);
			expect(data).toContainKeys(['client_id', 'scope', 'sub']);
			expect(data.sub).not.toBe('accountId');
		});

		it('returns token-endpoint-like cache headers', async function () {
			const { headers } = await agent.token.introspect.post(
				{},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(headers.get('cache-control')).toBe('no-store');
		});

		it('validates token param presence', async function () {
			const { error } = await agent.token.introspect.post(
				{},
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(error.status).toBe(422);
			expect(error.value).toHaveProperty('error', 'invalid_request');
			expect(error.value).toHaveProperty(
				'error_description',
				"Property 'token' is missing"
			);
		});

		it('responds with active=false for total bs', async function () {
			const { data, status } = await agent.token.introspect.post(
				{ token: 'this is not even a token' },
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(data).toEqual({ active: false });
		});

		it('responds with active=false when client auth = none and token does not belong to it', async function () {
			const at = new AccessToken({
				accountId: 'accountId',
				grantId: setup.getGrantId(),
				client: await Client.find('client'),
				scope: 'scope'
			});

			const token = await at.save();
			const { data, status } = await agent.token.introspect.post({
				token,
				client_id: 'client-none'
			});
			expect(status).toBe(200);
			expect(data).toEqual({ active: false });
		});

		it('emits on (i.e. auth) error', async function () {
			const spy = mock();
			provider.once('introspection.error', spy);

			const { status } = await agent.token.introspect.post(
				{ token: 'invalid' },
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'invalid')
				}
			);
			expect(status).toBe(401);
			expect(spy).toBeCalledTimes(1);
		});

		it('ignores unsupported tokens', async function () {
			const ac = new AuthorizationCode({ clientId: 'client' });
			const token = await ac.save();
			const { data, status } = await agent.token.introspect.post(
				{ token },
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(data).toEqual({ active: false });
		});

		it('responds only with active=false when token is expired', async function () {
			const at = new AccessToken({
				accountId: 'accountId',
				grantId: setup.getGrantId(),
				client: await Client.find('client'),
				scope: 'scope',
				expiresIn: -1
			});
			const token = await at.save();

			const { data, status } = await agent.token.introspect.post(
				{ token },
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(data).toEqual({ active: false });
		});

		it('responds only with active=false when token is already consumed', async function () {
			const rt = new RefreshToken({
				accountId: 'accountId',
				grantId: setup.getGrantId(),
				client: await Client.find('client'),
				scope: 'scope'
			});

			const token = await rt.save();
			await rt.consume();
			const { data, status } = await agent.token.introspect.post(
				{ token },
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);
			expect(status).toBe(200);
			expect(data).toEqual({ active: false });
		});

		it('does not allow to introspect the uninstrospectable (in case adapter is implemented wrong)', async function () {
			spyOn(AccessToken, 'find').mockReturnValue({
				isValid: true,
				kind: 'AuthorizationCode'
			});

			const { data, status } = await agent.token.introspect.post(
				{ token: 'foo' },
				{
					headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
				}
			);

			expect(status).toBe(200);
			expect(data).toEqual({ active: false });
		});

		describe('populates ctx.oidc.entities', () => {
			it('when introspecting an AccessToken', async function () {
				const spy = spyOn(OIDCContext.prototype, 'entity');

				const at = new AccessToken({
					accountId: 'accountId',
					client: await Client.find('client'),
					scope: 'scope'
				});

				const token = await at.save();
				await agent.token.introspect.post(
					{ token },
					{
						headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
					}
				);

				const entities = spy.mock.calls.map((call) => call[0]);
				expect(entities).toEqual(['Client', 'AccessToken']);
			});

			it('when introspecting a RefreshToken', async function () {
				const spy = spyOn(OIDCContext.prototype, 'entity');

				const rt = new RefreshToken({
					accountId: 'accountId',
					client: await Client.find('client'),
					scope: 'scope'
				});

				const token = await rt.save();
				await agent.token.introspect.post(
					{ token },
					{
						headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
					}
				);

				const entities = spy.mock.calls.map((call) => call[0]);
				expect(entities).toEqual(['Client', 'RefreshToken']);
			});

			it('when introspecting ClientCredentials', async function () {
				const spy = spyOn(OIDCContext.prototype, 'entity');

				const rt = new provider.ClientCredentials({
					client: await Client.find('client')
				});

				const token = await rt.save();
				await agent.token.introspect.post(
					{ token },
					{
						headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
					}
				);

				const entities = spy.mock.calls.map((call) => call[0]);
				expect(entities).toEqual(['Client', 'ClientCredentials']);
			});
		});
	});
});
