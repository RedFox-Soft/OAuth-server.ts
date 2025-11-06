import { beforeAll, describe, it, expect, mock, spyOn } from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import { provider } from 'lib/provider.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';

describe('grant_type=client_credentials', () => {
	beforeAll(async function () {
		await bootstrap(import.meta.url)();
	});

	it('provides a Bearer client credentials token', async function () {
		const spy = mock();
		provider.once('grant.success', spy);

		const { status, data } = await agent.token.post(
			{
				grant_type: 'client_credentials',
				scope: 'api:read'
			},
			{
				headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
			}
		);
		expect(status).toBe(200);
		expect(spy).toBeCalledTimes(1);
		console.log(data);
		['access_token', 'expires_in', 'token_type', 'scope'].forEach((prop) =>
			expect(data).toHaveProperty(prop)
		);
	});

	it('ignores unsupported scopes', async function () {
		const spy = mock();
		provider.once('client_credentials.saved', spy);
		provider.once('client_credentials.issued', spy);

		const { status, data } = await agent.token.post(
			{
				grant_type: 'client_credentials',
				scope: 'api:read api:admin'
			},
			{
				headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
			}
		);
		expect(status).toBe(200);
		expect(spy).toBeCalledTimes(1);
		['access_token', 'expires_in', 'token_type', 'scope'].forEach((prop) =>
			expect(data).toHaveProperty(prop)
		);

		const [[token]] = spy.mock.calls;
		expect(token).toHaveProperty('scope', 'api:read');
	});

	it('checks clients scope allow list', async function () {
		const { error } = await agent.token.post(
			{
				grant_type: 'client_credentials',
				scope: 'api:read api:write'
			},
			{
				headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
			}
		);
		expect(error.status).toBe(400);
		expect(error.value).toEqual({
			error: 'invalid_scope',
			error_description: 'requested scope is not allowed'
		});
	});

	it('populates ctx.oidc.entities', async function () {
		const spy = spyOn(OIDCContext.prototype, 'entity');
		const { status } = await agent.token.post(
			{
				grant_type: 'client_credentials',
				scope: 'api:read'
			},
			{
				headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
			}
		);
		expect(status).toBe(200);
		const entities = spy.mock.calls.map((call) => call[0]);
		expect(['Client', 'ClientCredentials']).toEqual(
			expect.arrayContaining(entities)
		);
	});
});
