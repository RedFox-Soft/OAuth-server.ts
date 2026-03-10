import {
	describe,
	beforeAll,
	it,
	mock,
	afterEach,
	expect,
	spyOn
} from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import { provider } from 'lib/provider.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';

describe('grant_type=client_credentials w/ resourceIndicators', () => {
	beforeAll(async function () {
		await bootstrap(import.meta.url, {
			config: 'client_credentials'
		})();
	});
	afterEach(function () {
		mock.restore();
	});

	it('provides a Bearer client credentials opaque token', async function () {
		const spy = mock();
		provider.once('client_credentials.saved', spy);

		const res = await agent.token.post(
			{
				grant_type: 'client_credentials',
				scope: 'api:read',
				resource: 'urn:wl:opaque'
			},
			{
				headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
			}
		);
		expect(res.status).toBe(200);
		expect(spy).toHaveBeenCalledTimes(1);
		expect(spy.mock.calls[0][0].payload).toEqual(
			expect.objectContaining({
				scope: 'api:read',
				aud: 'urn:wl:opaque'
			})
		);
		expect(res.data).toContainAllKeys([
			'access_token',
			'expires_in',
			'token_type',
			'scope'
		]);
		expect(res.data.scope).toBe('api:read');
	});

	it('provides a Bearer client credentials jwt token', async function () {
		const spy = mock();
		provider.once('client_credentials.issued', spy);

		const res = await agent.token.post(
			{
				grant_type: 'client_credentials',
				scope: 'api:read',
				resource: 'urn:wl:jwt'
			},
			{
				headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
			}
		);
		expect(res.status).toBe(200);
		expect(spy).toHaveBeenCalledTimes(1);
		expect(spy.mock.calls[0][0].payload).toEqual(
			expect.objectContaining({
				scope: 'api:read',
				aud: 'urn:wl:jwt'
			})
		);
		expect(res.data).toContainAllKeys([
			'access_token',
			'expires_in',
			'token_type',
			'scope'
		]);
		expect(res.data.scope).toBe('api:read');
	});

	it('ignores unsupported scopes', async function () {
		const res = await agent.token.post(
			{
				grant_type: 'client_credentials',
				scope: 'api:read api:admin',
				resource: 'urn:wl:opaque'
			},
			{
				headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
			}
		);
		expect(res.status).toBe(200);
		expect(res.data).toContainAllKeys([
			'access_token',
			'expires_in',
			'token_type',
			'scope'
		]);
		expect(res.data.scope).toBe('api:read');
	});

	it('can reject resource indicator', async function () {
		const { error } = await agent.token.post(
			{
				grant_type: 'client_credentials',
				scope: 'api:read api:admin',
				resource: 'urn:bl'
			},
			{
				headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
			}
		);
		expect(error.status).toBe(400);
		expect(error?.value).toEqual({
			error: 'invalid_target',
			error_description: 'resource indicator is missing, or unknown'
		});
	});

	it('only supports a single resource indicator', async function () {
		const { error } = await agent.token.post(
			{
				grant_type: 'client_credentials',
				scope: 'api:read',
				resource: ['urn:wl:opaque:default', 'urn:wl:opaque:explicit']
			},
			{
				headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
			}
		);
		expect(error.status).toBe(422);
		expect(error?.value).toEqual({
			error: 'invalid_request',
			error_description:
				"Expected property 'resource' to be string but found: urn:wl:opaque:default,urn:wl:opaque:explicit"
		});
	});

	it('validates each resource to be a valid URI individually', async function () {
		const { error } = await agent.token.post(
			{
				grant_type: 'client_credentials',
				scope: 'api:read',
				resource: 'invalid'
			},
			{
				headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
			}
		);
		expect(error.status).toBe(422);
		expect(error?.value).toEqual({
			error: 'invalid_request',
			error_description: "Property 'resource' should be uri"
		});
	});

	it('checks the policy and adds the resource', async function () {
		const spy = mock();
		provider.once('client_credentials.saved', spy);
		provider.once('client_credentials.issued', spy);

		const { error } = await agent.token.post(
			{
				grant_type: 'client_credentials',
				scope: 'api:read',
				resource: 'urn:not:allowed'
			},
			{
				headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
			}
		);
		expect(error.status).toBe(400);
		expect(error?.value).toEqual({
			error: 'invalid_target',
			error_description: 'resource indicator is missing, or unknown'
		});

		const res = await agent.token.post(
			{
				grant_type: 'client_credentials',
				scope: 'api:read',
				resource: 'urn:wl:opaque:explicit'
			},
			{
				headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
			}
		);
		expect(res.status).toBe(200);
		expect(spy).toHaveBeenCalledTimes(1);
		const token = spy.mock.calls[0][0];
		expect(token.payload.aud).toBe('urn:wl:opaque:explicit');
		expect(token.payload.scope).toBe('api:read');
	});

	it('also ignores resource unrecognized scopes', async function () {
		const spy = mock();
		provider.once('client_credentials.saved', spy);
		provider.once('client_credentials.issued', spy);

		const res = await agent.token.post(
			{
				grant_type: 'client_credentials',
				scope: 'api:read api:write unrecognized',
				resource: 'urn:wl:opaque:explicit'
			},
			{
				headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
			}
		);
		expect(res.status).toBe(200);
		expect(spy).toHaveBeenCalledTimes(1);
		const token = spy.mock.calls[0][0];
		expect(token.payload.aud).toBe('urn:wl:opaque:explicit');
		expect(token.payload.scope).toBe('api:read api:write');
	});

	it('applies the default resource', async function () {
		const spy = mock();
		provider.once('client_credentials.saved', spy);
		provider.once('client_credentials.issued', spy);

		const res = await agent.token.post(
			{
				grant_type: 'client_credentials',
				scope: 'api:read'
			},
			{
				headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
			}
		);
		expect(res.status).toBe(200);
		expect(spy).toHaveBeenCalledTimes(1);
		const token = spy.mock.calls[0][0];
		expect(token.payload.aud).toBe('urn:wl:opaque:default');
		expect(token.payload.scope).toBe('api:read');
	});

	it('populates ctx.oidc.entities', async function () {
		const spy = spyOn(OIDCContext.prototype, 'entity');

		await agent.token.post(
			{
				grant_type: 'client_credentials',
				scope: 'api:read'
			},
			{
				headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
			}
		);
		const entities = spy.mock.calls.map((call) => call[0]);
		expect(['Client', 'ClientCredentials']).toEqual(
			expect.arrayContaining(entities)
		);
	});
});
