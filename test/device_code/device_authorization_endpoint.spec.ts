import {
	describe,
	it,
	beforeAll,
	afterEach,
	expect,
	mock,
	spyOn
} from 'bun:test';

import bootstrap, { agent, jsonToFormUrlEncoded } from '../test_helper.js';
import { normalize } from '../../lib/helpers/user_codes.ts';
import { provider } from 'lib/provider.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { DeviceCode } from 'lib/models/device_code.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';

const form = { 'content-type': 'application/x-www-form-urlencoded' };

function post(body, headers = {}) {
	return agent.device.auth.post(jsonToFormUrlEncoded(body), {
		headers: { ...form, ...headers }
	});
}

describe('device_authorization_endpoint', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	afterEach(() => {
		mock.restore();
		provider.removeAllListeners('device_authorization.error');
		provider.removeAllListeners('device_authorization.success');
	});

	describe('client validation', () => {
		it('only responds to clients with urn:ietf:params:oauth:grant-type:device_code enabled', async () => {
			const spy = mock();
			provider.once('device_authorization.error', spy);

			const { error } = await post({ client_id: 'client-not-allowed' });
			if (!error) throw new Error('expected error response');

			expect(error.status).toBe(400);
			expect(error.value).toEqual({
				error: 'invalid_request',
				error_description:
					'urn:ietf:params:oauth:grant-type:device_code is not allowed for this client'
			});
			expect(spy).toBeCalledTimes(1);
		});

		it('rejects invalid clients', async () => {
			const spy = mock();
			provider.once('device_authorization.error', spy);

			const { error } = await post({ client_id: 'not-found-client' });
			if (!error) throw new Error('expected error response');

			expect(error.status).toBe(401);
			expect(spy).toBeCalledTimes(1);
			expect(error.value).toEqual({
				error: 'invalid_client',
				error_description: 'client authentication failed'
			});
		});
	});

	describe('param validation', () => {
		// The Elysia endpoint validates against a strict body schema: parameters not part of the
		// device authorization request (e.g. request_uri, registration) are rejected rather than
		// silently ignored. This is stricter than the original arbitrary-param pass-through.
		['request_uri', 'registration'].forEach((param) => {
			it(`rejects not supported parameter ${param}`, async () => {
				const { error } = await post({
					client_id: 'client',
					[param]: 'some'
				});
				if (!error) throw new Error('expected error response');

				expect(error.status).toBeGreaterThanOrEqual(400);
				expect(error.status).toBeLessThan(500);
			});
		});
	});

	it('responds with json 200', async () => {
		const spy = mock();
		provider.once('device_authorization.success', spy);

		const { status, data } = await post({
			client_id: 'client',
			scope: 'openid',
			claims: JSON.stringify({ userinfo: { email: null } })
		});
		if (!data) throw new Error('expected response data');

		expect(status).toBe(200);
		expect(spy).toBeCalledTimes(1);

		expect(Object.keys(data).sort()).toEqual(
			[
				'device_code',
				'user_code',
				'verification_uri',
				'verification_uri_complete',
				'expires_in'
			].sort()
		);
		expect(data.verification_uri_complete).toBe(
			`${data.verification_uri}?user_code=${data.user_code}`
		);
		expect(data.verification_uri).toMatch(/\/device$/);
		expect(data.expires_in).toBeCloseTo(600, 0);

		const dc = await DeviceCode.find(data.device_code);
		expect(dc).toBeTruthy();
		expect(dc.payload).toHaveProperty('clientId', 'client');
		expect(typeof dc.payload.userCode).toBe('string');
		expect(dc.payload.userCode).toBe(normalize(data.user_code));
		expect(typeof dc.payload.params).toBe('object');
		expect(dc.payload.params).toHaveProperty('client_id', 'client');
		expect(dc.payload.params).toHaveProperty('scope', 'openid');
		expect(dc.payload.params.claims).toEqual({ userinfo: { email: null } });
		expect(dc.payload.params).not.toHaveProperty('redirect_uri');
		expect(dc.payload.params).not.toHaveProperty('response_type');
		expect(dc.payload.params).not.toHaveProperty('state');
		expect(dc.payload.params).not.toHaveProperty('response_mode');
	});

	it('handles regular client auth', async () => {
		const { status, data } = await agent.device.auth.post(
			jsonToFormUrlEncoded({}),
			{
				headers: {
					...form,
					...AuthorizationRequest.basicAuthHeader('client-basic-auth', 'secret')
				}
			}
		);

		expect(status).toBe(200);
		expect(Object.keys(data).sort()).toEqual(
			[
				'device_code',
				'user_code',
				'verification_uri',
				'verification_uri_complete',
				'expires_in'
			].sort()
		);
	});

	it('populates ctx.oidc.entities', async () => {
		const spy = spyOn(OIDCContext.prototype, 'entity');

		await post({
			client_id: 'client',
			scope: 'openid'
		});

		const keys = spy.mock.calls.map((c) => c[0]);
		expect(keys).toContain('Client');
		expect(keys).toContain('DeviceCode');
	});
});
