import { describe, it, beforeAll, afterEach, expect, mock } from 'bun:test';
import { strict as assert } from 'node:assert';

import bootstrap, { agent, jsonToFormUrlEncoded } from '../test_helper.js';
import { defaults } from '../../lib/helpers/defaults.ts';
import { provider } from 'lib/provider.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { grantFlags, resetGrantFlags } from './grant_flags.ts';

const form = 'application/x-www-form-urlencoded';

const {
	features: { resourceIndicators }
} = defaults;

describe('features.resourceIndicators defaults', () => {
	it('defaultResource', async () => {
		expect(await resourceIndicators.defaultResource()).toBeUndefined();
		expect(
			await resourceIndicators.defaultResource(undefined, undefined, [
				'urn:example:rs'
			])
		).toEqual(['urn:example:rs']);
	});

	it('getResourceServerInfo', async () => {
		await assert.rejects(resourceIndicators.getResourceServerInfo(), (err) => {
			expect(err.message).toBe('invalid_target');
			expect(err.error_description).toBe(
				'resource indicator is missing, or unknown'
			);
			return true;
		});
	});
});

describe('features.resourceIndicators', () => {
	let setup = null;
	let cookie = null;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url)();
	});
	afterEach(() => {
		provider.removeAllListeners();
		mock.restore();
		resetGrantFlags();
	});
	beforeAll(async () => {
		cookie = await setup.login({
			resources: {
				'urn:wl:default': 'api:read api:write',
				'urn:wl:explicit': 'api:read api:write'
			}
		});
	});

	describe('resource validations', () => {
		it('must be a URI', async () => {
			const { error } = await agent.token.post({
				client_id: 'client',
				grant_type: 'client_credentials',
				scope: 'api:read',
				resource: 'wl-not-a-uri'
			});
			expect(error.status).toBe(422);
			expect(error.value).toEqual({
				error: 'invalid_request',
				error_description: "Property 'resource' should be uri"
			});
		});

		it('must not contain a fragment', async () => {
			const { error } = await agent.token.post({
				client_id: 'client',
				grant_type: 'client_credentials',
				scope: 'api:read',
				resource: 'urn:wl:foo/bar#'
			});
			expect(error.status).toBe(400);
			expect(error.value).toEqual({
				error: 'invalid_target',
				error_description:
					'resource indicator must not contain a fragment component'
			});
		});
	});

	['get', 'post'].forEach((verb) => {
		function authRequest(auth) {
			if (verb === 'get') {
				return agent.auth.get({ query: auth.params, headers: { cookie } });
			}
			return agent.auth.post(jsonToFormUrlEncoded(auth.params), {
				headers: { cookie, 'content-type': form }
			});
		}

		describe(`${verb} response_type includes code`, () => {
			it('checks the policy and adds the resource', async () => {
				const spy = mock();
				provider.once('authorization_code.saved', spy);

				const auth = new AuthorizationRequest({
					resource: 'urn:not:allowed',
					scope: 'api:read'
				});

				let res = await authRequest(auth);
				expect(res.status).toBe(303);
				auth.validatePresence(res.response, [
					'error',
					'error_description',
					'state'
				]);
				auth.validateState(res.response);
				auth.validateClientLocation(res.response);
				auth.validateError(res.response, 'invalid_target');
				auth.validateErrorDescription(
					res.response,
					'resource indicator is missing, or unknown'
				);

				auth.params.resource = 'urn:wl:explicit';
				res = await authRequest(auth);
				expect(res.status).toBe(303);
				auth.validatePresence(res.response, ['code', 'state']);
				auth.validateState(res.response);
				auth.validateClientLocation(res.response);

				expect(spy).toHaveBeenCalledTimes(1);
				const code = spy.mock.calls[0][0];
				expect(code.payload.resource).toBe('urn:wl:explicit');

				const spy2 = mock();
				provider.once('access_token.saved', spy2);
				provider.once('access_token.issued', spy2);
				const spy3 = mock();
				provider.once('refresh_token.saved', spy3);

				res = await agent.token.post({
					client_id: 'client',
					grant_type: 'authorization_code',
					code_verifier: auth.code_verifier,
					code: code.jti
				});
				expect(res.status).toBe(200);

				expect(spy2).toHaveBeenCalledTimes(1);
				let at = spy2.mock.calls[0][0];
				expect(at.payload.aud).toBe('urn:wl:explicit');

				expect(spy3).toHaveBeenCalledTimes(1);
				let rt = spy3.mock.calls[0][0];
				expect(rt.payload.resource).toBe('urn:wl:explicit');

				const spy4 = mock();
				provider.once('access_token.saved', spy4);
				provider.once('access_token.issued', spy4);
				const spy5 = mock();
				provider.once('refresh_token.saved', spy5);

				res = await agent.token.post({
					client_id: 'client',
					grant_type: 'refresh_token',
					refresh_token: rt.jti
				});
				expect(res.status).toBe(200);

				expect(spy4).toHaveBeenCalledTimes(1);
				at = spy4.mock.calls[0][0];
				expect(at.payload.aud).toBe('urn:wl:explicit');

				expect(spy5).toHaveBeenCalledTimes(1);
				rt = spy5.mock.calls[0][0];
				expect(rt.payload.resource).toBe('urn:wl:explicit');
			});

			it('applies the default resource', async () => {
				const spy = mock();
				provider.once('authorization_code.saved', spy);

				const auth = new AuthorizationRequest({
					scope: 'api:read'
				});

				let res = await authRequest(auth);
				expect(res.status).toBe(303);
				auth.validatePresence(res.response, ['code', 'state']);
				auth.validateState(res.response);
				auth.validateClientLocation(res.response);

				expect(spy).toHaveBeenCalledTimes(1);
				const code = spy.mock.calls[0][0];
				expect(code.payload.resource).toBe('urn:wl:default');

				const spy2 = mock();
				provider.once('access_token.saved', spy2);
				provider.once('access_token.issued', spy2);
				const spy3 = mock();
				provider.once('refresh_token.saved', spy3);

				res = await agent.token.post({
					client_id: 'client',
					grant_type: 'authorization_code',
					code_verifier: auth.code_verifier,
					code: code.jti
				});
				expect(res.status).toBe(200);

				expect(spy2).toHaveBeenCalledTimes(1);
				let at = spy2.mock.calls[0][0];
				expect(at.payload.aud).toBe('urn:wl:default');

				expect(spy3).toHaveBeenCalledTimes(1);
				let rt = spy3.mock.calls[0][0];
				expect(rt.payload.resource).toBe('urn:wl:default');

				const spy4 = mock();
				provider.once('access_token.saved', spy4);
				provider.once('access_token.issued', spy4);
				const spy5 = mock();
				provider.once('refresh_token.saved', spy5);

				res = await agent.token.post({
					client_id: 'client',
					grant_type: 'refresh_token',
					refresh_token: rt.jti
				});
				expect(res.status).toBe(200);

				expect(spy4).toHaveBeenCalledTimes(1);
				at = spy4.mock.calls[0][0];
				expect(at.payload.aud).toBe('urn:wl:default');

				expect(spy5).toHaveBeenCalledTimes(1);
				rt = spy5.mock.calls[0][0];
				expect(rt.payload.resource).toBe('urn:wl:default');
			});

			it('applies the default resource (when useGrantedResource returns true)', async () => {
				grantFlags.useGranted = true;

				const spy = mock();
				provider.once('authorization_code.saved', spy);

				const auth = new AuthorizationRequest({
					scope: 'openid api:read'
				});

				let res = await authRequest(auth);
				expect(res.status).toBe(303);
				auth.validatePresence(res.response, ['code', 'state']);
				auth.validateState(res.response);
				auth.validateClientLocation(res.response);

				expect(spy).toHaveBeenCalledTimes(1);
				const code = spy.mock.calls[0][0];
				expect(code.payload.resource).toBe('urn:wl:default');

				const spy2 = mock();
				provider.once('access_token.saved', spy2);
				provider.once('access_token.issued', spy2);
				const spy3 = mock();
				provider.once('refresh_token.saved', spy3);

				res = await agent.token.post({
					client_id: 'client',
					grant_type: 'authorization_code',
					code_verifier: auth.code_verifier,
					code: code.jti
				});
				expect(res.status).toBe(200);

				expect(spy2).toHaveBeenCalledTimes(1);
				let at = spy2.mock.calls[0][0];
				expect(at.payload.aud).toBe('urn:wl:default');

				expect(spy3).toHaveBeenCalledTimes(1);
				let rt = spy3.mock.calls[0][0];
				expect(rt.payload.resource).toBe('urn:wl:default');

				const spy4 = mock();
				provider.once('access_token.saved', spy4);
				provider.once('access_token.issued', spy4);
				const spy5 = mock();
				provider.once('refresh_token.saved', spy5);

				res = await agent.token.post({
					client_id: 'client',
					grant_type: 'refresh_token',
					refresh_token: rt.jti
				});
				expect(res.status).toBe(200);

				expect(spy4).toHaveBeenCalledTimes(1);
				at = spy4.mock.calls[0][0];
				expect(at.payload.aud).toBe('urn:wl:default');

				expect(spy5).toHaveBeenCalledTimes(1);
				rt = spy5.mock.calls[0][0];
				expect(rt.payload.resource).toBe('urn:wl:default');
			});

			it('applies the explicit resource', async () => {
				const spy = mock();
				provider.once('authorization_code.saved', spy);

				const auth = new AuthorizationRequest({
					scope: 'openid api:read'
				});

				let res = await authRequest(auth);
				expect(res.status).toBe(303);
				auth.validatePresence(res.response, ['code', 'state']);
				auth.validateState(res.response);
				auth.validateClientLocation(res.response);

				expect(spy).toHaveBeenCalledTimes(1);
				const code = spy.mock.calls[0][0];
				expect(code.payload.resource).toBe('urn:wl:default');

				const spy2 = mock();
				provider.once('access_token.saved', spy2);
				provider.once('access_token.issued', spy2);
				const spy3 = mock();
				provider.once('refresh_token.saved', spy3);

				res = await agent.token.post({
					client_id: 'client',
					grant_type: 'authorization_code',
					code_verifier: auth.code_verifier,
					code: code.jti,
					resource: 'urn:wl:default'
				});
				expect(res.status).toBe(200);

				expect(spy2).toHaveBeenCalledTimes(1);
				let at = spy2.mock.calls[0][0];
				expect(at.payload.aud).toBe('urn:wl:default');

				expect(spy3).toHaveBeenCalledTimes(1);
				let rt = spy3.mock.calls[0][0];
				expect(rt.payload.resource).toBe('urn:wl:default');

				const spy4 = mock();
				provider.once('access_token.saved', spy4);
				provider.once('access_token.issued', spy4);
				const spy5 = mock();
				provider.once('refresh_token.saved', spy5);

				res = await agent.token.post({
					client_id: 'client',
					grant_type: 'refresh_token',
					refresh_token: rt.jti,
					resource: 'urn:wl:default'
				});
				expect(res.status).toBe(200);

				expect(spy4).toHaveBeenCalledTimes(1);
				at = spy4.mock.calls[0][0];
				expect(at.payload.aud).toBe('urn:wl:default');

				expect(spy5).toHaveBeenCalledTimes(1);
				rt = spy5.mock.calls[0][0];
				expect(rt.payload.resource).toBe('urn:wl:default');
			});
		});
	});

	describe('urn:ietf:params:oauth:grant-type:device_code', () => {
		it('checks the policy and adds the resource', async () => {
			const denied = await agent.device.auth.post(
				jsonToFormUrlEncoded({
					client_id: 'client',
					resource: 'urn:not:allowed',
					scope: 'api:read'
				}),
				{ headers: { 'content-type': form } }
			);
			expect(denied.error.status).toBe(400);
			expect(denied.error.value).toEqual({
				error: 'invalid_target',
				error_description: 'resource indicator is missing, or unknown'
			});

			const authRes = await agent.device.auth.post(
				jsonToFormUrlEncoded({
					client_id: 'client',
					resource: 'urn:wl:explicit',
					scope: 'api:read'
				}),
				{ headers: { 'content-type': form } }
			);
			expect(authRes.status).toBe(200);
			const { user_code, device_code } = authRes.data;

			setup.getSession().state = { secret: 'foo' };

			const confirm = await agent.device.post(
				jsonToFormUrlEncoded({ user_code, xsrf: 'foo', confirm: true }),
				{
					headers: {
						'content-type': form,
						cookie: `_session=${setup.getSessionId()}`
					}
				}
			);
			expect(confirm.status).toBe(200);

			const spy = mock();
			provider.once('access_token.saved', spy);
			provider.once('access_token.issued', spy);
			const spy2 = mock();
			provider.once('refresh_token.saved', spy2);

			let res = await agent.token.post({
				client_id: 'client',
				grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
				device_code
			});
			expect(res.status).toBe(200);

			expect(spy).toHaveBeenCalledTimes(1);
			let at = spy.mock.calls[0][0];
			expect(at.payload.aud).toBe('urn:wl:explicit');

			expect(spy2).toHaveBeenCalledTimes(1);
			let rt = spy2.mock.calls[0][0];
			expect(rt.payload.resource).toBe('urn:wl:explicit');

			const spy3 = mock();
			provider.once('access_token.saved', spy3);
			provider.once('access_token.issued', spy3);
			const spy4 = mock();
			provider.once('refresh_token.saved', spy4);

			res = await agent.token.post({
				client_id: 'client',
				grant_type: 'refresh_token',
				refresh_token: rt.jti
			});
			expect(res.status).toBe(200);

			expect(spy3).toHaveBeenCalledTimes(1);
			at = spy3.mock.calls[0][0];
			expect(at.payload.aud).toBe('urn:wl:explicit');

			expect(spy4).toHaveBeenCalledTimes(1);
			rt = spy4.mock.calls[0][0];
			expect(rt.payload.resource).toBe('urn:wl:explicit');
		});

		it('applies the default resource', async () => {
			const authRes = await agent.device.auth.post(
				jsonToFormUrlEncoded({
					client_id: 'client',
					scope: 'api:read'
				}),
				{ headers: { 'content-type': form } }
			);
			expect(authRes.status).toBe(200);
			const { user_code, device_code } = authRes.data;

			setup.getSession().state = { secret: 'foo' };

			const confirm = await agent.device.post(
				jsonToFormUrlEncoded({ user_code, xsrf: 'foo', confirm: true }),
				{
					headers: {
						'content-type': form,
						cookie: `_session=${setup.getSessionId()}`
					}
				}
			);
			expect(confirm.status).toBe(200);

			const spy = mock();
			provider.once('access_token.saved', spy);
			provider.once('access_token.issued', spy);
			const spy2 = mock();
			provider.once('refresh_token.saved', spy2);

			let res = await agent.token.post({
				client_id: 'client',
				grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
				device_code
			});
			expect(res.status).toBe(200);

			expect(spy).toHaveBeenCalledTimes(1);
			let at = spy.mock.calls[0][0];
			expect(at.payload.aud).toBe('urn:wl:default');

			expect(spy2).toHaveBeenCalledTimes(1);
			let rt = spy2.mock.calls[0][0];
			expect(rt.payload.resource).toBe('urn:wl:default');

			const spy3 = mock();
			provider.once('access_token.saved', spy3);
			provider.once('access_token.issued', spy3);
			const spy4 = mock();
			provider.once('refresh_token.saved', spy4);

			res = await agent.token.post({
				client_id: 'client',
				grant_type: 'refresh_token',
				refresh_token: rt.jti
			});
			expect(res.status).toBe(200);

			expect(spy3).toHaveBeenCalledTimes(1);
			at = spy3.mock.calls[0][0];
			expect(at.payload.aud).toBe('urn:wl:default');

			expect(spy4).toHaveBeenCalledTimes(1);
			rt = spy4.mock.calls[0][0];
			expect(rt.payload.resource).toBe('urn:wl:default');
		});

		it('applies the default resource (when useGrantedResource returns true)', async () => {
			grantFlags.useGranted = true;

			const authRes = await agent.device.auth.post(
				jsonToFormUrlEncoded({
					client_id: 'client',
					scope: 'openid api:read'
				}),
				{ headers: { 'content-type': form } }
			);
			expect(authRes.status).toBe(200);
			const { user_code, device_code } = authRes.data;

			setup.getSession().state = { secret: 'foo' };

			const confirm = await agent.device.post(
				jsonToFormUrlEncoded({ user_code, xsrf: 'foo', confirm: true }),
				{
					headers: {
						'content-type': form,
						cookie: `_session=${setup.getSessionId()}`
					}
				}
			);
			expect(confirm.status).toBe(200);

			const spy = mock();
			provider.once('access_token.saved', spy);
			provider.once('access_token.issued', spy);
			const spy2 = mock();
			provider.once('refresh_token.saved', spy2);

			let res = await agent.token.post({
				client_id: 'client',
				grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
				device_code
			});
			expect(res.status).toBe(200);

			expect(spy).toHaveBeenCalledTimes(1);
			let at = spy.mock.calls[0][0];
			expect(at.payload.aud).toBe('urn:wl:default');

			expect(spy2).toHaveBeenCalledTimes(1);
			let rt = spy2.mock.calls[0][0];
			expect(rt.payload.resource).toBe('urn:wl:default');

			const spy3 = mock();
			provider.once('access_token.saved', spy3);
			provider.once('access_token.issued', spy3);
			const spy4 = mock();
			provider.once('refresh_token.saved', spy4);

			res = await agent.token.post({
				client_id: 'client',
				grant_type: 'refresh_token',
				refresh_token: rt.jti
			});
			expect(res.status).toBe(200);

			expect(spy3).toHaveBeenCalledTimes(1);
			at = spy3.mock.calls[0][0];
			expect(at.payload.aud).toBe('urn:wl:default');

			expect(spy4).toHaveBeenCalledTimes(1);
			rt = spy4.mock.calls[0][0];
			expect(rt.payload.resource).toBe('urn:wl:default');
		});

		it('applies the explicit resource', async () => {
			const authRes = await agent.device.auth.post(
				jsonToFormUrlEncoded({
					client_id: 'client',
					scope: 'openid api:read'
				}),
				{ headers: { 'content-type': form } }
			);
			expect(authRes.status).toBe(200);
			const { user_code, device_code } = authRes.data;

			setup.getSession().state = { secret: 'foo' };

			const confirm = await agent.device.post(
				jsonToFormUrlEncoded({ user_code, xsrf: 'foo', confirm: true }),
				{
					headers: {
						'content-type': form,
						cookie: `_session=${setup.getSessionId()}`
					}
				}
			);
			expect(confirm.status).toBe(200);

			const spy = mock();
			provider.once('access_token.saved', spy);
			provider.once('access_token.issued', spy);
			const spy2 = mock();
			provider.once('refresh_token.saved', spy2);

			let res = await agent.token.post({
				client_id: 'client',
				resource: 'urn:wl:default',
				grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
				device_code
			});
			expect(res.status).toBe(200);

			expect(spy).toHaveBeenCalledTimes(1);
			let at = spy.mock.calls[0][0];
			expect(at.payload.aud).toBe('urn:wl:default');

			expect(spy2).toHaveBeenCalledTimes(1);
			let rt = spy2.mock.calls[0][0];
			expect(rt.payload.resource).toBe('urn:wl:default');

			const spy3 = mock();
			provider.once('access_token.saved', spy3);
			provider.once('access_token.issued', spy3);
			const spy4 = mock();
			provider.once('refresh_token.saved', spy4);

			res = await agent.token.post({
				client_id: 'client',
				resource: 'urn:wl:default',
				grant_type: 'refresh_token',
				refresh_token: rt.jti
			});
			expect(res.status).toBe(200);

			expect(spy3).toHaveBeenCalledTimes(1);
			at = spy3.mock.calls[0][0];
			expect(at.payload.aud).toBe('urn:wl:default');

			expect(spy4).toHaveBeenCalledTimes(1);
			rt = spy4.mock.calls[0][0];
			expect(rt.payload.resource).toBe('urn:wl:default');
		});
	});

	describe('urn:openid:params:grant-type:ciba', () => {
		it('checks the policy and adds the resource', async () => {
			const denied = await agent.backchannel.post(
				jsonToFormUrlEncoded({
					client_id: 'client',
					resource: 'urn:not:allowed',
					scope: 'openid api:read',
					login_hint: 'accountId'
				}),
				{ headers: { 'content-type': form } }
			);
			expect(denied.error.status).toBe(400);
			expect(denied.error.value).toEqual({
				error: 'invalid_target',
				error_description: 'resource indicator is missing, or unknown'
			});

			const backchannel = await agent.backchannel.post(
				jsonToFormUrlEncoded({
					client_id: 'client',
					resource: 'urn:wl:explicit',
					scope: 'openid api:read',
					login_hint: 'accountId'
				}),
				{ headers: { 'content-type': form } }
			);
			expect(backchannel.status).toBe(200);
			const { auth_req_id } = backchannel.data;

			const spy = mock();
			provider.once('access_token.saved', spy);
			provider.once('access_token.issued', spy);
			const spy2 = mock();
			provider.once('refresh_token.saved', spy2);

			let res = await agent.token.post({
				client_id: 'client',
				grant_type: 'urn:openid:params:grant-type:ciba',
				auth_req_id,
				resource: 'urn:wl:explicit'
			});
			expect(res.status).toBe(200);

			expect(spy).toHaveBeenCalledTimes(1);
			let at = spy.mock.calls[0][0];
			expect(at.payload.aud).toBe('urn:wl:explicit');

			expect(spy2).toHaveBeenCalledTimes(1);
			let rt = spy2.mock.calls[0][0];
			expect(rt.payload.resource).toBe('urn:wl:explicit');

			const spy3 = mock();
			provider.once('access_token.saved', spy3);
			provider.once('access_token.issued', spy3);
			const spy4 = mock();
			provider.once('refresh_token.saved', spy4);

			res = await agent.token.post({
				client_id: 'client',
				grant_type: 'refresh_token',
				refresh_token: rt.jti,
				resource: 'urn:wl:explicit'
			});
			expect(res.status).toBe(200);

			expect(spy3).toHaveBeenCalledTimes(1);
			at = spy3.mock.calls[0][0];
			expect(at.payload.aud).toBe('urn:wl:explicit');

			expect(spy4).toHaveBeenCalledTimes(1);
			rt = spy4.mock.calls[0][0];
			expect(rt.payload.resource).toBe('urn:wl:explicit');
		});

		it('applies the default resource (when useGrantedResource returns true)', async () => {
			grantFlags.useGranted = true;

			const backchannel = await agent.backchannel.post(
				jsonToFormUrlEncoded({
					client_id: 'client',
					scope: 'openid api:read',
					login_hint: 'accountId'
				}),
				{ headers: { 'content-type': form } }
			);
			expect(backchannel.status).toBe(200);
			const { auth_req_id } = backchannel.data;

			const spy = mock();
			provider.once('access_token.saved', spy);
			provider.once('access_token.issued', spy);
			const spy2 = mock();
			provider.once('refresh_token.saved', spy2);

			let res = await agent.token.post({
				client_id: 'client',
				grant_type: 'urn:openid:params:grant-type:ciba',
				auth_req_id
			});
			expect(res.status).toBe(200);

			expect(spy).toHaveBeenCalledTimes(1);
			let at = spy.mock.calls[0][0];
			expect(at.payload.aud).toBe('urn:wl:default');

			expect(spy2).toHaveBeenCalledTimes(1);
			let rt = spy2.mock.calls[0][0];
			expect(rt.payload.resource).toBe('urn:wl:default');

			const spy3 = mock();
			provider.once('access_token.saved', spy3);
			provider.once('access_token.issued', spy3);
			const spy4 = mock();
			provider.once('refresh_token.saved', spy4);

			res = await agent.token.post({
				client_id: 'client',
				grant_type: 'refresh_token',
				refresh_token: rt.jti
			});
			expect(res.status).toBe(200);

			expect(spy3).toHaveBeenCalledTimes(1);
			at = spy3.mock.calls[0][0];
			expect(at.payload.aud).toBe('urn:wl:default');

			expect(spy4).toHaveBeenCalledTimes(1);
			rt = spy4.mock.calls[0][0];
			expect(rt.payload.resource).toBe('urn:wl:default');
		});

		it('issues access token for userinfo (when useGrantedResource returns false)', async () => {
			const backchannel = await agent.backchannel.post(
				jsonToFormUrlEncoded({
					client_id: 'client',
					scope: 'openid api:read',
					login_hint: 'accountId'
				}),
				{ headers: { 'content-type': form } }
			);
			expect(backchannel.status).toBe(200);
			const { auth_req_id } = backchannel.data;

			const spy = mock();
			provider.once('access_token.saved', spy);
			provider.once('access_token.issued', spy);
			const spy2 = mock();
			provider.once('refresh_token.saved', spy2);

			let res = await agent.token.post({
				client_id: 'client',
				grant_type: 'urn:openid:params:grant-type:ciba',
				auth_req_id
			});
			expect(res.status).toBe(200);

			expect(spy).toHaveBeenCalledTimes(1);
			let at = spy.mock.calls[0][0];
			expect(at.payload.aud).toBeUndefined();

			expect(spy2).toHaveBeenCalledTimes(1);
			let rt = spy2.mock.calls[0][0];
			expect(rt.payload.resource).toBe('urn:wl:default');

			const spy3 = mock();
			provider.once('access_token.saved', spy3);
			provider.once('access_token.issued', spy3);
			const spy4 = mock();
			provider.once('refresh_token.saved', spy4);

			res = await agent.token.post({
				client_id: 'client',
				grant_type: 'refresh_token',
				refresh_token: rt.jti
			});
			expect(res.status).toBe(200);

			expect(spy3).toHaveBeenCalledTimes(1);
			at = spy3.mock.calls[0][0];
			expect(at.payload.aud).toBeUndefined();

			expect(spy4).toHaveBeenCalledTimes(1);
			rt = spy4.mock.calls[0][0];
			expect(rt.payload.resource).toBe('urn:wl:default');
		});
	});

	describe('userinfo', () => {
		it('allows userinfo for audience-less tokens', async () => {
			const at = new AccessToken({
				accountId: setup.getAccountId(),
				grantId: setup.getGrantId(),
				client: await Client.find('client'),
				scope: 'openid api:read',
				aud: undefined
			});

			const bearer = await at.save();

			const res = await agent.userinfo.get({
				headers: { authorization: `Bearer ${bearer}` }
			});
			expect(res.status).toBe(200);
		});

		it('fails userinfo for string userinfo url tokens', async () => {
			const at = new AccessToken({
				accountId: setup.getAccountId(),
				grantId: setup.getGrantId(),
				client: await Client.find('client'),
				scope: 'openid api:read',
				aud: 'urn:foo:bar'
			});

			const bearer = await at.save();

			const spy = mock();
			provider.once('userinfo.error', spy);

			const { error } = await agent.userinfo.get({
				headers: { authorization: `Bearer ${bearer}` }
			});
			expect(error.status).toBe(401);
			expect(error.value).toEqual({
				error: 'invalid_token',
				error_description: 'invalid token provided'
			});

			expect(spy).toHaveBeenCalledTimes(1);
			expect(spy.mock.calls[0][0]).toHaveProperty(
				'error_detail',
				'token audience prevents accessing the userinfo endpoint'
			);
		});
	});
});
