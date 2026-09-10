import url from 'node:url';
import {
	describe,
	it,
	beforeAll,
	afterEach,
	beforeEach,
	expect,
	spyOn,
	mock,
	setSystemTime
} from 'bun:test';

import { eventBus } from 'lib/event_bus.js';
import { ApplicationConfig } from 'lib/configs/application.js';
import { Client } from 'lib/models/client.js';
import epochTime from '../../lib/helpers/epoch_time.ts';
import bootstrap, { agent, type Setup } from '../test_helper.js';
import { getUserStore } from 'lib/adapters/index.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { TestAdapter } from 'test/models.js';
import { ttl } from 'lib/configs/liveTime.js';

/**
 * @proves A client exchanging a valid authorization code receives tokens, and every way of
 * presenting a spent, expired, foreign or mismatched code is refused with the protocol error.
 */
describe('grant_type=authorization_code', () => {
	let setup: Setup;
	beforeAll(async function () {
		setup = await bootstrap(import.meta.url);
	});

	afterEach(() => {
		setSystemTime();
		mock.restore();

		eventBus.removeAllListeners('grant.success');
		eventBus.removeAllListeners('grant.error');
		eventBus.removeAllListeners('server_error');
	});

	describe('with real tokens (1/3) - more than one redirectUris registered', () => {
		let auth = null;
		let code: string | undefined;
		let codeStore = null;
		let session = null;

		beforeEach(async function () {
			const cookie = await setup.login();
			session = cookie;
			auth = new AuthorizationRequest({
				client_id: 'client',
				scope: 'openid',
				redirect_uri: 'https://client.example.com/cb'
			});
			const { response } = await agent.auth.get({
				query: auth.params,
				headers: {
					cookie
				}
			});

			expect(response.status).toBe(303);
			const { query } = url.parse(response.headers.get('location'), true);
			code = query.code;

			const jti = setup.getTokenJti(query.code);
			codeStore = TestAdapter.for('AuthorizationCode').syncFind(jti);
		});

		it('the token response carries access token, token type, expiry and scope', async function () {
			const spy = mock();
			eventBus.once('grant.success', spy);

			const { data, response } = await auth.getToken(code);
			expect(response.status).toBe(200);
			expect(spy).toHaveBeenCalledTimes(1);
			expect(Object.keys(data)).toEqual(
				expect.arrayContaining([
					'access_token',
					'id_token',
					'expires_in',
					'token_type',
					'scope'
				])
			);
			expect(data).not.toHaveProperty('refresh_token');
		});

		it('returns token-endpoint-like cache headers', async function () {
			const { response } = await auth.getToken(code);
			expect(response.status).toBe(200);
			expect(response.headers.get('cache-control')).toBe('no-store');
		});

		it('an expired code is refused as invalid_grant', async function () {
			spyOn(ttl, 'AuthorizationCode').mockReturnValue(5);
			const { response } = await agent.auth.get({
				query: auth.params,
				headers: {
					cookie: session
				}
			});
			const { query } = url.parse(response.headers.get('location'), true);
			const code = query.code;

			setSystemTime(Date.now() + 10 * 1000);
			const spy = mock();
			eventBus.on('grant.error', spy);

			const { error } = await auth.getToken(code);

			expect(error.status).toBe(400);
			expect(spy).toBeCalledTimes(1);
			expect(spy).toBeCalledWith(
				expect.objectContaining({
					error_detail: 'authorization code is expired'
				})
			);
			expect(error.value).toHaveProperty('error', 'invalid_grant');
		});

		it('a spent code is refused as invalid_grant', async function () {
			const grantErrorSpy = mock();
			const grantRevokeSpy = mock();
			eventBus.on('grant.error', grantErrorSpy);
			eventBus.on('grant.revoked', grantRevokeSpy);

			codeStore.consumed = epochTime();

			const { error } = await auth.getToken(code);
			console.log(error.value);
			expect(error.status).toBe(400);
			expect(grantRevokeSpy).toBeCalledTimes(1);
			expect(grantErrorSpy).toBeCalledTimes(1);
			expect(grantErrorSpy).toBeCalledWith(
				expect.objectContaining({
					error_detail: 'authorization code already consumed'
				})
			);
			expect(error.value).toHaveProperty('error', 'invalid_grant');
		});

		it('consumes the code', async function () {
			const { response } = await auth.getToken(code);
			expect(response.status).toBe(200);

			expect(codeStore).toHaveProperty('consumed');
			expect(codeStore.consumed).toBeLessThanOrEqual(epochTime());
		});

		it('a code issued to another client is refused', async function () {
			const spy = mock();
			eventBus.on('grant.error', spy);
			auth.clientId = 'client2';

			const { error } = await auth.getToken(code);
			expect(error.status).toBe(400);
			expect(spy).toBeCalledTimes(1);
			expect(spy).toBeCalledWith(
				expect.objectContaining({
					error_detail: 'client mismatch'
				})
			);
			expect(error.value).toHaveProperty('error', 'invalid_grant');
		});

		it('an unsupported grant_type is refused as unsupported_grant_type', async function () {
			auth.grant_type = 'foobar';

			const { error } = await auth.getToken(code);
			expect(error.status).toBe(422);
			expect(error.value).toHaveProperty('error', 'invalid_request');
			expect(error.value).toHaveProperty(
				'error_description',
				'invalid grant_type'
			);
		});

		it('a redirect_uri differing from the one the code was issued for is refused', async function () {
			const spy = mock();
			eventBus.on('grant.error', spy);

			auth.params.redirect_uri = 'https://client.example.com/cb?thensome';
			const { error } = await auth.getToken(code);
			expect(error.status).toBe(400);
			expect(spy).toBeCalledTimes(1);
			expect(spy).toBeCalledWith(
				expect.objectContaining({
					error_detail: 'authorization code redirect_uri mismatch'
				})
			);
			expect(error.value).toHaveProperty('error', 'invalid_grant');
		});

		it('a client with several registered redirect URIs must send one', async function () {
			auth.params.redirect_uri = undefined;

			const { error } = await auth.getToken(code);
			expect(error.status).toBe(400);
			expect(error.value).toHaveProperty('error', 'invalid_request');
			expect(error.value).toHaveProperty(
				'error_description',
				"missing required parameter 'redirect_uri'"
			);
		});

		it('a code for a deleted account is refused', async function () {
			// Simulate the account having been removed since the code was issued:
			// the DB-backed findAccount now resolves nothing for this subject.
			await getUserStore('redfox').destroy(setup.getAccountId());

			const spy = mock();
			eventBus.on('grant.error', spy);

			const { error } = await auth.getToken(code);
			expect(error.status).toBe(400);
			expect(spy).toBeCalledTimes(1);
			const err = spy.mock.calls[0][0];
			expect(err.error_detail).toBe(
				'authorization code invalid (referenced account not found)'
			);
			expect(error.value).toHaveProperty('error', 'invalid_grant');
		});
	});

	describe('with real tokens (2/3) - one redirect_uri registered with allowOmittingSingleRegisteredRedirectUri=false', () => {
		let auth = null;
		let code: string | undefined;

		beforeEach(async function () {
			const cookie = await setup.login();
			auth = new AuthorizationRequest({
				client_id: 'client2',
				scope: 'openid',
				response_type: 'code',
				redirect_uri: 'https://client.example.com/cb3'
			});
			const { response } = await agent.auth.get({
				query: auth.params,
				headers: {
					cookie
				}
			});

			expect(response.status).toBe(303);
			const { query } = url.parse(response.headers.get('location'), true);
			code = query.code;
		});

		it('a client with several registered redirect URIs must send one', async function () {
			const spy = mock();
			eventBus.on('grant.error', spy);

			auth.params.redirect_uri = undefined;
			const { error } = await auth.getToken(code);
			expect(error.status).toBe(400);
			expect(spy).toBeCalledTimes(1);
			expect(error.value).toHaveProperty('error', 'invalid_request');
			expect(error.value).toHaveProperty(
				'error_description',
				"missing required parameter 'redirect_uri'"
			);
		});
	});

	describe('with real tokens (3/3) - one redirect_uri registered with allowOmittingSingleRegisteredRedirectUri=true', () => {
		let auth = null;
		let code: string | undefined;
		let codeStore = null;
		let session = null;

		afterEach(function () {
			ApplicationConfig[
				'authorization.allowOmittingSingleRegisteredRedirectUri'
			] = false;
		});

		beforeEach(async function () {
			ApplicationConfig[
				'authorization.allowOmittingSingleRegisteredRedirectUri'
			] = true;
			const cookie = await setup.login();
			session = cookie;
			auth = new AuthorizationRequest({
				client_id: 'client2',
				scope: 'openid',
				response_type: 'code'
			});
			delete auth.redirect_uri;
			const { response } = await agent.auth.get({
				query: auth.params,
				headers: {
					cookie
				}
			});

			expect(response.status).toBe(303);
			const { query } = url.parse(response.headers.get('location'), true);
			code = query.code;

			const jti = setup.getTokenJti(query.code);
			codeStore = TestAdapter.for('AuthorizationCode').syncFind(jti);
		});

		it('returns the access token, token type, expiry and scope the client expects', async function () {
			const spy = mock();
			eventBus.on('grant.success', spy);

			const { data, response } = await auth.getToken(code);

			expect(response.status).toBe(200);
			expect(spy).toBeCalledTimes(1);
			expect(Object.keys(data)).toEqual(
				expect.arrayContaining([
					'access_token',
					'id_token',
					'expires_in',
					'token_type',
					'scope'
				])
			);
			expect(data).not.toHaveProperty('refresh_token');
		});

		it('returns token-endpoint-like cache headers', async function () {
			const { response } = await auth.getToken(code);
			expect(response.status).toBe(200);
			expect(response.headers.get('cache-control')).toBe('no-store');
		});

		it('an expired code is refused as invalid_grant', async function () {
			spyOn(ttl, 'AuthorizationCode').mockReturnValue(5);
			const { response } = await agent.auth.get({
				query: auth.params,
				headers: {
					cookie: session
				}
			});
			const { query } = url.parse(response.headers.get('location'), true);
			const code = query.code;

			setSystemTime(Date.now() + 10 * 1000);
			const spy = mock();
			eventBus.on('grant.error', spy);

			const { error } = await auth.getToken(code);

			expect(error.status).toBe(400);
			expect(spy).toBeCalledTimes(1);
			expect(spy).toBeCalledWith(
				expect.objectContaining({
					error_detail: 'authorization code is expired'
				})
			);
			expect(error.value).toHaveProperty('error', 'invalid_grant');
		});

		it('a spent code is refused as invalid_grant', async function () {
			const grantErrorSpy = mock();
			const grantRevokeSpy = mock();
			eventBus.on('grant.error', grantErrorSpy);
			eventBus.on('grant.revoked', grantRevokeSpy);

			codeStore.consumed = epochTime();

			const { error } = await auth.getToken(code);
			expect(error.status).toBe(400);
			expect(grantRevokeSpy).toBeCalledTimes(1);
			expect(grantErrorSpy).toBeCalledTimes(1);
			expect(grantErrorSpy).toBeCalledWith(
				expect.objectContaining({
					error_detail: 'authorization code already consumed'
				})
			);
			expect(error.value).toHaveProperty('error', 'invalid_grant');
		});

		it('consumes the code', async function () {
			const { response } = await auth.getToken(code);
			expect(response.status).toBe(200);
			expect(codeStore).toHaveProperty('consumed');
			expect(codeStore.consumed).toBeLessThanOrEqual(epochTime());
		});

		it('a code issued to another client is refused', async function () {
			const spy = mock();
			eventBus.on('grant.error', spy);

			auth.clientId = 'client';
			auth.redirect_uri = 'https://client.example.com/cb2';
			const { error } = await auth.getToken(code);
			expect(error.status).toBe(400);
			expect(spy).toBeCalledTimes(1);
			expect(spy).toBeCalledWith(
				expect.objectContaining({
					error_detail: 'client mismatch'
				})
			);
			expect(error.value).toHaveProperty('error', 'invalid_grant');
		});

		it('an unsupported grant_type is refused as unsupported_grant_type', async function () {
			auth.grant_type = 'foobar';
			const { error } = await auth.getToken(code);
			expect(error.status).toBe(422);
			expect(error.value).toHaveProperty('error', 'invalid_request');
			expect(error.value).toHaveProperty(
				'error_description',
				'invalid grant_type'
			);
		});

		it('a provided redirect_uri must still match even when it could have been omitted', async function () {
			const spy = mock();
			eventBus.on('grant.error', spy);

			auth.params.redirect_uri = 'https://client.example.com/cb?thensome';
			const { error } = await auth.getToken(code);
			expect(error.status).toBe(400);
			expect(spy).toBeCalledTimes(1);
			expect(spy).toBeCalledWith(
				expect.objectContaining({
					error_detail: 'authorization code redirect_uri mismatch'
				})
			);
			expect(error.value).toHaveProperty('error', 'invalid_grant');
		});

		it('a code for a deleted account is refused', async function () {
			// Simulate the account having been removed since the code was issued:
			// the DB-backed findAccount now resolves nothing for this subject.
			await getUserStore('redfox').destroy(setup.getAccountId());

			const spy = mock();
			eventBus.on('grant.error', spy);

			const { error } = await auth.getToken(code);
			expect(error.status).toBe(400);
			expect(spy).toBeCalledTimes(1);
			expect(spy).toBeCalledWith(
				expect.objectContaining({
					error_detail:
						'authorization code invalid (referenced account not found)'
				})
			);
			expect(error.value).toHaveProperty('error', 'invalid_grant');
		});
	});

	describe('validates', () => {
		it('a token request with no grant_type is refused as invalid_request', async function () {
			const auth = new AuthorizationRequest({
				client_id: 'client',
				scope: 'openid'
			});
			const { error } = await agent.token.post(
				{},
				{
					headers: auth.basicAuthHeader
				}
			);
			if (!error) throw new Error('expected error response');
			expect(error.status).toBe(422);
			expect(error.value).toHaveProperty('error', 'invalid_request');
			expect(error.value).toHaveProperty(
				'error_description',
				'invalid grant_type'
			);
		});

		it('a code grant with no code is refused', async function () {
			const auth = new AuthorizationRequest({
				client_id: 'client',
				scope: 'openid'
			});
			const { error } = await agent.token.post(
				{
					code_verifier: auth.code_verifier,
					grant_type: 'authorization_code',
					redirect_uri: 'blah'
				},
				{
					headers: auth.basicAuthHeader
				}
			);
			if (!error) throw new Error('expected error response');
			expect(error.status).toBe(400);
			expect(error.value).toHaveProperty('error', 'invalid_request');
			expect(error.value).toHaveProperty(
				'error_description',
				"missing required parameter 'code'"
			);
		});

		it('refuses a token request with no redirect_uri when several are registered', async function () {
			const auth = new AuthorizationRequest({
				client_id: 'client',
				scope: 'openid'
			});
			const { error } = await agent.token.post(
				{
					code_verifier: auth.code_verifier,
					grant_type: 'authorization_code',
					code: 'blah'
				},
				{
					headers: auth.basicAuthHeader
				}
			);
			if (!error) throw new Error('expected error response');
			expect(error.status).toBe(400);
			expect(error.value).toHaveProperty('error', 'invalid_request');
			expect(error.value).toHaveProperty(
				'error_description',
				"missing required parameter 'redirect_uri'"
			);
		});

		it('an unknown code is refused as invalid_grant', async function () {
			const spy = mock();
			eventBus.on('grant.error', spy);

			const auth = new AuthorizationRequest({
				client_id: 'client',
				scope: 'openid'
			});
			const { error } = await agent.token.post(
				{
					code_verifier: auth.code_verifier,
					grant_type: 'authorization_code',
					redirect_uri: 'http://client.example.com',
					code: 'eyJraW5kIjoiQXV0aG9yaXphdGlvbkNvZGUiLCJqdGkiOiIxNTU0M2RiYS0zYThmLTRiZWEtYmRjNi04NDQ2N2MwOWZjYTYiLCJpYXQiOjE0NjM2NTk2OTgsImV4cCI6MTQ2MzY1OTc1OCwiaXNzIjoiaHR0cHM6Ly9ndWFyZGVkLWNsaWZmcy04NjM1Lmhlcm9rdWFwcC5jb20vb3AifQ.qUTaR48lavULtmDWBcpwhcF9NXhP8xzc-643h3yWLEgIyxPzKINT-upNn-byflH7P7rQlzZ-9SJKSs72ZVqWWMNikUGgJo-XmLyersONQ8sVx7v0quo4CRXamwyXfz2gq76gFlv5mtsrWwCij1kUnSaFm_HhAcoDPzGtSqhsHNoz36KjdmC3R-m84reQk_LEGizUeV-OmsBWJs3gedPGYcRCvsnW9qa21B0yZO2-HT9VQYY68UIGucDKNvizFRmIgepDZ5PUtsvyPD0PQQ9UHiEZvICeArxPLE8t1xz-lukpTMn8vA_YJ0s7kD9HYJUwxiYIuLXwDUNpGhsegxdvbw'
				},
				{
					headers: auth.basicAuthHeader
				}
			);
			if (!error) throw new Error('expected error response');
			expect(error.status).toBe(400);
			expect(spy).toBeCalledTimes(1);
			expect(spy).toBeCalledWith(
				expect.objectContaining({
					error_detail: 'authorization code not found'
				})
			);
			expect(error.value).toHaveProperty('error', 'invalid_grant');
		});
	});

	it('an internal fault at the token endpoint answers server_error rather than leaking', async function () {
		spyOn(Client, 'find').mockRejectedValue(new Error());
		const spy = mock();
		eventBus.on('server_error', spy);

		const auth = new AuthorizationRequest({
			client_id: 'client',
			scope: 'openid'
		});
		const { error } = await agent.token.post(
			{
				grant_type: 'authorization_code',
				code: 'code',
				redirect_uri: 'is there too'
			},
			{
				headers: auth.basicAuthHeader
			}
		);
		if (!error) throw new Error('expected error response');
		expect(error.status).toBe(500);
		expect(spy).toBeCalledTimes(1);
		expect(error.value).toHaveProperty('error', 'server_error');
		expect(error.value).toHaveProperty(
			'error_description',
			'An unexpected error occurred'
		);
	});
});
