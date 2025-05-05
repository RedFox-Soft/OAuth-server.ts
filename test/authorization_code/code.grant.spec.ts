import url from 'node:url';
import {
	describe,
	it,
	beforeAll,
	afterEach,
	beforeEach,
	expect,
	spyOn,
	mock
} from 'bun:test';

import { createSandbox } from 'sinon';
import timekeeper from 'timekeeper';

import epochTime from '../../lib/helpers/epoch_time.ts';
import bootstrap from '../test_helper.js';
import e from 'express';

const sinon = createSandbox();

function errorDetail(spy) {
	return spy.args[0][0].error_detail;
}

describe('grant_type=authorization_code', () => {
	let setup = null;
	beforeAll(async function () {
		setup = await bootstrap(import.meta.url)();
	});

	afterEach(() => {
		timekeeper.reset();
		sinon.restore();
		mock.restore();

		setup.provider.removeAllListeners('grant.success');
		setup.provider.removeAllListeners('grant.error');
		setup.provider.removeAllListeners('server_error');
	});

	describe('with real tokens (1/3) - more than one redirect_uris registered', () => {
		let auth = null;
		let code: string | undefined;
		let codeStore = null;
		let session = null;

		beforeEach(async function () {
			const cookie = await setup.login();
			session = cookie;
			auth = new setup.AuthorizationRequest({
				client_id: 'client',
				scope: 'openid',
				redirect_uri: 'https://client.example.com/cb'
			});
			const { response, error } = await setup.agent.auth.get({
				query: auth.params,
				headers: {
					cookie
				}
			});

			expect(response.status).toBe(303);
			const { query } = url.parse(response.headers.get('location'), true);
			code = query.code;

			const jti = setup.getTokenJti(query.code);
			codeStore = setup.TestAdapter.for('AuthorizationCode').syncFind(jti);
		});

		afterEach(function () {
			return setup.logout();
		});

		it('Should return specific properties on token request', async function () {
			const spy = sinon.spy();
			setup.provider.on('grant.success', spy);

			const { data, response } = await auth.getToken(code);
			expect(response.status).toBe(200);
			expect(spy.calledOnce).toBe(true);
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

		it('populates ctx.oidc.entities (no offline_access)', async function () {
			const spy = spyOn(setup.provider.OIDCContext.prototype, 'entity');

			const { response } = await auth.getToken(code);
			expect(response.status).toBe(200);

			const entities = spy.mock.calls.map((call) => call[0]);
			const accessToken = spy.mock.calls.find(
				(call) => call[0] === 'AccessToken'
			);

			expect([
				'Account',
				'Grant',
				'Client',
				'AuthorizationCode',
				'AccessToken'
			]).toEqual(expect.arrayContaining(entities));
			expect(accessToken[1]).toHaveProperty('gty', 'authorization_code');
		});

		it('populates ctx.oidc.entities (w/ offline_access)', async function () {
			const spy = spyOn(setup.provider.OIDCContext.prototype, 'entity');
			setup.TestAdapter.for('Grant').syncUpdate(
				setup.getSession().authorizations.client.grantId,
				{
					scope: 'openid offline_access'
				}
			);
			setup.TestAdapter.for('AuthorizationCode').syncUpdate(
				setup.getTokenJti(code),
				{
					scope: 'openid offline_access'
				}
			);

			const { response } = await auth.getToken(code);
			expect(response.status).toBe(200);

			const entities = spy.mock.calls.map((call) => call[0]);
			const accessToken = spy.mock.calls.find(
				(call) => call[0] === 'AccessToken'
			);
			const refreshToken = spy.mock.calls.find(
				(call) => call[0] === 'RefreshToken'
			);

			expect([
				'Account',
				'Grant',
				'Client',
				'AuthorizationCode',
				'AccessToken',
				'RefreshToken'
			]).toEqual(expect.arrayContaining(entities));
			expect(accessToken[1]).toHaveProperty('gty', 'authorization_code');
			expect(refreshToken[1]).toHaveProperty('gty', 'authorization_code');
		});

		it('returns token-endpoint-like cache headers', async function () {
			const { response } = await auth.getToken(code);
			expect(response.status).toBe(200);
			expect(response.headers.get('cache-control')).toBe('no-store');
		});

		it('validates code is not expired', async function () {
			const { ttl } = i(setup.provider).configuration;
			spyOn(ttl, 'AuthorizationCode').mockReturnValue(5);
			const { response } = await setup.agent.auth.get({
				query: auth.params,
				headers: {
					cookie: session
				}
			});
			const { query } = url.parse(response.headers.get('location'), true);
			const code = query.code;

			timekeeper.travel(Date.now() + 10 * 1000);
			const spy = sinon.spy();
			setup.provider.on('grant.error', spy);

			const { error } = await auth.getToken(code);

			expect(error.status).toBe(400);
			expect(spy.calledOnce).toBe(true);
			expect(errorDetail(spy)).toBe('authorization code is expired');
			expect(error.value).toHaveProperty('error', 'invalid_grant');
		});

		it('validates code is not already used', async function () {
			const grantErrorSpy = sinon.spy();
			const grantRevokeSpy = sinon.spy();
			setup.provider.on('grant.error', grantErrorSpy);
			setup.provider.on('grant.revoked', grantRevokeSpy);

			codeStore.consumed = epochTime();

			const { error } = await auth.getToken(code);
			expect(error.status).toBe(400);
			expect(grantRevokeSpy.calledOnce).toBe(true);
			expect(grantErrorSpy.calledOnce).toBe(true);
			expect(errorDetail(grantErrorSpy)).toBe(
				'authorization code already consumed'
			);
			expect(error.value).toHaveProperty('error', 'invalid_grant');
		});

		it('consumes the code', async function () {
			const { response } = await auth.getToken(code);
			expect(response.status).toBe(200);

			expect(codeStore).toHaveProperty('consumed');
			expect(codeStore.consumed).toBeLessThanOrEqual(epochTime());
		});

		it('validates code belongs to client', async function () {
			const spy = sinon.spy();
			setup.provider.on('grant.error', spy);
			auth.client_id = 'client2';

			const { error } = await auth.getToken(code);
			expect(error.status).toBe(400);
			expect(spy.calledOnce).toBe(true);
			expect(errorDetail(spy)).toBe('client mismatch');
			expect(error.value).toHaveProperty('error', 'invalid_grant');
		});

		it('validates a grant type is supported', async function () {
			auth.grant_type = 'foobar';

			const { error } = await auth.getToken(code);
			expect(error.status).toBe(400);
			expect(error.value).toHaveProperty('error', 'unsupported_grant_type');
		});

		it('validates used redirect_uri', async function () {
			const spy = sinon.spy();
			setup.provider.on('grant.error', spy);

			auth.params.redirect_uri = 'https://client.example.com/cb?thensome';
			const { error } = await auth.getToken(code);
			expect(error.status).toBe(400);
			expect(spy.calledOnce).toBe(true);
			expect(errorDetail(spy)).toBe('authorization code redirect_uri mismatch');
			expect(error.value).toHaveProperty('error', 'invalid_grant');
		});

		it('validates redirect_uri presence', async function () {
			auth.params.redirect_uri = undefined;

			const { error } = await auth.getToken(code);
			expect(error.status).toBe(400);
			expect(error.value).toHaveProperty('error', 'invalid_request');
			expect(error.value).toHaveProperty(
				'error_description',
				"missing required parameter 'redirect_uri'"
			);
		});

		it('validates account is still there', async function () {
			sinon
				.stub(i(setup.provider).configuration, 'findAccount')
				.callsFake(() => Promise.resolve());

			const spy = sinon.spy();
			setup.provider.on('grant.error', spy);

			const { error } = await auth.getToken(code);
			expect(error.status).toBe(400);
			expect(spy.calledOnce).toBe(true);
			expect(errorDetail(spy)).toBe(
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
			auth = new setup.AuthorizationRequest({
				client_id: 'client2',
				scope: 'openid',
				response_type: 'code',
				redirect_uri: 'https://client.example.com/cb3'
			});
			const { response } = await setup.agent.auth.get({
				query: auth.params,
				headers: {
					cookie
				}
			});

			expect(response.status).toBe(303);
			const { query } = url.parse(response.headers.get('location'), true);
			code = query.code;
		});

		it('validates redirect_uri presence', async function () {
			const spy = sinon.spy();
			setup.provider.on('grant.error', spy);

			auth.params.redirect_uri = undefined;
			const { error } = await auth.getToken(code);
			expect(error.status).toBe(400);
			expect(spy.calledOnce).toBe(true);
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
			i(setup.provider).configuration.allowOmittingSingleRegisteredRedirectUri =
				false;
			return setup.logout();
		});

		beforeEach(async function () {
			i(setup.provider).configuration.allowOmittingSingleRegisteredRedirectUri =
				true;
			const cookie = await setup.login();
			session = cookie;
			auth = new setup.AuthorizationRequest({
				client_id: 'client2',
				scope: 'openid',
				response_type: 'code'
			});
			delete auth.redirect_uri;
			const { response } = await setup.agent.auth.get({
				query: auth.params,
				headers: {
					cookie
				}
			});

			expect(response.status).toBe(303);
			const { query } = url.parse(response.headers.get('location'), true);
			code = query.code;

			const jti = setup.getTokenJti(query.code);
			codeStore = setup.TestAdapter.for('AuthorizationCode').syncFind(jti);
		});

		it('returns the right stuff', async function () {
			const spy = sinon.spy();
			setup.provider.on('grant.success', spy);

			const { data, response } = await auth.getToken(code);

			expect(response.status).toBe(200);
			expect(spy.calledOnce).toBe(true);
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

		it('populates ctx.oidc.entities (no offline_access)', async function () {
			const spy = spyOn(setup.provider.OIDCContext.prototype, 'entity');
			const { response } = await auth.getToken(code);
			expect(response.status).toBe(200);
			const entities = spy.mock.calls.map((call) => call[0]);
			const accessToken = spy.mock.calls.find(
				(call) => call[0] === 'AccessToken'
			);
			expect([
				'Account',
				'Grant',
				'Client',
				'AuthorizationCode',
				'AccessToken'
			]).toEqual(expect.arrayContaining(entities));
			expect(accessToken[1]).toHaveProperty('gty', 'authorization_code');
		});

		it('populates ctx.oidc.entities (w/ offline_access)', async function () {
			const spy = spyOn(setup.provider.OIDCContext.prototype, 'entity');
			setup.TestAdapter.for('Grant').syncUpdate(
				setup.getSession().authorizations.client2.grantId,
				{
					scope: 'openid offline_access'
				}
			);
			setup.TestAdapter.for('AuthorizationCode').syncUpdate(
				setup.getTokenJti(code),
				{
					scope: 'openid offline_access'
				}
			);

			const { response } = await auth.getToken(code);
			expect(response.status).toBe(200);
			const entities = spy.mock.calls.map((call) => call[0]);
			const accessToken = spy.mock.calls.find(
				(call) => call[0] === 'AccessToken'
			);
			const refreshToken = spy.mock.calls.find(
				(call) => call[0] === 'RefreshToken'
			);
			expect([
				'Account',
				'Grant',
				'Client',
				'AuthorizationCode',
				'AccessToken',
				'RefreshToken'
			]).toEqual(expect.arrayContaining(entities));
			expect(accessToken[1]).toHaveProperty('gty', 'authorization_code');
			expect(refreshToken[1]).toHaveProperty('gty', 'authorization_code');
		});

		it('returns token-endpoint-like cache headers', async function () {
			const { response } = await auth.getToken(code);
			expect(response.status).toBe(200);
			expect(response.headers.get('cache-control')).toBe('no-store');
		});

		it('validates code is not expired', async function () {
			const { ttl } = i(setup.provider).configuration;
			spyOn(ttl, 'AuthorizationCode').mockReturnValue(5);
			const { response } = await setup.agent.auth.get({
				query: auth.params,
				headers: {
					cookie: session
				}
			});
			const { query } = url.parse(response.headers.get('location'), true);
			const code = query.code;

			timekeeper.travel(Date.now() + 10 * 1000);
			const spy = sinon.spy();
			setup.provider.on('grant.error', spy);

			const { error } = await auth.getToken(code);

			expect(error.status).toBe(400);
			expect(spy.calledOnce).toBe(true);
			expect(errorDetail(spy)).toBe('authorization code is expired');
			expect(error.value).toHaveProperty('error', 'invalid_grant');
		});

		it('validates code is not already used', async function () {
			const grantErrorSpy = sinon.spy();
			const grantRevokeSpy = sinon.spy();
			setup.provider.on('grant.error', grantErrorSpy);
			setup.provider.on('grant.revoked', grantRevokeSpy);

			codeStore.consumed = epochTime();

			const { error } = await auth.getToken(code);
			expect(error.status).toBe(400);
			expect(grantRevokeSpy.calledOnce).toBe(true);
			expect(grantErrorSpy.calledOnce).toBe(true);
			expect(errorDetail(grantErrorSpy)).toBe(
				'authorization code already consumed'
			);
			expect(error.value).toHaveProperty('error', 'invalid_grant');
		});

		it('consumes the code', async function () {
			const { response } = await auth.getToken(code);
			expect(response.status).toBe(200);
			expect(codeStore).toHaveProperty('consumed');
			expect(codeStore.consumed).toBeLessThanOrEqual(epochTime());
		});

		it('validates code belongs to client', async function () {
			const spy = sinon.spy();
			setup.provider.on('grant.error', spy);

			auth.client_id = 'client';
			auth.redirect_uri = 'https://client.example.com/cb2';
			const { error } = await auth.getToken(code);
			expect(error.status).toBe(400);
			expect(spy.calledOnce).toBe(true);
			expect(errorDetail(spy)).toBe('client mismatch');
			expect(error.value).toHaveProperty('error', 'invalid_grant');
		});

		it('validates a grant type is supported', async function () {
			auth.grant_type = 'foobar';
			const { error } = await auth.getToken(code);
			expect(error.status).toBe(400);
			expect(error.value).toHaveProperty('error', 'unsupported_grant_type');
		});

		it('validates used redirect_uri (should it be provided)', async function () {
			const spy = sinon.spy();
			setup.provider.on('grant.error', spy);

			auth.params.redirect_uri = 'https://client.example.com/cb?thensome';
			const { error } = await auth.getToken(code);
			expect(error.status).toBe(400);
			expect(spy.calledOnce).toBe(true);
			expect(errorDetail(spy)).toBe('authorization code redirect_uri mismatch');
			expect(error.value).toHaveProperty('error', 'invalid_grant');
		});

		it('validates account is still there', async function () {
			sinon
				.stub(i(setup.provider).configuration, 'findAccount')
				.callsFake(() => Promise.resolve());

			const spy = sinon.spy();
			setup.provider.on('grant.error', spy);

			const { error } = await auth.getToken(code);
			expect(error.status).toBe(400);
			expect(spy.calledOnce).toBe(true);
			expect(errorDetail(spy)).toBe(
				'authorization code invalid (referenced account not found)'
			);
			expect(error.value).toHaveProperty('error', 'invalid_grant');
		});
	});

	describe('validates', () => {
		it('grant_type presence', async function () {
			const auth = new setup.AuthorizationRequest({
				client_id: 'client',
				scope: 'openid'
			});
			const { error } = await setup.agent.token.post(
				{},
				{
					headers: auth.basicAuthHeader
				}
			);
			expect(error.status).toBe(422);
			expect(error.value).toHaveProperty('error', 'invalid_request');
			expect(error.value).toHaveProperty(
				'error_description',
				"Property 'grant_type' is missing"
			);
		});

		it('code presence', async function () {
			const auth = new setup.AuthorizationRequest({
				client_id: 'client',
				scope: 'openid'
			});
			const { error } = await setup.agent.token.post(
				{
					code_verifier: auth.code_verifier,
					grant_type: 'authorization_code',
					redirect_uri: 'blah'
				},
				{
					headers: auth.basicAuthHeader
				}
			);
			expect(error.status).toBe(400);
			expect(error.value).toHaveProperty('error', 'invalid_request');
			expect(error.value).toHaveProperty(
				'error_description',
				"missing required parameter 'code'"
			);
		});

		it('redirect_uri presence (more then one registered)', async function () {
			const auth = new setup.AuthorizationRequest({
				client_id: 'client',
				scope: 'openid'
			});
			const { error } = await setup.agent.token.post(
				{
					code_verifier: auth.code_verifier,
					grant_type: 'authorization_code',
					code: 'blah'
				},
				{
					headers: auth.basicAuthHeader
				}
			);
			expect(error.status).toBe(400);
			expect(error.value).toHaveProperty('error', 'invalid_request');
			expect(error.value).toHaveProperty(
				'error_description',
				"missing required parameter 'redirect_uri'"
			);
		});

		it('code being "found"', async function () {
			const spy = sinon.spy();
			setup.provider.on('grant.error', spy);

			const auth = new setup.AuthorizationRequest({
				client_id: 'client',
				scope: 'openid'
			});
			const { error } = await setup.agent.token.post(
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
			expect(error.status).toBe(400);
			expect(spy.calledOnce).toBe(true);
			expect(errorDetail(spy)).toBe('authorization code not found');
			expect(error.value).toHaveProperty('error', 'invalid_grant');
		});
	});

	it('handles exceptions', async function () {
		spyOn(setup.provider.Client, 'find').mockRejectedValue(new Error());
		const spy = sinon.spy();
		setup.provider.on('server_error', spy);

		const auth = new setup.AuthorizationRequest({
			client_id: 'client',
			scope: 'openid'
		});
		const { error } = await setup.agent.token.post(
			{
				grant_type: 'authorization_code',
				code: 'code',
				redirect_uri: 'is there too'
			},
			{
				headers: auth.basicAuthHeader
			}
		);
		expect(error.status).toBe(500);
		expect(spy.calledOnce).toBe(true);
		expect(error.value).toHaveProperty('error', 'server_error');
		expect(error.value).toHaveProperty(
			'error_description',
			'An unexpected error occurred'
		);
	});
});
