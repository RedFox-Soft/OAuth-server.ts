import i from 'lib/helpers/weak_cache.js';
import {
	describe,
	it,
	beforeAll,
	afterAll,
	beforeEach,
	afterEach,
	expect,
	spyOn,
	mock
} from 'bun:test';

import bootstrap, {
	agent,
	jsonToFormUrlEncoded,
	type Setup
} from '../../test_helper.js';
import epochTime from '../../../lib/helpers/epoch_time.ts';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { provider } from 'lib/provider.js';
import { Client } from 'lib/models/client.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';

const route = '/auth';
const response_type = 'code';
const scope = 'openid';

describe('BASIC code', () => {
	let setup: Setup;
	beforeAll(async function () {
		setup = await bootstrap(import.meta.url);
	});

	afterEach(function () {
		mock.restore();
	});

	['get', 'post'].forEach((verb) => {
		function authRequest(auth, { cookie, accept } = {}) {
			if (verb === 'get') {
				return agent.auth.get({
					query: auth.params,
					headers: {
						cookie,
						accept
					}
				});
			}

			return agent.auth.post(jsonToFormUrlEncoded(auth.params), {
				headers: {
					cookie,
					accept,
					['content-type']: 'application/x-www-form-urlencoded'
				}
			});
		}

		describe(`${verb} ${route} with session`, () => {
			let cookie;
			beforeAll(async function () {
				cookie = await setup.login();
			});

			it('responds with a code in search', async function () {
				const auth = new AuthorizationRequest({ scope });
				const { response } = await authRequest(auth, { cookie });

				expect(response.status).toBe(303);
				auth.validatePresence(response, ['code', 'state']);
				auth.validateState(response);
				auth.validateClientLocation(response);
			});

			it('populates ctx.oidc.entities', async function () {
				const spy = spyOn(OIDCContext.prototype, 'entity');

				const auth = new AuthorizationRequest({ scope });
				const { response } = await authRequest(auth, { cookie });
				expect(response.status).toBe(303);

				const entities = spy.mock.calls.map((call) => call[0]);
				expect([
					'AuthorizationCode',
					'Grant',
					'Client',
					'Account',
					'Session'
				]).toEqual(expect.arrayContaining(entities));
			});

			it('allows native apps to do none auth check when already authorized', async function () {
				const auth = new AuthorizationRequest({
					response_type: 'none',
					prompt: 'none',
					client_id: 'client-native',
					redirect_uri: 'com.example.app:/cb',
					scope
				});

				const { response } = await authRequest(auth, { cookie });
				expect(response.status).toBe(303);
				auth.validatePresence(response, ['state']);
				auth.validateState(response);
				auth.validateClientLocation(response);
			});

			it('ignores unsupported scopes', async function () {
				const spy = mock();
				provider.once('authorization_code.saved', spy);
				const auth = new AuthorizationRequest({
					scope: 'openid and unsupported'
				});

				const { response } = await authRequest(auth, { cookie });
				expect(response.status).toBe(303);
				auth.validateClientLocation(response);
				expect(spy.mock.calls[0][0].payload).toHaveProperty('scope', 'openid');
			});

			describe('ignoring the offline_access scope', () => {
				beforeEach(function () {
					spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(false);
				});

				it('ignores the scope offline_access unless prompt consent is present', async function () {
					const spy = mock();
					provider.once('authorization_code.saved', spy);
					const auth = new AuthorizationRequest({
						scope: 'openid offline_access'
					});

					const { response } = await authRequest(auth, { cookie });
					expect(response.status).toBe(303);
					auth.validateClientLocation(response);
					expect(spy.mock.calls[0][0].payload).toHaveProperty('scope');
					expect(spy.mock.calls[0][0].payload.scope).not.toContain(
						'offline_access'
					);
				});

				it('ignores the scope offline_access unless the client can do refresh_token exchange', async function () {
					const spy = mock();
					provider.once('authorization_code.saved', spy);
					const auth = new AuthorizationRequest({
						client_id: 'client-no-refresh',
						prompt: 'consent',
						scope: 'openid offline_access'
					});

					const { response } = await authRequest(auth, { cookie });
					expect(response.status).toBe(303);
					auth.validateClientLocation(response);
					expect(spy.mock.calls[0][0].payload).toHaveProperty('scope');
					expect(spy.mock.calls[0][0].payload.scope).not.toContain(
						'offline_access'
					);
				});
			});
		});

		describe(`${verb} ${route} interactions`, () => {
			let policy = null;

			beforeAll(function () {
				policy = i(provider).configuration.interactions.policy;
			});

			afterAll(function () {
				i(provider).configuration.interactions.policy = policy;
			});

			it('no account id was resolved and no interactions requested', async function () {
				i(provider).configuration.interactions.policy = [];
				const spy = mock();
				provider.on('authorization.error', spy);

				const auth = new AuthorizationRequest({ scope });
				const { response } = await authRequest(auth);

				expect(response.status).toBe(303);
				auth.validateClientLocation(response);
				auth.validatePresence(response, ['error', 'state']);
				auth.validateError(response, 'access_denied');

				expect(spy).toHaveBeenCalledTimes(1);
				expect(spy.mock.calls[0][0]).toHaveProperty(
					'error_detail',
					'authorization request resolved without requesting interactions but no account id was resolved'
				);
			});

			it('no scope was resolved and no interactions requested', async function () {
				i(provider).configuration.interactions.policy = [];
				const spy = mock();
				provider.on('authorization.error', spy);

				const cookie = await setup.login();
				const auth = new AuthorizationRequest();
				const { response } = await authRequest(auth, { cookie });

				expect(response.status).toBe(303);
				auth.validateClientLocation(response);
				auth.validatePresence(response, ['error', 'state']);
				auth.validateError(response, 'access_denied');

				expect(spy).toHaveBeenCalledTimes(1);
				expect(spy.mock.calls[0][0]).toHaveProperty(
					'error_detail',
					'authorization request resolved without requesting interactions but no scope was granted'
				);
			});
		});

		describe(`${verb} ${route} interactions`, () => {
			let cookie;
			beforeEach(async function () {
				cookie = await setup.login();
			});

			it('no account id was found in the session info', async function () {
				const session = setup.getSession();
				delete session.loginTs;
				delete session.accountId;

				const auth = new AuthorizationRequest({ scope });
				const { response } = await authRequest(auth, { cookie });
				auth.validateInteractionRedirect(response);
				auth.validateInteraction(response, 'login', 'no_session');
			});

			it('additional scopes are requested', async function () {
				const auth = new AuthorizationRequest({ scope: 'openid email' });
				const { response } = await authRequest(auth, { cookie });
				expect(response.status).toBe(303);
				auth.validateInteractionRedirect(response);
				auth.validateInteraction(response, 'consent', 'op_scopes_missing');
			});

			it('are required for native clients by default', async function () {
				const auth = new AuthorizationRequest({
					client_id: 'client-native',
					redirect_uri: 'com.example.app:/cb',
					scope,
					code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
					code_challenge_method: 'S256'
				});
				const { response } = await authRequest(auth, { cookie });
				expect(response.status).toBe(303);
				auth.validateInteractionRedirect(response);
				auth.validateInteraction(response, 'consent', 'native_client_prompt');
			});

			it('login was requested by the client by prompt parameter', async function () {
				const auth = new AuthorizationRequest({ prompt: 'login', scope });
				const { response } = await authRequest(auth, { cookie });
				expect(response.status).toBe(303);
				auth.validateInteractionRedirect(response);
				auth.validateInteraction(response, 'login', 'login_prompt');
			});

			it('login was requested by the client by max_age=0', async function () {
				const auth = new AuthorizationRequest({ max_age: 0, scope });
				const { response } = await authRequest(auth, { cookie });
				expect(response.status).toBe(303);
				auth.validateInteractionRedirect(response);
				auth.validateInteraction(response, 'login', 'login_prompt');
			});

			it('interaction check no session & max_age combo', async function () {
				const auth = new AuthorizationRequest({
					max_age: 1800, // 30 minutes old session max
					scope
				});
				const { response } = await authRequest(auth);
				expect(response.status).toBe(303);
				auth.validateInteractionRedirect(response);
				auth.validateInteraction(response, 'login', 'max_age', 'no_session');
			});

			it('session is too old for this authorization request (1/2)', async function () {
				const session = setup.getSession();
				session.loginTs = epochTime() - 3600; // an hour ago

				const auth = new AuthorizationRequest({
					max_age: 1800, // 30 minutes old session max
					scope
				});
				const { response } = await authRequest(auth, { cookie });
				expect(response.status).toBe(303);
				auth.validateInteractionRedirect(response);
				auth.validateInteraction(response, 'login', 'max_age');
			});

			it('session is too old for this authorization request (2/2)', async function () {
				const session = setup.getSession();
				delete session.loginTs;

				const auth = new AuthorizationRequest({
					max_age: 1800, // 30 minutes old session max
					scope
				});
				const { response } = await authRequest(auth, { cookie });
				expect(response.status).toBe(303);
				auth.validateInteractionRedirect(response);
				auth.validateInteraction(response, 'login', 'max_age');
			});

			it('session is too old for this client', async function () {
				const client = await Client.find('client');
				client.defaultMaxAge = 1800;

				const session = setup.getSession();
				session.loginTs = epochTime() - 3600; // an hour ago

				const auth = new AuthorizationRequest({ scope });
				const { response } = await authRequest(auth, { cookie });
				delete client.defaultMaxAge;
				expect(response.status).toBe(303);
				auth.validateInteractionRedirect(response);
				auth.validateInteraction(response, 'login', 'max_age');
			});
		});

		describe(`${verb} ${route} errors`, () => {
			it('dupe parameters are rejected and ignored in further processing', async function () {
				// fake a query like this state=foo&state=foo
				const spy = mock();
				provider.once('authorization.error', spy);
				const auth = new AuthorizationRequest({
					scope: ['openid', 'openid'],
					state: ['foo', 'foo'],
					response_type: ['code', 'code']
				});

				const { response } = await authRequest(auth);
				expect(response.status).toBe(303);
				expect(spy).toHaveBeenCalledTimes(1);
				auth.validatePresence(response, ['error', 'error_description']);
				auth.validateClientLocation(response);
				auth.validateError(response, 'invalid_request');
				if (verb === 'get') {
					auth.validateErrorDescription(
						response,
						'Duplicate query parameter "scope, state, response_type" detected'
					);
				}
				if (verb === 'post') {
					auth.validateErrorDescription(
						response,
						"Property 'response_type' should be one of: 'code', 'none'"
					);
				}
			});

			it('invalid response mode (not validated yet)', async function () {
				// fake a query like this state=foo&state=foo to trigger
				// a validation error prior to validating response mode
				const spy = mock();
				provider.once('authorization.error', spy);
				const auth = new AuthorizationRequest({
					scope,
					state: ['foo', 'bar'],
					response_mode: 'foo'
				});

				const { response } = await authRequest(auth);
				expect(response.status).toBe(303);
				expect(spy).toHaveBeenCalledTimes(1);
				auth.validatePresence(response, ['error', 'error_description']);
				auth.validateClientLocation(response);
				auth.validateError(response, 'invalid_request');
				if (verb === 'get') {
					auth.validateErrorDescription(
						response,
						'Duplicate query parameter "state" detected'
					);
				}
				if (verb === 'post') {
					auth.validateErrorDescription(
						response,
						"Expected property 'state' to be string but found: foo,bar"
					);
				}
			});

			it('response mode provided twice', async function () {
				const spy = mock();
				provider.once('authorization.error', spy);
				const auth = new AuthorizationRequest({
					scope,
					response_mode: ['query', 'query']
				});
				delete auth.params.state;

				const { response } = await authRequest(auth);
				expect(response.status).toBe(303);
				expect(spy).toHaveBeenCalledTimes(1);
				auth.validatePresence(response, ['error', 'error_description']);
				auth.validateClientLocation(response);
				auth.validateError(response, 'invalid_request');
				if (verb === 'get') {
					auth.validateErrorDescription(
						response,
						'Duplicate query parameter "response_mode" detected'
					);
				}
				if (verb === 'post') {
					auth.validateErrorDescription(
						response,
						"Expected property 'response_mode' to be string but found: query,query"
					);
				}
			});

			it('unregistered scope requested', async function () {
				const spy = mock();
				provider.once('authorization.error', spy);
				const auth = new AuthorizationRequest({
					client_id: 'client-limited-scope',
					prompt: 'consent',
					scope: 'openid foobar offline_access' // foobar is ignored, offline_access is not allowed
				});

				const { response } = await authRequest(auth);
				expect(response.status).toBe(303);
				expect(spy).toHaveBeenCalledTimes(1);
				auth.validatePresence(response, [
					'error',
					'error_description',
					'state'
				]);
				auth.validateState(response);
				auth.validateClientLocation(response);
				auth.validateError(response, 'invalid_scope');
				auth.validateErrorDescription(
					response,
					'requested scope is not allowed'
				);
			});

			['request', 'request_uri', 'registration'].forEach((param) => {
				it(`not supported parameter ${param}`, async function () {
					const spy = mock();
					provider.once('authorization.error', spy);
					const auth = new AuthorizationRequest({
						response_type,
						scope,
						[param]: 'http://sjssjsjsjs/sss'
					});

					const { response } = await authRequest(auth);
					expect(response.status).toBe(303);
					expect(spy).toHaveBeenCalledTimes(1);
					auth.validatePresence(response, [
						'error',
						'error_description',
						'state'
					]);
					auth.validateState(response);
					auth.validateClientLocation(response);
					auth.validateError(response, 'not_supported');
				});
			});

			describe('when client has a single redirect_uri', () => {
				afterEach(function () {
					i(provider).configuration.allowOmittingSingleRegisteredRedirectUri =
						false;
				});

				it('missing mandatory parameter redirect_uri', async function () {
					const emitSpy = mock();
					provider.once('authorization.error', emitSpy);
					const auth = new AuthorizationRequest({ scope });
					delete auth.params.redirect_uri;

					const { response } = await authRequest(auth, { accept: 'text/html' });
					expect(response.status).toBe(400);
					expect(response.headers.get('content-type')).toBe(
						'text/html; charset=utf-8'
					);
					expect(emitSpy).toHaveBeenCalledTimes(1);
				});

				it('unless allowOmittingSingleRegisteredRedirectUri is true', async function () {
					i(provider).configuration.allowOmittingSingleRegisteredRedirectUri =
						true;
					const cookie = await setup.login();
					const auth = new AuthorizationRequest({
						client_id: 'client',
						scope
					});
					delete auth.params.redirect_uri;

					const { response } = await authRequest(auth, { cookie });
					expect(response.status).toBe(303);
					auth.validatePresence(response, ['code', 'state']);
					auth.validateState(response);
					auth.validateClientLocation(response);
				});
			});

			describe('when client has more then one redirect_uri', () => {
				beforeEach(async function () {
					const client = await Client.find('client');
					client.redirectUris.push('https://someOtherUri.com');
				});

				afterEach(async function () {
					const client = await Client.find('client');
					client.redirectUris.pop();
				});

				it('missing mandatory parameter redirect_uri', async function () {
					const emitSpy = mock();
					provider.once('authorization.error', emitSpy);
					const auth = new AuthorizationRequest({ scope });
					delete auth.params.redirect_uri;

					const { response } = await authRequest(auth, { accept: 'text/html' });
					expect(response.status).toBe(400);
					expect(response.headers.get('content-type')).toBe(
						'text/html; charset=utf-8'
					);
					expect(emitSpy).toHaveBeenCalledTimes(1);
				});
			});

			it('missing mandatory parameter response_type', async function () {
				const spy = mock();
				provider.once('authorization.error', spy);
				const auth = new AuthorizationRequest({ scope });
				delete auth.params.response_type;

				const { response } = await authRequest(auth);
				expect(response.status).toBe(303);
				expect(spy).toHaveBeenCalledTimes(1);
				auth.validatePresence(response, [
					'error',
					'error_description',
					'state'
				]);
				auth.validateState(response);
				auth.validateClientLocation(response);
				auth.validateError(response, 'invalid_request');
				auth.validateErrorDescription(
					response,
					"missing required parameter 'response_type'"
				);
			});

			it('unsupported prompt', async function () {
				const spy = mock();
				provider.once('authorization.error', spy);
				const auth = new AuthorizationRequest({
					scope,
					prompt: 'unsupported'
				});

				const { response } = await authRequest(auth);
				expect(response.status).toBe(303);
				expect(spy).toHaveBeenCalledTimes(1);
				auth.validatePresence(response, [
					'error',
					'error_description',
					'state'
				]);
				auth.validateState(response);
				auth.validateClientLocation(response);
				auth.validateError(response, 'invalid_request');
				auth.validateErrorDescription(
					response,
					'unsupported prompt value requested'
				);
			});

			it('supported but not requestable prompt', async function () {
				const spy = mock();
				provider.once('authorization.error', spy);
				const auth = new AuthorizationRequest({
					scope,
					prompt: 'unrequestable'
				});

				const { response } = await authRequest(auth);
				expect(response.status).toBe(303);
				expect(spy).toHaveBeenCalledTimes(1);
				auth.validatePresence(response, [
					'error',
					'error_description',
					'state'
				]);
				auth.validateState(response);
				auth.validateClientLocation(response);
				auth.validateError(response, 'invalid_request');
				auth.validateErrorDescription(
					response,
					'unsupported prompt value requested'
				);
			});

			it('bad prompt combination', async function () {
				const spy = mock();
				provider.once('authorization.error', spy);
				const auth = new AuthorizationRequest({
					scope,
					prompt: 'none login'
				});

				const { response } = await authRequest(auth);
				expect(response.status).toBe(303);
				expect(spy).toHaveBeenCalledTimes(1);
				auth.validatePresence(response, [
					'error',
					'error_description',
					'state'
				]);
				auth.validateState(response);
				auth.validateClientLocation(response);
				auth.validateError(response, 'invalid_request');
				auth.validateErrorDescription(
					response,
					'prompt none must only be used alone'
				);
			});

			// section-4.1.2.1 RFC6749
			it('missing mandatory parameter client_id', async function () {
				const auth = new AuthorizationRequest({ scope });
				delete auth.params.client_id;

				const { response, error } = await authRequest(auth, {
					accept: 'text/html'
				});
				if (!error) throw new Error('expected error response');
				expect(response.status).toBe(422);
				expect(response.headers.get('content-type')).toBe(
					'text/html; charset=utf-8'
				);

				expect(error.value).toContain(
					'Property &#x27;client_id&#x27; is missing'
				);
			});

			// section-4.1.2.1 RFC6749
			it('unrecognized client_id provided', async function () {
				const auth = new AuthorizationRequest({
					client_id: 'foobar',
					scope
				});
				delete auth.params.redirect_uri;

				const { response, error } = await authRequest(auth, {
					accept: 'text/html'
				});
				if (!error) throw new Error('expected error response');
				expect(response.status).toBe(400);
				expect(response.headers.get('content-type')).toBe(
					'text/html; charset=utf-8'
				);
				expect(error.value).toContain('client is invalid');
			});

			describe('section-4.1.2.1 RFC6749', () => {
				it('validates redirect_uri ad acta [regular error]', async function () {
					const spy = mock();
					provider.on('authorization.error', spy);
					const auth = new AuthorizationRequest({
						// scope, => 'openid' required when id_token_hint is provided
						id_token_hint: 'foo',
						redirect_uri: 'https://attacker.example.com/foobar'
					});

					const { response, error } = await authRequest(auth, {
						accept: 'text/html'
					});
					if (!error) throw new Error('expected error response');
					expect(error.status).toBe(400);
					expect(spy).toHaveBeenCalledTimes(2);
					expect(spy.mock.calls[0][0]).toHaveProperty(
						'message',
						'invalid_request'
					);
					expect(spy.mock.calls[1][0]).toHaveProperty(
						'message',
						'invalid_redirect_uri'
					);
					expect(response.headers.get('content-type')).toBe(
						'text/html; charset=utf-8'
					);
					expect(error.value).toContain('invalid_redirect_uri');
					expect(error.value).toContain(
						'redirect_uri did not match any of the client&#x27;s registered redirectUris'
					);
				});

				it('validates redirect_uri ad acta [server error]', async function () {
					const authErrorSpy = mock();
					const serverErrorSpy = mock();
					provider.once('authorization.error', authErrorSpy);
					provider.once('server_error', serverErrorSpy);
					spyOn(i(provider).responseModes, 'has').mockImplementation(() => {
						throw new Error('foobar');
					});
					const auth = new AuthorizationRequest({
						scope,
						redirect_uri: 'https://attacker.example.com/foobar'
					});

					const { response, error } = await authRequest(auth, {
						accept: 'text/html'
					});
					if (!error) throw new Error('expected error response');
					expect(error.status).toBe(400);

					expect(serverErrorSpy).toHaveBeenCalledTimes(1);
					expect(authErrorSpy).toHaveBeenCalledTimes(1);
					expect(serverErrorSpy.mock.calls[0][0]).toHaveProperty(
						'message',
						'foobar'
					);
					expect(authErrorSpy.mock.calls[0][0]).toHaveProperty(
						'message',
						'invalid_redirect_uri'
					);

					expect(response.headers.get('content-type')).toBe(
						'text/html; charset=utf-8'
					);
					expect(error.value).toContain('invalid_redirect_uri');
					expect(error.value).toContain(
						'redirect_uri did not match any of the client&#x27;s registered redirectUris'
					);
				});
			});

			it('unsupported response_type', async function () {
				const spy = mock();
				provider.once('authorization.error', spy);
				const auth = new AuthorizationRequest({
					response_type: 'unsupported',
					scope
				});

				const { response } = await authRequest(auth);
				expect(response.status).toBe(303);
				expect(spy).toHaveBeenCalledTimes(1);
				auth.validatePresence(response, [
					'error',
					'error_description',
					'state'
				]);
				auth.validateState(response);
				auth.validateClientLocation(response);
				auth.validateError(response, 'invalid_request');
				auth.validateErrorDescription(
					response,
					"Property 'response_type' should be one of: 'code', 'none'"
				);
			});

			it('invalid max_age (negative)', async function () {
				const spy = mock();
				provider.once('authorization.error', spy);
				const auth = new AuthorizationRequest({
					scope: 'openid',
					max_age: -1
				});

				const { response } = await authRequest(auth);
				expect(response.status).toBe(303);
				expect(spy).toHaveBeenCalledTimes(1);
				auth.validatePresence(response, [
					'error',
					'error_description',
					'state'
				]);
				auth.validateState(response);
				auth.validateClientLocation(response);
				auth.validateError(response, 'invalid_request');
				auth.validateErrorDescription(
					response,
					'max_age must be a positive integer'
				);
			});

			it('invalid max_age (MAX_SAFE_INTEGER)', async function () {
				const spy = mock();
				provider.once('authorization.error', spy);
				const auth = new AuthorizationRequest({
					response_type,
					scope: 'openid',
					max_age: Number.MAX_SAFE_INTEGER + 1
				});

				const { response } = await authRequest(auth);
				expect(response.status).toBe(303);
				expect(spy).toHaveBeenCalledTimes(1);
				auth.validatePresence(response, [
					'error',
					'error_description',
					'state'
				]);
				auth.validateState(response);
				auth.validateClientLocation(response);
				auth.validateError(response, 'invalid_request');
				auth.validateErrorDescription(
					response,
					'max_age must be a positive integer'
				);
			});

			it('restricted response_type', async function () {
				const spy = mock();
				provider.once('authorization.error', spy);
				const auth = new AuthorizationRequest({
					client_id: 'client-without-none',
					response_type: 'none',
					scope
				});

				const { response } = await authRequest(auth);
				expect(response.status).toBe(303);
				expect(spy).toHaveBeenCalledTimes(1);
				auth.validatePresence(response, [
					'error',
					'error_description',
					'state'
				]);
				auth.validateState(response);
				auth.validateClientLocation(response);
				auth.validateError(response, 'invalid_request');
				auth.validateErrorDescription(
					response,
					'requested response_type is not allowed for this client'
				);
			});

			it('unsupported response type validation runs before oidc required params', async function () {
				const spy = mock();
				provider.once('authorization.error', spy);
				const auth = new AuthorizationRequest({
					response_type: 'id_token token',
					nonce: undefined,
					scope
				});

				const { response } = await authRequest(auth);
				expect(response.status).toBe(303);
				expect(spy).toHaveBeenCalledTimes(1);
				auth.validatePresence(response, [
					'error',
					'error_description',
					'state'
				]);
				auth.validateState(response);
				auth.validateClientLocation(response);
				auth.validateError(response, 'invalid_request');
				auth.validateErrorDescription(
					response,
					"Property 'response_type' should be one of: 'code', 'none'"
				);
			});

			it('redirect_uri mismatch', async function () {
				const emitSpy = mock();
				provider.once('authorization.error', emitSpy);
				const auth = new AuthorizationRequest({
					scope,
					redirect_uri: 'https://client.example.com/cb/not/registered'
				});

				const { response, error } = await authRequest(auth, {
					accept: 'text/html'
				});
				if (!error) throw new Error('expected error response');
				expect(response.status).toBe(400);
				expect(response.headers.get('content-type')).toBe(
					'text/html; charset=utf-8'
				);
				expect(emitSpy).toHaveBeenCalledTimes(1);
				expect(error.value).toContain('invalid_redirect_uri');
				expect(error.value).toContain(
					'redirect_uri did not match any of the client&#x27;s registered redirectUris'
				);
			});

			it('login state specific malformed id_token_hint', async function () {
				const spy = mock();
				provider.once('authorization.error', spy);
				const cookie = await setup.login();
				const auth = new AuthorizationRequest({
					scope,
					id_token_hint: 'invalid'
				});
				const { response } = await authRequest(auth, { cookie });
				expect(response.status).toBe(303);
				expect(spy).toHaveBeenCalledTimes(1);
				auth.validatePresence(response, [
					'error',
					'error_description',
					'state'
				]);
				auth.validateState(response);
				auth.validateClientLocation(response);
				auth.validateError(response, 'invalid_request');
				auth.validateErrorDescription(
					response,
					/could not validate id_token_hint/
				);
			});
		});
	});
});
