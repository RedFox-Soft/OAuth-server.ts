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

import { ApplicationConfig } from 'lib/configs/application.js';
import { addons } from 'lib/addon/registry.js';
import bootstrap, {
	agent,
	jsonToFormUrlEncoded,
	type Setup
} from '../../test_helper.js';
import epochTime from '../../../lib/helpers/epoch_time.ts';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { eventBus } from 'lib/event_bus.js';
// Imported after lib/provider.js on purpose. response_modes reaches the model graph (via the jwt
// handler -> id_token), so importing it first would start the model/provider import cycle from the
// wrong end and leave base_token half-initialised. Safe to move once that cycle is gone.
import { responseModes } from 'lib/response_modes/index.js';
import { Client } from 'lib/models/client.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';

const route = '/auth';
const response_type = 'code';
const scope = 'openid';

/**
 * @proves The authorization endpoint issues a code to a client that asked correctly, decides
 * which interactions are required, and refuses every malformed or unregistered request without
 * redirecting anywhere it did not verify.
 */
describe('BASIC code', () => {
	let setup: Setup;
	beforeAll(async function () {
		setup = await bootstrap(import.meta.url);
	});

	afterEach(function () {
		mock.restore();
	});

	['get', 'post'].forEach((verb) => {
		function authRequest(
			auth: AuthorizationRequest,
			{ cookie, accept }: { cookie?: string; accept?: string } = {}
		) {
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
			let cookie: string;
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

			/*
			 * The next three were re-anchored from test/helpers/redirect_uri.spec.ts, which asserted
			 * them of the URL builder rather than of the response a client actually receives. Where
			 * the browser lands is the outcome; how the URL was assembled is not.
			 */
			it('keeps a query the client registered in its own redirect_uri', async function () {
				const auth = new AuthorizationRequest({
					client_id: 'client-query-cb',
					redirect_uri:
						'https://client.example.com/cb?other=stuff&state=planted',
					scope
				});

				const { response } = await authRequest(auth, { cookie });
				expect(response.status).toBe(303);

				const location = new URL(response.headers.get('location'));
				expect(location.searchParams.get('other')).toBe('stuff');
				expect(location.searchParams.get('code')).toBeTruthy();
			});

			it('lets no client pin a response parameter through its own redirect_uri', async function () {
				const auth = new AuthorizationRequest({
					client_id: 'client-query-cb',
					redirect_uri:
						'https://client.example.com/cb?other=stuff&state=planted',
					scope
				});

				const { response } = await authRequest(auth, { cookie });
				expect(response.status).toBe(303);

				const location = new URL(response.headers.get('location'));
				expect(location.searchParams.getAll('state')).toHaveLength(1);
				expect(location.searchParams.get('state')).not.toBe('planted');
				auth.validateState(response);
			});

			it('lands in the query of a redirect_uri that carries no path', async function () {
				const auth = new AuthorizationRequest({
					client_id: 'client-bare-origin-cb',
					redirect_uri: 'https://client.example.com',
					scope
				});

				const { response } = await authRequest(auth, { cookie });
				expect(response.status).toBe(303);

				const location = new URL(response.headers.get('location'));
				expect(location.pathname).toBe('/');
				expect(location.searchParams.get('code')).toBeTruthy();
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
				eventBus.once('authorization_code.saved', spy);
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
					eventBus.once('authorization_code.saved', spy);
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
					eventBus.once('authorization_code.saved', spy);
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
			// An empty policy is registered through the addon seam; the global afterEach in
			// test/preload.ts resets to this spec's baseline, so no manual restore is needed.
			it('the request produces a login interaction', async function () {
				addons.override({ interactionPolicy: () => [] });
				const spy = mock();
				eventBus.on('authorization.error', spy);

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

			it('the request produces a consent interaction', async function () {
				addons.override({ interactionPolicy: () => [] });
				const spy = mock();
				eventBus.on('authorization.error', spy);

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
			let cookie: string;
			beforeEach(async function () {
				cookie = await setup.login();
			});

			it('produces a login interaction when the session names no account', async function () {
				const session = setup.getSession();
				delete session.loginTs;
				delete session.accountId;

				const auth = new AuthorizationRequest({ scope });
				const { response } = await authRequest(auth, { cookie });
				auth.validateInteractionRedirect(response);
				auth.validateInteraction(response, 'login', 'no_session');
			});

			it('a newly requested scope produces a consent interaction', async function () {
				const auth = new AuthorizationRequest({ scope: 'openid email' });
				const { response } = await authRequest(auth, { cookie });
				expect(response.status).toBe(303);
				auth.validateInteractionRedirect(response);
				auth.validateInteraction(response, 'consent', 'op_scopes_missing');
			});

			it('asks the user to confirm for a native client by default', async function () {
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

			it('prompt=login forces re-authentication even with a live session', async function () {
				const auth = new AuthorizationRequest({ prompt: 'login', scope });
				const { response } = await authRequest(auth, { cookie });
				expect(response.status).toBe(303);
				auth.validateInteractionRedirect(response);
				auth.validateInteraction(response, 'login', 'login_prompt');
			});

			it('forces re-authentication when the client sends max_age=0', async function () {
				const auth = new AuthorizationRequest({ max_age: 0, scope });
				const { response } = await authRequest(auth, { cookie });
				expect(response.status).toBe(303);
				auth.validateInteractionRedirect(response);
				auth.validateInteraction(response, 'login', 'login_prompt');
			});

			it('produces a login interaction when there is no session and max_age is set', async function () {
				const auth = new AuthorizationRequest({
					max_age: 1800, // 30 minutes old session max
					scope
				});
				const { response } = await authRequest(auth);
				expect(response.status).toBe(303);
				auth.validateInteractionRedirect(response);
				auth.validateInteraction(response, 'login', 'max_age', 'no_session');
			});

			it('a session older than max_age forces re-authentication', async function () {
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

			it('forces re-authentication when the session is older than max_age, on the second path', async function () {
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

			it('forces re-authentication when the session is older than the client default_max_age', async function () {
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
				eventBus.once('authorization.error', spy);
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

			it('refuses an unsupported response_mode', async function () {
				// fake a query like this state=foo&state=foo to trigger
				// a validation error prior to validating response mode
				const spy = mock();
				eventBus.once('authorization.error', spy);
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

			it('refuses a duplicated response_mode rather than resolving it', async function () {
				const spy = mock();
				eventBus.once('authorization.error', spy);
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

			it('refuses a scope the server does not declare', async function () {
				const spy = mock();
				eventBus.once('authorization.error', spy);
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
				it(`each unsupported parameter is refused`, async function () {
					const spy = mock();
					eventBus.once('authorization.error', spy);
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
					ApplicationConfig[
						'authorization.allowOmittingSingleRegisteredRedirectUri'
					] = false;
				});

				it('refuses a request with no redirect_uri', async function () {
					const emitSpy = mock();
					eventBus.once('authorization.error', emitSpy);
					const auth = new AuthorizationRequest({ scope });
					delete auth.params.redirect_uri;

					const { response } = await authRequest(auth, { accept: 'text/html' });
					expect(response.status).toBe(400);
					expect(response.headers.get('content-type')).toBe(
						'text/html; charset=utf-8'
					);
					expect(emitSpy).toHaveBeenCalledTimes(1);
				});

				it('with the setting on, a single registered URI may be omitted', async function () {
					ApplicationConfig[
						'authorization.allowOmittingSingleRegisteredRedirectUri'
					] = true;
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

				it('refuses a request with no redirect_uri', async function () {
					const emitSpy = mock();
					eventBus.once('authorization.error', emitSpy);
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

			it('refuses a request with no response_type', async function () {
				const spy = mock();
				eventBus.once('authorization.error', spy);
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

			it('refuses a prompt value the server does not support', async function () {
				const spy = mock();
				eventBus.once('authorization.error', spy);
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

			it('refuses a prompt a deployment added for its own use', async function () {
				const spy = mock();
				eventBus.once('authorization.error', spy);
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

			it('prompt=none with any other prompt is refused', async function () {
				const spy = mock();
				eventBus.once('authorization.error', spy);
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
			it('refuses a request with no client_id', async function () {
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
			it('renders the refusal for an unknown client rather than redirecting anywhere', async function () {
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
				it('an error is only redirected to a redirect_uri that was verified first', async function () {
					const spy = mock();
					eventBus.on('authorization.error', spy);
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

				it('redirects a fault only to a redirect_uri it verified first', async function () {
					const authErrorSpy = mock();
					const serverErrorSpy = mock();
					eventBus.once('authorization.error', authErrorSpy);
					eventBus.once('server_error', serverErrorSpy);
					spyOn(responseModes, 'has').mockImplementation(() => {
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

			it('refuses a response_type the server does not support', async function () {
				const spy = mock();
				eventBus.once('authorization.error', spy);
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

			it('refuses a negative max_age', async function () {
				const spy = mock();
				eventBus.once('authorization.error', spy);
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

			it('refuses a max_age large enough to disable re-authentication', async function () {
				const spy = mock();
				eventBus.once('authorization.error', spy);
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

			it('a response type the client did not register is refused', async function () {
				const spy = mock();
				eventBus.once('authorization.error', spy);
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

			it('answers an unsupported response_type before complaining about missing OIDC parameters', async function () {
				const spy = mock();
				eventBus.once('authorization.error', spy);
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

			it('a redirect_uri the client did not register is refused and not redirected to', async function () {
				const emitSpy = mock();
				eventBus.once('authorization.error', emitSpy);
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

			it('refuses a malformed id_token_hint', async function () {
				const spy = mock();
				eventBus.once('authorization.error', spy);
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
