import querystring from 'node:querystring';
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

import sinon from 'sinon';

import bootstrap, { agent } from '../../test_helper.js';
import epochTime from '../../../lib/helpers/epoch_time.ts';
import { InvalidRedirectUri } from '../../../lib/helpers/errors.ts';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { provider } from 'lib/provider.js';

const route = '/auth';
const response_type = 'code';
const scope = 'openid';

describe('BASIC code', () => {
	let setup = null;
	beforeAll(async function () {
		setup = await bootstrap(import.meta.url)();
	});

	afterEach(function () {
		mock.restore();
		sinon.restore();
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
			} else if (verb === 'post') {
				return agent.auth.post(
					new URLSearchParams(Object.entries(auth.params)).toString(),
					{
						headers: {
							cookie,
							accept
						}
					}
				);
			}
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
				const spy = spyOn(provider.OIDCContext.prototype, 'entity');

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
				const spy = sinon.spy();
				setup.provider.once('authorization_code.saved', spy);
				const auth = new AuthorizationRequest({
					scope: 'openid and unsupported'
				});

				const { response } = await authRequest(auth, { cookie });
				expect(response.status).toBe(303);
				auth.validateClientLocation(response);
				expect(spy.firstCall.args[0]).toHaveProperty('scope', 'openid');
			});

			describe('ignoring the offline_access scope', () => {
				beforeEach(function () {
					spyOn(
						setup.provider.OIDCContext.prototype,
						'promptPending'
					).mockReturnValue(false);
				});

				it('ignores the scope offline_access unless prompt consent is present', async function () {
					const spy = sinon.spy();
					provider.once('authorization_code.saved', spy);
					const auth = new AuthorizationRequest({
						scope: 'openid offline_access'
					});

					const { response } = await authRequest(auth, { cookie });
					expect(response.status).toBe(303);
					auth.validateClientLocation(response);
					expect(spy.firstCall.args[0]).toHaveProperty('scope');
					expect(spy.firstCall.args[0].scope).not.toContain('offline_access');
				});

				it('ignores the scope offline_access unless the client can do refresh_token exchange', async function () {
					const spy = sinon.spy();
					provider.once('authorization_code.saved', spy);
					const auth = new AuthorizationRequest({
						client_id: 'client-no-refresh',
						prompt: 'consent',
						scope: 'openid offline_access'
					});

					const { response } = await authRequest(auth, { cookie });
					expect(response.status).toBe(303);
					auth.validateClientLocation(response);
					expect(spy.firstCall.args[0]).toHaveProperty('scope');
					expect(spy.firstCall.args[0].scope).not.toContain('offline_access');
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
				const spy = sinon.spy();
				provider.on('authorization.error', spy);

				const auth = new AuthorizationRequest({ scope });
				const { response } = await authRequest(auth);

				expect(response.status).toBe(303);
				auth.validateClientLocation(response);
				auth.validatePresence(response, ['error', 'state']);
				auth.validateError(response, 'access_denied');

				expect(spy.calledOnce).toBe(true);
				expect(spy.args[0][0]).toHaveProperty(
					'error_detail',
					'authorization request resolved without requesting interactions but no account id was resolved'
				);
			});

			it('no scope was resolved and no interactions requested', async function () {
				i(provider).configuration.interactions.policy = [];
				const spy = sinon.spy();
				provider.on('authorization.error', spy);

				const cookie = await setup.login();
				const auth = new AuthorizationRequest();
				const { response } = await authRequest(auth, { cookie });

				expect(response.status).toBe(303);
				auth.validateClientLocation(response);
				auth.validatePresence(response, ['error', 'state']);
				auth.validateError(response, 'access_denied');

				expect(spy.calledOnce).toBe(true);
				expect(spy.args[0][0]).toHaveProperty(
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
				expect(response.status).toBe(303);
				auth.validateInteractionRedirect(response);
				auth.validateInteraction('login', 'no_session');
			});

			it('additional scopes are requested', async function () {
				const auth = new AuthorizationRequest({ scope: 'openid email' });
				const { response } = await authRequest(auth, { cookie });
				expect(response.status).toBe(303);
				auth.validateInteractionRedirect(response);
				auth.validateInteraction('consent', 'op_scopes_missing');
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
				auth.validateInteraction('consent', 'native_client_prompt');
			});

			it('login was requested by the client by prompt parameter', async function () {
				const auth = new AuthorizationRequest({ prompt: 'login', scope });
				const { response } = await authRequest(auth, { cookie });
				expect(response.status).toBe(303);
				auth.validateInteractionRedirect(response);
				auth.validateInteraction('login', 'login_prompt');
			});

			it('login was requested by the client by max_age=0', async function () {
				const auth = new AuthorizationRequest({ max_age: 0, scope });
				const { response } = await authRequest(auth, { cookie });
				expect(response.status).toBe(303);
				auth.validateInteractionRedirect(response);
				auth.validateInteraction('login', 'login_prompt');
			});

			it('interaction check no session & max_age combo', async function () {
				const auth = new AuthorizationRequest({
					max_age: 1800, // 30 minutes old session max
					scope
				});
				const { response } = await authRequest(auth);
				expect(response.status).toBe(303);
				auth.validateInteractionRedirect(response);
				auth.validateInteraction('login', 'max_age', 'no_session');
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
				auth.validateInteraction('login', 'max_age');
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
				auth.validateInteraction('login', 'max_age');
			});

			it('session is too old for this client', async function () {
				const client = await setup.provider.Client.find('client');
				client.defaultMaxAge = 1800;

				const session = setup.getSession();
				session.loginTs = epochTime() - 3600; // an hour ago

				const auth = new AuthorizationRequest({ scope });
				const { response } = await authRequest(auth, { cookie });
				delete client.defaultMaxAge;
				expect(response.status).toBe(303);
				auth.validateInteractionRedirect(response);
				auth.validateInteraction('login', 'max_age');
			});
		});

		describe(`${verb} ${route} errors`, () => {
			it('dupe parameters are rejected and ignored in further processing', function () {
				// fake a query like this state=foo&state=foo
				const spy = sinon.spy();
				this.provider.once('authorization.error', spy);
				const auth = new AuthorizationRequest({
					response_type,
					scope,
					state: 'foo'
				});

				const wrapped = ((data) => {
					// eslint-disable-line consistent-return
					switch (verb) {
						case 'get':
							return this.agent
								.get(route)
								.query(
									`${data}&state=foo&scope=openid&response_type=${response_type}`
								);
						case 'post':
							return this.agent
								.post(route)
								.send(
									`${data}&state=foo&scope=openid&response_type=${response_type}`
								)
								.type('form');
						default:
					}
				})(querystring.stringify(auth));

				return (
					wrapped
						.expect(303)
						.expect(() => {
							expect(spy.calledOnce).to.be.true;
						})
						.expect(auth.validatePresence(['error', 'error_description'])) // notice state is not expected
						// .expect(auth.validateState) // notice state is not expected
						.expect(auth.validateClientLocation)
						.expect(auth.validateError('invalid_request'))
						.expect(
							auth.validateErrorDescription(
								"'response_type', 'scope', and 'state' parameters must not be provided twice"
							)
						)
				);
			});

			it('invalid response mode (not validated yet)', function () {
				// fake a query like this state=foo&state=foo to trigger
				// a validation error prior to validating response mode
				const spy = sinon.spy();
				this.provider.once('authorization.error', spy);
				const auth = new AuthorizationRequest({
					response_type,
					scope,
					state: 'foo',
					response_mode: 'foo'
				});

				const wrapped = ((data) => {
					// eslint-disable-line consistent-return
					switch (verb) {
						case 'get':
							return this.agent.get(route).query(`${data}&state=bar`);
						case 'post':
							return this.agent
								.post(route)
								.send(`${data}&state=bar`)
								.type('form');
						default:
					}
				})(querystring.stringify(auth));

				return (
					wrapped
						.expect(303)
						.expect(() => {
							expect(spy.calledOnce).to.be.true;
						})
						.expect(auth.validatePresence(['error', 'error_description'])) // notice state is not expected
						// .expect(auth.validateState) // notice state is not expected
						.expect(auth.validateClientLocation)
						.expect(auth.validateError('invalid_request'))
						.expect(
							auth.validateErrorDescription(
								"'state' parameter must not be provided twice"
							)
						)
				);
			});

			it('response mode provided twice', function () {
				const spy = sinon.spy();
				this.provider.once('authorization.error', spy);
				const auth = new AuthorizationRequest({
					response_type,
					scope,
					response_mode: 'query'
				});

				const wrapped = ((data) => {
					// eslint-disable-line consistent-return
					switch (verb) {
						case 'get':
							return this.agent.get(route).query(`${data}&response_mode=query`);
						case 'post':
							return this.agent
								.post(route)
								.send(`${data}&response_mode=query`)
								.type('form');
						default:
					}
				})(querystring.stringify(auth));

				return wrapped
					.expect(303)
					.expect(() => {
						expect(spy.calledOnce).to.be.true;
					})
					.expect(
						auth.validatePresence(['error', 'error_description', 'state'])
					)
					.expect(auth.validateClientLocation)
					.expect(auth.validateError('invalid_request'))
					.expect(
						auth.validateErrorDescription(
							"'response_mode' parameter must not be provided twice"
						)
					);
			});

			it('unregistered scope requested', function () {
				const spy = sinon.spy();
				provider.once('authorization.error', spy);
				const auth = new AuthorizationRequest({
					client_id: 'client-limited-scope',
					response_type: 'code',
					prompt: 'consent',
					scope: 'openid foobar offline_access' // foobar is ignored, offline_access is not allowed
				});

				return this.wrap({ route, verb, auth })
					.expect(303)
					.expect(() => {
						expect(spy.calledOnce).to.be.true;
					})
					.expect(
						auth.validatePresence([
							'error',
							'error_description',
							'state',
							'scope'
						])
					)
					.expect(auth.validateState)
					.expect(auth.validateClientLocation)
					.expect(auth.validateError('invalid_scope'))
					.expect(auth.validateScope('offline_access'))
					.expect(
						auth.validateErrorDescription('requested scope is not allowed')
					);
			});

			['request', 'request_uri', 'registration'].forEach((param) => {
				it(`not supported parameter ${param}`, function () {
					const spy = sinon.spy();
					provider.once('authorization.error', spy);
					const auth = new AuthorizationRequest({
						response_type,
						scope,
						[param]: 'some'
					});

					return this.agent
						.get(route)
						.query(auth)
						.expect(303)
						.expect(() => {
							expect(spy.calledOnce).to.be.true;
						})
						.expect(auth.validatePresence(['error', 'state']))
						.expect(auth.validateState)
						.expect(auth.validateClientLocation)
						.expect(auth.validateError(`${param}_not_supported`));
				});
			});

			describe('when client has a single redirect_uri', () => {
				afterEach(function () {
					i(provider).configuration.allowOmittingSingleRegisteredRedirectUri =
						false;
				});

				it('missing mandatory parameter redirect_uri', async function () {
					const emitSpy = sinon.spy();
					provider.once('authorization.error', emitSpy);
					const auth = new AuthorizationRequest({ scope });
					delete auth.params.redirect_uri;

					const { response } = await authRequest(auth, { accept: 'text/html' });
					expect(response.status).toBe(400);
					expect(response.headers.get('content-type')).toBe(
						'text/html; charset=utf-8'
					);
					expect(emitSpy.calledOnce).toBe(true);
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
					const client = await provider.Client.find('client');
					client.redirectUris.push('https://someOtherUri.com');
				});

				afterEach(async function () {
					const client = await provider.Client.find('client');
					client.redirectUris.pop();
				});

				it('missing mandatory parameter redirect_uri', async function () {
					const emitSpy = sinon.spy();
					provider.once('authorization.error', emitSpy);
					const auth = new AuthorizationRequest({ scope });
					delete auth.params.redirect_uri;

					const { response } = await authRequest(auth, { accept: 'text/html' });
					expect(response.status).toBe(400);
					expect(response.headers.get('content-type')).toBe(
						'text/html; charset=utf-8'
					);
					expect(emitSpy.calledOnce).toBe(true);
				});
			});

			it('missing mandatory parameter response_type', function () {
				const spy = sinon.spy();
				provider.once('authorization.error', spy);
				const auth = new AuthorizationRequest({
					scope
				});
				delete auth.response_type;

				return this.agent
					.get(route)
					.query(auth)
					.expect(303)
					.expect(() => {
						expect(spy.calledOnce).to.be.true;
					})
					.expect(
						auth.validatePresence(['error', 'error_description', 'state'])
					)
					.expect(auth.validateState)
					.expect(auth.validateClientLocation)
					.expect(auth.validateError('invalid_request'))
					.expect(
						auth.validateErrorDescription(
							"missing required parameter 'response_type'"
						)
					);
			});

			it('unsupported prompt', function () {
				const spy = sinon.spy();
				provider.once('authorization.error', spy);
				const auth = new AuthorizationRequest({
					response_type,
					scope,
					prompt: 'unsupported'
				});

				return this.wrap({ route, verb, auth })
					.expect(303)
					.expect(() => {
						expect(spy.calledOnce).to.be.true;
					})
					.expect(
						auth.validatePresence(['error', 'error_description', 'state'])
					)
					.expect(auth.validateState)
					.expect(auth.validateClientLocation)
					.expect(auth.validateError('invalid_request'))
					.expect(
						auth.validateErrorDescription('unsupported prompt value requested')
					);
			});

			it('supported but not requestable prompt', function () {
				const spy = sinon.spy();
				provider.once('authorization.error', spy);
				const auth = new AuthorizationRequest({
					response_type,
					scope,
					prompt: 'unrequestable'
				});

				return this.wrap({ route, verb, auth })
					.expect(303)
					.expect(() => {
						expect(spy.calledOnce).to.be.true;
					})
					.expect(
						auth.validatePresence(['error', 'error_description', 'state'])
					)
					.expect(auth.validateState)
					.expect(auth.validateClientLocation)
					.expect(auth.validateError('invalid_request'))
					.expect(
						auth.validateErrorDescription('unsupported prompt value requested')
					);
			});

			it('bad prompt combination', function () {
				const spy = sinon.spy();
				provider.once('authorization.error', spy);
				const auth = new AuthorizationRequest({
					response_type,
					scope,
					prompt: 'none login'
				});

				return this.wrap({ route, verb, auth })
					.expect(303)
					.expect(() => {
						expect(spy.calledOnce).to.be.true;
					})
					.expect(
						auth.validatePresence(['error', 'error_description', 'state'])
					)
					.expect(auth.validateState)
					.expect(auth.validateClientLocation)
					.expect(auth.validateError('invalid_request'))
					.expect(
						auth.validateErrorDescription('prompt none must only be used alone')
					);
			});

			// section-4.1.2.1 RFC6749
			it('missing mandatory parameter client_id', async function () {
				const auth = new AuthorizationRequest({ scope });
				delete auth.params.client_id;

				const { response, error } = await authRequest(auth, {
					accept: 'text/html'
				});
				expect(response.status).toBe(422);
				expect(response.headers.get('content-type')).toBe(
					'text/html; charset=utf-8'
				);
				if (verb === 'get') {
					expect(error.value).toContain(
						'Expected  property &#x27;client_id&#x27; to be  string'
					);
				} else {
					expect(error.value).toContain(
						'Property &#x27;client_id&#x27; is missing'
					);
				}
			});

			// section-4.1.2.1 RFC6749
			it('unrecognized client_id provided', async function () {
				const auth = new AuthorizationRequest({
					client_id: 'foobar',
					scope
				});

				const { response, error } = await authRequest(auth, {
					accept: 'text/html'
				});
				expect(response.status).toBe(400);
				expect(response.headers.get('content-type')).toBe(
					'text/html; charset=utf-8'
				);
				console.log(error.value);
				expect(error.value).toContain('client is invalid');
			});

			describe('section-4.1.2.1 RFC6749', () => {
				it('validates redirect_uri ad acta [regular error]', async function () {
					const spy = sinon.spy();
					provider.on('authorization.error', spy);
					const auth = new AuthorizationRequest({
						// scope, => 'openid' required when id_token_hint is provided
						id_token_hint: 'foo',
						redirect_uri: 'https://attacker.example.com/foobar'
					});

					const { response, error } = await authRequest(auth, {
						//accept: 'text/html'
					});
					expect(response.status).toBe(400);
					expect(spy.calledTwice).toBeTrue();

					return this.agent
						.get(route)
						.query(auth)
						.expect(() => {
							this.provider.removeAllListeners('authorization.error');
							renderSpy.restore();
						})
						.expect(() => {
							expect(spy.calledTwice).to.be.true;
						})
						.expect(() => {
							expect(
								spy.firstCall.calledWithMatch(
									{},
									{ message: 'invalid_request' }
								)
							).to.be.true;
							expect(
								spy.secondCall.calledWithMatch(
									{},
									{ message: 'invalid_redirect_uri' }
								)
							).to.be.true;
						})
						.expect(() => {
							expect(renderSpy.calledOnce).to.be.true;
							const renderArgs = renderSpy.args[0];
							expect(renderArgs[1]).to.have.property(
								'error',
								'invalid_redirect_uri'
							);
							expect(renderArgs[2]).to.be.an.instanceof(InvalidRedirectUri);
						});
				});

				it('validates redirect_uri ad acta [server error]', function () {
					const renderSpy = sinon.spy(i(provider).configuration, 'renderError');
					const authErrorSpy = sinon.spy();
					const serverErrorSpy = sinon.spy();
					provider.on('authorization.error', authErrorSpy);
					provider.on('server_error', serverErrorSpy);
					sinon.stub(i(this.provider).responseModes, 'has').callsFake(() => {
						throw new Error('foobar');
					});
					const auth = new AuthorizationRequest({
						response_type,
						scope,
						response_mode: 'fragment',
						redirect_uri: 'https://attacker.example.com/foobar'
					});

					return this.agent
						.get(route)
						.query(auth)
						.expect(() => {
							i(this.provider).responseModes.has.restore();
							this.provider.removeAllListeners('authorization.error');
							this.provider.removeAllListeners('server_error');
							renderSpy.restore();
						})
						.expect(() => {
							expect(serverErrorSpy.calledOnce).to.be.true;
							expect(authErrorSpy.calledOnce).to.be.true;
						})
						.expect(() => {
							expect(serverErrorSpy.calledWithMatch({}, { message: 'foobar' }))
								.to.be.true;
							expect(
								authErrorSpy.calledWithMatch(
									{},
									{ message: 'invalid_redirect_uri' }
								)
							).to.be.true;
						})
						.expect(() => {
							expect(renderSpy.calledOnce).to.be.true;
							const renderArgs = renderSpy.args[0];
							expect(renderArgs[1]).to.have.property(
								'error',
								'invalid_redirect_uri'
							);
							expect(renderArgs[2]).to.be.an.instanceof(InvalidRedirectUri);
						});
				});
			});

			it('unsupported response_type', function () {
				const spy = sinon.spy();
				provider.once('authorization.error', spy);
				const auth = new AuthorizationRequest({
					response_type: 'unsupported',
					scope
				});

				return this.wrap({ route, verb, auth })
					.expect(303)
					.expect(() => {
						expect(spy.calledOnce).to.be.true;
					})
					.expect(
						auth.validatePresence(['error', 'error_description', 'state'])
					)
					.expect(auth.validateState)
					.expect(auth.validateClientLocation)
					.expect(auth.validateError('unsupported_response_type'))
					.expect(
						auth.validateErrorDescription('unsupported response_type requested')
					);
			});

			it('invalid max_age (negative)', function () {
				const spy = sinon.spy();
				provider.once('authorization.error', spy);
				const auth = new AuthorizationRequest({
					response_type,
					scope: 'openid',
					max_age: -1
				});

				return this.wrap({ route, verb, auth })
					.expect(303)
					.expect(() => {
						expect(spy.calledOnce).to.be.true;
					})
					.expect(
						auth.validatePresence(['error', 'error_description', 'state'])
					)
					.expect(auth.validateState)
					.expect(auth.validateClientLocation)
					.expect(auth.validateError('invalid_request'))
					.expect(
						auth.validateErrorDescription('invalid max_age parameter value')
					);
			});

			it('invalid max_age (MAX_SAFE_INTEGER)', function () {
				const spy = sinon.spy();
				provider.once('authorization.error', spy);
				const auth = new AuthorizationRequest({
					response_type,
					scope: 'openid',
					max_age: Number.MAX_SAFE_INTEGER + 1
				});

				return this.wrap({ route, verb, auth })
					.expect(303)
					.expect(() => {
						expect(spy.calledOnce).to.be.true;
					})
					.expect(
						auth.validatePresence(['error', 'error_description', 'state'])
					)
					.expect(auth.validateState)
					.expect(auth.validateClientLocation)
					.expect(auth.validateError('invalid_request'))
					.expect(
						auth.validateErrorDescription('invalid max_age parameter value')
					);
			});

			if (verb === 'post') {
				it('only supports application/x-www-form-urlencoded', function () {
					const spy = sinon.spy();
					provider.once('authorization.error', spy);
					const auth = new AuthorizationRequest({ scope });

					return this.wrap({ route, verb, auth })
						.type('json')
						.expect(400)
						.expect(
							/only application\/x-www-form-urlencoded content-type bodies are supported on POST \/auth/
						)
						.expect(/invalid_request/)
						.expect(() => {
							expect(spy.calledOnce).to.be.true;
						});
				});
			}

			it('restricted response_type', function () {
				const spy = sinon.spy();
				provider.once('authorization.error', spy);
				const auth = new AuthorizationRequest({
					client_id: 'client-without-none',
					response_type: 'none',
					scope
				});

				return this.wrap({ route, verb, auth })
					.expect(303)
					.expect(() => {
						expect(spy.calledOnce).to.be.true;
					})
					.expect(
						auth.validatePresence(['error', 'error_description', 'state'])
					)
					.expect(auth.validateState)
					.expect(auth.validateClientLocation)
					.expect(auth.validateError('invalid_request'))
					.expect(
						auth.validateErrorDescription(
							'requested response_type is not allowed for this client'
						)
					);
			});

			it('unsupported response type validation runs before oidc required params', function () {
				const spy = sinon.spy();
				provider.once('authorization.error', spy);
				const auth = new AuthorizationRequest({
					response_type: 'id_token token',
					nonce: undefined,
					scope
				});

				return this.wrap({ route, verb, auth })
					.expect(303)
					.expect(() => {
						expect(spy.calledOnce).to.be.true;
					})
					.expect(
						auth.validatePresence(['error', 'error_description', 'state'])
					)
					.expect(auth.validateState)
					.expect(auth.validateClientLocation)
					.expect(auth.validateError('unsupported_response_type'))
					.expect(
						auth.validateErrorDescription('unsupported response_type requested')
					);
			});

			it('redirect_uri mismatch', function () {
				const emitSpy = sinon.spy();
				const renderSpy = sinon.spy(i(provider).configuration, 'renderError');
				provider.once('authorization.error', emitSpy);
				const auth = new AuthorizationRequest({
					response_type,
					scope,
					redirect_uri: 'https://client.example.com/cb/not/registered'
				});

				return this.agent
					.get(route)
					.query(auth)
					.expect(() => {
						renderSpy.restore();
					})
					.expect(400)
					.expect(() => {
						expect(emitSpy.calledOnce).to.be.true;
						expect(renderSpy.calledOnce).to.be.true;
						const renderArgs = renderSpy.args[0];
						expect(renderArgs[1]).to.have.property(
							'error',
							'invalid_redirect_uri'
						);
						expect(renderArgs[1]).to.have.property(
							'error_description',
							"redirect_uri did not match any of the client's registered redirect_uris"
						);
						expect(renderArgs[2]).to.be.an.instanceof(InvalidRedirectUri);
					});
			});

			it('login state specific malformed id_token_hint', async function () {
				const spy = sinon.spy();
				provider.once('authorization.error', spy);
				const cookie = await setup.login();
				const auth = new AuthorizationRequest({
					scope,
					id_token_hint: 'invalid'
				});
				const { response } = await authRequest(auth, cookie);
				expect(response.status).toBe(303);
				expect(spy.calledOnce).toBeTrue();
				auth.validatePresence(['error', 'error_description', 'state']);
				auth.validateState(response);
				auth.validateClientLocation(response);
				auth.validateError('invalid_request');
				auth.validateErrorDescription(/could not validate id_token_hint/);
			});
		});
	});
});
