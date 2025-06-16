import get from 'lodash/get.js';
import url from 'node:url';
import {
	describe,
	it,
	beforeAll,
	expect,
	beforeEach,
	afterEach
} from 'bun:test';

import { decode as decodeJWT } from '../../lib/helpers/jwt.ts';
import bootstrap, { agent, jsonToFormUrlEncoded } from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { provider } from 'lib/provider.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';

const route = '/auth';
const expire = new Date();

expire.setDate(expire.getDate() + 1);
['get', 'post'].forEach((verb) => {
	function authRequest(auth, { cookie } = {}) {
		if (verb === 'get') {
			return agent.auth.get({
				query: auth.params,
				headers: { cookie }
			});
		}

		// @ts-expect-error string will be converted to form url encoded
		return agent.auth.post(jsonToFormUrlEncoded(auth.params), {
			headers: { cookie }
		});
	}

	describe(`claimsParameter via ${verb} ${route}`, () => {
		let setup = null;
		async function getToken(auth, { cookie: cookieHeader } = {}) {
			const cookie = cookieHeader || (await setup.login());
			const authRes = await authRequest(auth, { cookie });
			const location = authRes.response.headers.get('location');
			const {
				query: { code }
			} = url.parse(location, true);
			if (!code) {
				console.error('no code in location', location);
			}

			const token = await auth.getToken(code);
			expect(token.response.status).toBe(200);
			return token.data;
		}

		beforeAll(async function () {
			setup = await bootstrap(import.meta.url)();
		});

		it('specify id_token should return individual claims requested', async function () {
			const auth = new AuthorizationRequest({
				scope: 'openid',
				claims: {
					id_token: {
						email: null,
						middle_name: {},

						preferred_username: 'not returned',
						picture: 1, // not returned
						website: true // not returned
					}
				}
			});
			const cookie = await setup.login({
				claims: {
					id_token: {
						email: null,
						middle_name: {}
					}
				}
			});

			const { id_token } = await getToken(auth, { cookie });

			const { payload } = decodeJWT(id_token);
			expect(payload).toContainKeys(['email', 'middle_name']);
			expect(payload).not.toContainKeys([
				'preferred_username',
				'picture',
				'website'
			]);
		});

		describe('with acr_values on the client', () => {
			beforeEach(async function () {
				const client = await provider.Client.find('client');
				client.defaultAcrValues = ['1', '2'];
			});

			afterEach(async function () {
				const client = await provider.Client.find('client');
				delete client.defaultAcrValues;
			});

			it('(pre 4.x behavior backfill) should include the acr claim now', async function () {
				const descriptor = Object.getOwnPropertyDescriptor(
					OIDCContext.prototype,
					'acr'
				);

				Object.defineProperty(OIDCContext.prototype, 'acr', {
					get() {
						return get(this, 'result.login.acr', '0');
					}
				});

				const auth = new AuthorizationRequest({ scope: 'openid' });
				const { id_token } = await getToken(auth);

				const { payload } = decodeJWT(id_token);
				expect(payload).toContainKey('acr');
			});
		});

		it('specify userinfo should return individual claims requested', async function () {
			const auth = new AuthorizationRequest({
				scope: 'openid',
				claims: {
					userinfo: {
						email: null,
						middle_name: {},

						preferred_username: 'not returned',
						picture: 1, // not returned
						website: true // not returned
					}
				}
			});

			const cookie = await setup.login({
				claims: {
					id_token: {
						email: null,
						middle_name: {}
					}
				}
			});
			const { access_token } = await getToken(auth, { cookie });
			const { data, response } = await agent.userinfo.get({
				headers: {
					authorization: `Bearer ${access_token}`
				}
			});
			expect(response.status).toBe(200);
			expect(data).toContainKeys(['email', 'middle_name']);
			expect(data).not.toContainKeys([
				'preferred_username',
				'picture',
				'website'
			]);
		});

		describe('specify both id_token and userinfo', () => {
			it('should return individual claims requested', async function () {
				const auth = new AuthorizationRequest({
					scope: 'openid',
					claims: {
						id_token: {
							email: null
						},
						userinfo: {
							given_name: null
						}
					}
				});
				const cookie = await setup.login({
					claims: {
						id_token: {
							email: null
						},
						userinfo: {
							given_name: null
						}
					}
				});

				const { id_token, access_token } = await getToken(auth, { cookie });

				const { payload } = decodeJWT(id_token);
				expect(payload).toContainKey('email');
				expect(payload).not.toContainKey('given_name');

				const { data, response } = await agent.userinfo.get({
					headers: {
						authorization: `Bearer ${access_token}`
					}
				});
				expect(response.status).toBe(200);
				expect(data).toContainKey('given_name');
				expect(data).not.toContainKey('email');
			});
		});

		describe('related interactions', () => {
			describe('are met', () => {
				it('session subject value differs from the one requested [1/2]', async function () {
					const cookie = await setup.login();
					const session = setup.getSession();
					const auth = new AuthorizationRequest({
						client_id: 'client',
						scope: 'openid',
						prompt: 'none',
						claims: {
							id_token: {
								sub: {
									value: session.accountId
								}
							}
						}
					});

					const { response } = await authRequest(auth, { cookie });
					expect(response.status).toBe(303);
					auth.validatePresence(response, ['code', 'state']);
					auth.validateState(response);
					auth.validateClientLocation(response);
				});

				it('session subject value differs from the one requested [2/2]', async function () {
					const cookie = await setup.login();
					const session = setup.getSession();
					const auth = new AuthorizationRequest({
						client_id: 'client-pairwise',
						scope: 'openid',
						prompt: 'none',
						claims: {
							id_token: {
								sub: {
									value: `${session.accountId}-pairwise`
								}
							}
						}
					});

					const { response } = await authRequest(auth, { cookie });
					expect(response.status).toBe(303);
					auth.validatePresence(response, ['code', 'state']);
					auth.validateState(response);
					auth.validateClientLocation(response);
				});

				if (verb === 'get') {
					async function setupFun(auth, result) {
						const cookies = [];

						const sess = new provider.Interaction('resume', {
							uid: 'resume',
							cookieID: 'cookieID'
						});
						if (auth) {
							const cookie = `_interaction=cookieID; path=/ui/resume/resume; expires=${expire.toGMTString()}; httponly`;
							cookies.push(cookie);
							Object.assign(sess, { params: auth.params });
						}

						if (result) {
							Object.assign(sess, { result });
						}

						await sess.save(30);
						return cookies;
					}

					it('none of multiple authentication context class references requested are met', async function () {
						const seesion = await setup.login();
						const auth = new AuthorizationRequest({
							scope: 'openid',
							prompt: 'none',
							claims: {
								id_token: {
									acr: {
										essential: true,
										values: ['1', '2']
									}
								}
							}
						});

						const cookie = await setupFun(auth, {
							login: {
								accountId: setup.getAccountId(),
								acr: '2'
							}
						});

						const { response } = await agent.ui['resume'].resume.get({
							headers: { cookie: [seesion, cookie].join('; ') }
						});
						expect(response.status).toBe(303);
						auth.validatePresence(response, ['code', 'state']);
						auth.validateState(response);
						auth.validateClientLocation(response);
					});

					it('single requested authentication context class reference is not met', async function () {
						const session = await setup.login();
						const auth = new AuthorizationRequest({
							scope: 'openid',
							prompt: 'none',
							claims: {
								id_token: {
									acr: {
										essential: true,
										value: '1'
									}
								}
							}
						});

						const cookie = await setupFun(auth, {
							login: {
								accountId: setup.getAccountId(),
								acr: '1'
							}
						});

						const { response, error } = await agent.ui['resume'].resume.get({
							headers: { cookie: [session, cookie].join('; ') }
						});
						expect(response.status).toBe(303);
						auth.validatePresence(response, ['code', 'state']);
						auth.validateState(response);
						auth.validateClientLocation(response);
					});
				}
			});

			describe('are not met', () => {
				it('session subject value differs from the one requested [1/3]', async function () {
					const auth = new AuthorizationRequest({
						client_id: 'client',
						scope: 'openid',
						prompt: 'none',
						claims: {
							id_token: {
								sub: {
									value: 'iexpectthisid'
								}
							}
						}
					});

					const cookie = await setup.login();
					const { response } = await authRequest(auth, { cookie });

					expect(response.status).toBe(303);
					auth.validatePresence(response, [
						'error',
						'error_description',
						'state'
					]);
					auth.validateState(response);
					auth.validateClientLocation(response);
					auth.validateError(response, 'login_required');
					auth.validateErrorDescription(
						response,
						'requested subject could not be obtained'
					);
				});

				it('session subject value differs from the one requested [2/3]', async function () {
					const auth = new AuthorizationRequest({
						client_id: 'client-pairwise',
						scope: 'openid',
						prompt: 'none',
						claims: {
							id_token: {
								sub: {
									value: 'iexpectthisid-pairwise'
								}
							}
						}
					});

					const cookie = await setup.login();
					const { response } = await authRequest(auth, { cookie });
					expect(response.status).toBe(303);
					auth.validatePresence(response, [
						'error',
						'error_description',
						'state'
					]);
					auth.validateState(response);
					auth.validateClientLocation(response);
					auth.validateError(response, 'login_required');
					auth.validateErrorDescription(
						response,
						'requested subject could not be obtained'
					);
				});

				it('session subject value differs from the one requested [3/3]', async function () {
					const auth = new AuthorizationRequest({
						client_id: 'client-pairwise',
						scope: 'openid',
						claims: {
							id_token: {
								sub: {
									value: 'iexpectthisid-pairwise'
								}
							}
						}
					});

					const { response } = await authRequest(auth);
					expect(response.status).toBe(303);
					auth.validateInteractionRedirect(response);
					auth.validateInteraction(
						response,
						'login',
						'claims_id_token_sub_value',
						'no_session'
					);
				});

				it('none of multiple authentication context class references requested are met (1/2)', async function () {
					const auth = new AuthorizationRequest({
						scope: 'openid',
						prompt: 'none',
						claims: {
							id_token: {
								acr: {
									essential: true,
									values: ['1', '2']
								}
							}
						}
					});

					const cookie = await setup.login();
					const { response } = await authRequest(auth, { cookie });
					expect(response.status).toBe(303);
					auth.validatePresence(response, [
						'error',
						'error_description',
						'state'
					]);
					auth.validateState(response);
					auth.validateClientLocation(response);
					auth.validateError(response, 'login_required');
					auth.validateErrorDescription(
						response,
						'none of the requested ACRs could not be obtained'
					);
				});

				it('none of multiple authentication context class references requested are met (2/2)', async function () {
					const auth = new AuthorizationRequest({
						scope: 'openid',
						prompt: 'none',
						claims: {
							id_token: {
								acr: {
									essential: true,
									values: 'foo'
								}
							}
						}
					});

					const cookie = setup.login();
					const { response } = await authRequest(auth, { cookie });
					expect(response.status).toBe(303);
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
						'invalid claims.id_token.acr.values type'
					);
				});

				it('single requested authentication context class reference is not met', async function () {
					const auth = new AuthorizationRequest({
						scope: 'openid',
						prompt: 'none',
						claims: {
							id_token: {
								acr: {
									essential: true,
									value: '1'
								}
							}
						}
					});

					const cookie = await setup.login();
					const { response } = await authRequest(auth, { cookie });
					expect(response.status).toBe(303);
					auth.validatePresence(response, [
						'error',
						'error_description',
						'state'
					]);
					auth.validateState(response);
					auth.validateClientLocation(response);
					auth.validateError(response, 'login_required');
					auth.validateErrorDescription(
						response,
						'requested ACR could not be obtained'
					);
				});

				it('additional claims are requested', async function () {
					const auth = new AuthorizationRequest({
						scope: 'openid',
						prompt: 'none',
						claims: {
							id_token: { family_name: null }
						}
					});

					const cookie = await setup.login();
					const { response } = await authRequest(auth, { cookie });
					expect(response.status).toBe(303);
					auth.validatePresence(response, [
						'error',
						'error_description',
						'state'
					]);
					auth.validateState(response);
					auth.validateClientLocation(response);
					auth.validateError(response, 'consent_required');
					auth.validateErrorDescription(
						response,
						'requested claims not granted'
					);
				});

				it('id_token_hint belongs to a user that is not currently logged in [1/3]', async function () {
					const client = await provider.Client.find('client');
					const { IdToken } = provider;
					const idToken = new IdToken(
						{
							sub: 'not-the-droid-you-are-looking-for'
						},
						{ client, ctx: undefined }
					);

					idToken.scope = 'openid';
					const hint = await idToken.issue({ use: 'idtoken' });

					const auth = new AuthorizationRequest({
						scope: 'openid',
						prompt: 'none',
						id_token_hint: hint
					});

					const cookie = await setup.login();
					const { response } = await authRequest(auth, { cookie });
					expect(response.status).toBe(303);
					auth.validatePresence(response, [
						'error',
						'error_description',
						'state'
					]);
					auth.validateState(response);
					auth.validateClientLocation(response);
					auth.validateError(response, 'login_required');
					auth.validateErrorDescription(
						response,
						'id_token_hint and authenticated subject do not match'
					);
				});

				it('id_token_hint belongs to a user that is not currently logged in [2/3]', async function () {
					const client = await provider.Client.find('client-pairwise');
					const { IdToken } = provider;
					const idToken = new IdToken(
						{
							sub: 'not-the-droid-you-are-looking-for'
						},
						{ client, ctx: undefined }
					);

					idToken.scope = 'openid';
					const hint = await idToken.issue({ use: 'idtoken' });

					const auth = new AuthorizationRequest({
						client_id: 'client-pairwise',
						scope: 'openid',
						prompt: 'none',
						id_token_hint: hint
					});

					const cookie = await setup.login();
					const { response } = await authRequest(auth, { cookie });
					expect(response.status).toBe(303);
					auth.validatePresence(response, [
						'error',
						'error_description',
						'state'
					]);
					auth.validateState(response);
					auth.validateClientLocation(response);
					auth.validateError(response, 'login_required');
					auth.validateErrorDescription(
						response,
						'id_token_hint and authenticated subject do not match'
					);
				});

				it('id_token_hint belongs to a user that is not currently logged in [3/3]', async function () {
					const client = await provider.Client.find('client-pairwise');
					const { IdToken } = provider;
					const idToken = new IdToken(
						{
							sub: 'not-the-droid-you-are-looking-for'
						},
						{ client, ctx: undefined }
					);

					idToken.scope = 'openid';
					const hint = await idToken.issue({ use: 'idtoken' });

					const auth = new AuthorizationRequest({
						client_id: 'client-pairwise',
						scope: 'openid',
						id_token_hint: hint
					});

					const { response } = await authRequest(auth);
					expect(response.status).toBe(303);
					auth.validateInteractionRedirect(response);
					auth.validateInteraction(
						response,
						'login',
						'id_token_hint',
						'no_session'
					);
				});

				it('id_token_hint belongs to a user that is currently logged in [1/2]', async function () {
					const cookie = await setup.login();
					const session = setup.getSession();
					const client = await provider.Client.find('client');
					const { IdToken } = provider;
					const idToken = new IdToken(
						{ sub: session.accountId },
						{ client, ctx: undefined }
					);

					idToken.scope = 'openid';
					const hint = await idToken.issue({ use: 'idtoken' });

					const auth = new AuthorizationRequest({
						scope: 'openid',
						prompt: 'none',
						id_token_hint: hint
					});

					const { response } = await authRequest(auth, { cookie });
					expect(response.status).toBe(303);
					auth.validatePresence(response, ['code', 'state']);
					auth.validateState(response);
					auth.validateClientLocation(response);
				});

				it('id_token_hint belongs to a user that is currently logged in [2/2]', async function () {
					const cookie = await setup.login();
					const session = setup.getSession();
					const client = await provider.Client.find('client-pairwise');
					const { IdToken } = provider;
					const idToken = new IdToken(
						{ sub: session.accountId },
						{ client, ctx: undefined }
					);

					idToken.scope = 'openid';
					const hint = await idToken.issue({ use: 'idtoken' });

					const auth = new AuthorizationRequest({
						client_id: 'client-pairwise',
						scope: 'openid',
						prompt: 'none',
						id_token_hint: hint
					});

					const { response } = await authRequest(auth, { cookie });
					expect(response.status).toBe(303);
					auth.validatePresence(response, ['code', 'state']);
					auth.validateState(response);
					auth.validateClientLocation(response);
				});
			});
		});

		describe('parameter validations', () => {
			it('should not be combined with response_type=none', async function () {
				const auth = new AuthorizationRequest({
					response_type: 'none',
					scope: 'openid',
					claims: {
						id_token: {
							email: null,
							middle_name: {}
						}
					}
				});

				const cookie = await setup.login();
				const { response } = await authRequest(auth, { cookie });
				expect(response.status).toBe(303);
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
					'claims parameter should not be combined with response_type none'
				);
			});

			it('should handle when invalid json is provided', async function () {
				const auth = new AuthorizationRequest({
					scope: 'openid',
					claims: 'something'
				});

				const cookie = await setup.login();
				const { response } = await authRequest(auth, { cookie });
				expect(response.status).toBe(303);
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
					"Property 'claims' should be one of: 'ObjectString', 'undefined'"
				);
			});

			it('should validate an object is passed', async function () {
				const auth = new AuthorizationRequest({
					scope: 'openid',
					claims: 'true'
				});

				const cookie = await setup.login();
				const { response } = await authRequest(auth, { cookie });
				expect(response.status).toBe(303);
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
					"Property 'claims' should be one of: 'ObjectString', 'undefined'"
				);
			});

			it('should check accepted properties being present', async function () {
				const auth = new AuthorizationRequest({
					scope: 'openid',
					claims: '{"not_recognized": "does not matter"}'
				});

				const cookie = await setup.login();
				const { response } = await authRequest(auth, { cookie });
				expect(response.status).toBe(303);
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
					'claims parameter should be object with userinfo or id_token properties'
				);
			});

			it('should check userinfo property being a simple object', async function () {
				const auth = new AuthorizationRequest({
					scope: 'openid',
					claims: '{"userinfo": "Not an Object"}'
				});

				const cookie = await setup.login();
				const { response } = await authRequest(auth, { cookie });
				expect(response.status).toBe(303);
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
					'claims.userinfo must be an object'
				);
			});

			it('should check id_token property being a simple object', async function () {
				const auth = new AuthorizationRequest({
					scope: 'openid',
					claims: '{"id_token": "Not an Object"}'
				});

				const cookie = await setup.login();
				const { response } = await authRequest(auth, { cookie });
				expect(response.status).toBe(303);
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
					'claims.id_token must be an object'
				);
			});

			describe('when userinfo is disabled', () => {
				beforeEach(function () {
					i(provider).features.userinfo.enabled = false;
				});

				afterEach(function () {
					i(provider).features.userinfo.enabled = true;
				});

				it('should not accept userinfo as a property', async function () {
					const auth = new AuthorizationRequest({
						scope: 'openid',
						claims: {
							userinfo: {
								email: null,
								middle_name: {}
							}
						}
					});

					const cookie = await setup.login();
					const { response } = await authRequest(auth, { cookie });

					expect(response.status).toBe(303);
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
						'claims.userinfo should not be used since userinfo endpoint is not supported'
					);
				});
			});
		});
	});
});
