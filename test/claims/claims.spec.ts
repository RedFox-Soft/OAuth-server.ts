import {
	describe,
	it,
	beforeAll,
	expect,
	beforeEach,
	afterEach
} from 'bun:test';

import { decode as decodeJWT } from '../../lib/helpers/jwt.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { present } from 'test/shape.js';
import bootstrap, {
	agent,
	setSeedClaims,
	type Setup,
	changeClient,
	formAgent,
	getHeader,
	redirectParameter
} from '../test_helper.js';
import { isPlainObject } from 'lib/helpers/_/object.js';
import { fullProfileClaims } from '../models.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { Client } from 'lib/models/client.js';
import { IdToken } from 'lib/models/id_token.js';
import { Interaction } from 'lib/models/interaction.js';

const route = '/auth';
const expire = new Date();

expire.setDate(expire.getDate() + 1);
/**
 * @proves A relying party receives the individual claims it requested, and none whose value differs
 * from the one it asked for; it is refused when it names a different subject or an unmet
 * authentication context, and a malformed claims parameter is refused.
 */
['get', 'post'].forEach((verb) => {
	function authRequest(
		auth: AuthorizationRequest,
		{ cookie }: { cookie?: string } = {}
	) {
		if (verb === 'get') {
			return agent.auth.get({
				query: auth.params,
				headers: { cookie }
			});
		}

		return formAgent.auth.post(auth.params, {
			headers: { cookie }
		});
	}

	describe(`claimsParameter via ${verb} ${route}`, () => {
		let setup: Setup;
		async function getToken(
			auth: AuthorizationRequest,
			{ cookie: cookieHeader }: { cookie?: string } = {}
		) {
			const cookie = cookieHeader || (await setup.login());
			const authRes = await authRequest(auth, { cookie });
			const code = redirectParameter(authRes.response, 'code');

			const token = await auth.getToken(code);
			expect(token.response.status).toBe(200);
			if (!token.data?.id_token) throw new Error('expected an ID Token');
			return { ...token.data, id_token: token.data.id_token };
		}

		beforeAll(async function () {
			setup = await bootstrap(import.meta.url);
			setSeedClaims(fullProfileClaims);
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
			let restore: () => Promise<void>;

			beforeEach(async function () {
				restore = await changeClient('client', {
					default_acr_values: ['1', '2']
				});
			});

			afterEach(async function () {
				await restore();
			});

			it('carries the authentication context in the ID token when the client requests one by default', async function () {
				const cookie = await setup.login();
				setup.getSession().acr = '1';

				const auth = new AuthorizationRequest({ scope: 'openid' });
				const { id_token } = await getToken(auth, { cookie });

				const { payload } = decodeJWT(id_token);
				expect(payload.acr).toBe('1');
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

		/*
		 * OIDC Core §5.5.1: "When the Claim value does not match the requested value, the Claim is not
		 * included in the response", by an equality comparison, and `values` is processed the same way.
		 */
		describe('a claim requested with a particular value', () => {
			async function idTokenFor(request: Record<string, unknown>) {
				const auth = new AuthorizationRequest({
					scope: 'openid',
					claims: { id_token: request }
				});
				const cookie = await setup.login({
					claims: {
						id_token: Object.fromEntries(
							Object.keys(request).map((name) => [name, null])
						)
					}
				});
				const { id_token } = await getToken(auth, { cookie });
				return decodeJWT(id_token).payload;
			}

			it('is omitted from the ID token when the end user has a different value', async function () {
				const payload = await idTokenFor({
					email: { value: 'someone.else@example.com' },
					locale: null
				});
				expect(payload).not.toContainKey('email');
				expect(payload.locale).toBe('en-US');
			});

			it('is returned in the ID token when the end user has that value', async function () {
				const payload = await idTokenFor({
					email: { value: 'johndoe@example.com' }
				});
				expect(payload.email).toBe('johndoe@example.com');
			});

			it('is omitted from the ID token when the end user has none of the requested values', async function () {
				const payload = await idTokenFor({
					locale: { values: ['de-DE', 'fr-FR'] }
				});
				expect(payload).not.toContainKey('locale');
			});

			it('is returned in the ID token when the end user has one of the requested values', async function () {
				const payload = await idTokenFor({
					locale: { values: ['de-DE', 'en-US'] }
				});
				expect(payload.locale).toBe('en-US');
			});

			it('compares a structured claim by its content', async function () {
				const payload = await idTokenFor({
					address: { value: structuredClone(fullProfileClaims.address) }
				});
				expect(payload.address).toEqual(fullProfileClaims.address);
			});

			it('compares by type as well as by text', async function () {
				const payload = await idTokenFor({
					email_verified: { value: 'false' }
				});
				expect(payload).not.toContainKey('email_verified');
			});

			it('is omitted from the userinfo response when the end user has a different value', async function () {
				const auth = new AuthorizationRequest({
					scope: 'openid',
					claims: {
						userinfo: {
							email: { value: 'someone.else@example.com' },
							locale: null
						}
					}
				});
				const cookie = await setup.login({
					claims: { userinfo: { email: null, locale: null } }
				});
				const { access_token } = await getToken(auth, { cookie });
				const { data, response } = await agent.userinfo.get({
					headers: { authorization: `Bearer ${access_token}` }
				});

				expect(response.status).toBe(200);
				expect(data).not.toContainKey('email');
				expect(data).toContainKey('locale');
			});

			/*
			 * §5.5.1.1 overrides the general rule for acr: a voluntary request whose value cannot be
			 * met SHOULD be answered with the session's current context, not by leaving acr out.
			 */
			it('still carries the authentication context the session has when a voluntary acr request names another', async function () {
				const cookie = await setup.login();
				setup.getSession().acr = '1';

				const auth = new AuthorizationRequest({
					scope: 'openid',
					claims: { id_token: { acr: { values: ['2'] } } }
				});
				const { id_token } = await getToken(auth, { cookie });

				expect(decodeJWT(id_token).payload.acr).toBe('1');
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
									value: `${present(session.accountId, 'a signed-in account')}-pairwise`
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

				it('issues a code when the signed-in end user is among the requested subject values', async function () {
					const cookie = await setup.login();
					const session = setup.getSession();
					const auth = new AuthorizationRequest({
						client_id: 'client-pairwise',
						scope: 'openid',
						prompt: 'none',
						claims: {
							id_token: {
								sub: {
									values: [
										'someone-else',
										`${present(session.accountId, 'a signed-in account')}-pairwise`
									]
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

				/*
				 * OIDC Core §5.5: a member value that is not understood is ignored, so a subject request
				 * that is not an object asks for the subject with no constraint — the same as `null`.
				 */
				it('issues a code when the subject is requested with a value that is not an object', async function () {
					const cookie = await setup.login();
					const auth = new AuthorizationRequest({
						client_id: 'client',
						scope: 'openid',
						prompt: 'none',
						claims: { id_token: { sub: true } }
					});

					const { response } = await authRequest(auth, { cookie });
					expect(response.status).toBe(303);
					auth.validatePresence(response, ['code', 'state']);
					auth.validateState(response);
					auth.validateClientLocation(response);
				});

				if (verb === 'get') {
					async function setupFun(
						auth: AuthorizationRequest,
						result: Record<string, unknown>
					) {
						const cookies: string[] = [];

						const sess = new Interaction('resume', {
							uid: 'resume',
							cookieID: 'cookieID'
						});
						if (auth) {
							const cookie = `_interaction=cookieID; path=/ui/resume/resume; expires=${expire.toUTCString()}; httponly`;
							cookies.push(cookie);
							/*
							 * `claims` is stored as an object, the way a real interaction stores it. A case
							 * may hand it over as JSON text; storing that string here made
							 * `oidc.claims` a string on resume, so `oidc.claims.id_token` was
							 * undefined and every acr check returned early without comparing anything —
							 * the cases below passed while proving nothing.
							 */
							const params = { ...auth.params };
							if (typeof params.claims === 'string') {
								params.claims = JSON.parse(params.claims);
							}
							Object.assign(sess.payload, { params });
						}

						if (result) {
							Object.assign(sess.payload, { result });
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

						const { response } = await agent.ui({ uid: 'resume' }).resume.get({
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

						const { response } = await agent.ui({ uid: 'resume' }).resume.get({
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

				/*
				 * OIDC Core §5.5.1 processes `values` "equivalently to a value request", so a subject
				 * named only among `values` binds the response to that end user just as `value` does
				 * (§3.1.2.2: never an ID Token for a different user).
				 */
				it('refuses to answer for the signed-in end user when none of the requested subject values is theirs', async function () {
					const auth = new AuthorizationRequest({
						client_id: 'client',
						scope: 'openid',
						prompt: 'none',
						claims: {
							id_token: {
								sub: {
									values: ['iexpectthisid', 'orthisone']
								}
							}
						}
					});

					const cookie = await setup.login();
					const { response } = await authRequest(auth, { cookie });

					expect(response.status).toBe(303);
					auth.validateState(response);
					auth.validateClientLocation(response);
					auth.validateError(response, 'login_required');
					auth.validateErrorDescription(
						response,
						'requested subject could not be obtained'
					);
				});

				it('refuses a subject request whose values are not a list', async function () {
					const auth = new AuthorizationRequest({
						client_id: 'client',
						scope: 'openid',
						prompt: 'none',
						claims: {
							id_token: {
								sub: {
									values: 'iexpectthisid'
								}
							}
						}
					});

					const cookie = await setup.login();
					const { response } = await authRequest(auth, { cookie });

					expect(response.status).toBe(303);
					auth.validateState(response);
					auth.validateClientLocation(response);
					auth.validateError(response, 'invalid_request');
					auth.validateErrorDescription(
						response,
						'invalid claims.id_token.sub.values type'
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
					auth.validateError(response, 'unmet_authentication_requirements');
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
					auth.validateError(response, 'unmet_authentication_requirements');
					auth.validateErrorDescription(
						response,
						'requested ACR could not be obtained'
					);
				});

				it('claims beyond the standard set reach the response', async function () {
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
					const client = await Client.find('client');
					const idToken = new IdToken(client, {
						sub: 'not-the-droid-you-are-looking-for'
					});

					idToken.scope = 'openid';
					const hint = await idToken.issue('idtoken');

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
					const client = await Client.find('client-pairwise');
					const idToken = new IdToken(client, {
						sub: 'not-the-droid-you-are-looking-for'
					});

					idToken.scope = 'openid';
					const hint = await idToken.issue('idtoken');

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
					const client = await Client.find('client-pairwise');
					const idToken = new IdToken(client, {
						sub: 'not-the-droid-you-are-looking-for'
					});

					idToken.scope = 'openid';
					const hint = await idToken.issue('idtoken');

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
					const client = await Client.find('client');
					const idToken = new IdToken(client, { sub: session.accountId });

					idToken.scope = 'openid';
					const hint = await idToken.issue('idtoken');

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
					const client = await Client.find('client-pairwise');
					const idToken = new IdToken(client, { sub: session.accountId });

					idToken.scope = 'openid';
					const hint = await idToken.issue('idtoken');

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

			it('a malformed claims parameter is refused as invalid_request', async function () {
				const auth = new AuthorizationRequest({
					scope: 'openid',
					// @ts-expect-error the claims parameter is malformed on purpose: that is the case
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
					"Property 'claims' should be one of: 'ObjectString', 'object'"
				);
			});

			it('refuses a claims parameter that is not an object', async function () {
				const auth = new AuthorizationRequest({
					scope: 'openid',
					// @ts-expect-error the claims parameter is malformed on purpose: that is the case
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
					"Property 'claims' should be one of: 'ObjectString', 'object'"
				);
			});

			it('accepts a claims parameter naming only members it does not define', async function () {
				const auth = new AuthorizationRequest({
					scope: 'openid',
					// @ts-expect-error the case sends a claims member this server does not define
					claims: '{"not_recognized": "does not matter"}'
				});

				const cookie = await setup.login();
				const { response } = await authRequest(auth, { cookie });
				expect(response.status).toBe(303);
				auth.validatePresence(response, ['code', 'state']);
				auth.validateState(response);
				auth.validateClientLocation(response);
			});

			describe('when the claims parameter is not enabled', () => {
				beforeEach(function () {
					ApplicationConfig['claimsParameter.enabled'] = false;
				});

				afterEach(function () {
					ApplicationConfig['claimsParameter.enabled'] = true;
				});

				it('refuses a claims parameter carrying a member it does not define as unsupported', async function () {
					const auth = new AuthorizationRequest({
						scope: 'openid',
						// @ts-expect-error the case sends a claims member this server does not define
						claims: '{"urn_example_ext": {"anything": true}}'
					});

					const cookie = await setup.login();
					const { response } = await authRequest(auth, { cookie });

					// The operator's gate refuses it, not the schema: tolerating the member does not
					// make the parameter reachable on a deployment that has not turned it on.
					expect(response.status).toBe(303);
					auth.validatePresence(response, [
						'error',
						'error_description',
						'state'
					]);
					auth.validateErrorDescription(
						response,
						'Claims Parameter is not supported'
					);
				});
			});

			it('answers a claims parameter carrying a member it does not define as it answers one without it', async function () {
				const requested = {
					id_token: { email: null },
					userinfo: { website: null }
				};
				const cookie = await setup.login({ claims: requested });

				const withMember = new AuthorizationRequest({
					scope: 'openid',
					// @ts-expect-error the case sends a claims member this server does not define
					claims: { ...requested, urn_example_ext: { anything: true } }
				});
				const without = new AuthorizationRequest({
					scope: 'openid',
					claims: requested
				});

				const a = await authRequest(withMember, { cookie });
				const b = await authRequest(without, { cookie });

				expect(a.response.status).toBe(b.response.status);
				withMember.validatePresence(a.response, ['code', 'state']);
				without.validatePresence(b.response, ['code', 'state']);
				withMember.validateClientLocation(a.response);
				without.validateClientLocation(b.response);
			});

			it('honours the claims it does define when a member it does not sits beside them', async function () {
				const requested = { id_token: { email: null, website: null } };
				const cookie = await setup.login({ claims: requested });
				const auth = new AuthorizationRequest({
					scope: 'openid',
					// @ts-expect-error the case sends a claims member this server does not define
					claims: { ...requested, urn_example_ext: { anything: true } }
				});

				const { id_token } = await getToken(auth, { cookie });
				const { payload } = decodeJWT(id_token);

				expect(payload).toHaveProperty('email');
				expect(payload).toHaveProperty('website');
				expect(payload).not.toHaveProperty('urn_example_ext');
			});

			it('refuses a claims parameter that is an array, naming the shape at fault', async function () {
				const auth = new AuthorizationRequest({
					scope: 'openid',
					// @ts-expect-error the claims parameter is malformed on purpose: that is the case
					claims: '[]'
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
				expect(
					new URL(
						present(response.headers.get('location'), 'a redirect')
					).searchParams.get('error_description')
				).not.toContain('userinfo or id_token');
			});

			it('does not persist a claims member it does not define', async function () {
				// No seeded grant for `email`, so the request needs consent and an Interaction record
				// is written — which is one of the two places FR-006 says the member must not reach.
				const cookie = await setup.login();
				const auth = new AuthorizationRequest({
					scope: 'openid',
					claims: {
						id_token: { email: { essential: true } },
						// @ts-expect-error the case sends a claims member this server does not define
						urn_example_ext: { anything: true }
					}
				});

				const { response } = await authRequest(auth, { cookie });
				expect(response.status).toBe(303);

				const location = getHeader(response, 'location');
				const uid = new URL(location, 'http://e.ly').pathname.split('/')[2];
				expect(uid).toBeString();

				const interaction = await Interaction.find(uid);
				const { params } = interaction.payload;
				if (!isPlainObject(params))
					throw new Error('expected stored parameters');
				expect(params).toHaveProperty('claims');
				expect(params.claims).toHaveProperty('id_token');
				expect(params.claims).not.toHaveProperty('urn_example_ext');
			});

			it('refuses a claims parameter whose userinfo member is not a plain object', async function () {
				const auth = new AuthorizationRequest({
					scope: 'openid',
					// @ts-expect-error the claims parameter is malformed on purpose: that is the case
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

			it('refuses a claims parameter whose id_token member is not a plain object', async function () {
				const auth = new AuthorizationRequest({
					scope: 'openid',
					// @ts-expect-error the claims parameter is malformed on purpose: that is the case
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
					ApplicationConfig['userinfo.enabled'] = false;
				});

				afterEach(function () {
					ApplicationConfig['userinfo.enabled'] = true;
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
