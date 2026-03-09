import {
	beforeAll,
	describe,
	it,
	mock,
	expect,
	setSystemTime,
	beforeEach,
	afterEach,
	spyOn
} from 'bun:test';
import { parse as parseUrl } from 'node:url';

import bootstrap, { agent } from '../test_helper.js';
import * as JWT from '../../lib/helpers/jwt.js';
import { ISSUER } from 'lib/configs/env.js';
import { provider } from 'lib/provider.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { TestAdapter } from 'test/models.js';
import { Client } from 'lib/models/client.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';

async function getIdToken(options = {}, cookie = '') {
	const auth = new AuthorizationRequest({
		client_id: 'client',
		scope: 'openid',
		redirect_uri: 'https://client.example.com/cb',
		...options
	});

	const { response } = await agent.auth.get({
		query: auth.params,
		headers: {
			cookie
		}
	});

	expect(response.status).toBe(303);
	auth.validatePresence(response, ['code', 'state']);
	auth.validateState(response);
	auth.validateClientLocation(response);

	const {
		query: { code }
	} = parseUrl(response.headers.get('location'), true);

	const { data } = await auth.getToken(code);
	return data.id_token;
}

describe('logout endpoint', () => {
	let setup;
	beforeAll(async () => {
		setup = await bootstrap(import.meta.url)();
	});
	afterEach(function () {
		mock.restore();
		setSystemTime();
	});

	it('when logged out get end_session', async function () {
		const res = await agent.logout.get();
		expect(res.status).toBe(200);
		expect(res.data).toContain('You have been signed out successfully');
	});

	describe('when logged in', () => {
		let cookie;
		let idToken;
		beforeEach(async function () {
			cookie = await setup.login();
			idToken = await getIdToken({}, cookie);
		});

		describe('client with postLogoutRedirectUris', () => {
			beforeEach(async function () {
				(await Client.find('client')).postLogoutRedirectUris = [
					'https://client.example.com/logout/cb'
				];
			});
			afterEach(async function () {
				(await Client.find('client')).postLogoutRedirectUris = [];
			});

			it('even when expired', async function () {
				const date = Date.now() + (3600 + 10) * 1000;
				setSystemTime(date);
				const query = {
					id_token_hint: idToken,
					post_logout_redirect_uri: 'https://client.example.com/logout/cb'
				};

				const { status } = await agent.logout.get({
					query,
					headers: { cookie }
				});
				expect(status).toBe(200);
				const {
					state: { postLogoutRedirectUri }
				} = setup.getSession();
				expect(postLogoutRedirectUri).toBe(
					'https://client.example.com/logout/cb'
				);
			});

			it('allows to redirect there (with id_token_hint)', async function () {
				const query = {
					id_token_hint: idToken,
					post_logout_redirect_uri: 'https://client.example.com/logout/cb'
				};

				const { status } = await agent.logout.get({
					query,
					headers: { cookie }
				});
				expect(status).toBe(200);
				const {
					state: { postLogoutRedirectUri }
				} = setup.getSession();
				expect(postLogoutRedirectUri).toBe(
					'https://client.example.com/logout/cb'
				);
			});

			it('allows to redirect there (with client_id)', async function () {
				const query = {
					client_id: 'client',
					post_logout_redirect_uri: 'https://client.example.com/logout/cb'
				};

				const { status } = await agent.logout.get({
					query,
					headers: { cookie }
				});
				expect(status).toBe(200);
				const {
					state: { postLogoutRedirectUri }
				} = setup.getSession();
				expect(postLogoutRedirectUri).toBe(
					'https://client.example.com/logout/cb'
				);
			});

			it('allows to redirect there (with id_token_hint and client_id)', async function () {
				const query = {
					client_id: 'client',
					id_token_hint: idToken,
					post_logout_redirect_uri: 'https://client.example.com/logout/cb'
				};

				const { status } = await agent.logout.get({
					query,
					headers: { cookie }
				});
				expect(status).toBe(200);
				const {
					state: { postLogoutRedirectUri }
				} = setup.getSession();
				expect(postLogoutRedirectUri).toBe(
					'https://client.example.com/logout/cb'
				);
			});

			it('requires client_id to match the id_token_hint', async function () {
				const query = {
					client_id: 'client2',
					id_token_hint: idToken,
					post_logout_redirect_uri: 'https://client.example.com/logout/cb'
				};

				const spy = mock();
				provider.once('end_session.error', spy);
				const { status } = await agent.logout.get({
					query,
					headers: {
						cookie,
						headers: {
							accept: 'text/html'
						}
					}
				});

				expect(status).toBe(400);
				expect(spy).toHaveBeenCalled();
				expect(spy).toHaveBeenCalledWith(
					expect.objectContaining({
						error: 'invalid_request',
						error_description:
							'client_id does not match the provided id_token_hint'
					})
				);
			});

			it('requires client_id to be valid', async function () {
				const query = {
					client_id: 'client2',
					post_logout_redirect_uri: 'https://client.example.com/logout/cb'
				};

				const spy = mock();
				provider.once('end_session.error', spy);

				const { status } = await agent.logout.get({
					query,
					headers: {
						cookie,
						headers: {
							accept: 'text/html'
						}
					}
				});
				expect(status).toBe(400);
				expect(spy).toHaveBeenCalled();
				expect(spy).toHaveBeenCalledWith(
					expect.objectContaining({
						error: 'invalid_client',
						error_description: 'client is invalid'
					})
				);
			});

			describe('expired client secrets', () => {
				afterEach(async function () {
					const client = await Client.find('client-hmac');
					client.clientSecretExpiresAt = 0;
				});

				it('rejects HMAC hints if the secret is expired', async function () {
					const client = await Client.find('client-hmac');

					const idToken = await getIdToken(
						{
							client_id: 'client-hmac'
						},
						cookie
					);
					client.clientSecretExpiresAt = 1;

					const query = {
						id_token_hint: idToken,
						post_logout_redirect_uri: 'https://client.example.com/logout/cb'
					};

					const spy = mock();
					provider.once('end_session.error', spy);

					const { status } = await agent.logout.get({
						query,
						headers: {
							cookie,
							headers: {
								accept: 'text/html'
							}
						}
					});
					expect(status).toBe(400);
					expect(spy).toHaveBeenCalled();
					expect(spy).toHaveBeenCalledWith(
						expect.objectContaining({
							error: 'invalid_client',
							error_description:
								'client secret is expired - cannot validate ID Token Hint'
						})
					);
				});
			});

			it('populates ctx.oidc.entities', async function () {
				const spy = spyOn(OIDCContext.prototype, 'entity');

				const query = {
					id_token_hint: idToken,
					post_logout_redirect_uri: 'https://client.example.com/logout/cb'
				};

				await agent.logout.get({
					query,
					headers: {
						cookie
					}
				});
				const entities = spy.mock.calls.map((call) => call[0]);
				expect(['Client', 'IdTokenHint', 'Session']).toEqual(
					expect.arrayContaining(entities)
				);
			});

			it('also forwards the state if provided', async function () {
				const query = {
					id_token_hint: idToken,
					post_logout_redirect_uri: 'https://client.example.com/logout/cb',
					state: 'foobar'
				};

				const { status } = await agent.logout.get({
					query,
					headers: {
						cookie
					}
				});
				expect(status).toBe(200);
				const {
					state: { postLogoutRedirectUri, state }
				} = setup.getSession();
				expect(postLogoutRedirectUri).toBe(
					'https://client.example.com/logout/cb'
				);
				expect(state).toBe('foobar');
			});

			it('can omit the post_logout_redirect_uri and uses the default one', async function () {
				const query = { id_token_hint: idToken };

				const { status } = await agent.logout.get({
					query,
					headers: {
						cookie
					}
				});
				expect(status).toBe(200);
				const {
					state: { postLogoutRedirectUri }
				} = setup.getSession();
				expect(postLogoutRedirectUri).toBeUndefined();
			});

			it('ignores unverified post_logout_redirect_uri', async function () {
				const query = {
					post_logout_redirect_uri: 'https://client.example.com/logout/cb'
				};

				const { status } = await agent.logout.get({
					query,
					headers: {
						cookie
					}
				});
				expect(status).toBe(200);
				const {
					state: { postLogoutRedirectUri }
				} = setup.getSession();
				expect(postLogoutRedirectUri).toBeUndefined();
			});
		});

		it('validates post_logout_redirect_uri allowed on client', async function () {
			const spy = mock();
			provider.once('end_session.error', spy);
			const query = {
				id_token_hint: idToken,
				post_logout_redirect_uri: 'https://client.example.com/callback/logout'
			};

			const { status } = await agent.logout.get({
				query,
				headers: {
					cookie,
					headers: {
						accept: 'text/html'
					}
				}
			});
			expect(status).toBe(400);
			expect(spy).toHaveBeenCalled();
			expect(spy).toHaveBeenCalledWith(
				expect.objectContaining({
					error: 'invalid_request',
					error_description: 'post_logout_redirect_uri not registered'
				})
			);
		});

		it('rejects invalid JWTs', async function () {
			const spy = mock();
			provider.once('end_session.error', spy);
			const query = {
				id_token_hint: 'not.a.jwt'
			};

			const { status } = await agent.logout.get({
				query,
				headers: {
					cookie,
					headers: {
						accept: 'text/html'
					}
				}
			});
			expect(status).toBe(400);
			expect(spy).toHaveBeenCalled();
			expect(spy).toHaveBeenCalledWith(
				expect.objectContaining({
					error: 'invalid_request',
					error_description: 'could not decode id_token_hint'
				})
			);
		});

		it('rejects JWTs with unrecognized client', async function () {
			const spy = mock();
			provider.once('end_session.error', spy);
			const query = {
				id_token_hint: await JWT.sign(
					{
						aud: 'nonexistant',
						iss: ISSUER
					},
					Buffer.from('secret'),
					'HS256'
				)
			};

			const { status } = await agent.logout.get({
				query,
				headers: {
					cookie,
					headers: {
						accept: 'text/html'
					}
				}
			});
			expect(status).toBe(400);
			expect(spy).toHaveBeenCalled();
			expect(spy).toHaveBeenCalledWith(
				expect.objectContaining({
					error: 'invalid_client',
					error_description: 'unrecognized id_token_hint audience'
				})
			);
		});

		it('rejects JWTs with bad signatures', async function () {
			const spy = mock();
			provider.once('end_session.error', spy);
			const query = {
				id_token_hint: await JWT.sign(
					{
						aud: 'client',
						iss: ISSUER
					},
					Buffer.from('not THE secret'),
					'HS256'
				)
			};

			const { status } = await agent.logout.get({
				query,
				headers: {
					cookie,
					headers: {
						accept: 'text/html'
					}
				}
			});
			expect(status).toBe(400);
			expect(spy).toHaveBeenCalled();
			expect(spy).toHaveBeenCalledWith(
				expect.objectContaining({
					error: 'invalid_request',
					error_description: 'could not validate id_token_hint'
				})
			);
		});

		describe('POST end_session_confirm', () => {
			it('checks session.state is set', async function () {
				const { error } = await agent.logout.confirm.post(
					{},
					{
						headers: {
							cookie,
							accept: 'text/html'
						}
					}
				);
				expect(error.status).toBe(422);
				expect(error.value).toContain('Property &#x27;xsrf&#x27; is missing');
			});

			it('checks session.state.secret (xsrf is right)', async function () {
				const spy = mock();
				provider.once('end_session_confirm.error', spy);
				setup.getSession().state = { secret: '123' };

				const { status } = await agent.logout.confirm.post(
					{ xsrf: 'wrong' },
					{
						headers: {
							cookie,
							accept: 'text/html'
						}
					}
				);
				expect(status).toBe(400);
				expect(spy).toHaveBeenCalled();
				expect(spy).toHaveBeenCalledWith(
					expect.objectContaining({
						error: 'invalid_request',
						error_description: 'xsrf token invalid'
					})
				);
			});

			it('populates ctx.oidc.entities', async function () {
				const spy = spyOn(OIDCContext.prototype, 'entity');

				setup.getSession().state = {
					secret: '123',
					postLogoutRedirectUri: 'https://rp.example.com/',
					clientId: 'client'
				};

				await agent.logout.confirm.post(
					{ xsrf: '123', logout: 'true' },
					{
						headers: {
							cookie,
							accept: 'text/html'
						}
					}
				);

				const entities = spy.mock.calls.map((call) => call[0]);
				expect(['Client', 'Session']).toEqual(expect.arrayContaining(entities));
			});

			it('destroys complete session if user wants to', async function () {
				const sessionId = setup.getSessionId();
				const sessionAdapter = TestAdapter.for('Session');
				spyOn(sessionAdapter, 'destroy');
				spyOn(sessionAdapter, 'upsert');
				const authorizationCodeAdapter = TestAdapter.for('AuthorizationCode');
				spyOn(authorizationCodeAdapter, 'revokeByGrantId');
				const session = setup.getSession();

				session.state = {
					secret: '123',
					postLogoutRedirectUri: 'https://rp.example.com/',
					clientId: 'client'
				};
				session.authorizations.client.persistsLogout = true;

				const [firstGrant, secondGrant] = Object.keys(
					session.authorizations
				).map((x) => session.authorizations[x].grantId);

				const res = await agent.logout.confirm.post(
					{ xsrf: '123', logout: 'true' },
					{ headers: { cookie } }
				);
				expect(res.status).toBe(303);
				expect(sessionAdapter.destroy).toHaveBeenCalled();
				expect(sessionAdapter.upsert).not.toHaveBeenCalled();
				expect(sessionAdapter.destroy).toHaveBeenCalledWith(sessionId);
				expect(
					parseUrl(res.headers.get('location'), true).query
				).not.toHaveProperty('client_id');
				expect(authorizationCodeAdapter.revokeByGrantId).toHaveBeenCalledTimes(
					1
				);
				expect(
					authorizationCodeAdapter.revokeByGrantId
				).not.toHaveBeenCalledWith(firstGrant);
				expect(authorizationCodeAdapter.revokeByGrantId).toHaveBeenCalledWith(
					secondGrant
				);
			});

			it("only clears one clients session if user doesn't want to log out (using post_logout_redirect_uri)", async function () {
				const adapter = TestAdapter.for('Session');
				spyOn(adapter, 'destroy');
				const authorizationCodeAdapter = TestAdapter.for('AuthorizationCode');
				spyOn(authorizationCodeAdapter, 'revokeByGrantId');
				let session = setup.getSession();
				const oldId = setup.getSessionId();
				session.state = {
					secret: '123',
					postLogoutRedirectUri: 'https://rp.example.com/logout/cb',
					clientId: 'client'
				};
				session.authorizations.client.persistsLogout = true;

				expect(session.authorizations.client).toBeTruthy();

				const res = await agent.logout.confirm.post(
					{ xsrf: '123' },
					{
						headers: {
							cookie,
							accept: 'text/html'
						}
					}
				);
				expect(res.status).toBe(303);
				const sessionID = res.headers
					.get('set-cookie')
					.split(';')[0]
					.split('=')[1]
					.trim();
				session = setup.getSession(sessionID);
				expect(session.authorizations.client).toBeUndefined();
				expect(session.state).toBeUndefined();
				expect(sessionID).not.toBe(oldId);
				expect(adapter.destroy).toHaveBeenCalledWith(oldId);
				expect(authorizationCodeAdapter.revokeByGrantId).not.toHaveBeenCalled();
			});

			it("only clears one clients session if user doesn't want to log out (using end_session_success)", async function () {
				const adapter = TestAdapter.for('Session');
				spyOn(adapter, 'destroy');
				let session = setup.getSession();
				const oldId = setup.getSessionId();
				session.state = { secret: '123', clientId: 'client' };

				expect(session.authorizations.client).toBeTruthy();

				const res = await agent.logout.confirm.post(
					{ xsrf: '123' },
					{
						headers: {
							cookie,
							accept: 'text/html'
						}
					}
				);
				expect(res.status).toBe(200);
				const sessionID = res.headers
					.get('set-cookie')
					.split(';')[0]
					.split('=')[1]
					.trim();
				session = setup.getSession(sessionID);
				expect(session.authorizations.client).toBeUndefined();
				expect(session.state).toBeUndefined();
				expect(sessionID).not.toBe(oldId);
				expect(adapter.destroy).toHaveBeenCalledWith(oldId);
			});

			it('forwards the state too', async function () {
				setup.getSession().state = {
					secret: '123',
					postLogoutRedirectUri: 'https://rp.example.com/',
					clientId: 'client',
					state: 'foobar'
				};

				const res = await agent.logout.confirm.post(
					{ xsrf: '123', logout: 'true' },
					{
						headers: {
							cookie,
							accept: 'text/html'
						}
					}
				);
				expect(res.status).toBe(303);
				expect(res.headers.get('location')).toBe(
					'https://rp.example.com/?state=foobar'
				);
			});
		});
	});
});
