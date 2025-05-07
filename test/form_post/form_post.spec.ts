import sinon from 'sinon';

import { describe, it, beforeAll, expect } from 'bun:test';
import bootstrap, { agent } from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import provider from 'lib/index.js';

const route = '/auth';

describe('/auth', () => {
	let setup = null;
	let cookie = null;
	beforeAll(async function () {
		setup = await bootstrap(import.meta.url)();
		cookie = await setup.login();
	});

	['get', 'post'].forEach((verb) => {
		async function authRequest(auth: AuthorizationRequest, skipCookie = false) {
			if (verb === 'get') {
				return agent.auth.get({
					query: auth.params,
					headers: {
						cookie: skipCookie ? undefined : cookie
					}
				});
			} else if (verb === 'post') {
				return agent.auth.post(
					new URLSearchParams(Object.entries(auth.params)).toString(),
					{
						headers: {
							cookie: skipCookie ? undefined : cookie
						}
					}
				);
			}
		}

		describe(`${verb} response_mode=form_post`, () => {
			describe('logged in', () => {
				it('responds by rendering a self-submitting form with the response', async function () {
					const auth = new AuthorizationRequest({
						response_mode: 'form_post',
						scope: 'openid'
					});

					const { data, response } = await authRequest(auth);
					expect(response.status).toBe(200);
					expect(response.headers.get('content-type')).toBe(
						'text/html; charset=utf-8'
					);
					expect(data).toContain('input type="hidden" name="code" value=');
					expect(data).toContain(
						`input type="hidden" name="state" value="${auth.params.state}"`
					);
					expect(data).toContain(
						`form action="${auth.params.redirect_uri}" method="post"`
					);
				});

				it('sanitizes the action attribute', async function () {
					const auth = new AuthorizationRequest({
						response_mode: 'form_post',
						scope: 'openid',
						redirect_uri:
							'https://client.example.com/cb"><script>alert(0)</script><x="'
					});
					const { data, response } = await authRequest(auth);
					expect(response.status).toBe(200);
					expect(response.headers.get('content-type')).toBe(
						'text/html; charset=utf-8'
					);
					expect(data).toContain(
						'https://client.example.com/cb&quot;&gt;&lt;script&gt;alert(0)&lt;/script&gt;&lt;x=&quot;'
					);
				});
			});

			it('responds by rendering a self-submitting form with the error', async function () {
				const auth = new AuthorizationRequest({
					prompt: 'none',
					response_mode: 'form_post',
					scope: 'openid'
				});

				const spy = sinon.spy();
				provider.once('authorization.error', spy);

				const { response, error } = await authRequest(auth, true);
				expect(response.status).toBe(400);
				expect(response.headers.get('content-type')).toBe(
					'text/html; charset=utf-8'
				);
				expect(error.value).toContain(
					'input type="hidden" name="error" value="login_required"'
				);
				expect(error.value).toContain(
					`input type="hidden" name="state" value="${auth.params.state}"`
				);
				expect(error.value).toContain(
					`form action="${auth.params.redirect_uri}" method="post"`
				);
			});
		});
	});
});
