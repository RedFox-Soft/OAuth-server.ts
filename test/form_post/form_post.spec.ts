import { describe, it, beforeAll, expect, mock, afterEach } from 'bun:test';
import bootstrap, { agent, formAgent, type Setup } from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { eventBus } from 'lib/index.js';

/**
 * @proves The form_post response mode delivers a response or an error through a self-submitting
 * form whose action cannot carry script.
 */
describe('/auth', () => {
	let setup: Setup;
	let cookie: string;
	beforeAll(async function () {
		setup = await bootstrap(import.meta.url);
		cookie = await setup.login();
	});

	afterEach(function () {
		mock.restore();
	});

	['get', 'post'].forEach((verb) => {
		async function authRequest(auth: AuthorizationRequest, skipCookie = false) {
			const headers = skipCookie ? {} : { cookie };
			if (verb === 'get') {
				return agent.auth.get({ query: auth.params, headers });
			}
			return formAgent.auth.post(auth.params, { headers });
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

				it('delivers the response in a browser that runs classic scripts but not modules', async function () {
					const auth = new AuthorizationRequest({
						response_mode: 'form_post',
						scope: 'openid'
					});

					const { data, response } = await authRequest(auth);
					if (typeof data !== 'string')
						throw new Error('expected an HTML page');
					expect(response.status).toBe(200);

					/*
					 * A user agent that runs scripts but not ES modules skips a module script outright,
					 * and <noscript> does not render for it either — so a module here leaves that class
					 * with no way forward at all.
					 */
					expect(data).not.toContain('type="module"');

					const script = data.indexOf(
						'<script>document.forms[0].submit();</script>'
					);
					expect(script).toBeGreaterThan(-1);
					// document.forms[0] must already exist when a classic script runs.
					expect(script).toBeGreaterThan(data.indexOf('</form>'));
				});

				it('carries exactly one auto-submit script', async function () {
					const auth = new AuthorizationRequest({
						response_mode: 'form_post',
						scope: 'openid'
					});

					const { data } = await authRequest(auth);
					if (typeof data !== 'string')
						throw new Error('expected an HTML page');

					// Two would post the response twice, and the client would redeem one code twice.
					expect(data.match(/document\.forms\[0\]\.submit\(\)/g)).toHaveLength(
						1
					);
				});

				it('offers a manual control when scripting is unavailable', async function () {
					const auth = new AuthorizationRequest({
						response_mode: 'form_post',
						scope: 'openid'
					});

					const { data } = await authRequest(auth);
					if (typeof data !== 'string')
						throw new Error('expected an HTML page');

					const opening = data.indexOf('<noscript>');
					expect(opening).toBeGreaterThan(-1);
					expect(data.slice(opening, data.indexOf('</noscript>'))).toContain(
						'type="submit"'
					);
				});

				it('sanitizes the action attribute', async function () {
					const auth = new AuthorizationRequest({
						response_mode: 'form_post',
						scope: 'openid',
						redirect_uri:
							'https://client.example.com/cb"><script>alert(0)</script><x="/'
					});
					const { error } = await authRequest(auth);
					if (!error) throw new Error('expected error response');
					expect(error.status).toBe(400);

					expect(error.value).toEqual({
						error: 'invalid_request',
						error_description: "Property 'redirect_uri' should be uri"
					});
				});
			});

			/*
			 * A refusal from the parameter schema, not from the pipeline: it reaches the shared error
			 * handler, which has to read response_mode from the request itself — for a POST, from a
			 * parsed form body.
			 */
			it('delivers a refused request by the response mode it asked for', async function () {
				const auth = new AuthorizationRequest({
					response_mode: 'form_post',
					scope: 'openid',
					// @ts-expect-error a response type this server does not support, which the schema refuses
					response_type: 'token'
				});

				const { response, error } = await authRequest(auth);
				if (!error) throw new Error('expected error response');
				expect(response.headers.get('content-type')).toBe(
					'text/html; charset=utf-8'
				);
				expect(error.value).toContain(
					`form action="${auth.params.redirect_uri}" method="post"`
				);
				expect(error.value).toContain('name="error"');
			});

			it('responds by rendering a self-submitting form with the error', async function () {
				const auth = new AuthorizationRequest({
					prompt: 'none',
					response_mode: 'form_post',
					scope: 'openid'
				});

				const spy = mock();
				eventBus.once('authorization.error', spy);

				const { response, error } = await authRequest(auth, true);
				if (!error) throw new Error('expected error response');
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
				expect(spy).toHaveBeenCalled();
			});
		});
	});
});
