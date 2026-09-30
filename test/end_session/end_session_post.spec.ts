import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	mock
} from 'bun:test';

import bootstrap, {
	agent,
	changeClient,
	findSessionSetCookie,
	redirectParameter,
	type Setup
} from '../test_helper.js';
import { ISSUER } from 'lib/configs/env.js';
import { elysia } from 'lib/index.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { present } from 'test/shape.js';

const POST_LOGOUT_URI = 'https://client.example.com/logout/cb';

async function getIdToken(cookie: string) {
	const auth = new AuthorizationRequest({
		client_id: 'client',
		scope: 'openid',
		redirect_uri: 'https://client.example.com/cb'
	});
	const { response } = await agent.auth.get({
		query: auth.params,
		headers: { cookie }
	});
	expect(response.status).toBe(303);
	const { data } = await auth.getToken(redirectParameter(response, 'code'));
	if (!data?.id_token) throw new Error('expected an id_token');
	return data.id_token;
}

function postLogout(
	body: string | Record<string, string>,
	{
		cookie,
		query = '',
		contentType = 'application/x-www-form-urlencoded',
		headers = {}
	}: {
		cookie?: string;
		query?: string;
		contentType?: string;
		headers?: Record<string, string>;
	} = {}
) {
	return elysia.handle(
		new Request(`${ISSUER}/logout${query}`, {
			method: 'POST',
			headers: {
				'content-type': contentType,
				accept: 'text/html',
				...(cookie ? { cookie } : {}),
				...headers
			},
			body: typeof body === 'string' ? body : new URLSearchParams(body)
		})
	);
}

function getLogout(params: Record<string, string>, cookie?: string) {
	return elysia.handle(
		new Request(`${ISSUER}/logout?${new URLSearchParams(params)}`, {
			headers: { accept: 'text/html', ...(cookie ? { cookie } : {}) }
		})
	);
}

/* The value of the named attribute on the first element matching `tag` that carries `name="…"`. */
function attribute(html: string, pattern: RegExp): string | undefined {
	return pattern.exec(html)?.[1];
}

function formAction(html: string) {
	return attribute(html, /<form[^>]*action="([^"]+)"/);
}

function hiddenInputs(html: string): Record<string, string> {
	const inputs: Record<string, string> = {};
	for (const [tag] of html.matchAll(/<input[^>]*>/g)) {
		const name = /name="([^"]+)"/.exec(tag)?.[1];
		const value = /value="([^"]*)"/.exec(tag)?.[1];
		if (name && value !== undefined) inputs[name] = value;
	}
	return inputs;
}

/* The error code of a refusal — the error page carries it as its title, a JSON body as `error`. */
async function errorOf(response: Response): Promise<string> {
	const text = await response.text();
	return present(
		/"error":"([^"]+)"/.exec(text)?.[1] ??
			/<title>([a-z_]+)<\/title>/.exec(text)?.[1],
		'an error code'
	);
}

/* The session cookie a response wrote, as a `name=value` pair a request can send back. */
function writtenCookie(response: Response): string | undefined {
	return findSessionSetCookie(response.headers.getSetCookie())?.split(';')[0];
}

/**
 * @proves A relying party can sign a user out with a form post, as RP-Initiated Logout requires,
 * and gets exactly what the same sign-out by link gives — including when the browser withholds the
 * sign-in cookie from a cross-site post, where the user still reaches their own sign-in and nothing
 * signs them out without confirmation.
 */
describe('a sign-out sent as a form post', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'end_session' });
	});

	afterEach(() => {
		mock.restore();
	});

	describe('when signed in', () => {
		let cookie: string;
		let idToken: string;
		let restoreClient: () => Promise<void>;

		beforeEach(async () => {
			restoreClient = await changeClient('client', {
				post_logout_redirect_uris: [POST_LOGOUT_URI]
			});
			cookie = await setup.login();
			idToken = await getIdToken(cookie);
		});

		afterEach(async () => {
			await restoreClient();
		});

		it('returns the user to the relying party with its state after they confirm', async () => {
			const page = await postLogout(
				{
					id_token_hint: idToken,
					post_logout_redirect_uri: POST_LOGOUT_URI,
					state: 'af0ifjsldkj'
				},
				{ cookie }
			);
			expect(page.status).toBe(200);
			const html = await page.text();
			const secret = hiddenInputs(html).xsrf;
			expect(secret).toBeTruthy();

			const confirmed = await elysia.handle(
				new Request(new URL(formAction(html) ?? '', ISSUER), {
					method: 'POST',
					headers: {
						'content-type': 'application/x-www-form-urlencoded',
						cookie: [cookie, writtenCookie(page)].filter(Boolean).join('; ')
					},
					body: new URLSearchParams({ xsrf: secret, logout: 'true' })
				})
			);
			expect(confirmed.status).toBe(303);
			expect(confirmed.headers.get('location')).toBe(
				`${POST_LOGOUT_URI}?state=af0ifjsldkj`
			);
		});

		for (const [name, params] of [
			[
				'an id_token_hint that cannot be decoded',
				() => ({ id_token_hint: 'not-a-jwt' })
			],
			[
				'an id_token_hint whose signature does not verify',
				() => ({ id_token_hint: `${idToken.slice(0, -4)}AAAA` })
			],
			[
				'a client_id that disagrees with the id_token_hint',
				() => ({ id_token_hint: idToken, client_id: 'client-hmac' })
			],
			[
				'an unregistered post_logout_redirect_uri',
				() => ({
					client_id: 'client',
					post_logout_redirect_uri: 'https://client.example.com/not-registered'
				})
			]
		] as const) {
			it(`is refused with the error the link gives, for ${name}`, async () => {
				const input: Record<string, string> = params();
				const byLink = await getLogout(input, cookie);
				const byPost = await postLogout(input, { cookie });

				expect(byPost.status).toBe(400);
				expect(byLink.status).toBe(400);
				expect(await errorOf(byPost)).toBe(await errorOf(byLink));
			});
		}

		it('is refused when a parameter is sent twice', async () => {
			const res = await postLogout('state=first&state=second', { cookie });
			expect(res.status).toBe(400);
			expect(await errorOf(res)).toBe('invalid_request');
		});

		it('is refused when the body is JSON', async () => {
			const res = await postLogout('{"state":"a"}', {
				cookie,
				contentType: 'application/json'
			});
			expect(res.status).toBe(400);
			expect(await errorOf(res)).toBe('invalid_request');
		});

		it('is refused when the body is plain text', async () => {
			const res = await postLogout('state=a', {
				cookie,
				contentType: 'text/plain'
			});
			expect(res.status).toBe(400);
			expect(await errorOf(res)).toBe('invalid_request');
		});

		it('reads its parameters from the body, never the query string', async () => {
			const page = await postLogout(
				{
					state: 'from-body',
					client_id: 'client',
					post_logout_redirect_uri: POST_LOGOUT_URI
				},
				{ cookie, query: '?state=from-query' }
			);
			expect(page.status).toBe(200);

			expect(setup.getSession().state?.state).toBe('from-body');
		});
	});

	describe('when the browser withholds the sign-in cookie', () => {
		let cookie: string;

		beforeEach(async () => {
			cookie = await setup.login();
		});

		it('is answered with a resubmission that writes no session cookie', async () => {
			const res = await postLogout(
				{ client_id: 'client', state: 'xyz' },
				{ headers: { 'sec-fetch-site': 'cross-site' } }
			);

			expect(res.status).toBe(200);
			const html = await res.text();
			expect(formAction(html)).toBe(`${ISSUER}/logout`);
			expect(hiddenInputs(html)).toEqual({
				client_id: 'client',
				state: 'xyz',
				_resubmitted: '1'
			});
			expect(findSessionSetCookie(res.headers.getSetCookie())).toBeUndefined();

			const session = setup.getSession();
			expect(session.accountId).toBeTruthy();
			expect(session.state).toBeUndefined();
		});

		it('is answered with a bare resubmission for an empty body', async () => {
			const res = await postLogout('');

			expect(res.status).toBe(200);
			expect(hiddenInputs(await res.text())).toEqual({ _resubmitted: '1' });
		});

		it('reaches the confirmation for the sign-in once resubmitted with the cookie', async () => {
			const res = await postLogout(
				{ client_id: 'client', state: 'xyz', _resubmitted: '1' },
				{ cookie }
			);

			expect(res.status).toBe(200);
			expect(hiddenInputs(await res.text()).xsrf).toBeTruthy();
			expect(setup.getSession().state?.state).toBe('xyz');
		});

		it('shows the signed-out page, not another resubmission, when the resubmission has no cookie either', async () => {
			const res = await postLogout({ state: 'xyz', _resubmitted: '1' });

			expect(res.status).toBe(200);
			const html = await res.text();
			expect(html).toContain('You have been signed out successfully');
			expect(hiddenInputs(html)).not.toHaveProperty('_resubmitted');
		});
	});
});
