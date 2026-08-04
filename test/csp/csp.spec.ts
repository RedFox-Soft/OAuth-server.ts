import { describe, it, beforeAll, expect } from 'bun:test';
import * as crypto from 'node:crypto';

import bootstrap, { agent } from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { send, UNSERVED_PATH } from '../feature_gate/helpers.ts';
import { ISSUER } from 'lib/configs/env.js';

import { getErrorHtmlResponse } from 'lib/html/error.tsx';
import { formPost } from 'lib/html/formPost.tsx';
import { logout } from 'lib/html/logout.tsx';
import { logoutSuccess } from 'lib/html/logoutSuccess.tsx';
import {
	deviceInputPage,
	deviceConfirmPage,
	deviceSuccessPage
} from 'lib/html/device.tsx';
import {
	loginServer,
	registrationServer,
	consentServer
} from 'lib/interactions/serverRender.tsx';
import {
	verifySuccessPage,
	verifyFailurePage,
	codeEntryPage,
	resendAcceptedPage,
	verifyRateLimitedPage
} from 'lib/interactions/verifyPages.tsx';
import { renderAdminShell } from 'lib/admin/ui/serverRender.tsx';

/*
 * Every page this server renders declares what it is allowed to run.
 *
 * The assertion that matters is not "a header is present" but "the header authorizes exactly the
 * scripts this page actually serves" — a policy that misses one is worse than none, because the page
 * silently loses a capability while still rendering.
 */

function directives(res: Response): Map<string, string> {
	const header = res.headers.get('content-security-policy');
	if (!header) {
		throw new Error(
			`no content security policy on a ${res.headers.get('content-type')} response`
		);
	}
	return new Map(
		header.split(';').map((directive) => {
			const trimmed = directive.trim();
			const separator = trimmed.indexOf(' ');
			return separator === -1
				? [trimmed, '']
				: [trimmed.slice(0, separator), trimmed.slice(separator + 1)];
		})
	);
}

function hash(text: string): string {
	return `'sha256-${crypto.hash('sha256', text, 'base64')}'`;
}

// <script>…</script> blocks that carry a body rather than a src.
function inlineScripts(html: string): string[] {
	const found: string[] = [];
	for (const [, attributes, body] of html.matchAll(
		/<script([^>]*)>([\s\S]*?)<\/script>/g
	)) {
		if (!/\ssrc=/.test(attributes) && body.trim()) {
			found.push(body);
		}
	}
	return found;
}

function inlineHandlers(html: string): string[] {
	return [...html.matchAll(/\son[a-z]+="([^"]*)"/g)].map(([, value]) => value);
}

/*
 * The core check, applied to every page below: whatever the browser would refuse to run, this page
 * must have authorized — and it must not have reached for the blanket permission to do it.
 */
async function expectPolicyCoversItsOwnScripts(res: Response) {
	const html = await res.clone().text();
	const csp = directives(res);
	const scriptSrc = csp.get('script-src') ?? '';

	expect(scriptSrc).toContain("'self'");
	expect(scriptSrc).not.toContain("'unsafe-inline'");

	for (const script of inlineScripts(html)) {
		expect(scriptSrc).toContain(hash(script));
	}

	const handlers = inlineHandlers(html);
	if (handlers.length) {
		// Inline handlers need 'unsafe-hashes' as well as the hash; without it the hash alone is inert.
		expect(scriptSrc).toContain("'unsafe-hashes'");
		for (const handler of handlers) {
			expect(scriptSrc).toContain(hash(handler));
		}
	}

	expect(csp.get('default-src')).toBe("'none'");
	expect(csp.get('base-uri')).toBe("'none'");
	expect(csp.get('object-src')).toBe("'none'");
	expect(csp.get('form-action')).toBeTruthy();
	expect(res.headers.get('content-type')).toContain('text/html');
}

describe('content security policy: every rendered page', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	const pages: Array<[string, () => Response | Promise<Response>]> = [
		['error', () => getErrorHtmlResponse(400, 'invalid_request', 'nope')],
		['sign-in', () => loginServer('uid-1')],
		[
			'sign-in with an error',
			() => loginServer('uid-1', { errorMessage: 'wrong password' })
		],
		['registration', () => registrationServer('uid-1')],
		[
			'consent',
			() =>
				consentServer({
					uid: 'uid-1',
					clientName: 'Client</script>',
					permissions: [],
					items: []
				} as never)
		],
		[
			'device code entry',
			() =>
				deviceInputPage({
					action: `${ISSUER}/device`,
					secret: 'xsrf',
					charset: 'digits'
				})
		],
		[
			'device confirmation',
			() =>
				deviceConfirmPage({
					action: `${ISSUER}/device`,
					secret: 'xsrf',
					userCode: 'ABC-DEF',
					client: { clientId: 'client' }
				})
		],
		['device success', () => deviceSuccessPage({ client: {} })],
		['logout confirmation', () => logout('xsrf')],
		['logout success', () => logoutSuccess()],
		['email verified', () => verifySuccessPage()],
		['verification failed', () => verifyFailurePage('expired')],
		['verification code entry', () => codeEntryPage('ref-1', 'wrong code')],
		['verification resent', () => resendAcceptedPage()],
		['verification rate limited', () => verifyRateLimitedPage('slow down')],
		[
			'auto-submit callback',
			() =>
				formPost({}, 'https://client.example.com/cb', {
					code: 'abc',
					state: 'xyz'
				})
		],
		[
			'admin console shell',
			() => renderAdminShell({ needsSetup: true, me: null })
		]
	];

	for (const [name, render] of pages) {
		it(`authorizes exactly what the ${name} page serves`, async () => {
			await expectPolicyCoversItsOwnScripts(await render());
		});
	}

	it('frame-busts every page except the auto-submit callback', async () => {
		for (const [name, render] of pages) {
			const csp = directives(await render());
			if (name === 'auto-submit callback') {
				/*
				 * Deliberate: silent authentication (prompt=none in a hidden iframe) with
				 * response_mode=form_post renders this page inside the client's frame. There is no
				 * interactive UI on it to hijack.
				 */
				expect(csp.has('frame-ancestors')).toBe(false);
			} else {
				expect(csp.get('frame-ancestors')).toBe("'none'");
			}
		}
	});

	it('lets the auto-submit callback post to the client, and no one else post off-origin', async () => {
		const callback = directives(
			formPost({}, 'https://client.example.com/cb', { code: 'abc' })
		);
		expect(callback.get('form-action')).toBe('https://client.example.com');

		const signIn = directives(await loginServer('uid-1'));
		expect(signIn.get('form-action')).toBe("'self'");
	});

	/*
	 * The trap in deriving form-action from the document: the device pages build an ISSUER-absolute
	 * action, so a naive "absolute means foreign" reading would name this server as a foreign origin
	 * and — worse — drop frame-ancestors from a page that has a real form on it.
	 */
	it('reads an absolute action at this origin as self, not as a foreign target', async () => {
		const device = directives(
			deviceInputPage({
				action: `${ISSUER}/device`,
				secret: 'x',
				charset: 'digits'
			})
		);
		expect(device.get('form-action')).toBe("'self'");
		expect(device.get('frame-ancestors')).toBe("'none'");
	});

	// The props script carries request-derived data, so its hash has to move with the data.
	it('hashes the props script per response rather than once', async () => {
		const first = directives(await loginServer('uid-1'));
		const second = directives(await loginServer('uid-2'));
		expect(first.get('script-src')).not.toBe(second.get('script-src'));
	});
});

describe('content security policy: over the HTTP layer', () => {
	let cookie: string | null = null;

	beforeAll(async () => {
		const setup = await bootstrap(import.meta.url);
		cookie = await setup.login();
	});

	it('reaches the auto-submit callback rendered by a real authorization request', async () => {
		const auth = new AuthorizationRequest({
			response_mode: 'form_post',
			scope: 'openid'
		});
		const { response } = await agent.auth.get({
			query: auth.params,
			headers: { cookie }
		});

		expect(response.status).toBe(200);
		await expectPolicyCoversItsOwnScripts(response);
	});

	it('reaches the sign-in page rendered by a real interaction redirect', async () => {
		const auth = new AuthorizationRequest({ scope: 'openid' });
		const { response } = await agent.auth.get({ query: auth.params });
		const [, , uid] = (response.headers.get('location') ?? '').split('/');

		const login = await agent.ui[uid].login.get({
			headers: { cookie: response.headers.get('set-cookie') }
		});
		await expectPolicyCoversItsOwnScripts(login.response);
	});

	it('reaches the device user-code page', async () => {
		const res = await send('/device', { method: 'GET' });
		await expectPolicyCoversItsOwnScripts(res);
	});

	it('reaches the error page an unserved path renders for a browser', async () => {
		const res = await send(UNSERVED_PATH, {
			method: 'GET',
			headers: { accept: 'text/html' }
		});
		expect(res.status).toBe(404);
		await expectPolicyCoversItsOwnScripts(res);
	});

	it('leaves protocol responses alone', async () => {
		const { response } =
			await agent['.well-known']['openid-configuration'].get();
		expect(response.headers.get('content-security-policy')).toBeNull();
	});
});

/*
 * The other half of the guard. The walk above proves the pages that exist are covered; this proves a
 * new one cannot skip the constructor — which is the only reason the walk stays true.
 */
describe('content security policy: no page escapes the constructor', () => {
	it('builds text/html responses in exactly one place', async () => {
		const allowed = new Set([
			// The constructor itself.
			'lib/html/csp.ts',
			// Reads the *request's* Accept header to choose a body; builds no response.
			'lib/shared/authorization_error_handler.ts'
		]);

		const offenders: string[] = [];
		for await (const path of new Bun.Glob('lib/**/*.{ts,tsx}').scan('.')) {
			const normalized = path.replaceAll('\\', '/');
			if (allowed.has(normalized)) {
				continue;
			}
			if ((await Bun.file(path).text()).includes('text/html')) {
				offenders.push(normalized);
			}
		}

		expect(offenders).toEqual([]);
	});
});
