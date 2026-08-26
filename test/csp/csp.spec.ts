import { describe, it, beforeAll, expect } from 'bun:test';
import * as crypto from 'node:crypto';

import bootstrap, { agent } from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { send, UNSERVED_PATH } from '../feature_gate/helpers.ts';
import { ISSUER } from 'lib/configs/env.js';

import { contentSecurityPolicyFor } from 'lib/html/csp.js';
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

// <script src="…"> — the only thing that earns 'self'.
function externalScriptSources(html: string): string[] {
	return [...html.matchAll(/<script([^>]*)>/g)]
		.map(([, attributes]) => /\ssrc="([^"]*)"/.exec(attributes)?.[1])
		.filter((src): src is string => src !== undefined);
}

function referencesSameOriginScript(html: string): boolean {
	const self = new URL(ISSUER).origin;
	return externalScriptSources(html).some((src) => {
		try {
			return new URL(src).origin === self;
		} catch {
			return true; // relative
		}
	});
}

// <style>…</style> blocks that carry a body.
function inlineStyleBlocks(html: string): string[] {
	const found: string[] = [];
	for (const [, , body] of html.matchAll(
		/<style([^>]*)>([\s\S]*?)<\/style>/g
	)) {
		if (body.trim()) {
			found.push(body);
		}
	}
	return found;
}

function linksStylesheet(html: string): boolean {
	return [...html.matchAll(/<link([^>]*)>/g)].some(([, attributes]) =>
		/\srel="stylesheet"/.test(attributes)
	);
}

/*
 * Eden types `data` as `string | Record<string, unknown> | void` (the route schema,
 * `RedirectOrHtmlResponse` in lib/shared/response_schemas.ts, allows a redirect body too), and it
 * runs the response text through its own JSON/number/boolean/date-sniffing coercion before handing
 * it back — safe for these pages only because HTML starts with `<`, which none of those sniffs
 * accept. Every page this suite reads through eden is HTML, so `data` must land as a string; a
 * thrown error here beats silently asserting against a coerced value or an empty one.
 */
function htmlBodyOf(data: unknown): string {
	if (typeof data !== 'string') {
		throw new Error(
			`expected an HTML string body from eden, got ${typeof data}`
		);
	}
	return data;
}

/*
 * The core check, applied to every page below: whatever the browser would refuse to run, this page
 * must have authorized — and it must not have reached for the blanket permission to do it.
 *
 * `body` is only needed when `res` came back through eden treaty: eden reads the response to
 * populate its own `data` before handing the `Response` back, so `res.clone().text()` on it reads
 * an already-drained stream and comes back empty. Callers going through eden pass `data` (the text
 * eden already parsed, via `htmlBodyOf`); everyone else — a page rendered directly, or a `Response`
 * from `elysia.handle()` via `send()` — leaves the stream untouched and is read here as before.
 */
async function expectPolicyCoversItsOwnResources(res: Response, body?: string) {
	const html = body ?? (await res.clone().text());
	const csp = directives(res);
	const scriptSrc = csp.get('script-src') ?? '';

	expect(scriptSrc).not.toContain("'unsafe-inline'");

	// 'self' is earned by an actual same-origin <script src>, never granted by default.
	expect(scriptSrc.includes("'self'")).toBe(referencesSameOriginScript(html));

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

	/*
	 * The other half of "derived": a document with nothing to run must say so, and must say only so.
	 */
	const authorizesNothing =
		!externalScriptSources(html).length &&
		!inlineScripts(html).length &&
		!handlers.length;
	if (authorizesNothing) {
		expect(scriptSrc).toBe("'none'");
	} else {
		expect(scriptSrc).not.toContain("'none'");
	}

	const styleSrcElem = csp.get('style-src-elem') ?? '';
	const canInjectLater = externalScriptSources(html).length > 0;

	/*
	 * Asserted as a biconditional in both directions on purpose. A page keeping 'unsafe-inline' it no
	 * longer needs and a page losing it while its bundle can still inject are both regressions, and
	 * only one of them is visible.
	 */
	expect(styleSrcElem.includes("'unsafe-inline'")).toBe(canInjectLater);

	if (!canInjectLater) {
		for (const block of inlineStyleBlocks(html)) {
			expect(styleSrcElem).toContain(hash(block));
		}
		if (!inlineStyleBlocks(html).length && !linksStylesheet(html)) {
			expect(styleSrcElem).toBe("'none'");
		}
	}

	expect(styleSrcElem.includes("'self'")).toBe(linksStylesheet(html));
	expect(csp.get('style-src-attr')).toBe(
		/\sstyle="/.test(html) ? "'unsafe-inline'" : "'none'"
	);

	// The pre-CSP3 fallback, retained unnarrowed on purpose: browsers without style-src-elem /
	// style-src-attr fall through to this, and narrowing it would cost them every style on the page
	// rather than hardening anything. Pinned because deleting it is invisible in a modern browser.
	expect(csp.get('style-src')).toBe("'self' 'unsafe-inline'");

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
					permissions: []
				})
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
			await expectPolicyCoversItsOwnResources(await render());
		});
	}

	/*
	 * The point of deriving 'self' rather than granting it. The error page is the highest-volume
	 * rendered page here — every malformed request from every misconfigured client reaches it — and the
	 * only one whose body carries request-derived text. It references no script, so it authorizes none.
	 */
	it('forbids all script on the error page', () => {
		const csp = directives(
			getErrorHtmlResponse(404, 'not_found', 'nothing here')
		);
		expect(csp.get('script-src')).toBe("'none'");
	});

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
	 * A page rendered inside an interaction posts to itself, and the response to that post is a
	 * redirect chain that ends at the client's redirect_uri. Chrome enforces `form-action` against
	 * every hop of a form submission's redirect chain, not just its initial target, so a policy of
	 * `'self'` alone blocks the hand-off — the browser reports the same-origin action as the
	 * violation, which reads as nonsense until you know the block happened downstream.
	 *
	 * Verified in Chromium: consent was recorded and a code was issued server-side, and the browser
	 * still refused to leave the page. The console client never hit it because its callback is on this
	 * server's own origin; a native client's loopback callback never is.
	 */
	it('lets a page inside an interaction hand off to the client that started it', async () => {
		const consent = directives(
			await loginServer('uid-1', {
				handOffTo: 'http://localhost:39548/callback'
			})
		);
		expect(consent.get('form-action')).toBe("'self' http://localhost:39548");
	});

	it('adds nothing when the pending client is on this origin', async () => {
		const sameOrigin = directives(
			await loginServer('uid-1', { handOffTo: `${ISSUER}/admin/callback` })
		);
		expect(sameOrigin.get('form-action')).toBe("'self'");
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

	/*
	 * A <style> block is the dangerous form: it restyles the whole document and can exfiltrate input
	 * values by attribute selector. A style="…" attribute only decorates the element it is on. The
	 * error page carries one block, from extractStyle, and it is hashable — so no blanket permission.
	 */
	it('hashes the error page stylesheet rather than allowing any inline style', async () => {
		const res = getErrorHtmlResponse(404, 'not_found', 'nothing here');
		const html = await res.clone().text();
		const csp = directives(res);

		// Without this the loop below passes vacuously if the page stops emitting a style block.
		expect(inlineStyleBlocks(html).length).toBeGreaterThan(0);

		expect(csp.get('style-src-elem')).not.toContain("'unsafe-inline'");
		for (const block of inlineStyleBlocks(html)) {
			expect(csp.get('style-src-elem')).toContain(hash(block));
		}
	});

	/*
	 * The exception that makes the rule safe. @ant-design/icons calls useInsertStyles on every icon
	 * render (es/components/Icon.js:27, IconBase.js:14) through its own cssUtils — a package
	 * independent of antd, unaffected by zeroRuntime, injecting a <style> that does not exist when the
	 * document is built and so cannot be hashed. All four hydrated pages import icons. Dropping
	 * 'unsafe-inline' here takes the styling off every icon on the sign-in page and reports nothing but
	 * a console violation.
	 */
	it("keeps 'unsafe-inline' on style-src-elem wherever a bundle can inject", async () => {
		for (const render of [
			() => loginServer('uid-1'),
			() => registrationServer('uid-1'),
			() => renderAdminShell({ needsSetup: true, me: null })
		]) {
			const csp = directives(await render());
			expect(csp.get('style-src-elem')).toContain("'unsafe-inline'");
		}
	});

	/*
	 * The hydrated pages arrive server-rendered but unstyled today, and stay that way until ~1 MB of
	 * JavaScript parses and cssinjs generates 246,494 B of CSS in the browser. Linking the compiled
	 * stylesheet is what removes that.
	 */
	it('links the compiled stylesheets on the pages a bundle hydrates', async () => {
		for (const render of [
			() => loginServer('uid-1'),
			() =>
				consentServer({
					uid: 'uid-1',
					clientName: 'Client',
					permissions: []
				}),
			() => registrationServer('uid-1'),
			() => renderAdminShell({ needsSetup: true, me: null })
		]) {
			const html = await (await render()).clone().text();
			expect(html).toContain('rel="stylesheet"');
			expect(html).toContain('/public/antd.css');
			expect(html).toContain('/public/reset.css');
		}
	});

	/*
	 * Measured: the terminal pages inline 4,360-10,500 B gzip and are read once, so a render-blocking
	 * 109,545 B stylesheet on a cold cache is worse for them — and it would make them depend on
	 * public/ being built, which an error page must not.
	 */
	it('leaves the terminal pages inlining their own styles', async () => {
		for (const render of [
			() => getErrorHtmlResponse(404, 'not_found', 'nope'),
			() => logout('xsrf'),
			() => logoutSuccess(),
			() => deviceSuccessPage({ client: {} })
		]) {
			const html = await (await render()).clone().text();
			expect(html).not.toContain('/public/antd.css');
			// getErrorHtmlResponse embeds cssinjs's extractStyle() output directly, which already
			// carries its own `data-rc-order` attributes on the tag; the other three wrap it in a bare
			// `<style>`. Either way, it is an inline stylesheet rather than a link to one.
			expect(html).toMatch(/<style[ >]/);
		}
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
		const { data, response } = await agent.auth.get({
			query: auth.params,
			headers: { cookie }
		});

		expect(response.status).toBe(200);
		await expectPolicyCoversItsOwnResources(response, htmlBodyOf(data));
	});

	it('reaches the sign-in page rendered by a real interaction redirect', async () => {
		const auth = new AuthorizationRequest({ scope: 'openid' });
		const { response } = await agent.auth.get({ query: auth.params });
		const [, , uid] = (response.headers.get('location') ?? '').split('/');

		const login = await agent.ui[uid].login.get({
			headers: { cookie: response.headers.get('set-cookie') }
		});
		await expectPolicyCoversItsOwnResources(
			login.response,
			htmlBodyOf(login.data)
		);
	});

	it('reaches the device user-code page', async () => {
		const res = await send('/device', { method: 'GET' });
		await expectPolicyCoversItsOwnResources(res);
	});

	it('reaches the error page an unserved path renders for a browser', async () => {
		const res = await send(UNSERVED_PATH, {
			method: 'GET',
			headers: { accept: 'text/html' }
		});
		expect(res.status).toBe(404);
		await expectPolicyCoversItsOwnResources(res);
	});

	/*
	 * Until spec 026 a protocol response carried no policy at all, and this asserted exactly that.
	 * It now carries the non-page policy from lib/plugins/securityHeaders.ts — but what this case is
	 * really guarding is unchanged and is the second assertion: the *page* constructor must not be
	 * reaching responses it did not build. Asserting only the presence of the locked literal would
	 * drop that half silently.
	 */
	it('gives protocol responses the non-page policy, not a page policy', async () => {
		const { response } =
			await agent['.well-known']['openid-configuration'].get();
		expect(response.headers.get('content-security-policy')).toBe(
			"default-src 'none'; frame-ancestors 'none'"
		);
		expect(response.headers.get('content-security-policy')).not.toContain(
			'script-src'
		);
	});
});

/*
 * scriptOrigins names a foreign origin rather than dropping it, but no page this server renders
 * actually loads a third-party script — so nothing in the walk above exercises that branch. It
 * exists to turn a silently-blocked CDN script into a named, debuggable entry instead of a script
 * that just never runs; an untested branch whose purpose is preventing silent failure carries the
 * same risk it was added to remove.
 */
describe('content security policy: foreign script origins', () => {
	it('names a foreign script origin, keeps self and this-server-absolute scripts as self', () => {
		const html = `<!DOCTYPE html>
<html><head></head><body>
	<script src="/relative.js"></script>
	<script src="${ISSUER}/absolute-but-self.js"></script>
	<script src="https://cdn.example.com/x.js"></script>
</body></html>`;

		const scriptSrc =
			/script-src ([^;]*)/
				.exec(contentSecurityPolicyFor(html))?.[1]
				.split(' ') ?? [];

		expect(scriptSrc).toContain("'self'");
		expect(scriptSrc).toContain('https://cdn.example.com');
		// The foreign origin, not the path — CSP source expressions are origins, never full URLs.
		expect(scriptSrc.some((v) => v.includes('/x.js'))).toBe(false);
		// The ISSUER-absolute script must not also be named as if it were a foreign origin.
		expect(scriptSrc).not.toContain(ISSUER);
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
