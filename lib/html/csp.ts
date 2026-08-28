import * as crypto from 'node:crypto';

import { ISSUER } from 'lib/configs/env.js';

/*
 * The only place this server builds an HTML response, and the only place that knows what a content
 * security policy is.
 *
 * A page hands over its document and gets a policy derived from that document — it declares nothing.
 * That is what makes a hash and the script it authorizes impossible to drift apart: there is one
 * source for both. test/csp/csp.spec.ts fails the suite if a `text/html` response is built anywhere
 * else, so a new page cannot arrive unprotected.
 *
 * WHY not a lifecycle plugin. It was built and measured (spec 018, research.md M9):
 * `mapResponse({ as: 'global' })` does reach mounted sub-apps, but it never fires for a response
 * built by the error handler, and it did not fire for the named `adminApp` instance — the rendered
 * error page and the console shell, silently, while both still render perfectly. "Is there exactly
 * one place that builds a text/html response?" is a question a test can answer; "which named
 * sub-apps render HTML?" is not.
 */

function hash(text: string): string {
	return `'sha256-${crypto.hash('sha256', text, 'base64')}'`;
}

function ownOrigin(): string | undefined {
	try {
		return new URL(ISSUER).origin;
	} catch {
		return undefined;
	}
}

/*
 * One rule, three attributes. A relative URL, or an absolute one at this server's origin, is
 * `'self'`; anything else is named explicitly. Written once because a change to it — an unparseable
 * form — must not have to be found in three places.
 */
function resolveOrigin(raw: string, self: string | undefined): string {
	try {
		const { origin } = new URL(raw);
		return origin === self ? "'self'" : origin;
	} catch {
		// Relative — this server.
		return "'self'";
	}
}

/*
 * Inline <script> blocks that carry a body rather than a src. Their hashes go into `script-src`; the
 * blanket 'unsafe-inline' is never used, which is the whole point of hashing them.
 */
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

/*
 * Inline event-handler attributes. These need 'unsafe-hashes' as well as a hash — without it the
 * hash is inert and the handler silently stops running while the page still renders. One page has
 * one of these: the device user-code input's select-on-focus.
 */
function inlineHandlers(html: string): string[] {
	return [...html.matchAll(/\son[a-z]+="([^"]*)"/g)].map(([, value]) => value);
}

/*
 * Where this document's external scripts come from. A relative src, or an absolute one at this
 * server's origin, is `'self'`; a foreign origin is named explicitly — the same comparison
 * `foreignFormTargets` makes below, and wrong for the same reason if simplified to "absolute means
 * foreign".
 *
 * Naming foreign origins is not speculative generality. Until now `'self'` was unconditional, so a
 * page that added a CDN script was blocked with no error anywhere; deriving the origin closes that
 * silent failure symmetrically with `form-action`.
 */
function scriptOrigins(html: string): string[] {
	const self = ownOrigin();
	const sources = new Set<string>();

	for (const [, attributes] of html.matchAll(/<script([^>]*)>/g)) {
		const src = /\ssrc="([^"]*)"/.exec(attributes)?.[1];
		if (!src) {
			continue;
		}
		sources.add(resolveOrigin(src, self));
	}

	return [...sources];
}

/*
 * Stylesheets this document links. Same origin treatment as `scriptOrigins`.
 */
function stylesheetOrigins(html: string): string[] {
	const self = ownOrigin();
	const sources = new Set<string>();

	for (const [, attributes] of html.matchAll(/<link([^>]*)>/g)) {
		if (!/\srel="stylesheet"/.test(attributes)) {
			continue;
		}
		const href = /\shref="([^"]*)"/.exec(attributes)?.[1];
		if (!href) {
			continue;
		}
		sources.add(resolveOrigin(href, self));
	}

	return [...sources];
}

/*
 * Inline <style> blocks that carry a body. Hashed exactly as inline scripts are — a block is the
 * form worth constraining, since it restyles the whole document and can exfiltrate input values by
 * attribute selector.
 */
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

/*
 * Whether any element carries a style attribute. A false positive here — the pattern appearing inside
 * a hashed script's JSON, say — only loosens `style-src-attr` to what it already was, so the error
 * direction is the safe one. A false negative would stop a page styling itself.
 */
function hasStyleAttribute(html: string): boolean {
	return /\sstyle="/.test(html);
}

/*
 * Where this document's forms actually post. Anything relative, or absolute at this server's own
 * origin, is `'self'`; a foreign origin is named explicitly.
 *
 * The origin rather than the full URL: CSP path matching brings redirect-handling subtleties that
 * buy nothing here, since a callback address was validated against the client's registration long
 * before the page was rendered.
 */
function foreignFormTargets(html: string): string[] {
	const self = ownOrigin();
	const foreign = new Set<string>();

	for (const [, action] of html.matchAll(/<form[^>]*\saction="([^"]*)"/g)) {
		// A relative or same-origin action resolves to 'self', which contributes nothing here.
		const resolved = resolveOrigin(action, self);
		if (resolved !== "'self'") {
			foreign.add(resolved);
		}
	}

	return [...foreign];
}

/*
 * `handOffTo` is the pending authorization request's `redirect_uri`, and it is needed because
 * `form-action` governs a form submission's whole redirect chain, not just the URL in the action
 * attribute. An interaction page posts to itself; the response is a redirect that ends at the client's
 * callback. With a policy of `'self'` alone the browser refuses that final hop — after the server has
 * already recorded the consent and issued the code — and reports the same-origin action as the
 * violation, which sends the reader looking in the wrong place entirely.
 *
 * Naming the client's origin here is the same judgement the auto-submit callback page already makes:
 * this page may hand off to the client it names, and to nothing else. The address was validated against
 * the client's registration long before the page was rendered.
 *
 * A callback on this server's own origin resolves to `'self'` and so adds nothing — which is why the
 * admin console never met this, and why nothing changes for it now.
 */
/*
 * The policy and the framing verdict come out together because `htmlResponse` needs both and they must
 * not be decided twice. `X-Frame-Options` is the legacy fallback for `frame-ancestors`, so the two have
 * to agree on every page — including, and especially, on the one page that is deliberately framable.
 * Returning the verdict makes that agreement structural: there is one evaluation, so there is nothing
 * to keep in sync.
 */
function pagePolicy(
	html: string,
	handOffTo?: string
): { policy: string; deniesFraming: boolean } {
	const scripts = scriptOrigins(html);
	const scriptSrc = [...scripts, ...inlineScripts(html).map(hash)];

	const handlers = inlineHandlers(html);
	if (handlers.length) {
		scriptSrc.push("'unsafe-hashes'", ...handlers.map(hash));
	}

	const foreignTargets = foreignFormTargets(html);

	/*
	 * `'self'` is stated rather than implied here: this page's own form still posts to this origin, and a
	 * directive is a whole allow-list — naming only the hand-off would block the submission itself.
	 * Resolved through the same rule the attributes use, so a same-origin callback collapses to `'self'`
	 * and leaves the policy exactly as it was.
	 */
	const handOff = handOffTo ? resolveOrigin(handOffTo, ownOrigin()) : "'self'";
	const formTargets =
		handOff === "'self'"
			? foreignTargets
			: [...new Set(["'self'", ...foreignTargets, handOff])];

	/*
	 * The gate here is external scripts specifically, not "code that runs after the document is
	 * served" — the form_post auto-submit page and the device input page both run inline code after
	 * serving (a module script, an onfocus handler), and both are hashed rather than excepted, because
	 * that code is itself in the document. An external script is different: it is a linked bundle whose
	 * post-serve behaviour the document cannot describe — specifically @ant-design/icons'
	 * useInsertStyles, which injects a block that does not exist yet and therefore cannot be hashed. A
	 * document with no external script keeps its <style> blocks as the whole truth, so they can be
	 * hashed instead of falling back to `'unsafe-inline'`. See test/csp/csp.spec.ts, "keeps
	 * 'unsafe-inline' … wherever a bundle can inject" — removing it takes the styling off every icon on
	 * the sign-in page and reports nothing but a console violation.
	 */
	const styleSrcElem = [
		...stylesheetOrigins(html),
		...(scripts.length
			? ["'unsafe-inline'"]
			: inlineStyleBlocks(html).map(hash))
	];

	const directives = [
		"default-src 'none'",
		"base-uri 'none'",
		"object-src 'none'",
		/*
		 * Nothing to authorize means authorize nothing. `'none'` is only correct when it stands alone —
		 * beside a hash or an origin it is meaningless — so it is the empty case, never appended.
		 */
		`script-src ${scriptSrc.length ? scriptSrc.join(' ') : "'none'"}`,
		/*
		 * Retained unnarrowed for browsers without the CSP3 -elem/-attr pair, which supersedes it
		 * wherever it is understood. Narrowing this one too would block style attributes on those
		 * browsers instead of merely failing to harden them.
		 */
		"style-src 'self' 'unsafe-inline'",
		`style-src-elem ${styleSrcElem.length ? styleSrcElem.join(' ') : "'none'"}`,
		// The weak form: an attribute decorates the one element it is already attached to.
		`style-src-attr ${hasStyleAttribute(html) ? "'unsafe-inline'" : "'none'"}`,
		"img-src 'self' data:",
		"font-src 'self'",
		"connect-src 'self'",
		`form-action ${formTargets.length ? formTargets.join(' ') : "'self'"}`
	];

	/*
	 * A page whose form posts to another origin is a hand-off page, and the only one this server
	 * renders is the form_post auto-submit callback. That page must stay framable: silent
	 * authentication (prompt=none in a hidden iframe) renders it inside the client's frame, and
	 * frame-busting it would break the flow for no benefit — it carries no interactive UI to hijack,
	 * and its protection is the form-action above, pinned to the callback's origin.
	 */
	const deniesFraming = !foreignTargets.length;
	if (deniesFraming) {
		directives.push("frame-ancestors 'none'");
	}

	return { policy: directives.join('; '), deniesFraming };
}

/*
 * Kept as the exported shape because the policy string is what every caller and every test wants; the
 * framing verdict is only `htmlResponse`'s business.
 */
export function contentSecurityPolicyFor(
	html: string,
	handOffTo?: string
): string {
	return pagePolicy(html, handOffTo).policy;
}

/*
 * Sets the content type, the derived policy and the legacy framing fallback, and nothing else.
 * `Cache-Control: no-store` deliberately stays with the nocache plugin, which writes it on every
 * response — duplicating it here would give one header two sources.
 *
 * WHY `X-Frame-Options` is written here and not in lib/plugins/securityHeaders.ts with the rest of the
 * blanket profile. Not taste — a blanket emission is unimplementable. The plugin writes to
 * `set.headers` from a pre-routing hook, and a returned Response can *override* a name that merge also
 * carries but has no way to *remove* one. So the auto-submit hand-off page, which must not be
 * frame-busted, could not take the header back; and there is no permissive value to override it with
 * either, since ALLOW-FROM is dead in every current engine and ALLOWALL was never standard. A blanket
 * DENY therefore has exactly one outcome on that page: silent authentication (prompt=none in a hidden
 * iframe with response_mode=form_post) stops working, with nothing downstream able to fix it.
 *
 * So it is derived, from the same single evaluation as `frame-ancestors` — see `pagePolicy`. The two
 * cannot disagree because nothing keeps them in agreement; there is one decision.
 *
 * Non-page responses carry no `X-Frame-Options` at all, deliberately: their locked policy already has
 * `frame-ancestors 'none'`, and a framed JSON body has no interactive surface to hijack. The full
 * reasoning, with the measurements, is specs/029-hsts-permissions-framing/research.md M6, M7 and M10.
 */
export function htmlResponse(
	html: string,
	init: {
		status?: number;
		headers?: Record<string, string>;
		/* The pending authorization request's redirect_uri — see contentSecurityPolicyFor. */
		handOffTo?: string;
	} = {}
): Response {
	const { policy, deniesFraming } = pagePolicy(html, init.handOffTo);

	return new Response(html, {
		status: init.status,
		headers: {
			...init.headers,
			'Content-Type': 'text/html; charset=utf-8',
			'Content-Security-Policy': policy,
			...(deniesFraming ? { 'X-Frame-Options': 'DENY' } : {})
		}
	});
}
