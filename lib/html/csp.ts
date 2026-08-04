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
		let origin: string;
		try {
			origin = new URL(action).origin;
		} catch {
			// Relative — this server.
			continue;
		}
		if (origin !== self) {
			foreign.add(origin);
		}
	}

	return [...foreign];
}

export function contentSecurityPolicyFor(html: string): string {
	const scriptSrc = ["'self'", ...inlineScripts(html).map(hash)];

	const handlers = inlineHandlers(html);
	if (handlers.length) {
		scriptSrc.push("'unsafe-hashes'", ...handlers.map(hash));
	}

	const foreignTargets = foreignFormTargets(html);

	const directives = [
		"default-src 'none'",
		"base-uri 'none'",
		"object-src 'none'",
		`script-src ${scriptSrc.join(' ')}`,
		/*
		 * The one deliberately loose directive. antd's cssinjs injects styles into the document at
		 * runtime after hydration, and the page templates carry hand-written <style> blocks. A nonce
		 * would work — ConfigProvider accepts csp={{ nonce }} — but it would have to reach the client
		 * bundle, and it constrains styling rather than script execution.
		 */
		"style-src 'self' 'unsafe-inline'",
		"img-src 'self' data:",
		"font-src 'self'",
		"connect-src 'self'",
		`form-action ${foreignTargets.length ? foreignTargets.join(' ') : "'self'"}`
	];

	/*
	 * A page whose form posts to another origin is a hand-off page, and the only one this server
	 * renders is the form_post auto-submit callback. That page must stay framable: silent
	 * authentication (prompt=none in a hidden iframe) renders it inside the client's frame, and
	 * frame-busting it would break the flow for no benefit — it carries no interactive UI to hijack,
	 * and its protection is the form-action above, pinned to the callback's origin.
	 */
	if (!foreignTargets.length) {
		directives.push("frame-ancestors 'none'");
	}

	return directives.join('; ');
}

/*
 * Sets the content type and the derived policy, and nothing else. `Cache-Control: no-store`
 * deliberately stays with the nocache plugin, which writes it on every response — duplicating it
 * here would give one header two sources.
 */
export function htmlResponse(
	html: string,
	init: { status?: number; headers?: Record<string, string> } = {}
): Response {
	return new Response(html, {
		status: init.status,
		headers: {
			...init.headers,
			'Content-Type': 'text/html; charset=utf-8',
			'Content-Security-Policy': contentSecurityPolicyFor(html)
		}
	});
}
