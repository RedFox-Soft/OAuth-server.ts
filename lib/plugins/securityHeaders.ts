import type { Elysia } from 'elysia';

/*
 * The baseline hardening profile, on every response that is not a rendered page.
 *
 * WHY there is no page-detection branch. This writes `default-src 'none'` unconditionally, including
 * on requests that will end up rendering a page — and that is correct, not a bug waiting to be fixed
 * with a content-type check. `htmlResponse` (lib/html/csp.ts) builds its own Response carrying its own
 * derived `Content-Security-Policy`, and a header present on a returned Response wins over the
 * `set.headers` merge without being duplicated or comma-joined. So every page overrides this default
 * by construction, automatically, and a page that does not go through `htmlResponse` cannot exist —
 * test/csp/csp.spec.ts fails the suite if an HTML response is built anywhere else. (That guard is a
 * plain substring scan over lib/**, which is why the MIME type is described here rather than spelled
 * out: naming it would make this file an offender. Do not "fix" that by adding this file to the
 * guard's allow-list — an exemption granted for a comment would still be in force the day someone
 * adds real markup here.)
 *
 * Adding a content-type branch here would be actively worse: it would recreate the "which responses
 * are pages?" classification that spec 018 concluded a test cannot answer, and it would give the page
 * policy a second writer. The measurement behind all of this is
 * specs/026-non-html-security-headers/research.md, M1-M3.
 *
 * WHY onRequest rather than mapResponse or onAfterHandle. Both of those were built and measured in
 * spec 018 (research.md M9) and neither fires for a response the error handler builds, nor for the
 * named `adminApp` instance — the two surfaces that carry the most sensitive responses, failing
 * silently in both cases. onRequest precedes routing, so it reaches every response the server emits:
 * handler returns, raw Responses, error-pipeline output, named and unnamed sub-apps, and static files.
 * Being pre-routing also means it is immune to the registration-order constraint documented at
 * lib/plugins/cors.ts:33, which binds the per-route hooks that CORS must use.
 *
 * Callback-shaped (the lib/plugins/noCache.ts form) rather than a named Elysia instance, for the
 * reason cors.ts:33 gives: the hook is inlined into the caller's instance, so there is no
 * `as: 'scoped'` reasoning and no way for a header to leak onto a sibling route.
 *
 * `Cache-Control` deliberately stays with nocache, and the CORS headers with cors — one writer per
 * header is what makes any of these debuggable.
 */
export const securityHeaders = (app: Elysia) => {
	return app.onRequest(({ set }) => {
		set.headers['X-Content-Type-Options'] = 'nosniff';
		set.headers['Referrer-Policy'] = 'no-referrer';
		/*
		 * `default-src` is the fallback for every fetch directive, so one directive denies scripts,
		 * styles, images, frames, fonts and connections at once. `frame-ancestors` is a navigation
		 * directive with no such fallback — omitting it would leave the response framable.
		 */
		set.headers['Content-Security-Policy'] =
			"default-src 'none'; frame-ancestors 'none'";
	});
};
