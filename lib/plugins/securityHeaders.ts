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
		/*
		 * Two years, because that is what the browser preload programmes require and taking the higher
		 * of the two common figures costs nothing — the value never has to be revisited if the preload
		 * decision below is ever reversed.
		 *
		 * WHY unconditionally, including over plaintext. RFC 6797 §7.2 says a host MUST NOT send this
		 * over non-secure transport, and read literally that argues for a branch here. There is none,
		 * for two reasons. In production the hop the RFC governs — server to user agent — *is* HTTPS:
		 * TLS terminates at the platform proxy (fly.toml, `force_https`), so the plaintext this process
		 * sees on its internal port is an artefact of termination, not the transport the browser
		 * experiences. And in development the header is inert by §8.1, which requires the user agent to
		 * ignore it when it does arrive over plaintext — so nobody working on http://localhost can be
		 * locked out by it.
		 *
		 * Both alternatives are worse, which is the part worth remembering before "fixing" this.
		 * Deriving the scheme behind the proxy means trusting `X-Forwarded-Proto` — client-supplied and
		 * spoofable — to decide a security header, which inverts the intent. Gating on the ISSUER scheme
		 * instead is unspoofable but hides the header from the entire merge gate, because .env.test sets
		 * `ISSUER=http://e.ly`: the suite would assert nothing and the loss would be silent.
		 *
		 * WHY no `preload`. It is a deliberate omission, not an oversight. The deployment host is
		 * already preloaded by virtue of the whole `dev` TLD being on the browser lists, so the token
		 * would be inert here; submission is accepted only for an apex domain this deployment does not
		 * control; and the effect is global, hits every subdomain of whoever does deploy at an apex, and
		 * is slow to undo. That makes it a self-hoster's choice to add at their own edge.
		 * specs/029-hsts-permissions-framing/research.md M2-M4 has the measurements.
		 */
		set.headers['Strict-Transport-Security'] =
			'max-age=63072000; includeSubDomains';
		/*
		 * `()` is the empty allow-list: the feature is denied to every origin including this one. That
		 * is the right strength here because no page this server renders uses any of them — a policy
		 * narrowed to `(self)` would be indistinguishable from one nobody ever narrowed.
		 *
		 * WHY `clipboard-write` is NOT in this list, and must not be added. Five surfaces copy a value
		 * to the clipboard, one of them an end-user page: the TOTP enrolment secret
		 * (lib/interactions/totpPage.tsx), plus the client secret, two audit fields and an error
		 * payload in the console. They all go through antd's `copyable`, and antd
		 * (node_modules/antd/es/_util/copy.js) tries `navigator.clipboard.writeText` FIRST, falling back
		 * to the deprecated `document.execCommand('copy')` only on a caught failure. Denying the feature
		 * would therefore break nothing visible today — it would quietly move all five onto the
		 * deprecated path and fail on the browser release that finally removes it, long after this
		 * change and nowhere near it. Not worth one directive.
		 *
		 * `publickey-credentials-get` IS denied, with eyes open: there is no WebAuthn anywhere in the
		 * server today. A future passkey feature must remove it. That one is safe to deny now precisely
		 * because its failure mode is loud — a rejected promise, not a silent downgrade.
		 *
		 * WHY not the maximal list. Every extra name people reach for — ambient-light-sensor, battery,
		 * document-domain, execution-while-*, keyboard-map, navigation-override, sync-xhr, web-share —
		 * is removed from the spec, never shipped, or unrecognised by current engines. An unrecognised
		 * feature denies nothing and logs a warning on every page load, and console noise is not free
		 * here: it is where the @ant-design/icons style-injection violation hides (see
		 * wiki/concepts/html-response-security-policy.md). Real noise for zero protection is a bad
		 * trade. specs/029-hsts-permissions-framing/research.md M5.
		 */
		set.headers['Permissions-Policy'] =
			'accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), usb=(), xr-spatial-tracking=()';
	});
};
