---
type: concept
title: 'Hardening headers on responses that are not pages'
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-08-26
updated: 2026-08-28
graph:
  node_type: concept
  relationships:
    - predicate: complements
      object: concept:html-response-security-policy
      source: oauth-server-codebase
      evidence: "htmlResponse sets Content-Security-Policy on every response it builds, and a header present on a returned Response wins over the set.headers merge"
      confidence: high
      status: current
    - predicate: depends_on
      object: subsystem:elysia-lifecycle
      source: oauth-server-codebase
      evidence: "export const securityHeaders = (app: Elysia) => { return app.onRequest(({ set }) => { ... }) }"
      confidence: high
      status: current
---

# Hardening headers on responses that are not pages

Every response this server emits carries four headers, and every response that is **not** a rendered
page carries a fifth:

| Header | Value | Since |
| --- | --- | --- |
| `X-Content-Type-Options` | `nosniff` | spec 026 |
| `Referrer-Policy` | `no-referrer` | spec 026 |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` | spec 029 |
| `Permissions-Policy` | 17 features denied — see below | spec 029 |
| `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'` *(non-page only)* | spec 026 |

One `onRequest` hook writes all five: `securityHeaders` in `lib/plugins/securityHeaders.ts`, registered
once in `lib/index.ts:92`.

This is the companion to [[html-response-security-policy]], which owns the *page* policy. Between
them the rule is complete: a page gets the policy derived from its own document, everything else gets
a policy that authorizes nothing.

## The part that surprises people

**There is no page-detection branch, and adding one would be a regression.**

The plugin writes `default-src 'none'` on *every* request, including ones that go on to render a
sign-in page. Pages are not blank because `htmlResponse` (`lib/html/csp.ts:272`) builds its own
`Response` carrying its own derived policy, and **a header already present on a returned `Response`
wins over Elysia's `set.headers` merge** — it is not duplicated, not comma-joined, and the merged
value is dropped. So every page overrides the default *by construction*.

A reader who "fixes" the apparent bug by adding a `Content-Type` check would recreate the
classification problem spec 018 concluded a test cannot answer — "which responses are pages?" — and
would give the page policy a second writer. The source comment says so at length for exactly this
reason.

## Why onRequest, and not the plugin shape that was rejected

Spec 018 built and measured a `mapResponse({ as: 'global' })` policy plugin and rejected it: it never
fires for a response the error handler builds, nor for the **named** `adminApp` instance, and it fails
*silently* — the page renders perfectly with no policy. Spec 026 re-measured the same matrix against
`onRequest` and it clears all of it: handler return values, raw `Response` returns, error-pipeline
output, named and unnamed sub-apps, feature-gate refusals, the empty preflight 204, and static files.

## Gotcha: the mount-order caveat does not apply here

`lib/plugins/cors.ts:33` documents that "a hook only affects routes declared after it", and
`staticPlugin` is mounted at `lib/index.ts:88`, *before* this plugin. Static assets are covered
anyway. That caveat is scoped to **per-route** lifecycle hooks (`onTransform`, `onBeforeHandle`),
which is the class CORS must use; `onRequest` runs before routing and sees every request regardless of
declaration order. Measured in both mount orders. The same fact explains why `nocache` — also an
`onRequest` plugin registered after `staticPlugin` — successfully puts `no-store` on static assets.

## Gotcha: a comment can fail the single-writer guard

`test/csp/csp.spec.ts` enforces "only one place builds an HTML response" by scanning `lib/**` for the
**literal string** `text/html`, with a two-entry allow-list. It is a plain substring match, so it does
not care whether the occurrence is code or prose. Writing the MIME type inside a comment in any other
`lib/` file turns that file into an offender and reds the suite.

The fix is to reword the comment, **not** to add the file to the allow-list. An exemption granted for
a comment stays in force the day someone adds real markup to that file — which is precisely the
failure the guard exists to prevent.

## Gotcha: HSTS is emitted over plaintext too, and that is not a bug

RFC 6797 §7.2 says a host MUST NOT send `Strict-Transport-Security` over non-secure transport, so the
unconditional write looks wrong. It is not, and the branch must not be added back.

In production the hop the RFC governs — server to user agent — **is** HTTPS. TLS terminates at the Fly
proxy (`fly.toml`, `force_https`), so the plaintext this process sees on its internal port is an
artefact of termination, not what the browser experiences. In development the header is inert by RFC
6797 §8.1, which requires the user agent to *ignore* it when it does arrive over plaintext — nobody on
`http://localhost` can be locked out by it.

Both alternatives are worse. Deriving the scheme behind the proxy means trusting `X-Forwarded-Proto`,
which is client-supplied and spoofable, to decide a security header. Gating on the `ISSUER` scheme is
unspoofable but hides the header from the entire merge gate, because `.env.test` sets
`ISSUER=http://e.ly` — the suite would assert nothing and the loss would be silent.

**`preload` is deliberately omitted.** Not an oversight: the deployment host is already preloaded by
virtue of the whole `dev` TLD being on the browser lists (verified against `hstspreload.org`, which
reports `preloadedDomain: "dev"`), so the token would be inert here; submission is accepted only for an
apex domain this deployment does not control; and the effect is global, reaches every subdomain of
whoever *does* deploy at an apex, and is slow to undo. A self-hoster who wants it adds one token at
their own edge. There is no `runbooks/` page for this, so it is recorded here.

## Gotcha: `clipboard-write` is missing from `Permissions-Policy` on purpose

The policy denies 17 features outright — `accelerometer`, `autoplay`, `camera`, `display-capture`,
`encrypted-media`, `fullscreen`, `geolocation`, `gyroscope`, `magnetometer`, `microphone`, `midi`,
`payment`, `picture-in-picture`, `publickey-credentials-get`, `screen-wake-lock`, `usb`,
`xr-spatial-tracking` — each with the empty allow-list `()`, which denies the feature even to this
origin. That is the right strength because no page here uses any of them.

`clipboard-write` is **not** on that list and must not be added. Five surfaces copy a value to the
clipboard, one of them an end-user page: the TOTP enrolment secret (`lib/interactions/totpPage.tsx`),
plus the client secret and two audit fields and an error payload in the console. All go through antd's
`copyable`, and antd (`node_modules/antd/es/_util/copy.js`) tries `navigator.clipboard.writeText`
**first**, falling back to the deprecated `document.execCommand('copy')` only on a caught failure.
Denying the feature would break nothing visible today and would strand all five on the deprecated path,
to fail on the browser release that finally removes it — long after the change and nowhere near it.
`test/security_headers/security_headers.spec.ts` asserts the absence by name so the reasoning is
enforced rather than merely written down.

`publickey-credentials-get` **is** denied, with eyes open: there is no WebAuthn in the server today,
and a future passkey feature must remove the directive. Safe to deny now precisely because its failure
mode is loud — a rejected promise, not a silent downgrade.

The maximal list was rejected. `ambient-light-sensor`, `battery`, `document-domain`,
`execution-while-*`, `keyboard-map`, `navigation-override`, `sync-xhr`, `web-share` are each removed
from the spec, never shipped, or unrecognised by current engines — and an unrecognised feature denies
nothing while logging a warning on **every page load**. Console noise is not free here: it is where the
`@ant-design/icons` style-injection violation hides (see [[html-response-security-policy]]).

## What is deliberately not here

**`X-Frame-Options` is not written by this plugin** — but it does now exist, on rendered pages only,
written by `htmlResponse`. That split is forced, not stylistic: the auto-submit `form_post` hand-off
page must stay framable, a returned `Response` can override a merged header name but never remove one,
and `X-Frame-Options` has no permissive value to override with (`ALLOW-FROM` is dead, `ALLOWALL` was
never standard). A blanket `DENY` here would break silent authentication with nothing downstream able
to fix it. See [[html-response-security-policy]].

Non-page responses therefore carry no `X-Frame-Options`, deliberately: their locked policy already has
`frame-ancestors 'none'`, and a framed JSON body has no interactive surface to hijack.
`expectNonPageProfile` asserts that absence, so a future blanket emission fails the suite here before
it breaks the hand-off page there.

Still absent: the `Cross-Origin-Opener/Embedder/Resource-Policy` family, which would change
cross-origin behaviour that spec 011 settled deliberately.

## Related

- [[html-response-security-policy]] — the other half: the derived policy for rendered pages, and the
  single-writer guard this page's gotcha concerns.
- [[feature-flag-gating]] — the `onRequest` gate that this plugin must be registered *before*, so a
  refusal still carries the headers.
- [[interaction-page-families]] — the pages whose policies must stay untouched.
- [[elysia-lifecycle]] — the plugin subsystem this hook belongs to, and the mount order in
  `lib/index.ts` that the registration-order constraint makes load-bearing.
