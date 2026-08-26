---
type: concept
title: 'Hardening headers on responses that are not pages'
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-08-26
updated: 2026-08-26
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

Since `specs/026-non-html-security-headers`, every response this server emits carries
`X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`, and every response that is
**not** a rendered page also carries `Content-Security-Policy: default-src 'none'; frame-ancestors
'none'`. One `onRequest` hook writes all three: `securityHeaders` in `lib/plugins/securityHeaders.ts`,
registered once in `lib/index.ts:90`.

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

## What is deliberately not here

`Strict-Transport-Security` (deployment concern), `X-Frame-Options` (superseded by `frame-ancestors`;
adding it would be a compatibility shim, which Principle VII forbids), and the
`Cross-Origin-Opener/Embedder/Resource-Policy` family (would change cross-origin behaviour that spec
011 settled deliberately).

## Related

- [[html-response-security-policy]] — the other half: the derived policy for rendered pages, and the
  single-writer guard this page's gotcha concerns.
- [[feature-flag-gating]] — the `onRequest` gate that this plugin must be registered *before*, so a
  refusal still carries the headers.
- [[interaction-page-families]] — the pages whose policies must stay untouched.
