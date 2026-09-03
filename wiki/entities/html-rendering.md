---
type: entity
kind: subsystem
title: "HTML rendering (lib/html/)"
aliases: [htmlResponse, csp, lib/html]
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-09-01
updated: 2026-09-01
graph:
  node_id: subsystem:html-rendering
  node_type: subsystem
  canonical: true
  relationships:
    - predicate: implements
      object: concept:html-response-security-policy
      source: oauth-server-codebase
      evidence: "The only place this server builds an HTML response, and the only place that knows what a content security policy is."
      confidence: high
      status: current
---

# HTML rendering (lib/html/)

The chokepoint every `text/html` response passes through, and the shared parts the pages built on it
need. `csp.ts` is the module that matters; the rest of the directory is the page inventory and two
helpers.

## One constructor, or the guarantee collapses

`htmlResponse` is the only function in the server that builds an HTML response:

```ts
return new Response(html, {
    status: init.status,
    headers: {
        ...init.headers,
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Security-Policy': policy,
        ...(deniesFraming ? { 'X-Frame-Options': 'DENY' } : {})
    }
});
```

A page hands over its document and gets a policy **derived from that document** — it declares
nothing. That is what keeps a hash and the script it authorizes from drifting apart: one source
produces both. The rule is enforced, not merely intended — `test/csp/csp.spec.ts` fails the suite if
a `text/html` response is constructed anywhere else, so an unprotected page cannot arrive.

The full reasoning about what the derived policy contains lives in
[[html-response-security-policy]]; this page is about the module boundary.

## Why it is not a lifecycle plugin

This is the decision most likely to be "fixed" by someone who hasn't measured it. A global
`mapResponse({ as: 'global' })` was built and measured (spec 018, research.md M9): it does reach
mounted sub-apps, but it never fires for a response built by the error handler, and it did not fire
for the named `adminApp` instance — the rendered error page and the console shell, silently, while
both still render perfectly.

The deciding argument is testability, not coverage. *"Is there exactly one place that builds a
`text/html` response?"* is a question a test can answer. *"Which named sub-apps render HTML?"* is
not. See [[non-html-response-hardening]] for the companion policy covering everything that is not a
page, and why that one **is** a lifecycle hook.

## The framing verdict rides along

`pagePolicy` returns `{ policy, deniesFraming }` together because `htmlResponse` needs both and they
must not be decided twice. `X-Frame-Options` is the legacy fallback for `frame-ancestors`, so the two
have to agree on every page — including the one page that is deliberately framable, the `form_post`
auto-submit callback rendered inside a client's hidden iframe during silent authentication.

`X-Frame-Options` is therefore written here rather than in the blanket profile at
[[non-html-response-hardening]], and that placement is forced, not stylistic: the plugin writes to
`set.headers` from a pre-routing hook, and a returned `Response` can *override* a name the merge also
carries but has no way to *remove* one. A blanket `DENY` would have exactly one outcome on the
hand-off page — silent authentication stops working, with nothing downstream able to fix it.

## The rest of the directory

- `csp.ts` — policy derivation and `htmlResponse`, above.
- `device.tsx`, `error.tsx`, `formPost.tsx`, `logout.tsx`, `logoutSuccess.tsx` — the terminal pages.
  Self-contained: they extract their styles server-side and inline them, which is cheaper for a page
  read once. See [[interaction-page-families]] for the split between these and the hydrated shell.
- `zeroRuntime.tsx` — one component owning antd 6's `zeroRuntime` flag so the four entry points
  cannot drift. Server render and client hydrate must agree or hydration diverges, in the browser
  only, visible only as a mismatch warning. The name overpromises: it gates
  `genComponentStyleHook` but not `genCSSVarRegister`, so a measured floor of 7 tags / 17,540 B
  remains on `/admin`.
- `versionedAsset.ts` — one owner for cache-busting addresses, because `staticPlugin` serves
  `public/` with a long max-age. `lib/admin/ui/serverRender.tsx` open-coded it for `admin.js` while
  the interactions renderer had nothing, so a rebuilt sign-in bundle could be served stale for the
  whole max-age — a defect invisible from either file alone. An absent file yields an unversioned
  address, because the suite and a fresh server both run before `bun run build`.

## Related

- [[html-response-security-policy]] — what the derived policy actually contains, and why.
- [[non-html-response-hardening]] — the companion profile for non-page responses.
- [[form-action-redirect-chain]] — the redirect-chain rule that forced `handOffTo` into the signature.
- [[interaction-page-families]] — the two families of end-user screen built on `htmlResponse`.
- [[admin-console]] — the console shell is one of its callers.
