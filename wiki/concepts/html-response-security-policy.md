---
type: concept
title: "Rendered pages and their content security policy"
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-08-04
updated: 2026-08-04
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: subsystem:html-rendering
      source: oauth-server-codebase
      evidence: "return new Response(html, { status: init.status, headers: { ...init.headers, 'Content-Type': 'text/html; charset=utf-8', 'Content-Security-Policy': contentSecurityPolicy(init.policy) } });"
      confidence: high
      status: current
---

# Rendered pages and their content security policy

Since `specs/018-small-bugfix-batch`, every HTML response this server produces carries a
`Content-Security-Policy`, and **there is exactly one place that may build such a response**:
`htmlResponse` in `lib/html/csp.ts:76`.

## The contract

Do not construct a `text/html` response by hand. Call `htmlResponse(html)` — or
`htmlResponse(html, { status })` for a page that carries its own status. **That is the whole API: a
page declares nothing about its policy.** `test/csp/csp.spec.ts` scans `lib/**/*.{ts,tsx}` for the
literal `text/html` and fails the suite if it appears anywhere except `lib/html/csp.ts` and the
request-side `accept` check in `lib/shared/authorization_error_handler.ts:161`. A new page that skips
the constructor is a red suite, not a silently unprotected page.

The policy is derived from the document that is being sent:

- every inline `<script>` body → a `'sha256-…'` in `script-src` (never `'unsafe-inline'`);
- every inline `on*="…"` attribute → `'unsafe-hashes'` plus its hash;
- every `<script src>` → `'self'` when relative or at this server's origin, the foreign origin
  otherwise. **Nothing to authorize means `script-src 'none'`** — the error page, both logout pages,
  the verification and password-reset pages, device confirmation and success;
- every `<link rel="stylesheet">` → `'self'` or the foreign origin, in `style-src-elem`;
- every inline `<style>` body → a `'sha256-…'` in `style-src-elem`, **but only on a page that
  references no external script** (see the icons gotcha below);
- `style-src-attr` → `'unsafe-inline'` only where a `style="…"` attribute is actually present;
- every `<form action>` → `'self'` when relative or at this server's origin, the foreign origin
  otherwise;
- `frame-ancestors 'none'` unless a form targets a foreign origin.

Because the hash and the script have one source, they cannot drift apart. An earlier version had each
page declare its own scripts; that was replaced precisely because a declaration can go stale while the
page still renders.

**Same-origin comparison is load-bearing.** The device pages build an `ISSUER`-absolute form action,
so "absolute means foreign" would name this server as a foreign target *and* drop `frame-ancestors`
from a page with a real form on it. The comparison is against `new URL(ISSUER).origin`.

## What "derived" does and does not buy you

A derived policy authorizes whatever the served document names — no more, but also no less. Before
this branch, `script-src`'s `'self'` was unconditional, so a foreign `<script src>` was blocked by the
policy regardless of what the document said. Now `scriptOrigins` reads the document and names whatever
origin it finds there, so on these pages the header is a *description* of what the page legitimately
does, not a *backstop* against markup that should never have reached the document in the first place:
an injected `<script src="https://evil/x.js">` would be authorized by the very header meant to
constrain it. This is not new to this branch — inline-script hashing already had the property, since a
hash computed over injected text just as faithfully authorizes it. The actual defense against HTML
injection is output escaping at every interpolation point (`propsScript` mapping `<` to its escaped
`<` form in both server-render files, `esc()` in `lib/interactions/plainPage.tsx`, and React's own
escaping on the error and device pages) — CSP here is not a substitute for that.

## Why a constructor and not a plugin

This was **built and measured**, not assumed — see `specs/018-small-bugfix-batch/research.md` M9.
A `mapResponse({ as: 'global' })` plugin deriving the whole policy from the served document works for
the root instance and for *unnamed* mounted sub-apps (`ui`, `codeVerification`), which corrects a
belief carried over from the CORS work: `{ as: 'global' }` does reach descendants, and spec 011 had to
mount per sub-app only because its plugins are deliberately callback-shaped (`lib/plugins/cors.ts:33`).

But the plugin never fires for:

- a response built by the **error handler** (`onError`) — the rendered error page, and
- the **named** `adminApp` instance (`lib/admin/index.ts:21`) — the console shell.

The admin gap survived mounting the plugin inside `adminApp` and survived removing the plugin's
`name` to rule out Elysia's named-plugin dedup. Both misses are pages that carry a request-derived
inline script, and both fail *silently* — the page renders perfectly with no policy. The constructor
wins on the failure mode, not on elegance: "is there exactly one place that builds a `text/html`
response?" is answerable by a test; "which named sub-apps render HTML?" is not.

## Two deliberate looseness points

`style-src` itself keeps `'self' 'unsafe-inline'`, unnarrowed, as the fallback for browsers without
the CSP3 `style-src-elem`/`style-src-attr` pair — which supersedes it wherever it is understood.
Narrowing it too would block style attributes on those browsers rather than merely failing to harden
them.

`style-src-attr` keeps `'unsafe-inline'` on most pages, and that is not laziness: 62 `style={{…}}`
props across `lib/interactions/{loginPage,consentPage,registration}.tsx` and ten pages under
`lib/admin/ui/pages/` each render one, and `lib/interactions/plainPage.tsx` builds its markup from
them by hand. An attribute decorates the one element it is attached to; a `<style>` block restyles the
whole document and can exfiltrate input values by attribute selector. The block form is the one
`style-src-elem` closes.

The `form_post` auto-submit page (`lib/html/formPost.tsx`) omits `frame-ancestors`. Silent
authentication (`prompt=none` in a hidden iframe) with `response_mode=form_post` renders that page
inside the client's frame, so frame-busting it breaks the flow. It has no interactive UI to hijack;
its protection is `form-action`, pinned to the callback's origin.

## Gotcha: the lone inline event handler

The device user-code input carries an `onfocus` attribute (`lib/helpers/user_code_form.ts:15`) — the
only inline event handler in the server. CSP blocks these by default and **the failure is silent**:
the page still renders, it just stops selecting a pre-filled code. The constructor sees the attribute
in the document and emits `'unsafe-hashes'` plus its hash, so the file itself needs no CSP awareness.
If you ever hand-roll a policy for a page, remember that a hash without `'unsafe-hashes'` is inert.

## Gotcha: the stylesheet no page's source mentions

`@ant-design/icons` calls `useInsertStyles` on **every icon render**
(`node_modules/@ant-design/icons/es/components/Icon.js:27`, `IconBase.js:14`), injecting a `<style>`
into the document through its own `cssUtils`. That package is independent of antd: antd's
`zeroRuntime` does not stop it, and the compiled `antd.css` does not contain it.

This is why `style-src-elem` cannot simply hash every `<style>` block. The injected one does not exist
when the document is built, so it has no hash, and all four hydrated pages import icons. The
derivation therefore keys off whether the document references an *external* script — a linked bundle
is the case whose post-serve behaviour the document cannot describe — not off whether anything runs
after the document is served at all. Two pages run inline code after serving (the `form_post`
auto-submit page's module script, the device input page's `onfocus` handler) and both are hashed
rather than excepted, because that code is itself in the document. No external script means nothing
*unaccounted for* can inject later and the `<style>` blocks are the whole truth; a bundle means they
are not.

Like the `onfocus` handler above, this is invisible in the source of every page it affects, and the
failure is near-silent — the icons render, unstyled, with one console violation.

## Related

- [[feature-flag-gating]] — the other two-way drift guard in this codebase, and the origin of the
  rule that a rendered error must carry a real status rather than defaulting to 200.
- [[admin-console-signin]] — the console shell is the heaviest inline-script page here.
- [[first-run-setup-had-two-surfaces]] — removed alongside this work.
- [[interaction-page-families]] — the two families whose every page goes through this constructor, and the
  rendered-error status rule applied to the registration refusals.
