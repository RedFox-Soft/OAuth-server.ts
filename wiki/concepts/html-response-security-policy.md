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
- every `<form action>` → `'self'` when relative or at this server's origin, the foreign origin
  otherwise;
- `frame-ancestors 'none'` unless a form targets a foreign origin.

Because the hash and the script have one source, they cannot drift apart. An earlier version had each
page declare its own scripts; that was replaced precisely because a declaration can go stale while the
page still renders.

**Same-origin comparison is load-bearing.** The device pages build an `ISSUER`-absolute form action,
so "absolute means foreign" would name this server as a foreign target *and* drop `frame-ancestors`
from a page with a real form on it. The comparison is against `new URL(ISSUER).origin`.

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

`style-src` keeps `'unsafe-inline'`. antd's cssinjs injects styles into the document at runtime after
hydration, and the page templates carry hand-written `<style>` blocks. A nonce *would* work — antd's
`ConfigProvider` accepts `csp={{ nonce }}` — but it would have to reach the client bundle, and it
constrains styling rather than script execution.

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

## Related

- [[feature-flag-gating]] — the other two-way drift guard in this codebase, and the origin of the
  rule that a rendered error must carry a real status rather than defaulting to 200.
- [[admin-console-signin]] — the console shell is the heaviest inline-script page here.
- [[first-run-setup-had-two-surfaces]] — removed alongside this work.
