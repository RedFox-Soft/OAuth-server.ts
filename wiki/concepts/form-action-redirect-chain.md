---
type: concept
title: "form-action governs the whole redirect chain"
tags: [contract, gotcha, oauth]
sources: [oauth-server-codebase]
created: 2026-08-25
updated: 2026-08-25
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:html-response-security-policy
      source: oauth-server-codebase
      evidence: "contentSecurityPolicyFor derives every directive from the document; form-action now also takes the pending redirect_uri, threaded through htmlResponse."
      confidence: high
      status: current
---

# form-action governs the whole redirect chain

A browser checks `form-action` against **every hop** of a form submission's navigation, not just the
URL in the `action` attribute. An interaction page posts to itself and the server answers with a
redirect that ends at the client's `redirect_uri` — so a policy of `form-action 'self'` blocks the
hand-off, even though the form's own target was same-origin all along.

`contentSecurityPolicyFor` therefore takes the pending authorization request's `redirect_uri`
(`handOffTo`), threaded from each interaction route through `htmlResponse`
(`lib/interactions/serverRender.tsx`, `lib/html/csp.ts`). A callback on this server's own origin
resolves to `'self'` and changes nothing; a foreign one is named beside `'self'`, which the page still
needs for its own submission.

`frame-ancestors` deliberately keeps keying off the *document's* form targets, not this one. An
interaction page has real UI to hijack and must stay unframable; only the `form_post` auto-submit page,
which posts off-origin by construction, is framable.

## What it looked like

Chromium reports the violation against the **original** action URL, so the console read:

```
Sending form data to 'http://localhost:3000/ui/<uid>/consent' violates the following
Content Security Policy directive: "form-action 'self'". The request has been blocked.
```

A same-origin URL refused by `'self'` — which is nonsense on its face, and sends you looking at the
consent page instead of at the redirect three hops later.

The server side had already succeeded: the Grant was written and an authorization code issued. Only the
browser's final navigation was refused, so the client waited for a callback that could never arrive and
timed out. Any diagnosis that reads server state alone concludes the flow worked.

## Why nothing caught it

- **The suite can't see it.** Tests drive redirects with a fetch client, which has no CSP. Every hop
  succeeded and the specs were right to pass.
- **The console client can't trigger it.** `admin-panel`'s callback is on this server's own origin
  (`${ISSUER}/admin/callback`), so its hand-off was always `'self'`. The first client with a foreign
  callback — a native client on loopback — was the first to meet the rule.

It took a real browser to find: driving the flow in Chromium via Playwright reproduced it in one click.
For anything CSP-, cookie-, or navigation-shaped, a headless fetch script is not a browser and cannot
stand in for one.

## Related

- [[html-response-security-policy]] — how the policy is derived per document, and why one constructor owns it.
- [[loopback-redirect-port-matching]] — the earlier failure in the same flow; a foreign callback is what makes this rule bite.
- [[first-consent-grant-id]] — the failure between them, and the one whose 401 this was mistaken for.
- [[interaction-page-families]] — which pages this policy is attached to.
