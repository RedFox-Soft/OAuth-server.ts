---
type: concept
title: "First-run admin setup: one surface, not two"
tags: [architecture, gotcha]
sources: [oauth-server-codebase]
created: 2026-08-04
updated: 2026-08-04
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: subsystem:admin-console
      source: oauth-server-codebase
      evidence: "if (!(await hasSuperAdmin())) { return renderAdminShell({ needsSetup: true, me: null }); }"
      confidence: high
      status: current
---

# First-run admin setup: one surface, not two

A fresh deployment is bootstrapped through **`GET /admin`**. When no super-administrator exists,
`lib/admin/index.ts:38-44` server-renders the console shell with `needsSetup: true`, which renders the
`<Setup />` page; the form posts to `POST /admin/api/setup`, which creates the first super-admin
audit-first and then hard-gates with 409.

## The trap that was removed

There used to be a second surface, `GET /admin/setup`, which hand-wrote:

```html
<!doctype html><meta charset=utf-8><div id=root></div><script src="/admin.js"></script>
```

The bundle is served by `staticPlugin` under `/public`, so `/admin.js` 404s and the page rendered an
empty white document with no error visible to the operator — on the only entry point into a new
install. It was reachable **only by typing the URL**: nothing in `lib/`, `test/`, `database/` or the
SPA linked to it.

It was deleted rather than repaired (`specs/018-small-bugfix-batch`, D6). Correcting the address
would have left two first-run surfaces, the second one strictly worse — no server-rendered markup, no
hydration props, no cache-busted bundle, no favicon — and, after the same batch, needing its own
content security policy. `POST /admin/api/setup` and the exported `hasSuperAdmin` are unchanged.

## Why this is worth remembering

Two things generalise:

1. **A hand-written HTML string competing with a real renderer will drift, and its drift is silent.**
   The renderer gained `?v=` cache-busting and a favicon; the hand-written twin did not, and nothing
   noticed because nothing linked to it. This is now structurally prevented for pages —
   see [[html-response-security-policy]], where a single constructor is the only way to build one.
2. **Deleting a route under `/admin` needs no `route_classification.ts` edit.** That table's
   `alwaysAvailablePrefixes` covers `/admin` wholesale (`lib/consts/route_classification.ts:112-117`),
   so the two-way drift guard stays green. A route under a *listed* path would have needed the edit.

## Related

- [[admin-console-signin]] — what happens once an administrator exists.
- [[html-response-security-policy]] — the constructor that now owns every rendered page.
- [[feature-flag-gating]] — the classification table and its prefixes.
