---
type: entity
kind: subsystem
title: "Admin console (lib/admin/)"
aliases: [adminApp, admin console, control plane, lib/admin]
tags: [architecture, gotcha]
sources: [oauth-server-codebase]
created: 2026-09-01
updated: 2026-09-01
graph:
  node_id: subsystem:admin-console
  node_type: subsystem
  canonical: true
  relationships:
    - predicate: depends_on
      object: subsystem:html-rendering
      source: oauth-server-codebase
      evidence: "import { htmlResponse } from '../../html/csp.js'; import { versionedAsset } from '../../html/versionedAsset.js'; import { ZeroRuntime } from '../../html/zeroRuntime.js';"
      confidence: high
      status: current
    - predicate: implements
      object: concept:admin-plane-error-shape
      source: oauth-server-codebase
      evidence: "if (error instanceof AdminError) { set.status = error.status; ... const body = adminErrorBody(error); return reference ? { ...body, error_reference: reference } : body; }"
      confidence: high
      status: current
---

# Admin console (lib/admin/)

The administrative control plane: the admin API, plus the HTML shell that drives it. Its own
description, from `index.ts`, is exact — *"The console: the admin API plus the HTML shell that drives
it."*

## The split that exists for a second consumer

`routes.ts` holds every route of the plane **except** the console's own HTML shell; `index.ts` mounts
those routes and adds the shell on top. The split is not organisational tidiness:

> Split out of `index.ts` so there is exactly one definition of "the admin API", mounted by two
> consumers: `adminApp` adds the shell on top, and `lib/mcp/dispatch.ts` re-dispatches agent tool
> calls into it.

That single source is what makes the MCP surface's parity guard meaningful — the drift check compares
the tool catalogue against *this* route set, so a route added here is either published to agents,
named as a deliberate exclusion, or a test failure. See [[admin-mcp-control-plane]].

**The MCP layer must not mount `adminApp` instead.** `renderAdminShell` pulls React and antd's
CSS-in-JS, measured at ~86s to import against ~350ms for the API plugins alone. The same measurement
is why `me.ts` exists separately.

## Two error handlers, and the marker between them

Both `adminApp` and `adminApiRoutes` register an `onError` that recognises `AdminError` and answers
`adminErrorBody(error)`. The plane's shape is `{ error: 'admin_error', message }`, not an OAuth error
body — and the root OAuth handler is registered first, which silently replaced it with `server_error`
in the composed app while every standalone-mounted admin spec passed. That story is
[[admin-plane-error-shape]].

The outer handler additionally captures 5xx faults:

```ts
const reference = error.status >= 500 ? captureFault({ surface: 'admin', ... }) : undefined;
```

This is the second of the two capture sites, and it exists because an `AdminError` carries the
`adminPlane` marker the root handler stands aside for — without it, the only faults the store would
miss are the ones the admin plane took the trouble to explain. See [[error-store-capture-sites]].

## One bootstrap surface

`GET /admin` is the whole first-run path:

```ts
if (!(await hasSuperAdmin())) {
    return renderAdminShell({ needsSetup: true, me: null });
}
if (!admin) return redirect('/admin/login', 302);
return renderAdminShell({ needsSetup: false, me: admin });
```

There was once a second `/admin/setup` twin; it pointed at an unserved bundle and rendered a blank
page nothing linked to. [[first-run-setup-had-two-surfaces]] records why one surface is the fix.

## The shell

`ui/serverRender.tsx` reads an HTML template off disk, substitutes versioned asset addresses through
[[html-rendering]]'s `versionedAsset`, renders React inside `ZeroRuntime`, and returns the document
through `htmlResponse` so the console's policy is derived like every other page's. The props are
injected as an inline script and hashed by that derivation — *"the authorization is derived from the
script that is actually served rather than restated beside it"* — with every `<` in the JSON
escaped to a unicode escape so the props cannot close the script tag.

## The route groups

`auth` (setup, login, RBAC), `me`, `groups` (plus invitation acceptance), `scope`, `projects`,
`clients`, `users` (administrators) and `users-end` (per-bucket end users), `buckets`, `federation`,
`settings` (plus SMTP), `jwks`, `audit`, `errors`. Ownership and visibility across all of them is
decided by [[group-ownership]], not by a per-container manager list.

## Related

- [[admin-mcp-control-plane]] — the second consumer of `routes.ts`, and the parity guard it enables.
- [[admin-plane-error-shape]] — why the plane's error body differs, and how registration order hid it.
- [[admin-console-signin]] — the console is a relying party on its own issuer.
- [[group-ownership]] — what grants access to anything the plane administers.
- [[first-run-setup-had-two-surfaces]] — the deleted bootstrap twin.
- [[error-store-capture-sites]] — the two places a fault is recorded.
- [[html-rendering]] — the shell's page constructor.
- [[settings-console-descriptor]] — the settings pane, whose panes and cards are read from the
  catalog so the page holds no second list of settings.
