---
type: concept
title: 'Admin plane error shape'
tags: [contract, gotcha, architecture]
sources: [oauth-server-codebase]
created: 2026-08-04
updated: 2026-08-04
graph:
  node_type: concept
---

# Admin plane error shape

The administrative control plane answers errors in its own shape, not the OAuth one:

```json
{ "error": "admin_error", "message": "project not found" }
```

plus `blockers` on a deletion conflict and `failedAreas` on a partial cascade failure
(`lib/admin/auth/rbac.ts`, `adminErrorBody`). The console renders `message` and
[[deletion-and-revocation]]'s dialogs read `blockers`, so the shape is a consumed contract rather than a
presentation detail — and the same contract MCP-initiated administration answers on.

## It was silently lost in the real server

Every admin route group registers its own `onError` returning that body. But
`lib/index.ts` registers the OAuth `errorHandler` on the **root** app at line 81 and mounts `adminApp` at
line 109. Elysia runs error handlers in registration order and the first one to return a value wins — so
the OAuth handler answered first, and every admin API error reached the caller as:

```json
{ "error": "server_error", "error_description": "An unexpected error occurred" }
```

Right status, wrong shape, `message` gone. Measured on `DELETE /admin/api/projects/does-not-exist`:
`404` with `admin_error` through a standalone `new Elysia().use(adminApp)`, `404` with `server_error`
through the composed app.

**Every admin spec in `test/admin/` mounted the routes standalone**, so the whole suite asserted a shape
production never produced. That is the general lesson: a plugin's own `onError` proves nothing about the
plugin once it is composed, and a test that mounts it in isolation cannot see the difference.

## The fix is a marker on the error, not a path check

`AdminError` carries `readonly adminPlane = true`, and `errorHandler` stands aside for anything carrying
it (`lib/shared/authorization_error_handler.ts`). Returning nothing hands the error to the next handler —
the admin group's, which knows what to say.

Two deliberate choices:

- **A marker, not a request path.** An admin error raised from anywhere is still an admin error. Same
  reasoning the neighbouring `FeatureDisabled` branch already records for itself.
- **Duck-typed, not `instanceof`.** Importing `AdminError` would pull the admin graph into the protocol
  error path, for a check that only needs to know whose error this is.

The exit sits **before** the event-bus emit, so a correctly-refused admin request is no longer filed on
the channel operators watch for genuine faults.

Pinned by `test/admin/admin_error_shape.spec.ts`, which now asserts through the composed app as well as
the standalone mount.

## Related

- [[deletion-and-revocation]] — the `blockers` and `failedAreas` fields this shape carries.
- [[admin-audit-trail]] — the other admin-plane contract that route tables and drift guards protect.
- [[feature-flag-gating]] — `FeatureDisabled`, the precedent for recognising an error by a marker it
  carries rather than by the route that raised it.
