---
type: concept
title: "Feature flags and endpoint gating"
tags: [config, architecture, oauth, contract]
sources: [oauth-server-codebase]
created: 2026-07-31
updated: 2026-07-31
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: subsystem:event-bus
      source: oauth-server-codebase
      evidence: "eventBus.emit('feature_disabled', { method: request.method, path, flag });"
      confidence: high
      status: current
---

# Feature flags and endpoint gating

Optional protocol capabilities are controlled by named flags on `ApplicationConfig`, and since
commit `18d03a4` a flag governs whether its endpoint is **served at all** — not merely whether
discovery advertises it.

## Flags are flat keys, read directly

`lib/configs/application.ts` declares one object whose keys are dotted strings —
`'par.enabled'`, `'dpop.enabled'`, `'introspection.enabled'`,
`'authorization.allowOmittingSingleRegisteredRedirectUri'`, and so on. They are flat keys, not a
nested `features.*.enabled` tree; code reads `ApplicationConfig['par.enabled']` directly. Each key
carries a doc comment naming the RFC it implements and why it defaults as it does — the redirect-uri
flag, for instance, records that it is a deliberate deviation from strict OAuth 2.1 isolated behind
a flag and defaulted off, secure-by-default.

Defaults are overlaid with persisted settings at module scope
(`application.ts`, `Object.assign(ApplicationConfig, await configStore.get())`).

## Derived configuration is validated once, at load

`configuration` is the derived view — collections as `Set`s, scopes cross-referenced against claims —
produced by `validateConfiguration(ApplicationConfig)` at the point the settings finish loading, "so
an unrunnable configuration fails at startup and no code can observe an unvalidated one". Anything
not derived is read flat from `ApplicationConfig`.

Two properties follow from how it is maintained:

- **Boot-only.** Settings are persisted and applied by a restart. An invalid configuration therefore
  crashes startup, which is why the admin settings endpoint validates the *merged* configuration
  against `configuration.ts` invariants before persisting.
- **Mutated in place, never reassigned**, so every module holding the imported reference sees current
  values — the same rule the signing keys follow in `configs/keystore.ts`. `reloadConfiguration()`
  re-derives after in-place changes and exists for the tests, which reconfigure per spec.

## The gate

`lib/plugins/featureGate.ts` refuses a request to an endpoint whose governing flag is off, answering
exactly as the server answers for a path it does not serve. The design constraints, from
`18d03a4` and `lib/consts/route_classification.ts`:

- **`onRequest` is the mount stage**, because it is the only lifecycle stage ahead of client
  authentication, body parsing and validation — so a disabled endpoint cannot leak a 401 challenge
  or a 422 describing its own request contract.
- **It mounts after `nocache`.** `onRequest` hooks run in registration order and a refusal throws, so
  gating first would omit `Cache-Control: no-store` from the refusal.
- **Matching is exact on `(method, path)`, never a prefix test.** `POST /token` is always available
  while `POST /token/introspect` and `POST /token/revocation` are gated, so a `startsWith('/token')`
  would take down every grant flow. The same trap sits under `/device` and `/reg`.
- **Refusals emit one `feature_disabled` signal** carrying method, path and flag
  (`featureGate.ts:66`), and no longer reach the generic `server_error` channel. None of it reaches
  the caller. See [[event-bus]].

The motivating defect is worth recording: on a default deployment `POST /reg` accepted anonymous
dynamic client registration, so a stranger could mint OAuth clients on a server whose operator had
registration switched off. See [[client-identity-from-database]] for what such a record would grant.

## The route table and its drift guard

`lib/consts/route_classification.ts` declares every mounted route as either gated by a named flag
(15 routes) or explicitly always-available (59). Two mechanisms keep it honest:

- `flag` is typed as `keyof ApplicationConfigType`, so a renamed flag is a compile error rather than
  a silently disabled endpoint.
- A two-way drift guard fails the test suite when a route carries no classification, so a future
  endpoint cannot escape gating unnoticed.

Paths are written in Elysia's declaration form so they compare directly against `elysia.routes`,
sourced from `routeNames` wherever one exists. `lib/plugins/cors.ts` reads the same table, so route
classes serve both the gate and cross-origin policy.

## Related

- [[event-bus]] — where refusals and other lifecycle signals are emitted.
- [[client-identity-from-database]] — the registration endpoints this gate protects.

Verified against [[oauth-server-codebase]] at commit `2125ad0`.
