---
type: entity
kind: subsystem
title: "Elysia lifecycle plugins (lib/plugins/)"
aliases: [plugins, onRequest, lifecycle hooks, lib/plugins]
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-09-01
updated: 2026-09-01
graph:
  node_id: subsystem:elysia-lifecycle
  node_type: subsystem
  canonical: true
  relationships:
    - predicate: implements
      object: concept:non-html-response-hardening
      source: oauth-server-codebase
      evidence: "export const securityHeaders = (app: Elysia) => { return app.onRequest(({ set }) => { set.headers['X-Content-Type-Options'] = 'nosniff'; ... }) }"
      confidence: high
      status: current
    - predicate: implements
      object: concept:per-origin-rate-limiting
      source: oauth-server-codebase
      evidence: "lib/plugins/rateLimit.ts is mounted before featureGate in lib/index.ts, with the comment: 'Counted first, both answer identically in both states.'"
      confidence: high
      status: current
---

# Elysia lifecycle plugins (lib/plugins/)

The cross-cutting hooks every response passes through before routing. Eight modules —
`auth`, `coerce_array_params`, `cors`, `featureGate`, `noCache`, `noQueryDup`, `rateLimit`,
`securityHeaders` — plus the mount order in `lib/index.ts` that makes them correct.

## Callback-shaped, not named instances

Every plugin here takes the caller's instance and returns it:

```ts
export const securityHeaders = (app: Elysia) => {
    return app.onRequest(({ set }) => { ... });
};
```

A callback receives the caller's instance, so the hook is **inlined there** and applies to that
instance's routes and descendants only. No `as: 'scoped'` reasoning, and no way for a header to leak
onto a sibling route.

The cost of that choice is stated at `lib/plugins/cors.ts:33`: **registration order matters**. A hook
only affects routes declared after it, so every `.use(...)` must precede the route it protects.

## Mount order is correctness, not performance

The ordering comments in [lib/index.ts](lib/index.ts) are the load-bearing part of this subsystem.
Read them before reordering anything.

`nocache` → `securityHeaders` → `rateLimit` → `featureGate` → `corsPreflight` → routes.

- **`rateLimit` must precede `featureGate`.** This looks like an optimisation and is a correctness
  call. Were the gate to run first, a capability-disabled endpoint would answer 404 without ever
  being counted, while an unserved path would be counted and answer 429 under load — the two become
  distinguishable, which is precisely the fingerprint `featureGate` exists to eliminate. Counted
  first, both answer identically in both states. See [[per-origin-rate-limiting]] and
  [[feature-flag-gating]].
- **`featureGate` must follow `nocache` and `securityHeaders`.** `onRequest` hooks run in
  registration order and a gate refusal *throws*, so gating first would skip the `no-store` and
  hardening headers every other response carries.
- **`corsPreflight` must follow all of them.** It answers preflights by short-circuiting, which ends
  the `onRequest` chain: mounted before `nocache` it would omit `no-store` from the 204, and before
  `featureGate` it would confirm an endpoint whose capability is switched off.

## Which hook, and why that one

The queue is Request → Parse → Transform → Validation → BeforeHandle → Handle, and the choice of
stage is argued per plugin rather than defaulted.

`securityHeaders` uses `onRequest` rather than `mapResponse` or `onAfterHandle`. Both alternatives
were built and measured in spec 018 (research.md M9) and neither fires for a response the error
handler builds, nor for the named `adminApp` instance — the two surfaces carrying the most sensitive
responses, failing silently in both cases. `onRequest` precedes routing, so it reaches every response
the server emits: handler returns, raw `Response`s, error-pipeline output, named and unnamed
sub-apps, and static files. Being pre-routing also makes it immune to the registration-order
constraint above.

CORS uses `onTransform`, not `onBeforeHandle`. Client authentication happens in `AuthPlugin`'s
`derive`, which runs in the transform queue and throws `invalid_client` from there; body-schema
failures raise a 422 in validation immediately after. Both precede `beforeHandle`, so a header
written there would be absent from exactly the responses a misconfigured browser app hits most — the
401 and the 422. `set.headers` survives onto the error response because the global handler mutates
`set` rather than building its own `Response`.

## One writer per header

`Cache-Control` belongs to `noCache`, the CORS headers to `cors`, the baseline profile to
`securityHeaders`, and the page policy to [[html-rendering]] — which is deliberately *not* a plugin
here. Duplicating any of them would give one header two sources, and that is what makes these
debuggable at all.

`securityHeaders` writes `default-src 'none'` unconditionally, including on requests that will render
a page, and that is correct rather than a bug awaiting a content-type check: a page's own returned
`Response` carries its derived policy and wins over the `set.headers` merge without being duplicated
or comma-joined. Adding a content-type branch would recreate the "which responses are pages?"
classification spec 018 concluded a test cannot answer, and hand the page policy a second writer.

## Related

- [[non-html-response-hardening]] — what the baseline profile contains, and the HSTS/Permissions-Policy reasoning.
- [[html-rendering]] — the page path, deliberately outside this subsystem.
- [[per-origin-rate-limiting]] — bounded in-process counters; a resource protection, not a security boundary.
- [[feature-flag-gating]] — the gate that makes a disabled endpoint answer as unserved.
