---
type: concept
title: "Override seams read as dead code"
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-08-28
updated: 2026-08-28
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: subsystem:addon-registry
      source: oauth-server-codebase
      evidence: "return overrides[key] ?? fallback;"
      confidence: high
      status: current
---

# Override seams read as dead code

An addon function with an empty body and no direct importers is not abandoned code. It is the
**default of an extension point**, and deleting it breaks a published API. Issue #19 listed two
such functions as removal candidates on exactly this misreading; both were kept.

## Why the usual liveness check fails here

Source modules never import an addon's default implementation. They import an **accessor** from
`lib/addon/index.ts`, which resolves the active implementation on every call:

```ts
export const assertClaimsParameter: typeof claimsMod.assertClaimsParameter = (
	...args
) => resolve('assertClaimsParameter', claimsMod.assertClaimsParameter)(...args);
```

`resolve` (`lib/addon/registry.ts`) returns `overrides[key] ?? fallback`. Call-time resolution is
the load-bearing detail: an override registered at any point — deployment bootstrap or a test's
setup — takes effect regardless of module load order.

So grepping "who imports `assertClaimsParameter`" finds `lib/addon/index.ts` and stops. The real
call site is one indirection further out, and an importer census reports the function as dead. It
is not: `lib/actions/authorization/check_claims.ts:32` invokes it on every authorization request
carrying a `claims` parameter while `claimsParameter.enabled` is set, and
`lib/shared/token_jwt_auth.ts:91` invokes `assertJwtClientAuthClaimsAndHeader` on every JWT client
authentication.

## The test before deleting an inert-looking function

Follow the accessor, not the importers. A function is a live seam — keep it — when all four hold:

1. an accessor in `lib/addon/index.ts` wraps it in `resolve(key, default)`,
2. its key is present in `AddonImplementations` (`lib/addon/types.ts`),
3. some module outside `lib/addon/` imports that accessor and calls it,
4. `addons.override()` can reach it.

Deleting one breaks all four at once: the call site fails to resolve, `AddonImplementations`
silently narrows, `resolve()` loses the fallback it requires, and a deployment's custom validation
stops running with no error — a security-relevant silent failure, since these hooks exist to
*reject* things.

An empty body means "no additional deployment policy", not "unimplemented". The server's own
spec-mandated validation lives in the caller; the seam is for policy layered on top.

## Document them, and say why the body is empty

Because the emptiness is the trap, the comment has to defuse it — stating that the function is a
seam, naming the call site, and naming `addons.override({ key })`. A comment restating the
signature does not, and the pre-existing ones were worse than absent: `lib/addon/claims.ts`
described its first parameter as a "koa request context" in a server built on Elysia. That also
violates the WHY-not-WHAT comment rule in the constitution's Code Discipline principle.

`sectorIdentifierUriValidate` (`lib/addon/claims.ts`, called from
`lib/helpers/sector_validate.ts:9`) is the same shape with a hardcoded `return true` instead of an
empty body, and is still undocumented — left alone by issue #19 only because it was not on that
issue's list.

## A related trap: resolving a deletion by symbol name

Issue #19 also listed `provider.urlFor` / `pathFor`. `lib/provider.ts` was already gone and
`ProviderClass` has no references, but `oidc.urlFor` — a different function at
`lib/helpers/oidc_context.ts:59` — is live with seven call sites building the device-flow action
URL and the dynamic-registration `registration_client_uri`. Matching the issue's entry by name
would have deleted working code. Resolve removal candidates by **path**, and keep a count of the
colliding symbol as a tripwire across the change.

## Related

- [[feature-flag-gating]] — the other mechanism that makes a code path look unreachable when it is
  merely conditional; both are read from `ApplicationConfig` rather than from control flow.
- [[rich-authorization-requests]] — spec 015 moved RAR rendering to the `'rar-detail'` consent
  group, which is what made the legacy `lib/views/interaction.ts` template safe to delete. Zero
  importers proved nothing loaded it; only the supersession proved nothing needed it.
- [[html-response-security-policy]] — the CSP constructor that superseded `script_src_sha.ts`,
  another entry that had already been handled by the time the sweep ran.
- [[model-graph-import-order]] — the other place where indirection through a registry defeats a
  naive import-graph reading.
