---
type: entity
kind: subsystem
title: "Addon override registry (lib/addon/)"
aliases: [addons, override registry, resolve, lib/addon]
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-09-01
updated: 2026-09-24
graph:
  node_id: subsystem:addon-registry
  node_type: subsystem
  canonical: true
  relationships:
    - predicate: implements
      object: concept:override-seams-vs-dead-code
      source: oauth-server-codebase
      evidence: "The override seam. Deployments and tests replace behavior here; source modules never read these functions off the merged configuration."
      confidence: high
      status: current
    - predicate: constrained_by
      object: concept:model-graph-import-order
      source: oauth-server-codebase
      evidence: "lib/addon/types.ts:2 states the reason for the type-only signatures: 'Uses type-only typeof import(...) so this module pulls in NO runtime code' — which is what lets the test preload import the registry without loading the model graph."
      confidence: high
      status: current
---

# Addon override registry (lib/addon/)

The server's single seam for replaceable behaviour. Where `oidc-provider` took overridable functions
off a merged configuration object, this takes them off a call-time registry — and the difference is
what makes an override work regardless of module load order.

## Three files carry the mechanism

`registry.ts` holds the mutable map and the resolver:

```ts
const overrides: Partial<AddonImplementations> = {};

export function resolve<K extends keyof AddonImplementations>(
    key: K,
    fallback: AddonImplementations[K]
): AddonImplementations[K] {
    return overrides[key] ?? fallback;
}
```

`types.ts` declares the signature of every overridable function as `typeof import(...)` — **type-only,
so the module pulls in no runtime code**. `index.ts` exports one accessor per key, each resolving at
call time against its addon-module default.

Since 2026-09-24 each signature is wrapped in `Overridable<...>`: an override may answer synchronously
where the default is async, because every caller awaits. An accessor whose default is async is itself
`async`, so its callers always receive a promise whatever the override returns. The extension seams
whose default only warns and throws (CIBA's `processLoginHint`, `validateBindingMessage`, …) declare
their contract's return type explicitly, and `getResourceServerInfo` answers a `ResourceServerInfo`
(`lib/helpers/resource_server.ts`); a signature inferred from a stub had said `Promise<void>`.

That layering is deliberate and load-bearing. Because `registry.ts` and `types.ts` import no runtime
code, the registry can be imported anywhere — including the test preload — without loading the addon
modules and, through them, the model graph. See [[model-graph-import-order]] for what happens when
that graph is entered cold.

## Resolution happens at call time

```ts
export const findAccount: typeof accountMod.findAccount = async (...args) =>
    resolve('findAccount', accountMod.findAccount)(...args);
```

Every accessor re-resolves on every call rather than capturing at import. An override registered at
any point — deployment bootstrap or a test's `beforeEach` — therefore takes effect immediately, and
no module needs to be imported in a particular order for it to apply.

Source modules import these accessors; they **never** read the functions off the merged
configuration. A global `afterEach` in `test/preload.ts` calls `addons.reset()`, which deletes each
key rather than reassigning the object, so suites stay isolated without the map identity changing.
It resets to a **baseline**, not to empty: `test/addon_baseline.ts` takes a `*.config.ts`'s `addons`
export as the spec's baseline when `bootstrap()` runs, so a per-test `addons.override(...)` is wiped
after each case while the config-declared overrides persist across the spec, and never into the next
file.

## One calling convention

Every key that needs the request takes the request context itself, `oidc: OIDCContext`, as its first
argument; the four that do not (`assertJwtClientAuthClaimsAndHeader`, `pairwiseIdentifier`,
`sectorIdentifierUriValidate`, `interactionPolicy`) take none. Until `060-typed-oidc-context` about
twenty keys instead received `{ oidc }` — the shape of the Koa request object this server was ported
from, built at every call site only to be taken apart inside — while three already took the context,
so an override had to know which convention each key used. Interaction-policy `check`/`details`
functions, registration policies and RAR type validators follow the same convention. Token lifetime
functions (`ttl.*`) are not addon keys and take no context at all — see [[refresh-token-chain-bound]].

`deviceInfo` became reachable in the same change: the device authorization endpoint used to build the
record itself, so an override of the key had no effect on any request.

## The census trap

This is the failure this subsystem is most likely to cause, and it is documented at length in
[[override-seams-vs-dead-code]]. Because source modules import the *accessor* from `lib/addon/index.js`
rather than the implementation in `lib/addon/account.js`, an importer census run over the
implementation modules reports live seams as dead code. An empty addon body is an extension point's
default, not an abandoned stub.

The companion hazard: resolving a removal candidate by symbol name instead of by path nearly deleted
a live `urlFor`.

## The keys

Thirty-odd keys grouped by the module that supplies the default: `account` (`findAccount`,
`loadExistingGrant`), `tokens` (`issueRefreshToken`, `rotateRefreshToken`, `pairwiseIdentifier`,
`idFactory`, `secretFactory`, `expiresWithSession`), `claims`, `resources`, `interactions`,
`introspection`, `mtls`, `ciba`, `rar`, and `default` (JWT client-auth assertion). `_warn.ts` exports
`shouldChange` / `mustChange`, the markers for defaults a deployment is expected to replace.

## Related

- [[override-seams-vs-dead-code]] — why an empty body is a seam, and the census that misread them.
- [[account-resolution]] — `findAccount` is one of these keys, and a direct-import DB resolver rather than a config option.
- [[model-graph-import-order]] — the cycle this module's type-only imports are designed to avoid entering.
- [[pairwise-identifier-salt]] — a seam whose default is deliberately not deployment-ready.
- [[refresh-token-chain-bound]] — what bounds the tokens `rotateRefreshToken` decides to rotate.
