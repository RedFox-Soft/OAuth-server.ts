---
type: entity
kind: subsystem
title: "Addon override registry (lib/addon/)"
aliases: [addons, override registry, resolve, lib/addon]
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-09-01
updated: 2026-09-01
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

That layering is deliberate and load-bearing. Because `registry.ts` and `types.ts` import no runtime
code, the registry can be imported anywhere — including the test preload — without loading the addon
modules and, through them, the model graph. See [[model-graph-import-order]] for what happens when
that graph is entered cold.

## Resolution happens at call time

```ts
export const findAccount: typeof accountMod.findAccount = (...args) =>
    resolve('findAccount', accountMod.findAccount)(...args);
```

Every accessor re-resolves on every call rather than capturing at import. An override registered at
any point — deployment bootstrap or a test's `beforeEach` — therefore takes effect immediately, and
no module needs to be imported in a particular order for it to apply.

Source modules import these accessors; they **never** read the functions off the merged
configuration. A global `afterEach` in `test/preload.ts` calls `addons.reset()`, which deletes each
key rather than reassigning the object, so suites stay isolated without the map identity changing.

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
