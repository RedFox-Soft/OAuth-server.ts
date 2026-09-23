---
type: concept
title: "Signing keys: a store, module state, and a provider that holds neither"
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-09-23
updated: 2026-09-23
---

# Signing keys

The server's signing and decryption keys are **not** an environment variable and **not** part of the
provider. They live in the `jwksStore` adapter and are loaded once, at startup, into module state —
the same "module state, single-sourced from a store" shape `ApplicationConfig` has
([[feature-flag-gating]]).

## Where they come from

`resolveKeys` (`lib/configs/keys.ts:21`) reads the store. A non-empty store is used verbatim; an empty
one — the in-memory adapter, or a store nobody provisioned — gets a single RS256 keypair generated and
persisted, so a fresh process can always sign. A provisioned deployment already has one:
`bun run db:setup` and `bun run db:setup:pg` write the initial key during schema creation. Tests seed
the in-memory store from `test/preload.ts`, once, and it is never reset between spec files.

## Two exports, mutated in place

`lib/configs/keystore.ts` exports `keystore` (sign, verify, encrypt, decrypt) and `publicJWKS` (what
`/jwks` serves) at `lib/configs/keystore.ts:37-38`. Import them directly; never reach for them through
`instance(provider)`, which has no configuration and no keys of its own — constructing the provider
only opens the internals map the request path writes to.

Both are **mutated in place and never reassigned**, so a module that imported the reference always sees
the current keys. The admin API relies on this to hot-apply a generated key.

`keystore.ts` is deliberately a leaf: it imports nothing that reaches the adapters, `ApplicationConfig`
or the models. Loading keys means a top-level `await` on the store, and an await inside the model import
graph reorders module evaluation and trips the `base_model → provider → models` cycle — see
[[model-graph-import-order]]. Keeping the loaded result in a leaf keeps the await out of that graph.

## Managing them at runtime

A super administrator views, generates and deletes keys through `lib/admin/jwks/`. The asymmetry
between the two writes is the thing to know:

- **Generation is hot-applied.** `generateKey` (`lib/admin/jwks/service.ts:129`) persists the key and
  appends it to the live keystore, so it can sign immediately; it goes at the end, so the existing key
  keeps signing until a rotation removes it. Every algorithm the server knows is offered
  (`SUPPORTED_ALGS`, `lib/admin/jwks/schema.ts:26`) — RSA only was the old rule, and it meant a FAPI 2.0
  deployment, which needs PS256 or ES256, could not be assembled through the console at all.
- **Deletion waits for a restart.** The key stays served and honoured, reported as `pending removal`,
  because dropping it from the live `/jwks` would break verification of tokens already signed with it.
- A key in an algorithm the process **did not boot with** signs at once but is advertised in discovery
  only after a restart: the algorithm sets are derived once at module scope and nothing re-runs them.
  The state reports `restartRequired` for this separately from key drift, since the remedy is the same
  but the reason is not.

Status is the drift between the persisted store and the boot-time `JWKS_KEYS`. Private members are never
returned. Both writes are audit-first — see [[admin-audit-trail]].

## Related

- [[feature-flag-gating]] — the other module state single-sourced from a store, applied the same way
- [[model-graph-import-order]] — why the keystore must stay a leaf
- [[admin-audit-trail]] — the record every key action writes before it acts
