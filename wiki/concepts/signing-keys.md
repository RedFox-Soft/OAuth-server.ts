---
type: concept
title: "Signing keys: a store, module state, and a provider that holds neither"
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-09-23
updated: 2026-09-29
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

## An addressable bucket signs with keys of its own

Everything above is the **root issuer's** key set, and it is unchanged. Since 2026-09-29 an addressable
bucket — addressed by path or by hostname, it is its own issuer — signs, verifies and decrypts with keys
of its own, held in the `bucketKeys` store area (`BucketKey`, `lib/adapters/types.ts`), so a token one
bucket mints fails signature verification at a resource server trusting another bucket's or the root's
keys. Before, every bucket's `jwks_uri` pointed at the root `/jwks` and tenant separation at a resource
server rested entirely on its `iss` check — the Entra ID model, where skipping that check is a known
class of vulnerability.

- **One seam, `keysFor(bucket)`** (`lib/keys/issuer_keys.ts`). A root-served bucket — default,
  administrators, one with no address — gets the root `keystore`/`publicJWKS` above; an addressable
  one gets its own signing, verification and decryption `KeyStore`s and public set. `IdToken.issue`,
  the JWT access-token format, `IdToken.validate` (id_token_hint) and request-object decryption all ask
  it with the issuing or addressed bucket. It lives outside `configs/keystore.ts`, which stays a leaf.
- **Cached per instance for 30 s** (`KEY_CACHE_SECONDS`) and dropped on this instance's own writes.
  There is no cross-instance messaging in this server, so the TTL bounds how far another instance can
  lag; rotation is written against it (a key is published longer than the TTL before it may sign).
- **The first key is created once, when first needed** (`ensureBucketKey`): an RS256 key inserted under
  the fixed id `<bucketId> #initial`, so concurrent first uses leave exactly one. Lazily on first use for
  a bucket that predates bucket keys — the switch is immediate, with no period on the root keys — and
  not audited on that path, for the reason the root's own first key is not.
- **`/jwks` answers per issuer**: mounted beneath `/:bucket` as well as at the bare path, resolved host
  first like every endpoint, so a tenant hostname serves its tenant's keys; an address naming no bucket
  is 404, never the root's keys. Discovery advertises `jwks_uri` under the issuer and, for a bucket, the
  signing algorithms of its own keys.

**Rotation is the owning group's**, not only a super administrator's (`lib/admin/bucket_keys/`,
`/admin/api/buckets/:id/keys`, the Keys panel on a bucket, MCP `bucket_key_*`): the keys are that
tenant's issuer, and a mistake breaks that tenant alone. Three steps, each written against the 30 s
cache — **generate** publishes a key that does not sign; **promote** is refused until the key has been
published for twice the cache (`KEY_PUBLICATION_SECONDS`), then makes it the signing key of its key type
and returns the one it replaces to published; **retire** keeps a non-signing key published for a day
(`RETIRED_KEY_LIFETIME_SECONDS`, the longest a signed artefact lives). Retiring the signing key is
refused, and so is a promotion that would leave no signing key in an algorithm one of the bucket's
clients requires — the only step that can lose an algorithm, since one key per key type signs. Retire is
the one `high` tool; all three audit against the bucket, audit-first.

What is not observable in the default test run: request-object decryption with a bucket's own
encryption key. The boot-time algorithm list is derived from the root keys the suite preloads, which
hold no encryption key, so an asymmetrically encrypted request object is refused before decryption at
every address alike.

## Related

- [[per-issuer-isolation]] — why a bucket signs with keys of its own, and why the switch had no transition
- [[feature-flag-gating]] — the other module state single-sourced from a store, applied the same way
- [[model-graph-import-order]] — why the keystore must stay a leaf
- [[admin-audit-trail]] — the record every key action writes before it acts
