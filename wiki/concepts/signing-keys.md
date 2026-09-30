---
type: concept
title: "Signing keys: one lifecycle for every issuer, and a provider that holds none"
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-09-23
updated: 2026-09-30
---

# Signing keys

The server's signing and decryption keys are **not** an environment variable and **not** part of the
provider. Every issuer's keys — the root issuer's and each addressable bucket's — are records of one
store area, `bucketKeys` (`BucketKey`, `lib/adapters/types.ts`), and follow one lifecycle.

Corrected 2026-09-30 (spec 063): the root keys used to live in their own `jwksStore` area as flat JWKs
with no state, loaded once at boot by `lib/configs/keys.ts`, so deleting one waited for a restart. That
area, its three adapters and `configs/keys.ts` are gone; the root is now the owner `'#root'`
(`ROOT_KEY_OWNER`, `lib/consts/key_owner.ts:7`) in the same area.

## Where they come from

`rootKeys()` (`lib/keys/issuer_keys.ts:181`) assembles the `'#root'` records through the same 30-second
cache every bucket uses. The first key is created exactly once: `ensureRootKey()`
(`lib/keys/issuer_keys.ts:135`) inserts an RS256 key under the fixed id `'#root #initial'` with
`createIfAbsent`, so concurrent first boots leave one. Boot calls `rootKeys()` right after the migration
gate (`lib/index.ts:227`); `bun run db:setup` and `bun run db:setup:pg` write the same first key, and
write none while legacy keys still await the migration below. Tests seed the in-memory store from
`test/preload.ts` (`writeRootKeys`, `test/root_keys.ts`), once, and it is never reset between spec files.

## The mirror, mutated in place

`lib/configs/keystore.ts` exports `keystore` and `publicJWKS` (`lib/configs/keystore.ts:38-39`). They are
now a **mirror** of the root set, refreshed in place by `rootKeys()` on every fresh reload through
`loadKeys` (`lib/configs/keystore.ts:80`) — never reassigned, so a module that imported the reference sees
the current keys. The mirror holds only the **signing and encryption** keys, not every published one: the
algorithm lists (`lib/configs/jwaAlgorithms.ts`) are functions of the live `publicJWKS`, and a key that
cannot sign yet must not have its algorithm advertised or accepted at client registration.

Sign, verify and decrypt through `keysFor(bucket)` (`lib/keys/issuer_keys.ts:203`), which answers a
root-served bucket with `rootKeys()`. Readers that ran against the mirror before any request had loaded
it — root discovery, the administrator ID Token check (`lib/admin/auth/verifyIdToken.ts`),
`tryFindClient`, `registerClient` — now `await rootKeys()` first. Never reach for keys through
`instance(provider)`, which has none.

`keystore.ts` is deliberately a leaf: it imports nothing that reaches the adapters, `ApplicationConfig`
or the models. An await inside the model import graph reorders module evaluation and trips the
`base_model → provider → models` cycle — see [[model-graph-import-order]]. The awaiting happens in
`issuer_keys.ts`, outside that graph.

## The lifecycle — generate, promote, retire, hidden

One core, `lib/admin/key_lifecycle.ts`, serves both owners: the root (`lib/admin/jwks/`, super
administrators) and a bucket (`lib/admin/bucket_keys/`, its owning group). Each is a `KeyOwner`
(`lib/admin/key_lifecycle.ts:24`) naming its audit verb and its cache invalidator. Every step is written
against the 30 s cache (`KEY_CACHE_SECONDS`, `lib/keys/issuer_keys.ts:33`), because there is no
cross-instance messaging and the TTL is how far another instance can lag:

- **generate** (`:101`) stores a *published* key — served in `/jwks`, verifying, not signing. Every
  algorithm the server knows is offered (`SUPPORTED_ALGS`); RSA-only once meant a FAPI 2.0 deployment
  could not be assembled from the console at all.
- **promote** (`:134`) is refused (409 `too_soon`) until the key has been published for twice the cache
  (`KEY_PUBLICATION_SECONDS`, `:36`), so no instance signs with a key another instance does not serve. It
  makes the key the signer **of its algorithm** and returns that algorithm's previous signer to
  published — the new signer is written first, so there is no moment without one.
- **retire** (`:184`) requires `{ confirm: <kid> }` — checked before anything else, refused 422
  `confirmation_mismatch` — because nothing it signed verifies once its window closes. The console makes
  the operator type the kid; the MCP tools `jwks_retire` and `bucket_key_retire` are `high` as well.
  Retiring a signing key is refused (409), so an algorithm never loses its signer.
- A retired key stays published for a day (`RETIRED_KEY_LIFETIME_SECONDS`, `:43`, the longest a signed
  artefact lives) and is then **hidden, not deleted**: absent from `/jwks`, the view and every
  verification, its record kept, 404 to every operation.

None of it needs a restart. All three are audit-first — see [[admin-audit-trail]].

**One signer per algorithm, not per key type.** Decided 2026-09-30: RS256 and PS256 share the RSA key
type, and an issuer with a default client (RS256, constitution §VI as amended in 3.1.0) and a FAPI client
(PS256) needs a signer in each. With that rule a promotion only replaces its own algorithm's signer, so no
operation can leave a client's algorithm unsigned — the "required algorithm" refusal the bucket keys used
to carry became unreachable and was removed.

## Upgrading a deployment

The migration `2026-09-30-root-keys-lifecycle` (`lib/consts/migrations.ts:254`, applied by
`bun run db:migrate`) moves the legacy flat keys into `'#root'` records and deletes them. Per algorithm
the signer is the key the old server would have picked — the first in MongoDB's natural order; PostgreSQL
has no order, so there the **lowest kid** (`rootSignersOf`, `:199`). The chosen signers are printed.
Everything else is published, with timestamps of the migration time, so a migrated key is not promotable
until the window passes. Both halves are checked against real databases by `database/verify_mongodb.ts`
and `database/verify_postgres.ts`.

## An addressable bucket signs with keys of its own

Since 2026-09-29 an addressable bucket — addressed by path or by hostname, it is its own issuer — signs,
verifies and decrypts with keys of its own, so a token one bucket mints fails signature verification at a
resource server trusting another bucket's or the root's keys. Before, every bucket's `jwks_uri` pointed at
the root `/jwks` and tenant separation at a resource server rested entirely on its `iss` check — the Entra
ID model, where skipping that check is a known class of vulnerability.

- `keysFor` gives an addressable bucket its own signing, verification and decryption `KeyStore`s and
  public set; `IdToken.issue`, the JWT access-token format, `IdToken.validate` (id_token_hint) and
  request-object decryption all ask it with the issuing or addressed bucket.
- **The first key is created once, when first needed** (`ensureBucketKey`, `lib/keys/issuer_keys.ts:111`):
  an RS256 key under the fixed id `<bucketId> #initial`. Lazily on first use for a bucket that predates
  bucket keys, and not audited on that path, for the reason the root's own first key is not.
- **`/jwks` answers per issuer**: mounted beneath `/:bucket` as well as at the bare path, resolved host
  first like every endpoint, so a tenant hostname serves its tenant's keys; an address naming no bucket
  is 404, never the root's keys. Discovery advertises `jwks_uri` under the issuer and, for a bucket, the
  signing algorithms of its own keys.
- A bucket served at the root has no keys of its own: its key routes answer 409 and the console sends the
  operator to the instance Keys page.

What is not observable in the default test run: request-object decryption with a bucket's own
encryption key. The algorithm list is derived from the root keys the suite preloads, which hold no
encryption key, so an asymmetrically encrypted request object is refused before decryption at every
address alike.

## Related

- [[per-issuer-isolation]] — why a bucket signs with keys of its own, and why the switch had no transition
- [[feature-flag-gating]] — the other module state single-sourced from a store, applied the same way
- [[model-graph-import-order]] — why the keystore must stay a leaf
- [[admin-audit-trail]] — the record every key action writes before it acts
- [[postgresql-backend]] — how a declared migration is applied, and why startup refuses a database behind
