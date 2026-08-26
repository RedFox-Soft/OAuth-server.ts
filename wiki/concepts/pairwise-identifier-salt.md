---
type: concept
title: 'Pairwise identifiers and the salt they depend on'
tags: [oidc, contract, gotcha, architecture]
sources: [oauth-server-codebase]
created: 2026-08-23
updated: 2026-08-23
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:client-identity-from-database
      source: oauth-server-codebase
      evidence: '.update(client.sectorIdentifier)'
      confidence: high
      status: current
    - predicate: depends_on
      object: concept:account-resolution
      source: oauth-server-codebase
      evidence: "if (this.client.subjectType === 'pairwise' && claims.sub) { claims.sub = await pairwiseIdentifier(claims.sub, this.client); }"
      confidence: high
      status: current
---

# Pairwise identifiers and the salt they depend on

A client registered `subjectType: 'pairwise'` receives a per-sector pseudonym instead of the
account's own identifier. That pseudonym is the relying party's **account key** — how it recognises a
returning person — so it must be reproducible for as long as the account exists.

## The derivation, and where it lives

`pairwiseIdentifier` in `lib/addon/tokens.ts` hashes three inputs in order: the client's sector
identifier, the account id, and the server's salt. The sector comes from
`lib/helpers/sector_identifier.ts` — the host of `sectorIdentifierUri` when set, otherwise the host
of the first redirect URI. Two clients under one host therefore share a pseudonym; clients under
different hosts do not.

It is an **overridable addon**, reached through the accessor at `lib/addon/index.ts:40`, which
resolves the implementation at call time. Four surfaces call it and they all go through that
accessor:

| Surface | Site |
| --- | --- |
| ID token / userinfo claims | `lib/helpers/claims.ts:71` |
| Token introspection | `lib/actions/introspection.ts:101-105` |
| Interaction prompts | `lib/helpers/interaction_policy/prompts/login.ts:71` |
| Back-channel logout notification | via `IdToken.payload()` — see the gotcha below |

One guard in the default implementation therefore covers every surface, and a fifth added later
inherits it.

## The salt is server state, not the hostname

Until spec 023 the third input was `os.hostname()`, with an inline comment calling it unfit for
anything but development. The hostname is not server state — it is a property of whichever container
answered — so a reschedule, a scale-out or a host rename silently handed each relying party a `sub`
it had never seen, and the relying party treated a returning user as a new account. Nothing reported
an error, because from the server's point of view nothing had gone wrong.

The salt is now 32 random bytes resolved once at startup by `lib/configs/pairwiseSalt.ts` and stored
as a fourth singleton document in the shared `serviceConfig` area (see the `STORE_AREAS` comment in
`lib/consts/storage_inventory.ts`, which explains why permanence matters: the area is declared
`reaped: null`, so nothing can expire the salt and cause a silent regeneration).

Two structural choices are worth knowing before touching it:

- **It is module state, not an `ApplicationConfig` key.** The DPoP nonce secret is a config key
  because the validator cross-checks it against `dpop.requireNonce`; nothing cross-checks the salt,
  so a key would only add a catalogue exclusion, a settings-merge exclusion, and a test pinning its
  absence. It follows `lib/configs/keys.ts` instead — key material single-sourced from a store.
- **Resolution is driven from `configs/application.ts`, with the store passed in.** The resolver
  module imports nothing but the store's *type*, and that is load-bearing: its consumer,
  `addon/tokens.ts`, is a leaf the model graph imports, so a store import there would close a cycle
  back into a module still evaluating. Same discipline as `configs/nonceSecret.ts`, and its comment
  says why.

## An unusable salt fails closed, and is never replaced

If the stored value is not 32 bytes of usable material, the server **starts**, serves every client
that needs no pairwise identifier, and refuses the ones that do with `temporarily_unavailable`. It
does not generate a replacement.

This deliberately splits the DPoP nonce secret's behaviour, which *does* replace an unusable value
(`lib/configs/nonceSecret.ts`). Both halves have a reason:

- **Still start**, because the administrative plane is served by this same process — a server that
  will not boot cannot be repaired through any supported surface.
- **Never replace**, because the costs are not comparable. A replaced nonce secret costs each client
  one retry. A replaced salt permanently breaks every relying party's account linkage — and the
  realistic cause of an unusable value is a storage-layer representation defect that recurs on
  *every* read — BSON has no `Buffer`, so a buffer written to MongoDB reads back as the driver's
  `Binary` wrapper, which is not a `Uint8Array` and fails the predicate. That defect took the whole
  server's boot down once (task 35 in `TASKS.md`); unwrapping is the adapter's job, in
  `lib/adapters/mongodb/singletonSecretStore.ts`'s `read()`. A replacing resolver would therefore
  reassign every pairwise identifier on every restart while reporting a healthy boot: the original
  bug, wearing a new hat.

**The refusal lands at the token endpoint, not the authorization endpoint.** The authorization
endpoint issues a code without needing a subject identifier, so it succeeds; refusing there would
mean deriving an identifier nobody asked for purely to fail early.

## Gotcha: the logout notification derives its `sub` a layer away

`lib/actions/end_session.ts:163` passes `session.payload.accountId` — the raw account id — into
`client.backchannelLogout(...)`, and `lib/models/client/backchannel.ts:46` builds the notification as
`new IdToken(client, { sub })`. Grepping `lib/models/id_token.ts` for `pairwise` finds nothing.

All of that is true, and the conclusion "the logout token leaks the account id to pairwise clients"
is still **wrong**. `IdToken.payload()` (`lib/models/id_token.ts:54-62`) builds its claims through
`Claims`, and `Claims.result()` applies the pairwise derivation. The pseudonym has always gone out.

This misreading was made during spec 023's clarification phase and survived into the spec as a
requirement to fix a defect that did not exist. It is recorded here because the shape is reusable:
grepping the file where a behaviour *should* live and reading silence as absence. Following the call
one step further settles it. `test/pairwise/pairwise_logout.spec.ts` now pins the behaviour, which is
worth having precisely because the derivation sits a layer away from the notification.

## Operational consequences

- **Identifiers changed once**, when the version carrying spec 023 first started. Only
  `subjectType: 'pairwise'` clients were affected. After that they never move again — including
  across restarts, reschedules and scale-out.
- **The salt lives in the datastore.** Losing the datastore permanently loses every pairwise
  identifier, the same exposure the signing keys already carry. One backup covers both.
- **There is no rotation surface, and no admin surface at all.** Rotating the salt would invalidate
  every pairwise identifier the server ever issued; that is a product decision, not an operational
  one. The salt appears in no response, no discovery document, no admin API and no audit record.

## Related

- [[client-identity-from-database]] — the client record the sector identifier is read from.
- [[feature-flag-gating]] — why `ApplicationConfig` keys are boot-only, which is the same
  arrangement the salt follows without being a key.
- [[account-resolution]] — the account id that is the derivation's second input.
- [[token-payload-access-contract]] — the `payload.*` discipline that `end_session.ts` reads the
  account id through.
- [[mongodb-test-fidelity]] — the salt shares its store class with the DPoP nonce secret, and that
  class is the one whose BSON round trip broke unnoticed; the two-tier strategy exists to make the
  same lesson unlearnable a second time.
