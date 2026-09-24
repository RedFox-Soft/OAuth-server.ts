---
type: concept
title: "Token payload access contract"
tags: [contract, gotcha, architecture]
sources: [oauth-server-codebase]
created: 2026-07-31
updated: 2026-09-24
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:client-identity-from-database
      source: oauth-server-codebase
      evidence: "BaseTokenPayload composes `clientId: t.String()`, and BaseToken resolves the client from it."
      confidence: high
      status: current
---

# Token payload access contract

Every persisted model in this server keeps its state in a single `payload` object, and that object
is the only place field values live. `token.payload.clientId` is correct;
`token.clientId` is not a shorter spelling of it — it is `undefined`. The distinction is invisible
at the type level in the places that matter most, which is what makes it a recurring source of
bugs rather than a stylistic detail.

## The mechanism

`BaseModel` holds one property, `payload`, assigned in the constructor after the payload is
validated against the model's TypeBox schema (`lib/models/base_model.ts:24-34`). A payload that
fails `Value.Check` throws `TypeError('invalid payload')`, so a constructed model always carries a
schema-valid payload. Everything else on the class — `jti`, `exp`, TTL handling, persistence —
reads and writes through `this.payload` (`lib/models/base_model.ts:44-72`, `144-159`).

There are no generated per-field accessors. An earlier design mirrored payload fields onto the
instance via an `IN_PAYLOAD` list; that indirection was removed, and the only surviving reference
to it in the tree is a comment in `lib/actions/registration.ts:120` explaining why one call site
still reads `client.*` directly (a validated client is a plain object, not a model).

## What is persisted: only what the schema declares

Every persisted model — the tokens, `Grant`, `Session`, `Interaction`, `ReplayDetection` — stores only
the top-level keys its TypeBox schema declares (`getValueAndPayload`, `lib/models/formats/opaque.ts:28`).
A field a model must persist is added to that schema; there is no whole-payload fallback, so an
undeclared field is dropped on save without an error.

The filter is **shallow** on purpose, and must not be replaced with `Value.Clean`. Several persisted
fields are freeform — `claims`, `rar`, `params`, `session.state` — and `Value.Clean` recurses into
nested object schemas and would prune them to `{}`, silently losing ID token and userinfo claims.

## Finding a model: `tryFind` or `find`

Every `BaseModel`/`BaseToken` subclass, and the `Client` namespace (`lib/models/client.ts:62`), has two
static lookups sharing one set of semantics — verification, expiry, session binding, policy — and
differing only on a miss:

- `tryFind(id, opts?)` returns `undefined`: use it where absence is a handled outcome.
- `find(id, opts?)` **throws**: use it where the item is required, so the call site needs no `undefined`
  check and no non-null assertion. It throws `opts.error` if given, otherwise the model's
  `static notFoundError` (`lib/models/base_model.ts:94`) — `InvalidToken` for the token hierarchy,
  `InvalidClient` for `Client`.

`find` delegates to `tryFind`, which is why a test simulates a miss with `spyOn(Model, 'tryFind')`:
mocking `find` would bypass the throw path it exists to exercise.

## Why reading a bare field is a latent bug, not a type error

The failure is silent. Reading `token.clientId` yields `undefined`, and `undefined` flows onward as
"no client" rather than raising — so the defect surfaces far from its cause, as an authorization
failure or a mis-scoped token. This is how it broke CIBA: the delivery path read the client id off
the instance instead of the payload.

**The second recorded instance was inside an accessor, which is worse.** `OIDCContext` exposed
`get acr() { return this.session.acr; }` — one indirection away from every call site, so each caller
read `oidc.acr` and looked entirely correct. `Session` keeps `acr` on its payload, so the getter
returned `undefined` unconditionally, and the interaction policy compared a requested authentication
context against it. The result was not a mis-scoped token but a **permanently unsatisfiable protocol
feature**: an essential `acr` request could never be met, and the end user was returned to the login
page forever. `amr` had the identical defect on the next line. See
[[authentication-context-reporting]].

The general lesson the two instances share: when the bare read is hidden behind a getter, the
contract cannot be enforced by reviewing call sites, because the call sites are right. It has to be
enforced where the getter is written.

**The request context's entity store was the third place, and it is now typed.** Until
`060-typed-oidc-context`, `oidc.entities` was an untyped bag keyed by strings, so a bare read through
it compiled. Two had lived there unnoticed: `oidc.entities.Interaction?.cid` and
`oidc.entities.Interaction?.deviceCode`, both fields that exist only on the interaction's payload, so
both read `undefined` for as long as they existed (the first fed a value nothing read; the second sat
in a module nothing imported). `OIDCEntities` in `lib/helpers/oidc_context.ts` now declares every
entity with its model type and `entity()`/`entities` are checked against it, so the same read is a
compile error. The reads follow one rule: a getter (`oidc.client`, `oidc.session`) is a guarantee
and throws a server defect when its entity is absent, `oidc.require(name)` is the same for any other
entity, and whatever may legitimately be absent — a grant before consent, an account before sign-in —
is read as `oidc.entities.X?`, so the `?.` at the call site says which of the two the reader relies on.

The request's own parameters are typed the same way since `061-typed-request-params`:
`PipelineParams` and `TokenParams` are derived from the schemas the endpoints validate against
(`lib/consts/param_list.ts`, `lib/actions/token.ts`), closed so a misspelt member is a compile error.
Where a step needs a parameter a caller has already checked with `presence`, it declares that with
`PipelineParamsWith<'name'>`, and `presence` — an assertion function — narrows the caller's context to
match. `claims` members are `unknown` until read through `claimRequest()`
(`lib/helpers/claim_request.ts`): the server accepts any JSON value there, so a member is only a claim
request once a reader has checked it is an object. Typing them caught the contract broken twice more:
`pushedAuthorizationRequest.trusted` (the flag lives on `payload.trusted`, so a pushed request was never
trusted) and `session.state` (written off the payload, so the sign-out confirmation after an account
change always failed). Both are fixed.

Code that must tolerate a partially populated context reaches through the payload explicitly, for
example `lib/addon/account.ts:14`:

```ts
const clientId = oidc?.entities.Client?.clientId ?? _token?.payload?.clientId;
```

Note the asymmetry in that line, which is the contract in miniature: the client is a validated
client object and is read directly (through `entities`, because on the userinfo path none may be
resolved), while the token is read through `.payload`. See
[[client-identity-from-database]] for why validated clients are plain objects.

## Payload schemas are composed, not inherited flat

`lib/models/base_token.ts:13-38` builds token payloads from three pieces, and which pieces a model
composes is a deliberate persistence decision:

- `BaseTokenPayload` — the shared base, adding `clientId` to `BaseModelPayload`.
- `SessionBoundPayload` — `expiresWithSession`, `sessionUid`, `accountId`, `grantId`. Composed only
  into session-bound schemas (access, authorization code, refresh, device, backchannel) and
  deliberately excluded from the shared base "so tokens like ClientCredentials do not persist
  them".
- `AudiencePayload` — `aud`, composed only into schemas that persist an audience (access tokens and
  client credentials), per RFC 8707 resource indicators.

So the absence of a field on a given token type is a designed property of that type. Adding a field
to `BaseTokenPayload` to make one flow convenient silently changes what every other token type
persists.

## Related

- [[deletion-and-revocation]] — owner fields live under `.payload.*`, which is what an owner sweep queries.
- [[model-graph-import-order]] — the same `base_token` cycle, seen from the import side.
- [[account-resolution]] — reads `_token.payload.clientId` to resolve the user bucket.
- [[client-identity-from-database]] — the validated-client object this contract does *not* apply to.
- [[event-bus]] — why `base_token` → `base_model` → event bus module cycles matter for initialisation.
- [[authentication-context-reporting]] — the second instance of this contract being broken, and the
  one that cost a protocol feature rather than one delivery path.

Verified against [[oauth-server-codebase]] at commit `2125ad0`, except the accessor instance above,
which is verified at `4101b93`.
