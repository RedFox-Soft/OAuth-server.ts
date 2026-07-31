---
type: concept
title: "Token payload access contract"
tags: [contract, gotcha, architecture]
sources: [oauth-server-codebase]
created: 2026-07-31
updated: 2026-07-31
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

## Why reading a bare field is a latent bug, not a type error

The failure is silent. Reading `token.clientId` yields `undefined`, and `undefined` flows onward as
"no client" rather than raising — so the defect surfaces far from its cause, as an authorization
failure or a mis-scoped token. This is how it broke CIBA: the delivery path read the client id off
the instance instead of the payload.

Code that must tolerate a partially populated context reaches through the payload explicitly, for
example `lib/addon/account.ts:14`:

```ts
const clientId = oidc?.client?.clientId ?? _token?.payload?.clientId;
```

Note the asymmetry in that line, which is the contract in miniature: `oidc.client` is a validated
client object and is read directly, while the token is read through `.payload`. See
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

- [[account-resolution]] — reads `_token.payload.clientId` to resolve the user bucket.
- [[client-identity-from-database]] — the validated-client object this contract does *not* apply to.
- [[event-bus]] — why `base_token` → `base_model` → event bus module cycles matter for initialisation.

Verified against [[oauth-server-codebase]] at commit `2125ad0`.
