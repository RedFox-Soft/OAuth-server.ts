---
type: concept
title: "Account resolution (findAccount)"
tags: [contract, architecture, oidc]
sources: [oauth-server-codebase]
created: 2026-07-31
updated: 2026-07-31
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:client-identity-from-database
      source: oauth-server-codebase
      evidence: "const clientId = oidc?.client?.clientId ?? _token?.payload?.clientId; const bucketId = await resolveBucketForClient(clientId);"
      confidence: high
      status: current
---

# Account resolution (findAccount)

`findAccount` is the function that turns a subject identifier into an account object with claims.
In this server it is a direct-import, database-backed resolver at `lib/addon/account.ts:5` — **not**
a configuration option a deployment supplies. Code that expects to override account resolution by
passing a function into configuration is working from the upstream `oidc-provider` model, which this
server no longer follows.

## Signature and inputs

```ts
export async function findAccount(oidc, sub, _token?)
```

- `oidc` — the OIDC context (`ctx.oidc`) for the current request.
- `sub` — the account identifier; equals the user record `_id`.
- `_token` — the token the account is being loaded for. **Undefined at the authorization endpoint**,
  which is why every read of it is optional-chained.

## Bucket resolution mirrors login

The resolver picks the user bucket exactly as login does, via `resolveBucketForClient`
(`lib/admin/auth/resolveBucket.js`), preferring the live client and falling back to the token's
client (`account.ts:11-16`):

```ts
const clientId = oidc?.client?.clientId ?? _token?.payload?.clientId;
const bucketId = await resolveBucketForClient(clientId);
const user = await getUserStore(bucketId).find(sub);
```

The fallback is required because `oidc.client` may not be populated on the token and userinfo flows.
The token side of that expression is also a concrete instance of
[[token-payload-access-contract]] — `_token.payload.clientId`, never `_token.clientId`.

## Active status is enforced at every resolution, not just at login

A missing **or deactivated** user resolves to `undefined` so the calling flow rejects it
(`account.ts:18-24`). The comment states the security property directly: active status is enforced
at every account resolution, so "a user deactivated after login can no longer mint tokens via
refresh/device/CIBA". Deactivation is therefore effective immediately across all grant types rather
than only blocking new logins.

## Claims live on the user record

Extra claims — profile fields and distributed/aggregated claims — are stored on the user record and
merged into the returned account's claims (`account.ts:26-30`). There is no separate claims
configuration and no per-deployment claims override; the provider masks the returned claims by
granted scope automatically. Test harnesses seed accounts together with their claims rather than
supplying overrides.

## Related

- [[client-identity-from-database]] — the client id fed into bucket resolution.
- [[token-payload-access-contract]] — why the token is read through `.payload`.

Verified against [[oauth-server-codebase]] at commit `2125ad0`.
