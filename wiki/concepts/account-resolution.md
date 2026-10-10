---
type: concept
title: "Account resolution (findAccount)"
tags: [contract, architecture, oidc]
sources: [oauth-server-codebase]
created: 2026-07-31
updated: 2026-10-10
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:client-identity-from-database
      source: oauth-server-codebase
      evidence: "const bucketId = await resolveBucketForRequest(clientId, resource, oidc?.bucket ?? DEFAULT_REQUEST_BUCKET);"
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
export async function findAccount<P extends Record<string, unknown> & { resource?: string | readonly string[] }>(
	oidc: OIDCContext<P> | undefined,
	sub: string | undefined,
	_token?: AccountToken // { payload: { clientId?, resource? } }
)
```

- `oidc` — the request context (`OIDCContext`) for the current request. Generic over the endpoint's
  parameters (authorization or token), because all it reads from them is `resource`.
- `sub` — the account identifier; equals the user record `_id`. **May be absent**: a token issued to
  no account (client credentials) carries none, and that resolves to `undefined` before any bucket is
  looked up.
- `_token` — the token the account is being loaded for. **Undefined at the authorization endpoint**,
  which is why every read of it is optional-chained.

(Typed on 2026-09-24; until then all three parameters were implicit `any`.)

## Bucket resolution mirrors login

> **Narrowed once buckets became tenants.** `resolveBucketForRequest` no longer decides which bucket a
> *request* belongs to — the address does, and a request to a bare path is the default bucket's. What
> it still answers, and what this page describes, is which bucket a given **client** belongs to: the
> question `findAccount` asks to know which population to look a subject up in, and the question the
> cross-address refusal checks a client against. See [[bucket-is-an-issuer]].

The resolver picks the user bucket exactly as login does, via `resolveBucketForRequest`
(`lib/admin/auth/resolveBucket.js`), preferring the live client and falling back to the token's
client (`account.ts:11-16`):

```ts
const clientId = oidc?.entities.Client?.clientId ?? _token?.payload?.clientId;
const resource = oidc?.params?.resource ?? _token?.payload?.resource;
const bucketId = await resolveBucketForRequest(
	clientId,
	resource,
	oidc?.bucket ?? DEFAULT_REQUEST_BUCKET
);
const user = await getUserStore(bucketId).find(sub);
```

The third argument is the bucket whose address the request arrived at, required since 2026-09-29:
rule 3 reads a declared resource only in that issuer's namespace ([[mcp-server-authorization]]), so a
caller that could omit it would resolve against every tenant's declarations again.

The fallback is required because `oidc.client` may not be populated on the token and userinfo flows.
The token side of that expression is also a concrete instance of
[[token-payload-access-contract]] — `_token.payload.clientId`, never `_token.clientId`.

## The account carries the bucket it was read from

Since 2026-10-10 (spec 076) the returned account also carries `bucketId` — the bucket resolved above — and
`provisioned`, whether a directory created it (`lib/addon/account.ts:78-79`). The activity recorder reads
them instead of deriving the population again ([[monthly-active-users]]): a second derivation is how a
console session reused at the root, whose token records the default bucket, would have counted an
administrator in the default bucket's figure. An overriding resolver must return both; the `Account` type is
derived from this function's return, so the compiler says so.

## Active status is enforced at every resolution, not just at login

A missing **or deactivated** user resolves to `undefined` so the calling flow rejects it
(`account.ts:61`). The comment states the security property directly: active status is enforced
at every account resolution, so "a user deactivated after login can no longer mint tokens via
refresh/device/CIBA". Deactivation is therefore effective immediately across all grant types rather
than only blocking new logins.

Since spec 069 the test is `canSignIn(user)` — `active && !lockedLocally` — shared with both sign-in
doors, and this lazy check is no longer the whole of deactivation: the admin operation also ends the
user's sessions, grants and tokens and notifies relying parties at once. See [[end-user-lifecycle]].

## Claims live on the user record

Extra claims — profile fields and distributed/aggregated claims — are stored on the user record and
merged into the returned account's claims (`account.ts:80-86`). Since spec 069 a provisioned `profile`
also yields standard claims through `lib/consts/profile_claims.ts`, merged before the stored claims so
an administrator's value still wins ([[end-user-lifecycle]]). There is no separate claims
configuration and no per-deployment claims override; the provider masks the returned claims by
granted scope automatically. Test harnesses seed accounts together with their claims rather than
supplying overrides.

## Related

- [[client-identity-from-database]] — the client id fed into bucket resolution.
- [[token-payload-access-contract]] — why the token is read through `.payload`.
- [[admin-audit-trail]] — per-bucket storage is why an audited end-user action records its bucket
  alongside the user id.

- [[group-ownership]] — which administrators may administer a bucket's end-users, now resolved through the group that owns it.
Verified against [[oauth-server-codebase]] at commit `2125ad0`.
