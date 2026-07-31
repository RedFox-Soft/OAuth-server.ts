---
type: concept
title: "Client identity from the database"
tags: [contract, architecture, oauth]
sources: [oauth-server-codebase]
created: 2026-07-31
updated: 2026-07-31
graph:
  node_type: concept
---

# Client identity from the database

`adapter('Client')` is the single source of client identity in this server. There is no
`staticClients` or `dynamicClients` configuration option and no `clients` array to seed at boot —
a client exists because a record exists. Every lookup goes through `Client.tryFind` / `Client.find`,
which read the adapter on **every call**.

## The lookup and its memo

`tryFindClient` (`lib/models/client/validate.ts:208-228`) reads the adapter first, and only then
consults a cache:

```ts
const properties = await adapter('Client').find(id);
if (!properties) return;
const propHash = crypto.hash('sha256', JSON.stringify(properties), 'base64url');
let client = clientCache.get(propHash);
if (!client) {
  client = await addClient(properties, { store: false });
  clientCache.set(propHash, client);
}
```

The cache is keyed by a hash of the stored properties, not by client id. That is what makes it a
*validation* memo rather than a client cache: changed properties hash differently, so the entry is
missed and the client is re-validated, while an unchanged client skips the work. Updates and deletes
are reflected immediately because the adapter read is unconditional — the comment at
`validate.ts:201-207` ties this to FR-009 and the security-first principle, since a stale-metadata
window would let a revoked or edited client keep operating.

The store is a size-bounded `QuickLRU` with `maxSize: 100` and **no time-based expiry**
(`validate.ts:197-199`). The comment records why entries are not evicted on a timer: doing so would
"drop entries out from under in-flight resolutions".

## Client is a namespace function, not a class

`lib/models/client.ts:52-81` collapses what used to be a class:

- `export type Client = ClientSchemaType` — the validated-object type, kept under the historical
  name so existing `import { type Client }` sites still resolve.
- `export function Client(metadata)` returns `validateClient(metadata)`, with
  `Client.prototype = clientPrototype` so `value instanceof Client` still holds for validated
  objects.
- Former statics hang off the function: `Client.tryFind`, `Client.find`, `Client.validate`,
  `Client.needsSecret`, and an `adapter` getter.

A validated client is therefore a plain object, which is why call sites read `client.clientId`
directly rather than through a payload — the opposite of the rule for models in
[[token-payload-access-contract]].

Two details in this file are load-bearing for tests. `Client.find` deliberately calls
`Client.tryFind` through the property rather than the imported binding, so that
`spyOn(Client, 'tryFind')` is honoured (`client.ts:66`). And `Client.find` throws `InvalidClient`
by default, with callers passing `{ error }` when their flow needs a different OAuth error code
(`client.ts:63-72`).

## Consequences

Because identity lives in the database, every client is manageable at runtime — there is no
non-manageable tier for clients declared in configuration, so the admin plane can edit any of them.
Tests seed clients through a `seedClient` helper rather than by configuring them.

New admin-plane code should call `adapter('Client')` directly rather than the `Client.adapter`
getter; the getter exists for the historical call sites.

## Related

- [[token-payload-access-contract]] — models keep state under `.payload`; validated clients do not.
- [[account-resolution]] — maps a client id to the user bucket a subject is resolved from.
- [[feature-flag-gating]] — the registration endpoints that create clients are flag-gated.

Verified against [[oauth-server-codebase]] at commit `2125ad0`.
