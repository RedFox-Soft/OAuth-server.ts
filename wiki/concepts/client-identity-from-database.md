---
type: concept
title: "Client identity from the database"
tags: [contract, architecture, oauth]
sources: [oauth-server-codebase]
created: 2026-07-31
updated: 2026-09-23
graph:
  node_type: concept
---

# Client identity from the database

`adapter('Client')` is the single source of client identity in this server. There is no
`staticClients` or `dynamicClients` configuration option and no `clients` array to seed at boot —
a client exists because a record exists. Every lookup goes through `Client.tryFind` / `Client.find`,
which read the adapter on **every call**.

## The lookup and its memo

`tryFindClient` (`lib/models/client/validate.ts:134`) reads the adapter first, and only then
consults a cache:

```ts
const properties = await adapter('Client').find(id);
if (!properties) return;
const propHash = crypto.hash('sha256', JSON.stringify(properties), 'base64url');
let client = clientCache.get(propHash);
if (!client) {
  client = validateClient(properties);
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
(`validate.ts:117`), emptied on every settings save (`validate.ts:125`). The comment records why entries are not evicted on a timer: doing so would
"drop entries out from under in-flight resolutions".

## A resolved client is frozen data

A validated client is a plain object carrying its registration attributes and nothing else — no
methods, getters or key stores; it used to be a prototype-backed object carrying eleven forwarding
methods, two aliases and two key stores. Everything done with a client is a function taking it first,
exported from `lib/models/client.ts`: `redirectUriAllowed(client, uri)`,
`checkClientSecretExpiration(client, …)`, `toStored(client)`, and so on.

- **It is frozen.** `validateClient` returns `deepFreeze(structuredClone(client))`
  (`lib/models/client/validate.ts:122`). One validated object is shared by every request using that
  client until its record changes, so a write from one request would be seen by all of them. A copy is
  frozen because the object built during validation holds references into the stored record and into
  the shared `ClientDefaults`.
- **Derived state lives beside it.** `clientKeys(client)` (`lib/models/client/keys.ts:27`) returns the
  symmetric keys derived from the secret and the public key set with its fetch state, kept in a
  `WeakMap` keyed by the client object (`keys.ts:25`) — so they live exactly as long as the memoized
  client, and a changed record gets new keys. `sectorIdentifier(client)` follows the same pattern.
- **Outbound notifications are not the model's.** Back-channel logout and CIBA ping perform network
  requests and mint a logout token, so they sit in `lib/shared/client_notifications.ts` on one object
  (`clientNotifications`, line 11) that a test can spy on.
- **`Client` is an object**, `{ tryFind, find }` (`lib/models/client.ts`), and the type of the same
  name is the validated client (`lib/models/client/types.ts`): `ClientSchema`'s attributes, read-only
  all the way down as the object is frozen, with the ones a default always fills marked present. There
  is no `instanceof Client`.
- **Closed sets are named in the type, not in the schema.** `ClientSchema` declares the authentication
  method, the CIBA delivery mode and the response signing algorithms as any string, because the set a
  deployment admits is resolved while validation runs. Each such set is a subset of a fixed list —
  `TOKEN_ENDPOINT_AUTH_METHODS` and `CIBA_DELIVERY_MODES` in `lib/consts/client_attributes.ts`, which the
  configuration check itself uses, and the JWA lists — so the client's type names the list while the
  runtime schema is left as it was. The stored record is typed too: `adapter('Client')` holds a
  `StoredClient`.
- **The type describes the object.** `ALWAYS_PRESENT` (`types.ts:15`) lists the attributes defaulted
  whatever is switched on, and `test/dynamic_registration/defaults.spec.ts` holds it to the declaration
  in both directions — on its first run it found `dpop_bound_access_tokens`, which the list had missed.
  The request context carries the client typed: `oidc.client` is `Client | undefined`, and code that
  runs only after client authentication reads `oidc.authenticatedClient`
  (`lib/helpers/oidc_context.ts:256`), whose absence is a defect rather than a refusal. Each allowance
  function takes a `Pick` of the attributes it reads, so its dependencies are in its signature.

A validated client is therefore read directly — `client.clientId` rather than a payload — the opposite
of the rule for models in [[token-payload-access-contract]].

Two details are load-bearing for tests. `Client.find` calls `Client.tryFind` through the property
rather than the imported binding, so that `spyOn(Client, 'tryFind')` is honoured
(`lib/models/client.ts:46`), and it throws `InvalidClient` by default, with callers passing
`{ error }` when their flow needs a different OAuth error code. And because the object is frozen, a
case that needs a client in another state changes the stored record it is resolved from —
`changeClient` in `test/test_helper.ts:217` — rather than assigning to the resolved object. Several
cases used to assign attributes the deployment would not have accepted at registration (an HMAC
algorithm it does not support, an unconfigured ACR value, a signed-userinfo algorithm with signed
userinfo switched off); going through the record makes such a state impossible to reach by accident.

## One write path, and the sector check sits on it

Every surface that writes a client — dynamic registration, registration management, the console, the
agent — goes through `registerClient` (`lib/models/client/register.ts:18`): validate, check the
sector identifier document, store `toStored(client)`. Resolving a **stored** client only validates it;
it retrieves no sector document (`validate.ts:170`). So a client stays usable while its sector host is
unreachable, and a settings save — which empties the memo — no longer turns into one outbound request
per pairwise client. The cost, accepted: a sector document changed after registration is not
re-checked until the client is next written. OIDC Core §8.1 places the check at registration.

Before this, the surfaces disagreed: the console stored without the check, which then ran on the next
resolution instead, as an unrelated failure for whoever used the client next.

A client described by a metadata document is the exception, because it is never stored: its
resolution *is* its registration, so it goes through `registerClient(document, { store: false })` and
keeps the check.

The three shapes have one conversion each (`lib/models/client/projection.ts`): `fromWire` from a
registration body to a record, `toStored` from a validated client back to one, `toWire` to the
metadata echoed to a registering client. A record — base attributes canonical, recognised metadata
under wire names — is both what storage holds and what validation reads.

## Consequences

Because identity lives in the database, every client is manageable at runtime — there is no
non-manageable tier for clients declared in configuration, so the admin plane can edit any of them.
Tests seed clients through a `seedClient` helper rather than by configuring them.

Storage is reached through `adapter('Client')`; the former `Client.adapter` getter is gone.

## Related

- [[deletion-and-revocation]] — a deleted client cannot authenticate on the next request, while every token it issued kept working until the cascade existed.
- [[token-payload-access-contract]] — models keep state under `.payload`; validated clients do not.
- [[account-resolution]] — maps a client id to the user bucket a subject is resolved from.
- [[feature-flag-gating]] — the registration endpoints that create clients are flag-gated.
- [[pairwise-identifier-salt]] — a pairwise client's sector identifier, read from this record, is the first input to the pseudonym every relying party keys its accounts on.

Verified against [[oauth-server-codebase]] at commit `2125ad0`.
