---
type: concept
title: 'Model graph import order'
tags: [gotcha, architecture]
sources: [oauth-server-codebase]
created: 2026-08-04
updated: 2026-08-04
graph:
  node_type: concept
---

# Model graph import order

`lib/models/` contains an import cycle. A module that reaches the model graph **cold** — with
`lib/models/access_token.ts` as the first thing loaded — dies at import time:

```
ReferenceError: Cannot access 'BaseTokenPayload' before initialization.
    at lib/models/grant.ts:16
```

`base_token.ts` reaches `grant.ts` through its own import chain, and `grant.ts` composes
`BaseTokenPayload` while `base_token.ts` is still evaluating. Reproduced with a **static** top-level
import and with a dynamic one; it is not a bundler artifact.

## The fix is entering through `test_helper`

```ts
import '../test_helper.js';        // must come first
import { AccessToken } from 'lib/models/access_token.js';
```

`test_helper.js` enters the graph in an order that resolves. Every working storage-contract spec already
does this (`test/storage_contract/grant.round_trip.spec.ts` imports `bootstrap` above its model imports),
which is why the cycle is invisible until you write a spec that does not.

## The existing drift guard survives by accident

`test/storage_contract/inventory_drift.spec.ts` dynamically imports every file in `lib/models/` and does
**not** import `test_helper`. It passes only because that import loop sits in the file's **second** test,
and `test/preload.ts`'s `afterEach` has run `await import('lib/addon/interactions.js')` by then — warming
the graph as a side effect.

**Move that loop into the first test of the file and the guard explodes.** Nothing in the file says so.
Recorded here rather than fixed, because the fix (an explicit warming import) is a one-line change
somebody should make deliberately rather than discover.

## Why the drift guard reads schemas, not source text

The ownership drift guard for [[deletion-and-revocation]] needed each area's payload fields at runtime.
Two obvious routes are both wrong:

- **Constructing the model classes** to read `instance.model`: measured, 6 of 14 persisted classes throw
  on a no-argument construction — five from the `consumable` mixin (`payload.consumed`), plus `Client`
  (`invalid_client_metadata`). `model` is an instance field, so there is no way to reach it without
  running the constructor.
- **Scanning the source text**, the technique the existing guard uses for `adapter('X')` calls. Wrong,
  not merely fragile: `lib/models/session.ts` declares `clientId: t.Optional(t.String())` *inside* its
  nested `authorizations` object, so a text scan reports `Session` as client-owned. Its composed
  top-level properties are `uid, accountId, loginTs, amr, acr, transient, state, authorizations` — no
  top-level `clientId`.

The working route is the composed TypeBox schema's `properties`, which is why the 13 model payload consts
are exported and the two verification payloads were converted from interfaces
(`test/storage_contract/payload_schemas.ts`).

## A composed field can appear twice in the sources

The four session-bound token areas take `accountId` from **two** composed parts — `SessionBoundPayload`
in `base_token.ts` and `authPayloadModel` in `mixins/stores_auth.ts`. `t.Composite` merges them; there is
nothing to reconcile, but a reader comparing a property list against the sources will otherwise wonder.

## Related

- [[deletion-and-revocation]] — the guard this was discovered while building.
- [[token-payload-access-contract]] — how payload schemas are composed per token type.
