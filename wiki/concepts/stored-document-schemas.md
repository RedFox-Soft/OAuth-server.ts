---
type: concept
title: 'Stored documents are checked against their schema on the way out'
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-09-28
updated: 2026-09-28
graph:
  node_type: concept
  relationships:
    - predicate: constrained_by
      object: concept:error-store-capture-sites
      source: oauth-server-codebase
      evidence: "lib/adapters/documents.ts throws on a mismatch so the fault reaches the global handler as a 500 and is recorded at the existing capture site, rather than adding a third one."
      confidence: high
      status: current
    - predicate: complements
      object: concept:token-payload-access-contract
      source: oauth-server-codebase
      evidence: "The model classes check their records in BaseModel.fromStored; documentOf is the same rule for the stores' documents."
      confidence: high
      status: current
---

# Stored documents are checked against their schema on the way out

Every store document type in `lib/adapters/types.ts` — `User`, `UserBucket`, `Group`, `Project`,
`AdminSession`, `ErrorGroup` and the rest, with `FederationProvider` and `FederatedIdentity` in
`lib/federation/types.ts` and `StoredJWK` in `lib/configs/verifyJWKs.ts` — is a TypeBox schema, and its
TypeScript type is `Static<typeof …>` of it. One declaration, so the type and the check cannot drift.

Every read in the PostgreSQL and MongoDB stores goes through `documentOf(store, schema, value)`
(`lib/adapters/documents.ts`). Before 2026-09-28 the drivers were simply told what they returned —
`db.collection<User>()`, `docOf<User>(row)` — and in PostgreSQL that claim was knowingly false: a value
typed `User` carried strings in its Date fields until a reviver fixed them a line later. The memory
stores need no check: they hold the objects they were handed.

## A mismatch throws; it is not an absence

A document that does not match its schema is a defect, so the read throws, naming the store and the
first mismatching path. Reading it as missing would be worse than failing: a stored account that looks
absent lets its email be registered again. The throw reaches the global handler as a 500 and the error
store records it at its existing capture site ([[error-store-capture-sites]] — only two, and this is
not a third). Model records differ on purpose: a token that fails its schema is not found
([[token-payload-access-contract]]), because an unknown token is an ordinary refusal.

## Two encodings are translated back, only where the schema says so

- **Dates.** jsonb has no date type, so PostgreSQL returns as a string what MongoDB returns as a
  `Date`. A string is revived only where the schema declares `t.Date()` — at any depth, which the
  per-store field lists it replaced did not reach (`User.totp.enrolledAt`, `federated[].linkedAt` came
  back as strings before).
- **`undefined` stored as null.** The MongoDB driver's `ignoreUndefined` is off, so a member a writer
  left `undefined` is stored as BSON null. Where the schema declares the member optional and does not
  admit null, null is read as the absence it was written as. Found before it shipped: every console
  session holds `tokens.refreshToken: null`, a host-addressed bucket `slug: null`, and a federation
  provider update `signingKey: null` — each would otherwise have failed its read.

Nothing is sniffed from the value: a string that looks like a date stays a string unless the schema
declares a date there.

## What checks it

`test/storage_contract/stored_documents.spec.ts` holds the reviving, the null rule and the refusal. The
hermetic suite runs on the memory stores, so it cannot exercise the two database paths; a read-through
of a real MongoDB (every store's documents read through its own methods) and
`database/verify_postgres.ts` against a throwaway PostgreSQL are what do.
