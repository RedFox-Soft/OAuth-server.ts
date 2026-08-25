---
type: concept
title: "First consent and the unstored grantId"
tags: [contract, gotcha, architecture]
sources: [oauth-server-codebase]
created: 2026-08-25
updated: 2026-08-25
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:token-payload-access-contract
      source: oauth-server-codebase
      evidence: "base_model declares `static notFoundError = InvalidToken`, so every model find() that misses answers 401 invalid_token."
      confidence: high
      status: current
---

# First consent and the unstored grantId

An interaction's `grantId` is a **hint, not proof that a grant was stored.**

The Interaction constructor copies the id off whatever `Grant` instance the authorization pipeline put
in the context (`lib/models/interaction.ts` — "the constructor derives `grantId` from the Grant
instance"). `loadGrant` (`lib/actions/authorization/load_grant.ts`) puts an **unsaved** instance there
whenever the account has no grant for this client yet, and nothing persists it until consent is
actually given (`createGrant`, `lib/interactions/index.ts`). So on a first authorization the
interaction names a grant that is not in storage.

`createGrant` therefore resolves it with `Grant.tryFind`, and falls back to establishing a new grant.
A grantId that resolves to nothing is the same state as no grantId: there is no prior consent to
extend.

## Why it read as an authentication failure

`lib/models/base_model.ts` declares `static notFoundError = InvalidToken`. So **every** model `find()`
that misses answers `401 invalid_token / "invalid token provided"` — including one for a record on a
request that carries no token at all.

Approving consent on a first authorization therefore returned `401 invalid token provided`. Read
literally that points at credentials, which is the wrong place entirely: the credential was fine and a
grant record was missing. When this message appears somewhere a token is not the subject, look for a
`find()` on a record that was never written.

## Why the suite could not see it

`test/interaction/interaction.spec.ts` drives consent through the real pipeline and passed throughout.
The harness always has a **stored** grant to point at — `setup.getGrantId()` reads one straight out of
the session — so the interaction's id always resolved, and the branch that mattered was never taken.

The regression test forces the production shape by rewriting the interaction's `grantId` to an id
nothing stored, then asserting consent still resumes *and* that a grant is created. A test that only
exercises the state your fixtures happen to produce is not covering the branch, only visiting it.

Every client whose consent is genuinely required hit this on its first sign-in — which for a long time
meant only the reserved MCP agent (`consent.require: true`), so it stayed hidden behind a surface whose
browser leg the quickstart records as never verified.

## Related

- [[admin-mcp-control-plane]] — the client whose `consent.require` made it the only one affected.
- [[loopback-redirect-port-matching]] — the failure immediately before this one in the same flow.
- [[admin-console-signin]] — the console's own login, which auto-grants and so never reached here.
