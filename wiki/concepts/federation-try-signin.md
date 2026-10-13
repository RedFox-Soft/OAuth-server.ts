---
type: concept
title: 'Try sign-in: the real decision ladder, stopped before it writes'
tags: [architecture, contract, gotcha, oidc]
sources: [oauth-server-codebase]
created: 2026-10-12
updated: 2026-10-12
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:upstream-federation
      source: oauth-server-codebase
      evidence: "lib/federation/try.ts:112 computes a try's outcome with decideFederatedAccount, the reads-only half of the sign-in ladder in lib/federation/resolve.ts."
      confidence: high
      status: current
---

# Try sign-in

Since spec 088 a provider's page in the console has **Try sign-in**. Saving a provider proves its issuer and
its keys. It does not prove that this bucket's callback is registered at the provider, and it does not show what
the decision rules would do with a real person: link, create, or refuse for the domain. Until spec 088 the
first person to find out was a customer at the sign-in page.

A try sends a new browser tab to the provider's sign-in with the bucket's **real** callback address. Proving
that address is registered upstream is the point. The administrator signs in there with any account they
control. The console tab then shows:

- **what the provider answered**: the subject, the address and whether the provider says it is verified, and the
  other claims, without `nonce`, `at_hash` and `c_hash`, which describe the exchange rather than the person;
- **what a real sign-in would do now**: sign in a linked account, link by email, ask for the password first,
  create an account, match a provisioned person, or refuse with the reason (`TryResult`,
  `lib/federation/types.ts:171`);
- **or what went wrong**: the provider declined, the exchange failed, or the response named another issuer.

## One ladder, two steps

`lib/federation/resolve.ts` is split in two:

- `decideFederatedAccount` (`:191`) runs the ladder and only reads. It returns a `Decision`: `signin`, `refuse`,
  `conflict`, `link` (via email or a provisioning connection's correlation), `password_required` or
  `provision`.
- `applyDecision` (`:297`) makes every write the ladder used to make, and emits its event.

`resolveFederatedAccount` (`:370`) is `applyDecision(await decideFederatedAccount(input))`, so a real sign-in
does exactly what it did before. A try calls only the first half (`completeTry`, `lib/federation/try.ts:47`).
A copy of the ladder for the try would drift from the real one; the split cannot.

Two refusals exist only after a write, so they are not decisions: `link_not_permitted` when the link write finds
nothing to update, and `inactive` after linking or creating. Those checks guard races, and a try reports the
decision that preceded them. Running the real ladder against a throw-away store was rejected: the user store is
module state per bucket, and a fake would have to mirror every read.

## Nothing is written

No account, link, pending link, handoff, session, administrator registration, sign-in activity or upstream
session record. The one write is the result, into the try's own record (`finishTry`,
`lib/federation/state.ts:143`).

**Whether a round trip is a try is decided only by what the server stored when it started.** `openTry`
(`state.ts:91`) writes the stage-one record with `purpose: 'try'` and a `tryId`, and a third kind of
`FederationState` record (`stage: 'try'`) keyed by the digest of a fresh `tryRef`. The callback branches on
the stored `purpose` (`lib/federation/routes.ts:111`) before it touches any interaction. Nothing in the
returning request can turn a sign-in into a try or a try into a sign-in. A try has no interaction, so
`interactionUid` became optional; a handoff without one is refused by the comparison that already checks it.

**A disabled provider can be tried.** Testing before switching a provider on is the main use. The start route
finds the provider without the enabled filter (`findProvider`, `lib/admin/federation/service.ts:180`), and so
does `completeTry`. That is safe because no sign-in follows from a try. Every real sign-in still goes through
`findEnabledProvider`. The result says the provider is off. With `federation.enabled` off there is nothing to
try: the start answers 409, and the provider read's `capabilities.trySignIn` tells the console to show the
button disabled with the reason.

## Bound to the console session, read by polling

The try record holds the SHA-256 of the console session cookie that started it (`sessionDigestOf`,
`state.ts:176`). `readTry` (`:158`) compares it in constant time. Another session, even the same
administrator's, another bucket or provider, an unknown try and an expired one all get the same 404
(`GET …/federation/:providerId/try/:tryRef`, `lib/admin/federation/routes.ts:240`). The record lives ten
minutes. A start without a console session, such as an agent's bearer token, is refused 403 (`:182`): nobody
could read its result.

- RFC 9700 §2.1.1 requires the transaction to be "securely bound to the client and the user agent in which the
  transaction was started", and RFC 6749 §10.12 suggests a hash of the session cookie. The first design bound the
  try to the administrator's user id; the standards review rejected it, because a user id is not a user agent.

**The callback cannot send the browser back into the console.** The console's session cookie is
`SameSite=Strict` with `path: /admin` (`lib/admin/auth/session.ts:37`). RFC 6265bis §5.6.7.1: a Strict cookie is
not sent on a navigation started from a cross-site document, and a redirect does not change that. A 303 from the
callback into `/admin` would therefore land on the console's login. The cookie's path excludes the callback
anyway, and a host-addressed bucket's callback is another origin. So:

- the callback answers a plain self-contained page, "Try finished" (`tryFinishedPage`,
  `lib/federation/pages.tsx:129`), in the plain family of [[interaction-page-families]];
- the console tab that started the try polls every two seconds (`POLL_MS`,
  `lib/admin/ui/pages/providers/TrySignIn.tsx:26`);
- no return address is taken from the request (RFC 9700 §4.11);
- the new tab is opened synchronously in the click handler as `about:blank` and pointed at the provider when the
  start answers (`TrySignIn.tsx:154`), so popup blockers allow it.

When the provider never sends the browser back — the usual sign of an unregistered callback — the console says
what to check and shows the callback with Copy.

## Audit and agents

- Starting a try is audited, `federation.provider.try`, before anything happens. It changes no managed entity,
  but it sends a browser to an upstream with the bucket's client credentials. The result is not recorded.
- The start and the result are excluded from MCP as **inapplicable** (`lib/mcp/catalogue.ts:1949`): a try needs a
  person signing in at the provider in a browser, and its result belongs to the console session that started it.
  The guessed name `federation_provider_try` answers with that reason ([[admin-mcp-control-plane]]).
- The [[upstream-federation]] RFC 9207 `iss` check applies to a try too; a refusal is reported as
  `error.stage = 'rejected'` with `issuer_mismatch` or `issuer_missing`.

## Not adopted

- `prompt=select_account` or `prompt=login`: support varies by provider. When the upstream is already signed in
  as the administrator, the console suggests a private window instead.
- Sending a try link to a customer's IT administrator (Auth0's partner test). It would relax the session binding
  on purpose; a later spec may take it up.

`test/federation/try_signin.spec.ts` holds the outcomes, the nothing-written checks and the session binding.

## Related

- [[upstream-federation]] — the ladder, the round-trip records and the callback this reuses.
- [[scim-provisioning]] — the correlation step a try of a bound provider reports as a match.
- [[admin-audit-trail]] — the start's entry.

Verified against [[oauth-server-codebase]].
