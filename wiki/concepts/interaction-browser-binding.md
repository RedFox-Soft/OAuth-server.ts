---
type: concept
title: 'An interaction is bound to its browser by the cookie’s value, not its presence'
tags: [security, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-09-28
updated: 2026-09-28
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:cookie-path-scoping
      source: oauth-server-codebase
      evidence: "_interaction is set with path /ui/${uid} and a value, cookieID, that never appears in a URL."
      confidence: high
      status: current
---

# An interaction is bound to its browser by the cookie’s value, not its presence

The `uid` of an interaction is in every URL of a sign-in (`/ui/${uid}/login`, `/totp/enroll`,
`/consent`, …), so it is **not a secret**: it reaches access logs, browser history, screenshots and
support tickets. What ties a sign-in to the browser that began it is a second value, `cookieID`, minted
beside the uid and sent only in the `_interaction` cookie (`lib/actions/authorization/interactions.ts:114`,
`:140`). The `ui` guard's cookie schema proves only that *some* `_interaction` cookie arrived; the
comparison against `interaction.payload.cookieID` in the shared `resolve`
(`lib/interactions/index.ts:393-408`) is the whole of the binding. It is constant-time and answers
exactly as an unknown uid does, so it is no oracle for which uids are live.

## It was missing from `53341c6` until 2026-09-28

The fork's `resume` compared its cookie to the interaction (`cookieId !== interactionSession.uid`). When
`53341c6` (2025-05-14) moved interactions onto the `ui` routes, the new `resolve` read the cookie into a
variable and never compared it — the variable surfaced only as an ESLint `no-unused-vars` finding. For
sixteen months any browser holding a uid could continue that sign-in with a cookie of its choosing.

What that allowed, measured with a forged cookie:

- **After the end user's correct password in a bucket requiring a second factor**, the interaction
  carries only `secondFactor.accountId` (`lib/interactions/index.ts:588`) and, on a first sign-in, no
  session to compare. The enrolment page showed the account's new authenticator secret to the other
  browser, which confirmed it, left with a session for the account, and left **its own** authenticator
  enrolled as the account's second factor.
- On the password screen, the other browser signed in as itself and destroyed the end user's pending
  sign-in.
- After sign-in, `resume`'s session comparison (`lib/actions/authorization/resume.ts:25`) refused the
  foreign browser — but the consent POST had already saved the grant (`lib/interactions/index.ts:1150`).

Presence plus the per-uid cookie path did stop the opposite direction — pushing a victim's browser into
the *attacker's* interaction — because no browser holds a cookie for someone else's `/ui/${uid}`. That
is why nothing looked broken: every flow a real browser drives carried the right cookie anyway.

## Consequences for anything new

- A step inside an interaction may rely on `interaction` being this browser's. The federation callback
  is deliberately cookieless ([[upstream-federation]]) and relies on hop 3 for exactly this.
- A spec that builds an `Interaction` by hand must give it a `cookieID` and send that value; a made-up
  cookie is now refused with 400 (`test/device_code/device_resume.spec.ts`,
  `test/bucket_addressing/flows.spec.ts`). The binding's own cases are in `test/interaction_binding/`.
