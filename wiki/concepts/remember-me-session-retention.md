---
type: concept
title: 'A decorative control, broken in four places at once'
tags: [gotcha, contract, security]
sources: [oauth-server-codebase]
created: 2026-09-14
updated: 2026-09-14
graph:
  node_type: concept
  relationships:
    - predicate: complements
      object: concept:cookie-path-scoping
      source: oauth-server-codebase
      evidence: 'Both are defects in the _session cookie that no test could see, and both are closed by asserting on the response Set-Cookie header rather than on a cookie string threaded through by hand.'
      confidence: high
      status: current
---

# A decorative control, broken in four places at once

The sign-in page offered a "Remember me" checkbox, pre-ticked, for the whole life of the product.
Whatever the end user did with it, the outcome was identical: the sign-in was remembered. Closed at
`f7473ee`+1; reported as issue #45, which named one of the four breaks.

The interesting property is not any single break. It is that **four independent defects sat on one
path and each alone was sufficient**, so no partial repair would have been observable — and the
audience with the most at stake, the end user on a shared machine who unticks the box deliberately,
was told their choice mattered and it did not.

## The four

1. **The choice was dropped in transit.** `lib/actions/authorization/resume.ts` destructured
   `remember = true` from the login result. Every producer writes `transient`. The key never
   matched, so the default fired on every sign-in and every session was persistent.
2. **The answer was recorded backwards.** Both password producers in `lib/interactions/index.ts`
   wrote `transient: body.remember === 'on'` — ticking "Remember me" marked the session *not* to be
   kept. Repairing only break 1 would have shipped the control working in reverse, which is worse
   than inert: the shared-machine user gets the opposite of what they chose.
3. **Nothing read the flag.** `setCookies` in `lib/shared/session.ts` wrote
   `expires: session.payload.exp` unconditionally. `session.payload.transient` had no reader
   anywhere, so no session this server ever issued was scoped to the browsing session.
4. **A decline was never cleared.** `loginAccount` did `transient ? { transient: true } : undefined`
   — it set the flag and never removed it. Since `resume` destroys a session only when the *account*
   changes, a user who signed in again ticking the box kept the earlier decline. This one is not in
   the issue; it was found while planning the repair and would have survived fixing the other three.

## Which name was right

Settled by counting, not taste. `transient` was already the vocabulary in eight places — both
persisted schemas (`SessionPayload`, `Interaction.secondFactor`), all five producers, and
`loginAccount`'s own parameter — while `remember` appeared in exactly one, the defect. The consumer
was corrected; no producer was renamed. Accepting both keys was rejected under Constitution VII:
there is nothing to be compatible with, because `remember` never had an effect.

Note the polarity trap in the name itself. `transient` is the *negative* of what the checkbox says,
which is precisely what break 2 fell into. Absent means remembered, on all three fields.

## Why omitting `expires` is enough

Elysia's `Cookie.set(config)` assigns onto `{ ...this.initial, value }` — a **reset** from the route
schema's initial attributes, not a merge onto the cookie's current state (`update()` is the merging
one). `endUserCookieAttributes` declares `httpOnly`, `sameSite` and `secure` and no lifetime, so a
call that omits `expires` yields a cookie with neither `Expires` nor `Max-Age`, which RFC 6265
§4.1.2.1–2 makes non-persistent.

This was verified in `node_modules` rather than assumed, and the assumption was worth checking: had
`set` merged, the same edit would have compiled, type-checked and silently done nothing on any
request that wrote the cookie twice.

## Why the suite looked like it covered this

Two cases in `test/interaction/interaction.spec.ts` were *named* for the distinction — "should
process an explicitly permanent (remember) login result" and "should process a transient
(remember: false) login result" — and asserted only that the redirect carried a code and state.
They injected a key nothing read, into a mechanism that did nothing, and passed either way.

That is the same blindness as [[cookie-path-scoping]] one field over, and it has the same cure:
**assert on the response's `Set-Cookie` header**. A cookie string threaded through a test by hand
carries `name=value` and no attributes, so it cannot observe an attribute that is wrong or missing.
Both cases were re-anchored rather than deleted, per Constitution V — the subject matter was real.

The repair added seven cases across three files and changed no existing one: nothing in the suite
asserted `Expires` on `_session`, which is why the whole thing was invisible.

## Related

- [[cookie-path-scoping]] — the other `_session` defect no test could see, and the origin of the
  rule about reading the response header.
- [[end-user-cookie-attributes]] — the attributes that travel with every write of this cookie.
- [[totp-second-factor]] — the two-step path the choice has to survive, staged on the interaction.
