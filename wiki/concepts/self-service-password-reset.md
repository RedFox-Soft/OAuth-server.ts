---
type: concept
title: 'Self-service password reset'
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-08-04
updated: 2026-09-01
graph:
  node_type: concept
---

# Self-service password reset

A locked-out end user requests a reset from the login page, receives a single-use link, and sets a new
password; the reset also ends that account's sessions. Before this, the login page's "Forgot password"
control was `href=""` and the only path was an operator setting a password by hand through
`POST /admin/api/buckets/:id/users/:uid/password` — a support ticket per lockout, and a password handed
over out of band.

The flow deliberately mirrors email verification (`lib/verification/`) — TTL'd challenge written straight
through `adapter()`, per-address cooldown and daily cap, plain standalone pages, mail captured under test —
and departs from it in exactly four places. **Each departure exists because a reset secret changes a
credential where a verification secret only proves an address.**

## The two artifacts

| Area | Id | Owner | Reaped |
|---|---|---|---|
| `PasswordResetChallenge` | `sha256hex(token)` | `accountId` | `expiresAt` |
| `PasswordResetThrottle` | `${bucketId}:${email}` | none — addressed, never swept | `expiresAt` |

The throttle record is written **only when mail is actually sent**, so an address with no account leaves
nothing behind: the area holds no data that could be read to enumerate non-members. It carries the pointer
to the account's outstanding challenge (`challengeId`), which is how a new request supersedes the old one —
the challenge cannot be found by account without a scan.

## Departure 1 — the stored record cannot reproduce the emailed secret

A verification challenge's record id **is** its emailed token. That is adequate for proving an address and
not for a credential change: a datastore dump would hand over password-change authority over every account
with an outstanding request. The reset record is keyed by the SHA-256 digest instead, and the token appears
in no field (`lib/password_reset/challenge.ts`).

Unsalted SHA-256 is correct here and would be wrong for a password: the input is 256 bits of uniform
randomness, so there is nothing to brute-force — and a per-record salt would make the digest underivable
from the token alone, which is what keeps the lookup a point read rather than a scan.

## Departure 2 — expiry is compared, not delegated to the store

`verifyLink`/`verifyCode` never compare `challenge.exp` to now; they rely on the adapter dropping the
record. **MongoDB's TTL monitor deletes lazily** — roughly once a minute, worse under load — so an expired
verification link keeps working for a while. Tolerable for address-proof; not for a takeover-capable
secret, so `load()` refuses on `challenge.exp <= epochTime()`.

This is also what makes expiry *testable* without a fake clock: a spec ages a live record with
`TestAdapter.for(...).syncUpdate(id, { exp: epochTime() - 1 })`, which is exactly the state the lazy monitor
leaves behind. Note the harness blocks the obvious alternative — `TestAdapter.upsert` asserts that a written
`exp` matches the TTL it was given, so an inconsistent record cannot be forged through the front door.

## Departure 3 — a GET never consumes

Mail clients, security gateways and link-preview bots fetch URLs found in email. `GET /reset-password`
validates and renders the form; only the POST consumes, and it destroys the challenge **before** the account
update so a replay arriving mid-flight finds nothing. The password-mismatch check lives in the route, not the
engine, which makes "a mismatch does not consume the secret" true by construction.

## Departure 4 — the reserved admin bucket is refused

`resolveBucketForClient` maps the reserved console client straight to the admin bucket, so **every end-user
surface mounted under `/ui` is operator-reachable unless it says otherwise**. A self-service reset records no
audit entry (there is no actor to attribute), so allowing it here would have created an unaudited path to
changing console credentials from the console's own sign-in page. `request()` refuses that bucket with the
same non-committal page as any other unresolvable address; operator password changes stay in the audited
admin-plane route. The next end-user feature mounted under `/ui` will have to make the same call.

## One response, and the one bounded exception

Registered, unregistered, another bucket's address, deactivated, admin bucket, and *delivery failed* all
return the same accepted page — a constant with nothing interpolated, so the property belongs to the page
function rather than to its callers. A delivery failure is swallowed deliberately: a send only happens for an
address that does have an account, so surfacing it would answer the question the uniform page exists to
refuse. (Registration surfaces its 502 for the opposite reason — there, the failure reveals nothing about
anyone else.)

The exception is the rate-limited page (429, distinct wording for cooldown vs cap). Reaching it requires
having already caused accepted sends to that address, so it confirms nothing a first request would reveal,
and refusing to state a limit just produces a user who retries and stays locked out.

**Timing is not a claim.** The accepted path hashes, writes and sends; the unresolvable one returns
immediately. The two are distinguishable by duration, and constant-time behaviour would mean doing the work
either way.

## Consuming a reset marks the address verified

Receiving the secret proves control of the address on file — precisely what the verification challenge
proves. Without this an unverified account in a verification-required bucket is a permanent dead end: sign-in
is gated on `verified`, and re-registering is deliberately non-committal about an existing address, so
nothing resends anything. The same `update()` writes the password hash and `verified: true`.

## Sessions, and nothing more

`endSessionsForAccount` (in `lib/helpers/cascade.ts`) sweeps the `Session` area by its **declared** owner
field, reusing the deletion engine's mechanism rather than adding a second invalidation path. It is
deliberately neither a narrowed `cascadeForAccount` nor something that one is rebuilt on: a deletion sweeps
everything a principal owns, a reset sweeps sessions. Tokens and grants keep their own lifetimes — see
[[deletion-and-revocation]] for why revocation and consent are separate ideas.

Two consequences worth knowing:

- The sweep runs **after** the account update, so a session is never destroyed for a change that did not
  land; and a failed sweep is logged and reported while the user is still told the truth — the password did
  change.
- An authorization request already **in flight** whose session the reset just destroyed fails its next step
  with `session_not_found` rather than re-prompting, because the `ui` guard refuses an interaction whose
  recorded session is gone. Restarting from the client yields a login prompt, which is the correct end state.

## Why the rate arithmetic is shared but the numbers are not

`lib/helpers/rate_window.ts` holds the pure window arithmetic (`rateRefusal`, `nextRateFields`), used by both
the verification resend and the reset request. It is shared because "how often can one address be made to
receive a security email" is a security rule, and two hand-maintained copies of one answer differently after
the first edit. The bounds, the storage area, and whether a send counts stay per flow: verification's initial
registration send deliberately does not spend the window (`bumpRate: false`), while **every** reset request
does — there is no "initial" reset. The two flows also keep separate counters, so exhausting verification
resends cannot lock a user out of a password reset.

## Related

- [[deletion-and-revocation]] — the ownership table and cascade engine this reuses; the computed-id parameter
  now covers two areas because of this feature.
- [[login-door-throttle]] — this flow is the escape hatch from a shut door, and the distinction that
  matters there is request vs complete.
- [[account-resolution]] — `active` is enforced at every resolution, which is why a deactivated account gets
  no reset mail and a live secret stops working the moment the account is frozen.
- [[admin-audit-trail]] — why an anonymous, actorless flow must not write to the trail, and why the operator
  route still does.
- [[html-response-security-policy]] — every page here is built through `htmlResponse`, which is the only
  sanctioned way to build HTML; `test/csp/csp.spec.ts` fails the suite otherwise.
- [[feature-flag-gating]] — the reset pages join the unconditional `/ui` and `/verify-email` prefixes in the
  route classification table, which accounts for the whole mounted surface.
- [[interaction-page-families]] — this flow's pages are the plain family's second user; its `page()` shell
  was extracted to `plainPage.tsx` when a third arrived, and the "Forgot password" link this feature made
  real is why § 17's request to delete it was refused.
