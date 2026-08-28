---
type: concept
title: 'The TOTP second factor'
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-08-27
updated: 2026-08-27
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:interaction-page-families
      source: oauth-server-codebase
      evidence: "case 'totp': return <TotpPage uid={calculateUid()} mode=\"verify\" {...props} />;"
      confidence: high
      status: current
---

# The TOTP second factor

A bucket may require that a password sign-in also carry a six-digit code from an authenticator app. The
requirement is one boolean, `UserBucket.totpRequired`; everything else follows from where the state is
put, and each of those placements buys a guarantee that would otherwise have to be enforced by code
somebody remembers to write.

## The algorithm is in the repository, not in a dependency

`lib/totp/` implements RFC 4226 and RFC 6238 over `node:crypto` — about eighty lines across `base32.ts`
and `code.ts`. The reason is not minimalism. Both RFCs publish exact test vectors (RFC 4226 Appendix D,
RFC 6238 Appendix B), so conformance is provable **against the specification itself** rather than
against a library's interpretation of it, which is what Principle I asks for and what no dependency can
offer. `test/totp/algorithm.spec.ts` is that proof.

`verifyAt` takes the time as an argument rather than reading a clock. That is what makes the Appendix B
vectors testable with no fake clock and no injected time source, and it is why the function is pure.

**HMAC-SHA1, deliberately.** RFC 6238 permits SHA-256 and SHA-512, and the `otpauth://` URI has an
`algorithm=` parameter to say which — but Google Authenticator and several other widely deployed apps
ignore that parameter and assume SHA-1 unconditionally. An enrolment those apps compute wrong codes for
is a failed enrolment the person cannot diagnose. The choice costs nothing: HMAC does not rest on the
collision resistance SHA-1 lost.

## Four placements, four free guarantees

| State | Where it lives | What that buys |
|---|---|---|
| The standing enrolment | `User.totp`, embedded | Deletion integrity. The account cascade destroys the row and bucket deletion destroys the area, so no cascade arm knows the field exists — the same reasoning `federated` records. |
| The half-finished sign-in | `InteractionPayload.secondFactor` | Expiry. The interaction already has a TTL, so a sign-in stuck between the password and the code dies with the attempt it belongs to. No expiry logic exists for it. |
| The unproved secret | `TotpEnrollment`, **keyed by the interaction uid** | No handle to leak or guess; completable only from inside the interaction that started it; and the same secret re-offered on every reload. |
| The failure window | `TotpAttempt`, id `${bucketId}:${accountId}` | Survives across interactions, which is the only way the throttle means anything. |

**Present ⇔ enrolled.** There is no `enrolled` boolean beside the secret. Two fields claiming to say the
same thing disagree after the first edit — the rule `passwordLogin` states about federation
availability, applied again.

## Why the bucket field is a boolean and not an enum

`signInMethod: 'password' | 'password_totp'` reads better in isolation and is wrong here. `UserBucket`
already carries `passwordLogin`, whose own comment records the rule: *"Two fields that both claim to say
whether federation works is the shape that disagrees after the first edit."* An enum whose values both
begin with `password` is a second field claiming to say whether the password door is open. As a boolean
the two compose — `passwordLogin` says whether the door exists, `totpRequired` says whether it needs two
keys — and "permitted but inert when password login is off" becomes a plain consequence rather than a
special case. The admin route says so in an `advisory` rather than refusing.

## One enrolment flow, entered from two places

A registrant in a requiring bucket and an existing account in a bucket that was just raised are the same
situation: neither holds an authenticator, and both must get one before their sign-in completes. The
login POST forks on `user.totp ? 'totp' : 'totp/enroll'` and that single line is the whole of the
migration story — bringing existing accounts under the requirement needed no code of its own, and
`test/totp/migration.spec.ts` passed the first time it ran.

It also makes abandonment safe for free. A registrant who closes the tab mid-enrolment leaves an account
that exists and is unenrolled; because the bucket requires the factor, their next sign-in is routed
straight back to enrolment. Nothing has to clean up.

## The secret cannot be hashed, so it must never be read

TOTP verification is symmetric. Unlike a password there is no one-way form to store, so the only
available protection is that the value never appears in a read. `presentUser`
(`lib/admin/users-end/routes.ts`) is that protection, and it lives in one function rather than at four
call sites for a recorded reason: a presenter somebody forgets on one route is exactly how every
administrator came to be handed every bucket's federation secrets. It substitutes `totpEnrolled` and
`totpEnrolledAt`, which is everything an operator legitimately needs.

`test/mcp/secrecy.spec.ts` sweeps every published read for this, which is why that sweep iterates rather
than checking the ones somebody thought of.

## Two guards that only exist in the failure path

**The replay guard.** `verifyForAccount` writes the accepted step to `user.totp.lastStep`, and a code at
or below it is refused. This is the easiest part of the design to lose: implement verification as a pure
predicate and it disappears, leaving a code observed in flight usable for the rest of its ~90-second
band. `verifyAt` returns the matching **step** rather than a boolean precisely so the guard is
expressible.

**Two throttles, not one.** A counter on the interaction alone is defeated by starting a new interaction,
which costs an attacker a single request — hence the per-account window as well. Every failure answers
with the same words (`Invalid code`), throttled included: a distinct "too many attempts" tells someone
guessing that the account is real and that their guesses are landing.

**No account window on enrolment**, only the per-interaction cap. The pending secret already expires on
its own, and an account-wide lockout there would let a stranger who knows an email stop a real person
from ever enrolling — the throttle would become the attack.

## What deliberately did not change

`amr` is set to `['pwd', 'otp']` on a two-factor sign-in and a password-only sign-in is left carrying no
`amr` at all. Stamping `['pwd']` on the latter would be an observable change to the ID token of every
bucket that does not use this feature, so the test a relying party makes is "does `amr` contain `otp`".
Both values are registered in RFC 8176. `acr` is not set and `acr_values` requests are not honoured —
there is no registered value meaning "two factors".

Federated sign-in is never gated. The upstream provider owns its own factor policy, mirroring the
existing split where `passwordLogin` governs password doors and federation is enabled per provider.

A password reset neither clears nor bypasses an enrolment: a reset proves an address, and the next
sign-in still asks for a code.

## The administrator bucket needs its own door

The console signs in through this same flow — `resolveBucketForClient` maps the reserved console
client straight to the admin bucket — so enforcement works there for free. Reaching the *setting* does
not: `assertNotReserved` (`lib/admin/buckets/access.ts`) refuses the admin bucket on both
`loadBucketForEdit` and `loadBucketForUsers`, and its 403 names `/admin/api/admins` as where that
bucket is managed. Until `GET`/`PATCH /admin/api/admins/settings` existed, that promise had nothing
behind it and administrators could not be put behind a second factor at all.

**That endpoint carries `totpRequired` and nothing else, and the exclusions are the design.** The
bucket has nine settings; one of them is a console brick:

`emailVerificationRequired` must never be true for this bucket. Both paths that create an
administrator write `verified: false` — `POST /admin/api/admins` and the first-run bootstrap
(`lib/admin/auth/setup.ts`) — and no verification mail is ever sent here, because `issueAndSend` is
reached only from the self-service registration route, which this bucket refuses. Setting it would
refuse every administrator at the door with no way to clear it short of editing the database. It is
now pinned at the point of enforcement (`verificationGates` in `lib/interactions/index.ts`) rather
than left to the schema, because the flag only has to become settable once.

The rest fail on their own merits. `passwordLogin: false` is a permanent lockout — this bucket accepts
no providers, and `assertSomeWayToSignIn` looks for an *enabled provider*, so it would not catch it.
`registrationOpen: true` would let anyone who can reach `/admin/login` create a row in the reserved
bucket through the ordinary registration page. `roles` is inert: nothing constrains an
administrator's roles against it. `managedBy` is meaningless where access is by role, `federation` is
refused by its own routes and is a separate decision, and `name` is cosmetic — though no longer
invisible, since it is the issuer label an authenticator app displays.

Turning it on locks nobody out: an administrator without an authenticator meets enrolment at their
next sign-in, the same path that brings any existing account under the requirement. It does also
cover an agent obtaining a token through the console's own client, which is stated in the tool
summary rather than exempted — an exemption there would be a hole in exactly the surface the
constitution says must not have one.

## Two things found on the way

`Interaction.persist()` cannot work and never could: its guard tests `this.exp` while the value lives at
`this.payload.exp` (`lib/models/base_model.ts`), so it throws *"persist can only be called on previously
persisted Interactions"* for every interaction that has in fact been persisted. It had no callers, which
is why nothing noticed. `lib/interactions/index.ts` uses a local `persistInteraction` written the way
`lib/actions/authorization/resume.ts` already writes it.

The `MongoDB` user store's `update` now splits its patch into `$set` and `$unset`. The driver drops
undefined values from `$set`, so clearing an enrolment through it would have left the secret in place —
an account still verifying against an authenticator the operator believed they had revoked, with nothing
failing anywhere to reveal it.

## Related

- [[interaction-page-families]] — the enrolment and code pages are antd-family, and both hydrate through
  one `'totp'` arm distinguished by a prop, because the page name comes from the URL path.
- [[self-service-password-reset]] — the TTL'd-challenge pattern this follows, including comparing expiry
  in code rather than trusting MongoDB's lazy TTL monitor.
- [[admin-audit-trail]] — entries carry field *names* and never values, which is why clearing an
  enrolment records the act and nothing else.
- [[admin-console-signin]] — the console is a relying party on this server's own issuer, which is why
  putting the admin bucket behind a second factor needed no new enforcement, only a way to say so.
- [[feature-flag-gating]] — this is bucket state rather than a feature flag, and deliberately so.
- [[html-response-security-policy]] — both new pages build through `htmlResponse`; the QR is inline SVG
  and needs no directive.
- [[token-payload-access-contract]] — `amr` reaches the ID token via `session.payload.amr`.
