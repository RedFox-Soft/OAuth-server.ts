---
type: concept
title: 'Sign-in brute-force throttle'
tags: [architecture, contract, gotcha, config]
sources: [oauth-server-codebase]
created: 2026-08-28
updated: 2026-08-28
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:deletion-and-revocation
      source: oauth-server-codebase
      evidence: "const EMAIL_SCOPED_AREAS = ['VerificationResend', 'PasswordResetThrottle', 'LoginThrottle'];"
      confidence: high
      status: current
---

# Sign-in brute-force throttle

`POST /ui/:uid/login` counts failed password attempts per `${bucketId}:${email}` and shuts that
address's door for a window that grows each time it is exhausted. Five things about it cannot be
re-derived from reading the code, and they are why this page exists.

## It is the second-factor throttle, moved one door earlier

`lib/totp/verify.ts` already held this exact mechanism for the code step, backed by `TotpAttempt`:
keyed on an identity, checked **before** verifying so a locked account is refused even with a correct
secret, written only on failure, destroyed on success, and given a record whose lifetime bounds the
lockout. Spec 027 gave the second factor a throttle and left the password door with none — so this
feature is that pattern applied to the other secret, deliberately and visibly.

The one place the two diverge is ownership, and it is forced:

| | `TotpAttempt` | `LoginThrottle` |
|---|---|---|
| Key | `${bucketId}:${accountId}` | `${bucketId}:${email}` |
| Inventory | account-owned, carries `accountId` | **unowned**, carries no principal |
| Written for a non-member | impossible — there is no account id | **required** |

A counter must exist for an address that resolves to nothing, or the throttle's behaviour becomes an
account-existence oracle. An account-owned area cannot express that, which is why these are two areas
and not one. See [[deletion-and-revocation]] for the ownership table this joins.

## Two horizons, and confusing them silently removes the escalation

The record carries `windowStart` **and** `step`, and there are two different deadlines over it:

- `windowStart + windowFor(step)` — when the **door** reopens. Minutes.
- `exp` — when the **record** dies, 24 hours after the most recent failure.

The second must outlive the first. The instinctive design — TTL the record to the end of its own
lockout, which is what `TotpAttempt` does and what this feature's first draft specified — reaps the
counter at the exact moment the door reopens, so `step` is forgotten and the next failure starts at
the shortest window again. **An attacker who simply waits keeps the opening allowance for ever, and
nothing anywhere reports a problem.** `lib/configs/configuration.ts` enforces the ordering at boot by
capping `windowCeilingSeconds` at `LOGIN_RETENTION_SECONDS`, so the invariant cannot be configured
away.

`TotpAttempt` is right to do the opposite: it has no escalation to remember, so a record that dies
with its window is exactly what makes *its* lockout non-permanent.

## The ceiling reads the bucket's second factor, never the bucket's id

`windowFor` stops doubling at a ceiling that is the *first* window when the bucket sets
`totpRequired`, and the configured ceiling otherwise. The rule exists for the reserved admin bucket —
its operators sign in through this same door, and `lib/password_reset/challenge.ts` refuses that
bucket, so they have no self-service escape from a long lockout — but it is **not** written as
`bucketId === ADMIN_BUCKET_ID`.

Stating it as the policy rather than the identity buys two things. It says the actual reason (a
guessed password is not a sign-in where a second factor is required, so deep escalation buys little
and risks the one lockout nobody can undo), and it self-corrects: turn a bucket's second factor off
and its escalation deepens automatically, with nothing to remember. It also satisfies Principle II,
which forbids deployment-shaped branches in business logic.

The coupling to know: `totpRequired` **defaults to false** and is absent from both admin-bucket seeds
(`lib/admin/seed.ts`, `database/mongodb.ts`). Issue #26 shipped the capability opt-in, so on a
deployment that never enabled it the console escalates like any other bucket. That is the correct
fallback, and it is also the argument for changing that default.

## The escape hatch is the reset flow, and the distinction is request vs complete

Escalating lockouts are only safe while the honest user holds a route back that an attacker guessing
passwords does not. That route is mailbox control — and the obvious way to offer it, an "enter the
code from your email to keep trying" step, is wrong four times over: the prompt is truthful only for
an address that has an account, so showing it selectively rebuilds the oracle; it is an email-bombing
vector, so it needs its own cap and therefore only relocates the lockout; it makes the mailer a hard
dependency of sign-in, on a server where mail is best-effort everywhere else; and it cannot serve the
admin bucket at all.

So `consume()` in `lib/password_reset/challenge.ts` calls `clearFailures` — a **completed** reset
clears the counter, a *requested* one does not. Requesting proves nothing and would hand anyone who
knows an address a way to wipe the counter holding them off; consuming the single-use secret proves
control of the address on file, which is the same evidence the code step would have collected.

## Casing: the bypass that passes every test

`findByEmail` is case-insensitive in both adapters
(`lib/adapters/mongodb/userStore.ts`, `lib/adapters/memory/userStore.ts`), so `alice@example.com` has
2^16 spellings that all resolve to one account. A counter keyed on the raw submission would give each
spelling its own allowance — 65,536 × the cap — while **every test written with a lower-case address
still passed**. That is the whole reason `lib/helpers/email_scoped_id.ts` exists as one function
rather than a fourth copy of the expression, and why its comment states the rule as *parity with the
account lookup* rather than "call `toLowerCase()`": the day the lookup starts trimming or folding
Unicode, lower-casing stops being sufficient and the key has to follow.

### The divergence that helper also fixed

The two user stores disagree about what they **store**: MongoDB's `create` lower-cases the address,
the in-memory one keeps it as given. `lib/admin/users-end/routes.ts` built the cascade id from the
*stored* value, inline and without `toLowerCase()` — so under the in-memory adapter a mixed-case
account's email-scoped records were missed, silently, with the cascade reporting success. Pinned now
by a mixed-case case in `test/deletion/cascade_enduser.spec.ts`. The stores' own divergence is still
there and is tracked separately.

## Smaller things worth knowing

- **The refusal is an expression, not a string.** All four turn-aways in the handler call one local
  `refuse()`, so "a throttled attempt is indistinguishable from a wrong password" holds structurally
  rather than by four copies of the same wording staying in step.
- **No error is thrown.** The refusal renders a page, so unlike [[per-origin-rate-limiting]] this
  needs no handler branch, no `allow_redirect` decision, and no exclusion from the `server_error`
  channel. It emits `login_throttled` with the bucket and nothing else.
- **Nothing fails open.** No storage error is caught: the throttle read sits one line ahead of the
  account lookup, which reaches the same datastore, so propagating reveals nothing new and lets the
  error store record a real fault.
- **There is no `enabled` setting**, deliberately — a kill switch for a security boundary is a switch
  that reopens the vulnerability. `checkLoginThrottle` bounds the numbers to a range in which the
  protection still means something instead.
- **Test gotcha**: at bun's default 5s per-test timeout, an argon2-heavy spec wedges the whole run
  with no output rather than reporting a timeout. Once the throttle is wired the refused attempts stop
  hashing and the spec comes back under the limit — but a spec that exhausts the cap several times
  before the door is implemented will appear to hang.

## Related

- [[totp-second-factor]] — the throttle this one is modelled on, and the `totpRequired` flag whose
  value now also decides this door's escalation ceiling.
- [[self-service-password-reset]] — the flow that supplies the escape hatch; its own cooldown and cap
  are what keep that hatch from becoming an email-bombing vector.
- [[per-origin-rate-limiting]] — the resource protection this sits behind; its page names issue #9 as
  separately necessary, and this is that issue.
- [[deletion-and-revocation]] — the ownership declaration and the email-scoped cascade arm, which now
  covers three areas.
- [[account-resolution]] — `findByEmail`'s case-insensitivity, which the counter's key must match.
- [[feature-flag-gating]] — where server settings live, and why these three are boot-only.
