---
type: concept
title: "End-user onboarding: bucket-scoped registration and email verification"
tags: [architecture, config, oidc]
sources: [oauth-server-codebase]
created: 2026-09-23
updated: 2026-10-11
---

# End-user onboarding

Whether a person may register, and whether they must prove their address first, is decided **per
user bucket**, not per server. Each bucket carries `registrationOpen`, `emailVerificationRequired` and
`verificationMethod` (`'link' | 'code'`). A bucket created through the admin API is **closed** with
verification off unless its creator opens it (spec 083: `registrationOpen: body.registrationOpen ?? false`,
`lib/admin/buckets/routes.ts:721`); before 083 it was open. Only the route defaults it: a stored bucket
without the field still reads as open. The reserved admin bucket is seeded closed
([[admin-provisioning]]), and since spec 078 a super administrator may open it and require verification
there like anywhere else ([[admin-bucket-settings]]). Since spec 083, tightening any of these is previewed
with its counts and confirmed, and opening sign-up is previewed on the default and admin buckets
([[bucket-sign-in-policy]]).

## The door

The registration screen resolves its bucket from the interaction's client through
`resolveBucketForRequest` — on the **GET as well as the POST** (`lib/interactions/index.ts:1023`),
because a form that can only be refused on submission is a dead end dressed as an invitation. A closed
bucket refuses; a bucket that requires verification creates the user unverified and issues a challenge.
The login POST then refuses an unverified user in such a bucket — and, since spec 078, sends what they
need rather than only saying "check your inbox": an account that existed before its bucket required
verification had never been sent anything. A live challenge is reused, so a registrant who signs in
before following their link keeps it (`sendOnDemand`, `lib/verification/challenge.ts`).

For a lost letter whose link is still valid, the page then offers **"Send the link again"**
(`POST /ui/:uid/verification/resend`, `lib/interactions/index.ts:1309`). It cannot reuse the public
`/verify-email/resend`: that takes the challenge's reference, and for a link the reference *is* the token,
so putting it on the page would let anyone who knows the password verify without the mailbox. Instead the
sign-in records the proven account on the interaction (`pendingVerification`,
`lib/models/interaction.ts:99`), and the button posts nothing — it can mail only the account whose
password this interaction just proved, within the resend cooldown and daily cap. It answers with a
redirect to the login path and a notice (`verify_resent`, `verify_recent`, `verify_unsent`), never by
rendering the page itself: the client bundle reads the page from the path, so a login document served at
`…/verification/resend` never hydrates.

The sign-in page links to registration only when the bucket accepts it, and to password reset only when
the bucket allows it, read from the same bucket the doors resolve (`lib/interactions/loginOptions.ts`).

**An administrator's create follows the same policy** (spec 082): a person created in the console or by an
agent starts verified only when the bucket does not require verification
(`lib/admin/users-end/routes.ts:269`). The route used to write `verified: true` whatever the bucket said, so an
address nobody had proven counted as proven because an administrator typed it. It may now create a person
with no password at all, and an administrator may mail anyone unverified a fresh message from the person's
page; neither sends anything by itself ([[end-user-lifecycle]]).

*Corrected in spec 078:* the admin bucket used to be exempt from the verification check
(`verificationGates`), as a lockout guard — its administrators were all unverified and nothing could
send them a message. The exemption is gone; the guard moved to the setting, which refuses to turn on
without mail delivery or while the acting administrator is unverified ([[admin-bucket-settings]]).

*Corrected in spec 083:* the mail-delivery refusal holds on **every** bucket, not only the admin bucket
("people could not receive the verification message: configure mail delivery first",
`lib/admin/buckets/routes.ts:838-849`). An ordinary bucket used to accept the requirement without mail, after
which every unverified person was sent to a message that could not be sent. Turning it off is always
allowed ([[bucket-sign-in-policy]]).

## The challenge

`lib/verification/challenge.ts` issues, verifies and resends over the `VerificationChallenge` and
`VerificationResend` areas, each with a TTL. The bounds are in `lib/verification/consts.ts`, one source
for the challenge logic, the rate limiter and the tests:

- a link token is single-use and valid for about a day;
- a code is six digits, **hashed at rest**, valid for fifteen minutes, and capped at five attempts —
  after which even a correct code is refused until a new one is issued (`lib/verification/challenge.ts:202`);
- a resend has a cooldown and a rolling daily cap;
- a link or code verifies only an account that still holds the address it was sent to — after an address
  change it is refused like an unknown token (spec 082, [[end-user-lifecycle]]).

The public verification endpoints — `GET /verify-email`, `GET|POST /verify-email/code`,
`POST /verify-email/resend` — are a standalone, cookie-less group in `lib/routes/verification.ts`. They
belong to the plain page family and must work in a different browser opened from an email; see
[[interaction-page-families]].

## Mail and SMTP

`lib/mail/` builds the message and delivers it through Nodemailer. The transport is read **live from
the SMTP settings store on every send** (`lib/mail/mailer.ts:34`), not from `ApplicationConfig` — so SMTP
is deliberately absent from the settings catalogue, and a restart neither applies nor disturbs it. A
super administrator sets it at `/admin/api/settings/smtp`; the password is write-only, masked on read,
and the change is audited. Under `NODE_ENV=test` nothing reaches the network: every message is captured
in memory (`sentEmails`, `lib/mail/mailer.ts:20`).

## Related

- [[self-service-password-reset]] — the other mailed flow, which keeps the admin bucket out for a related reason
- [[interaction-page-families]] — why the verification pages carry no script
- [[account-resolution]] — the bucket a sign-in resolves, which the door must agree with
