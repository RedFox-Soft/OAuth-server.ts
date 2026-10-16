---
type: concept
title: "End-user onboarding: project-scoped registration and email verification"
tags: [architecture, config, oidc]
sources: [oauth-server-codebase]
created: 2026-09-23
updated: 2026-10-15
---

# End-user onboarding

Whether a person may register, and whether they must prove their address first, is decided **per
project**, not per server (a project is stored as a bucket, `UserBucket`). Each project carries
`registrationOpen`, `emailVerificationRequired` and
`verificationMethod` (`'link' | 'code'`). A project created through the admin API is **closed** with
verification off unless its creator opens it (spec 083: `registrationOpen: body.registrationOpen ?? false`,
`lib/admin/buckets/routes.ts:825`); before 083 it was open. Only the route defaults it: a stored project
without the field still reads as open. The reserved administrators' project is seeded closed
([[admin-provisioning]]), and since spec 078 a super administrator may open it and require verification
there like anywhere else ([[admin-project-settings]]). Since spec 083, tightening any of these is previewed
with its counts and confirmed, and opening sign-up is previewed on the default and administrators' projects
([[project-sign-in-policy]]).

## The door

The registration screen resolves its project from the interaction's client through
`resolveBucketForRequest` — on the **GET as well as the POST** (`lib/interactions/index.ts:1040`),
because a form that can only be refused on submission is a dead end dressed as an invitation. A closed
project refuses; every project creates the user unverified, and one that requires verification also issues a
challenge. Until spec 104 a project that did not require verification created the user *verified*, and the ID token
and userinfo said `email_verified: true` for an address nobody had proven (`lib/addon/account.ts:116`) — a stranger
signing up under someone's address was presented to every application as that address's owner, and a project that
later turned verification on never asked them. Only the requirement gates sign-in, so storing the truth locks nobody
out.
The login POST then refuses an unverified user in such a project — and, since spec 078, sends what they
need rather than only saying "check your inbox": an account that existed before its project required
verification had never been sent anything. A live challenge is reused, so a registrant who signs in
before following their link keeps it (`sendOnDemand`, `lib/verification/challenge.ts`).

For a lost letter whose link is still valid, the page then offers **"Send the link again"**
(`POST /ui/:uid/verification/resend`, `lib/interactions/index.ts:1326`). It cannot reuse the public
`/verify-email/resend`: that takes the challenge's reference, and for a link the reference *is* the token,
so putting it on the page would let anyone who knows the password verify without the mailbox. Instead the
sign-in records the proven account on the interaction (`pendingVerification`,
`lib/models/interaction.ts:99`), and the button posts nothing — it can mail only the account whose
password this interaction just proved, within the resend cooldown and daily cap. It answers with a
redirect to the login path and a notice (`verify_resent`, `verify_recent`, `verify_unsent`), never by
rendering the page itself: the client bundle reads the page from the path, so a login document served at
`…/verification/resend` never hydrates.

The sign-in page links to registration only when the project accepts it, and to password reset only when
the project allows it, read from the same project the doors resolve (`lib/interactions/loginOptions.ts`).

**An administrator's create follows the same rule** (spec 104): a person created in the console or by an agent
starts unverified whatever the project requires (`lib/admin/users-end/routes.ts:341`); marking them verified is a
separate, audited act. Spec 082 had made it follow the project's setting, which still recorded an address nobody had
proven as proven whenever the project did not require verification.

**What makes an address verified** — proof, and nothing else: following a reset, invitation or verification link
from the mailbox (`lib/password_reset/challenge.ts`, `lib/verification/`), a federated sign-in whose provider is
trusted for `email_verified`, a SCIM connection trusted for addresses, or an administrator's explicit mark. Accounts
recorded verified before spec 104 keep that value: nothing records *why* an account is verified, so a migration
could only have flipped the proven ones too. Turning verification on asks whoever is not verified, and only them. It may now create a person
with no password at all, and an administrator may mail anyone unverified a fresh message from the person's
page; neither sends anything by itself ([[end-user-lifecycle]]).

*Corrected in spec 078:* the administrators' project used to be exempt from the verification check
(`verificationGates`), as a lockout guard — its administrators were all unverified and nothing could
send them a message. The exemption is gone; the guard moved to the setting, which refuses to turn on
without mail delivery or while the acting administrator is unverified ([[admin-project-settings]]).

*Corrected in spec 083:* the mail-delivery refusal holds on **every** project, not only the administrators'
project ("people could not receive the verification message: configure mail delivery first",
`lib/admin/buckets/routes.ts:939-948`). An ordinary project used to accept the requirement without mail, after
which every unverified person was sent to a message that could not be sent. Turning it off is always
allowed ([[project-sign-in-policy]]).

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

- [[self-service-password-reset]] — the other mailed flow, which keeps the administrators' project out for a related reason
- [[interaction-page-families]] — why the verification pages carry no script
- [[account-resolution]] — the project a sign-in resolves, which the door must agree with
