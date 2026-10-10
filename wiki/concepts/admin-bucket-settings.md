---
type: concept
title: "The administrators' bucket: ordinary settings, a guard per setting"
tags: [architecture, contract]
sources: [oauth-server-codebase]
created: 2026-10-10
updated: 2026-10-10
---

# The administrators' bucket: ordinary settings, a guard per setting

Administrator accounts live in a reserved bucket (`ADMIN_BUCKET_ID`). Until spec 078 that bucket was a
**blanket exception**. Every generic bucket route refused it, and its own settings endpoint,
`/admin/api/admins/settings`, carried one field, the second-factor requirement. So an operator could not
open sign-up for other administrators, could not require them to verify their email, and the console's
sign-in page still linked to registration and password reset, which the bucket refused.

The refusal was a lockout guard, not a statement that this bucket differs from others. Almost every
bucket setting, set carelessly here, shuts the console, and with it the only surface that could undo the
setting. Spec 078 kept the guarding and dropped the blanket. A super administrator now edits the bucket
on the ordinary settings page, and each dangerous setting carries a guard of its own.

## One narrow loader, not an opened pair

`assertNotReserved` (`lib/admin/buckets/access.ts:30`) stays inside `loadBucketForUsers` and
`loadBucketForEdit`. Those two loaders guard about forty routes: federation, users, provisioning, bucket
groups and more. Several of them have no second check of their own. Moving the reserved check out of the
loaders would have opened all of those routes to super administrators with nothing behind them.

Instead, a third loader, `loadBucketForSettings` (`access.ts:60`), admits the bucket. Only
`GET /admin/api/buckets/:id` and `PATCH /admin/api/buckets/:id` use it.
- It refuses the administrators' bucket to anyone who is not a super administrator, explicitly. It does
  not rely on the bucket's owner, the System group, having no members. That invariant is real but is not
  enforced anywhere near here.
- The bucket list includes the bucket only for a super administrator
  (`lib/admin/buckets/routes.ts:355`).
- Every response marks it `reserved: 'administrators'` (`routes.ts:248`), so the console and an agent
  learn what it is from what they were sent.

Deleting it, moving it, re-addressing it, keys, federation and provisioning stay refused. Each of those
already had its own reason, and the refusal message now says the operation is not available for this
bucket.

## The guards

`assertAdminBucketChange` (`lib/admin/buckets/admin_bucket.ts:20`) runs after access is checked and
before the audit entry, so a refused change records nothing.

| Setting | Guard |
|---|---|
| `passwordLogin: false` | Refused by the existing `assertSomeWayToSignIn`, as for any bucket with no enabled provider. This bucket has none, and federation stays closed to it, so this is always refused today. |
| `emailVerificationRequired: true` | Refused while mail delivery is not configured (`mailDeliveryConfigured`, `lib/mail/mailer.ts:39`, the same test `deliver()` applies). Also refused while the **acting** administrator's own address is unverified, so the requirement can never refuse the person who set it. |
| `registrationOpen`, `verificationMethod`, `totpRequired`, `name` | No guard. Opening registration while verification is off answers with an advisory (`adminBucketAdvisory`, `admin_bucket.ts:45`), and an agent reads the same sentence the console shows. |

A super administrator cannot change **their own** address while verification is required
(`assertAddressChangeable`, `lib/admin/users/routes.ts:37`). The new address would be unproven, a typo
would lock out the person making the change, and when that person is the last super administrator it
would lock out the instance. Changing somebody else's address cannot lock you out. A changed address
leaves the account unverified, and the personal group, whose stored name *is* the owner's address,
follows it (`routes.ts:145`).

## The door has no exception any more

The sign-in check used to skip this bucket (`verificationGates`). It now gates on
`emailVerificationRequired` like any bucket (`lib/interactions/index.ts:845`), because the lockout guard
moved from the door to the setting.

In every bucket that requires verification, a correct password for an unverified account is now sent
what it needs (`unverifiedAtSignIn`, `index.ts:533`). It is no longer just told to "check your inbox",
which was a dead end for any account that existed before its bucket required verification.

`sendOnDemand` (`lib/verification/challenge.ts:254`) works within the existing cooldown and daily cap.
- At sign-in it **reuses** a live challenge rather than issuing a new one. Issuing supersedes the
  outstanding challenge, and a registrant who signs in before following their link must not have it
  replaced under them.
- The console's "verify my address" (`POST /admin/api/me/verification`, `lib/admin/me.ts:49`) forces a
  fresh challenge, and so does the sign-in page's "Send the link again" for a letter that went astray
  ([[end-user-onboarding]]).

## Sign-up

A registration into this bucket goes through the ordinary registration page.
`registeredAdministrator` (`lib/admin/administrators.ts:20`) pairs the new account with its personal
group, as every other admin-creation path does. It records `admin.register` with the bootstrap actor.
That action has no admin route, so it is declared among the non-route audit actions
(`lib/consts/admin_audit_routes.ts:579`) rather than in the route table the drift guard checks.

Registering an address that is already taken was always non-committal. A **race** between two
registrations for one address used to surface the store's uniqueness error. It now gets the same
non-committal answer, in every bucket (`index.ts:1407`).

## Links on the sign-in page

The page links to registration and to password reset only when its bucket keeps those doors open. The
two flags come from the same bucket read the page already makes, using the same resolution the doors
use (`lib/interactions/loginOptions.ts:64-65`). Reset eligibility is one predicate shared by the page,
the request and the link (`selfServiceResetAllowed`, `lib/password_reset/eligibility.ts:19`).

## Not here: federation into the console

Letting administrators sign in through an upstream identity provider is a separate feature (079). It
carries its own security decisions:
- whoever controls the upstream provider controls console access;
- an account created at a first federated sign-in needs a personal group and must obey the sign-up
  policy;
- password sign-in may be turned off only by someone who can still get in through a provider.

Until then federation stays refused for this bucket, which is also why `passwordLogin: false` is always
refused.

## Related

- [[end-user-onboarding]]: registration and verification per bucket.
- [[totp-second-factor]]: the second factor, whose administrator setting this replaced.
- [[self-service-password-reset]]: why reset stays refused for this bucket.
- [[admin-mcp-control-plane]]: why "verify my address" is excluded from the agent rather than published.
- [[group-ownership]]: personal groups and the System group that owns this bucket.
