---
type: concept
title: "The administrators' bucket: ordinary settings, a guard per setting"
tags: [architecture, contract]
sources: [oauth-server-codebase]
created: 2026-10-10
updated: 2026-10-12
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
`GET /admin/api/buckets/:id`, its `/summary` and `PATCH /admin/api/buckets/:id` use it (and, through
`loadBucketForProviders`, the provider routes).
- It refuses the administrators' bucket to anyone who is not a super administrator, explicitly. It does
  not rely on the bucket's owner, the System group, having no members. That invariant is real but is not
  enforced anywhere near here.
- The bucket list includes the bucket only for a super administrator
  (`lib/admin/buckets/routes.ts:355`).
- Every response marks it `reserved: 'administrators'` (`routes.ts:248`), so the console and an agent
  learn what it is from what they were sent.

Deleting it, moving it, re-addressing it, keys and provisioning stay refused. Each of those already had
its own reason, and the refusal message now says the operation is not available for this bucket. Its
identity providers are admitted since spec 080 through `loadBucketForProviders`, which has the same
super-administrator-only rule as `loadBucketForSettings`; see [[console-federation]].

## The guards

`assertAdminBucketChange` (`lib/admin/buckets/admin_bucket.ts:27`) runs after access is checked and
before the preview and the audit entry, so a refused change records nothing. Since spec 083 a change that
tightens sign-in here is also previewed and must be confirmed with its counts, as on every bucket; the order
and the preview are on [[bucket-sign-in-policy]].

| Setting | Guard |
|---|---|
| `passwordLogin: false` | Since spec 080: refused unless the acting session signed in through an enabled provider of this bucket where the actor is linked (an agent never qualifies), and unless some active super administrator stays reachable through a provider ([[console-federation]]). `assertSomeWayToSignIn` still applies on top. Since spec 083, once allowed it is previewed, naming the administrators without a linked identity. |
| `emailVerificationRequired: true` | Refused while mail delivery is not configured (`mailDeliveryConfigured`, `lib/mail/mailer.ts:39`, the same test `deliver()` applies). Since spec 083 that refusal is the route's and holds on every bucket, worded "people could not receive the verification message: configure mail delivery first" ([[bucket-sign-in-policy]]). This bucket adds its own: refused while the **acting** administrator's own address is unverified, so the requirement can never refuse the person who set it. |
| `registrationOpen`, `verificationMethod`, `totpRequired`, `name` | No guard. Opening registration while verification is off answers with an advisory (`adminBucketAdvisory`, `admin_bucket.ts:50`), and an agent reads the same sentence the console shows. Since spec 083 opening registration and requiring an authenticator are previewed and confirmed first. |

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

`sendOnDemand` (`lib/verification/challenge.ts:295`) works within the existing cooldown and daily cap.
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
use (`signInOptionsOf`, `lib/interactions/signInOptions.ts:76-77`, since spec 091; the console's sign-in preview
runs the same function). Reset eligibility is one predicate shared by the page,
the request and the link (`selfServiceResetAllowed`, `lib/password_reset/eligibility.ts:19`).

## Federation into the console

Letting administrators sign in through an upstream identity provider was kept out of this feature and
shipped as spec 080 (this page called it "079" before; 079 became the console frame). Its decisions —
super administrators only, creation obeying the closed sign-up, a password proof on every link, and
password sign-in off only for someone who can get back in — are on [[console-federation]].

## Related

- [[end-user-onboarding]]: registration and verification per bucket.
- [[totp-second-factor]]: the second factor, whose administrator setting this replaced.
- [[self-service-password-reset]]: why reset stays refused for this bucket.
- [[admin-mcp-control-plane]]: why "verify my address" is excluded from the agent rather than published.
- [[group-ownership]]: personal groups and the System group that owns this bucket.
