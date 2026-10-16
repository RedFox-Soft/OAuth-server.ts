---
type: concept
title: "The administrators' project: ordinary settings, a guard per setting"
tags: [architecture, contract]
sources: [oauth-server-codebase]
created: 2026-10-10
updated: 2026-10-15
---

# The administrators' project: ordinary settings, a guard per setting

A project is stored as a bucket (`UserBucket`, area `userBuckets`), and a team as an administrator group
(`Group`); the code keeps those names. Spec 100 renamed them only where a person or an agent reads them:
the API paths are `/admin/api/projects/…`, the console's `/admin/projects/…`.

Administrator accounts live in a reserved project (`ADMIN_BUCKET_ID`). Until spec 078 that project was a
**blanket exception**. Every generic project route refused it, and its own settings endpoint,
`/admin/api/admins/settings`, carried one field, the second-factor requirement. So an operator could not
open sign-up for other administrators, could not require them to verify their email, and the console's
sign-in page still linked to registration and password reset, which the project refused.

The refusal was a lockout guard, not a statement that this project differs from others. Almost every
project setting, set carelessly here, shuts the console, and with it the only surface that could undo the
setting. Spec 078 kept the guarding and dropped the blanket. A super administrator now edits the project
on the ordinary settings page, and each dangerous setting carries a guard of its own.

## One narrow loader, not an opened pair

`assertNotReserved` (`lib/admin/buckets/access.ts:39`) stays inside `loadBucketForUsers` and
`loadBucketForEdit`. Those two loaders guard about forty routes: federation, users, provisioning, the
project's groups and more. Several of them have no second check of their own. Moving the reserved check
out of the loaders would have opened all of those routes to super administrators with nothing behind them.

Instead, a third loader, `loadBucketForSettings` (`access.ts:71`), admits the project. Only
`GET /admin/api/projects/:id`, its `/summary` and `PATCH /admin/api/projects/:id` use it (and, through
`loadBucketForProviders`, the provider routes).
- It refuses the administrators' project to anyone who is not a super administrator, explicitly. It does
  not rely on the project's owner, the System team, having no members. That invariant is real but is not
  enforced anywhere near here.
- The project list includes the project only for a super administrator
  (`visibleBuckets`, `lib/admin/buckets/visible.ts:14-20`).
- Every response marks it `reserved: 'administrators'` (`lib/admin/buckets/routes.ts:469`), so the console
  and an agent learn what it is from what they were sent.

Deleting it, moving it, re-addressing it, keys and provisioning stay refused. Each of those already had
its own reason, and the refusal message now says "this operation is not available for the administrators'
project" (`access.ts:43`). Its identity providers are admitted since spec 080 through
`loadBucketForProviders`, which has the same super-administrator-only rule as `loadBucketForSettings`; see
[[console-federation]].

## The guards

`assertAdminBucketChange` (`lib/admin/buckets/admin_bucket.ts:27`) runs after access is checked and
before the preview and the audit entry, so a refused change records nothing. Since spec 083 a change that
tightens sign-in here is also previewed and must be confirmed with its counts, as on every project; the order
and the preview are on [[project-sign-in-policy]].

| Setting | Guard |
|---|---|
| `passwordLogin: false` | Since spec 080: refused unless the acting session signed in through an enabled provider of this project where the actor is linked (an agent never qualifies), and unless some active super administrator stays reachable through a provider ([[console-federation]]). `assertSomeWayToSignIn` still applies on top. Since spec 083, once allowed it is previewed, naming the administrators without a linked identity. |
| `emailVerificationRequired: true` | Refused while mail delivery is not configured (`mailDeliveryConfigured`, `lib/mail/mailer.ts:39`, the same test `deliver()` applies). Since spec 083 that refusal is the route's and holds on every project, worded "people could not receive the verification message: configure mail delivery first" ([[project-sign-in-policy]]). This project adds its own: refused while the **acting** administrator's own address is unverified, so the requirement can never refuse the person who set it. |
| `displayName` (since spec 092) | No guard beyond its shape: 1–60 characters, trimmed, blank refused with 400 (`acceptedDisplayName`, `lib/admin/buckets/routes.ts:106`); `null` removes it. It is the name end users see at the top of the consent page, never the console's label for the project ([[consent-screen-decisions]]). The field's comment and the MCP tool text also name the sign-in page, which does not read it yet (2026-10-13). |
| `registrationOpen`, `verificationMethod`, `totpRequired`, `name` | Sign-up may be open only while verification is required: any change leaving `registrationOpen` true and `emailVerificationRequired` off is a 409 (`assertSignUpNeedsVerification`, `admin_bucket.ts`), since spec 103. Until then it was allowed with an advisory, as a choice for an instance behind its own network; it was not one — anyone could register under a colleague's address, and that colleague's next team invitation joined the stranger's account ([[team-ownership]]). The migration `2026-10-19-admin-signup-requires-verification` closes sign-up where it finds that state; it does not turn verification on, which would refuse every unproven administrator, super administrators included. Since spec 083 opening registration and requiring an authenticator are previewed and confirmed first. |

A super administrator cannot change **their own** address while verification is required
(`assertAddressChangeable`, `lib/admin/users/routes.ts:37`). The new address would be unproven, a typo
would lock out the person making the change, and when that person is the last super administrator it
would lock out the instance. Changing somebody else's address cannot lock you out. A changed address
leaves the account unverified, and the personal team, whose stored name *is* the owner's address,
follows it (`routes.ts:145`).

## The door has no exception any more

The sign-in check used to skip this project (`verificationGates`). It now gates on
`emailVerificationRequired` like any project (`lib/interactions/index.ts:862`), because the lockout guard
moved from the door to the setting.

In every project that requires verification, a correct password for an unverified account is now sent
what it needs (`unverifiedAtSignIn`, `index.ts:533`). It is no longer just told to "check your inbox",
which was a dead end for any account that existed before its project required verification.

`sendOnDemand` (`lib/verification/challenge.ts:295`) works within the existing cooldown and daily cap.
- At sign-in it **reuses** a live challenge rather than issuing a new one. Issuing supersedes the
  outstanding challenge, and a registrant who signs in before following their link must not have it
  replaced under them.
- The console's "verify my address" (`POST /admin/api/me/verification`, `lib/admin/me.ts:49`) forces a
  fresh challenge, and so does the sign-in page's "Send the link again" for a letter that went astray
  ([[end-user-onboarding]]).

## Sign-up

A registration into this project goes through the ordinary registration page.
`registeredAdministrator` (`lib/admin/administrators.ts:20`) pairs the new account with its personal
team, as every other admin-creation path does. It records `admin.register` with the bootstrap actor.
That action has no admin route, so it is declared among the non-route audit actions
(`lib/consts/admin_audit_routes.ts:579`) rather than in the route table the drift guard checks.

Registering an address that is already taken was always non-committal. A **race** between two
registrations for one address used to surface the store's uniqueness error. It now gets the same
non-committal answer, in every project (`index.ts:1407`).

## Links on the sign-in page

The page links to registration and to password reset only when its project keeps those doors open. The
two flags come from the same project read the page already makes, using the same resolution the doors
use (`signInOptionsOf`, `lib/interactions/signInOptions.ts:76-77`, since spec 091; the console's sign-in preview
runs the same function). Reset eligibility is one predicate shared by the page,
the request and the link (`selfServiceResetAllowed`, `lib/password_reset/eligibility.ts:19`).

## Federation into the console

Letting administrators sign in through an upstream identity provider was kept out of this feature and
shipped as spec 080 (this page called it "079" before; 079 became the console frame). Its decisions —
super administrators only, creation obeying the closed sign-up, a password proof on every link, and
password sign-in off only for someone who can get back in — are on [[console-federation]].

## Related

- [[end-user-onboarding]]: registration and verification per project.
- [[totp-second-factor]]: the second factor, whose administrator setting this replaced.
- [[self-service-password-reset]]: why reset stays refused for this project.
- [[admin-mcp-control-plane]]: why "verify my address" is excluded from the agent rather than published.
- [[team-ownership]]: personal teams and the System team that owns this project.
