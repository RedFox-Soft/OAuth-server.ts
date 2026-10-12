---
type: concept
title: 'End-user support: invitations on the reset challenge, mark verified, sessions per application, local profiles, bulk acts'
tags: [architecture, contract, gotcha, security]
sources: [oauth-server-codebase]
created: 2026-10-12
updated: 2026-10-12
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:end-user-lifecycle
    - predicate: depends_on
      object: concept:self-service-password-reset
    - predicate: relates_to
      object: concept:bucket-users-workspace
    - predicate: relates_to
      object: concept:admin-audit-trail
---

# End-user support

Spec 089 gave an administrator supporting real people what they used to work around:
- an invitation instead of an invented password;
- a manual "mark verified";
- the applications a person is signed in to, with a sign-out per application;
- an editable profile for local users;
- bulk acts on a selection of up to 100;
- a member search inside a group.

## An invitation is a password-reset challenge with a purpose

There is no second secret store. `PasswordResetChallenge` gained `purpose: 'reset' | 'invite'`, and an invitation
lives `INVITE_TTL_SECONDS` = 7 days (`lib/password_reset/consts.ts:17`). `invite()` sends it, awaited, so the
administrator learns of a delivery failure (`lib/password_reset/challenge.ts:418`). It shares with the reset:
- the digest-only token;
- `ReplayDetection` single use;
- the account-owned cleanup on lock, deactivation and deletion;
- the link `/reset-password?token=`, its plain page and its throttle.

The page's copy follows the loaded purpose ("Set your password for <bucket>"). An invalid link has no purpose,
so one neutral failure page covers both. One outstanding set-password secret per person is the rule: an
invitation supersedes a reset link and the reverse.

### Two defects the reuse exposed

1. **A reset link survived an email change.** `updateEndUser` only cleared `verified`, and `load()` never compared
   the challenge's address with the account's. So a link sent to the old address set the password and marked the
   *new* address verified — a verification bypass. `load()` now refuses a challenge whose `email` is not the
   account's current one (`challenge.ts:288`), as verification's `addressStillHeld` always did.
   `test/password_reset/address_change.spec.ts` failed (200, 200) before the fix.
2. **The supersession pointer lived 24 hours.** The pointer to the live challenge sits on the throttle record,
   whose lifetime was the rate window. A 7-day invitation resent after a day would have left the first link alive.
   The record now lives `max(window, challenge lifetime)` (`challenge.ts:136`).

## Mark verified is a named act

`markEndUserVerified` (`lib/end_users/service.ts:471`) is refused for a provisioned user: a directory's address
trust is the connection's. Already verified is a 409 with no audit entry. It destroys any pending verification
challenge and resend pointer (`discardPending`, `lib/verification/challenge.ts:353`). The admin PATCH still cannot
set `verified`. The resend route gained the same provisioned refusal.

## Sessions are read from grants

`applicationSessions` (`lib/end_users/sessions.ts:81`) groups the person's **grants** by client, because an
offline grant outlives its session.
- **Signed in** is the holding session's `loginTs`, else the grant's creation.
- **Last token issued** is the newest stored refresh or access token of the grant. JWT access tokens are never
  stored, so the console names it honestly and says a token an app checks by itself is invisible here.

No IP or user agent: none is stored.

"Sign out of this app" (`endApplicationAccess`, `service.ts:496`) follows the partial logout of `end_session.ts`:
1. back-channel logout to that client only, and the client's entry dropped from each session;
2. every token under its grants revoked, `persistsLogout` ignored, so offline access goes too;
3. the grants destroyed (`endGrants`, `lib/end_users/revoke_access.ts:47`). A kept grant is reused by the next
   authorization.

**The session's lifetime is not extended.** `Session.save(lifetime)` (`lib/models/session.ts:142`) takes the
remaining seconds for a change its holder is not making. Saving with the default would have handed every one of the
person's sessions a fresh full lifetime as a side effect of signing them out of one app.

## Local profiles, and the profile now wins

An administrator may write a local user's `profile` (the closed SCIM shape) on the PATCH. The admin path validates:
- locale as BCP 47, via `Intl.getCanonicalLocales`;
- timezone as an IANA zone;
- phone numbers as E.164.

Refusals name `profile.<field>`. SCIM stays tolerant: a directory's data is the directory's. Provisioned users stay
read-only.

**Precedence changed.** `findAccount`'s `claims()` used to merge the profile *before* the stored `claims`, so a blob
claim beat the profile. It now merges the blob first, then what `profileClaims` produces (`lib/addon/account.ts:113`),
then `sub`, `email` and `email_verified`. The profile wins for the claims it sets; the blob supplies the rest.
- **For a provisioned user**, a blob `given_name` now loses to the directory's. That is the right owner.
- **The blob can no longer override `email`** either. Those claims are reserved, so nothing in production stored
  them, and the test harness's seeding was corrected instead.

## Bulk acts: four routes, one entry per person

`POST …/users/bulk/{deactivate,activate,sign-out,delete}` each take 1–100 ids.

**Why four routes, not one route with an `action`:**
- every audited action belongs to exactly one route;
- MCP consequence is per tool — deactivate and delete are high, activate and sign-out ordinary.

**How a bulk act runs.** `applyBulk` (`lib/end_users/bulk.ts:84`):
- calls the single act's service function per person, sequentially;
- records `enduser.bulk.<act>` for that person, so each history is findable by its id;
- answers per person: changed, skipped with a reason (`provisioned`, `already_active`, `already_inactive`,
  `not_found`), or failed with its message and `failedAreas`.

A repeat is harmless. Bulk activation never unlocks.

**Add to group stays the existing member-add route**, which already takes up to 1000 ids and records one entry on
the group.

## Member search

`GET …/groups/:gid/members?q=` reuses the user list's prefix search (email or `userNameKey` prefix, or an exact id),
through a `memberOf` filter on all three user stores. PostgreSQL uses an `EXISTS` on the membership table; MongoDB
and memory use the group's member ids. `totalResults` is exact.

## Related

- [[self-service-password-reset]] — the challenge an invitation reuses.
- [[end-user-lifecycle]] — the single acts every bulk act repeats.
- [[bucket-users-workspace]] — the console where all of this lives.
- [[admin-audit-trail]] — the per-person bulk entries and the new `clientId` field.
