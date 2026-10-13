---
type: concept
title: "Bucket sign-in policy: refusals first, then a counted preview to confirm"
tags: [architecture, contract]
sources: [oauth-server-codebase]
created: 2026-10-11
updated: 2026-10-12
---

# Bucket sign-in policy

Spec 083. A bucket's sign-in settings are five values on the bucket: `passwordLogin`, `registrationOpen`,
`emailVerificationRequired`, `verificationMethod` and `totpRequired`. They are changed with the ordinary
bucket PATCH (`PATCH /admin/api/buckets/:id`, `lib/admin/buckets/routes.ts:824`), by the console and by an
agent through `bucket_update`. Before spec 083 a change that locked people out went through in one request,
and the console asked its own question with no numbers in it. Now the server says what the change does to
whom, counted, and applies it only when the caller repeats the request with those counts.

## The order a PATCH is decided in

1. **Rights**: `loadBucketForSettings(…, 'edit')`, the `editSettings` right (`routes.ts:827`).
2. **Refusals** (409 `{ error, message }`, nothing recorded):
   - the change would leave no way to sign in (`assertSomeWayToSignIn`, `lib/admin/federation/validate.ts`);
   - verification turned on while mail delivery is not configured, on **every** bucket (`routes.ts:838-849`,
     below);
   - the administrators' bucket's own guards (`assertAdminBucketChange`,
     `lib/admin/buckets/admin_bucket.ts:27`; see [[admin-bucket-settings]]).
3. **Preview**: a change that tightens who can get in answers 409 with what it would do, unless it is
   confirmed (`routes.ts:857-878`).
4. **Audit**, then **write** (`routes.ts:884-890`).

Refusals run before the preview so a preview is never offered for a change that would then be refused.
Nothing is audited for any 409: the entry is written only when the change applies.

## What is previewed

`signInPreview(bucket, changes)` (`lib/admin/buckets/sign_in_preview.ts:79`) answers `null` or
`{ consequences, expect, changes }`. A change is previewed only when it moves in the tightening direction:

| Change | Kind | Sentence | Count in `expect` |
|---|---|---|---|
| `passwordLogin` true → false | `passwordsOff` | "N of M users have no account at an enabled identity provider and could no longer sign in." | `withoutEnabledLink` |
| `emailVerificationRequired` false → true | `verificationOn` | "N users haven't verified their address; each is sent a message at their next sign-in and cannot continue until they follow it." | `unverified` |
| `totpRequired` false → true, while passwords stay on | `authenticatorOn` | "N password users have no authenticator yet; they set one up at their next sign-in." | `passwordWithoutAuthenticator` |
| `registrationOpen` false → true, on the default or the administrators' bucket only | `signUpOpen` | "Anyone who can reach the sign-in page can create an account." (an administrator account, on the console's bucket) | none |

On the default bucket (`redfox`) every preview adds "This changes sign-in for N projects." with
`expect.projects` (`sign_in_preview.ts:158`).

Not previewed: renaming, the verification method, closing sign-up, turning any requirement off, and opening
sign-up on an ordinary bucket. Opening sign-up is what an ordinary bucket is for. On the two buckets served
at the root it means anyone who reaches this server's own sign-in page can make an account. An
authenticator requirement while passwords are off is inert (it governs the password door only), so it
applies at once with the existing advisory.

On the administrators' bucket, passwords off names the administrators who could no longer get in, by email,
and counts them. It reads them as the sign-in readiness does (`loadReachabilityState`,
`sign_in_preview.ts:113`), so an address outside a provider's admitted domains counts as unlinked there too.
They are colleagues, few, and the person turning passwords off has to tell each of them.

## Confirming

The protocol is the address change's ([[bucket-workspace]]):

- Without `confirm`: 409 `{ confirmationRequired: true, consequences, expect, changes }`.
- With `confirm: true` and an `expect` whose keys equal the fresh preview's counts: applied. Only the keys of
  the fresh `expect` are compared (`sameExpect`, `sign_in_preview.ts:168`).
- With `confirm: true` and `expect` missing or different: 409 with `error`, a `message` ("confirm with the
  counts of the preview you reviewed (expect)" or "what this change affects changed since you reviewed it")
  and the fresh preview.

Consent is to the numbers shown. Somebody who registered, or lost a link, while the preview was open is not
covered by a consent given before them. `confirm` and `expect` never reach the store or the audit entry:
the route splits them off the body first (`routes.ts:828`), and the entry's `attributes` are the changed
setting names (`routes.ts:887`).

The 409 is returned with Elysia's `status()` rather than thrown. A thrown error with a body of its own would
have to be shaped by the routes' `onError`, and Elysia counts an `onError` return as a response of every
route in the plugin, so every bucket route's success type would have gained the preview.

An agent receives the same 409 as a `conflict` carrying the preview (`lib/mcp/result.ts:79`) and repeats
the call with `confirm` and `expect`. `bucket_update` stays `ordinary` on the MCP surface: the confirmation is
the route's own, not the two-call token gate.

## The counts

The counts come from `tally(options)` on every user store (memory, MongoDB, PostgreSQL;
`lib/adapters/types.ts:413`):

- `withoutEnabledLink`: no `federated` entry whose `providerId` is one of the bucket's enabled providers.
  With no enabled provider it equals `total`. MongoDB uses `$nin` on `federated.providerId`, which matches an
  absent, null or empty array. PostgreSQL uses `NOT EXISTS` over `jsonb_array_elements` with `= ANY` (an
  empty array matches nothing).
- `passwordWithoutAuthenticator`: no TOTP enrolment, and `passwordSet !== false`. An account written before
  `passwordSet` existed counts. That is the conservative reading of an unknown: such a person may well have a
  password.

Inactive and locked accounts are counted, as in the rest of the tally. `signInCounts(bucket)`
(`sign_in_preview.ts:50`) feeds both the bucket summary and the preview, so the numbers shown under the
console's switches are the numbers a confirmation has to repeat. The summary
(`GET /admin/api/buckets/:id/summary`, `routes.ts:777`) adds `withoutEnabledLink`,
`passwordWithoutAuthenticator`, and, on the default bucket only, `projects`. `projects` counts projects
whose `bucketId` is `redfox` or empty, because a project naming no bucket signs in at the default one
(`resolveBucketForRequest`).

## Verification needs mail, on every bucket

Turning `emailVerificationRequired` on while mail delivery is not configured is refused on every bucket with
"people could not receive the verification message: configure mail delivery first" (`routes.ts:838-849`).
Before spec 083 only the administrators' bucket refused it. On an ordinary bucket the requirement was
accepted, and then every unverified person was sent to a message that could not be sent. Turning the
requirement off is always allowed. The administrators' bucket keeps its own extra rule: the acting
administrator must have verified their own address.

## New buckets are closed

`POST /admin/api/buckets` writes `registrationOpen: body.registrationOpen ?? false` (`routes.ts:721`). A
bucket's people arrive through its administrators, its identity providers and its directories. A door anyone
can walk through is a decision to state when the bucket is created. The stores' own defaults are untouched,
so a stored bucket without the field still reads as open, as it always has.

## Recovering an administrator

Two super-administrator routes in `lib/admin/users/routes.ts`, both refused on the caller's own account:

- `POST /admin/api/admins/:id/sign-out` (`routes.ts:301`): every console session of that administrator ends
  (`AdminSessionStore.destroyByUser`, served by a `{ userId: 1 }` index declared on the admin-session area in
  `lib/consts/storage_inventory.ts:711`). So does every grant and token at the console's issuer
  (`revokeAccountAccess`), agents' tokens included. The account is left as it was. Answers `{ sessions }`,
  the number of console sessions ended. Refused on oneself with "you cannot sign yourself out from here —
  use Log out".
- `DELETE /admin/api/admins/:id/totp` (`routes.ts:317`): refused with "no authenticator to reset" when there
  is none. Otherwise clears the enrolment, clears failed attempts (`clearAttempts`), then signs out as above.
  Answers `{ sessions }`.

Both are audited first, after the guards (`admin.signout`, `admin.totp.clear`,
`lib/consts/admin_audit_routes.ts:186-192`). Both are published as `high`, super-administrator-only MCP
tools: `admin_sign_out` and `admin_totp_clear`. Unlike `bucket_user_totp_clear`, which is ordinary, the
authenticator reset is gated: it removes a second factor from an account that administers the instance.

## Related

- [[admin-bucket-settings]]: the administrators' bucket's own guards, which run among the refusals.
- [[bucket-workspace]]: the address change whose preview protocol this copies.
- [[end-user-onboarding]]: registration and verification per bucket.
- [[console-federation]]: who may turn passwords off on the console's bucket.
- [[admin-mcp-control-plane]]: how a preview reaches an agent, and the high-consequence tools.

## In the console

The settings are a tab of their own, `/admin/buckets/:id/sign-in`, between User groups and Identity
providers; the dialog behind "Edit sign-in…" is gone. `lib/admin/ui/pages/signin/SignInTab.tsx` serves every
bucket, and the administrators' bucket through its `consoleBucket` mode.

- **One draft, one save.** The five values are a draft; the instance Settings page's `SaveBar` counts the
  changes and saves them in one PATCH, and `useLeaveGuard` asks before leaving with any unsaved. A saved bucket
  remounts the tab (`key={signInKey(bucket)}`), so the stored values become the new starting point.
- **What the server would refuse is unavailable beforehand.** Passwords cannot be turned off while no provider
  is enabled (on the console's bucket: outside a session that came in through a linked provider); verification
  cannot be turned on without mail (on the console's bucket, also before the operator's own address is
  verified, with "Send me a verification email" beside it). Each says why and where to go.
- **Counts while deciding, the server's words when saving.** Under a switch moved in the tightening direction,
  the summary's count is shown; Save sends the change, and a preview comes back as the danger question
  `bucket.signIn.confirm` listing the server's sentences, with Cancel labelled "Keep editing" (an optional
  `cancelText` on the action table). Confirming repeats the request with the preview's `expect`; a moved count
  asks again with the fresh lines. The console asks no question of its own: `bucket.passwordSignIn.off` is gone.
- **What people will see.** Every switch carries one sentence about the experience of the people signing in,
  in both of its states.
- **And the page itself (spec 091).** Beside the switches (below them on a narrow window) the card "What people
  see" draws the bucket's sign-in page with the draft, before anything is saved
  (`lib/admin/ui/pages/signin/SignInPreview.tsx`). It is the real `LoginPage` component (`embedded`, inside a
  `<div inert>`, so nothing in it can be focused, clicked or submitted), fed by `signInOptionsOf`
  (`lib/interactions/signInOptions.ts`) — the rule the server renders the page with, split out of
  `loginOptions.ts` so a browser can run it; a preview with its own idea of which buttons to draw would be a
  second opinion the operator trusted. Its inputs are the draft, the `GET …/federation` list (already in sign-in
  order, so its ids are passed as the order; leaving the order out would fall back to catalogue rank) and the
  summary's `federationEnabled`. Only the first screen is drawn: the authenticator requirement and verification
  act after it. `test/federation/signin_preview.spec.ts` compares the preview's options, read through the admin
  API, with the real page's `window.PROPS` across configurations.

## The Administrators page

`/admin/administrators` is the administrators' bucket's home (`lib/admin/ui/pages/administrators/
AdministratorsHome.tsx`): Accounts, Sign-in, Identity providers, Activity (monthly sign-ins, linking to the
audit entries about administrator accounts), Settings (its name). Every former `/admin/buckets/admin/...`
address redirects to the matching tab (`lib/admin/ui/frame/routes.ts`, `REDIRECTS`), and the Buckets list links
the bucket there. Accounts (`Admins.tsx`) searches and filters in the browser — tens of rows, not thousands —
and offers each act at its class: change email, grant or withdraw super administration, reset the
authenticator, sign out everywhere, deactivate and activate. The caller's own row omits the acts that would end
their own access, and its Change email says why it is unavailable while verification is required.
