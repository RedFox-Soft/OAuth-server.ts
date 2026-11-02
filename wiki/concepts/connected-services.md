---
type: concept
title: 'Connected services: a person connects accounts at other services'
tags: [architecture, security, storage, decision, gotcha]
sources: [oauth-server-codebase]
created: 2026-11-02
updated: 2026-11-02
---

# Connected services

Spec 117, the floor of the token vault (spec 116 sealed stored secrets; 118 will issue the stored tokens to
agents by token exchange; 119 adds the agent's connect link). A project declares **connected services**
(Google, GitHub, Slack, Microsoft, an OpenID Connect issuer, or a plain OAuth 2.0 provider) with its own
registration at each provider. A person **connects** their account at one from their account page, and the
provider's tokens are stored sealed. Nothing reads the tokens yet.

Words: a *connected service* is the project's registration at a provider; a *connected account* is one person's
account at one service. The account page's older list is *connected applications* (specs/095), the opposite
direction.

## Where things live

- **A service is embedded on the project record**, beside `federation`: `UserBucket.connectedServices`
  (`lib/adapters/types.ts:2214`). Owned by the project for life, deleted with it, sealed by the project store's
  decorator (`lib/sealing/decorators.ts`, `services()`), at most a handful per project (a plan limit, Free 10).
  Its provider and client id never change: the accounts' tokens belong to that registration.
- **An account is a row of the `connectedAccounts` store** (`lib/consts/storage_inventory.ts:685`), three
  backends, `_id` derived from (project, service, person, upstream account)
  (`lib/connected_services/accounts.ts:59`), so a reconnect of the same upstream account replaces the row by its
  primary key on every backend and no second unique index exists.
- **A connect flow in flight is a `ConnectState` model record** (`storage_inventory.ts:423`), keyed by
  sha256(state), ten minutes, account-owned.

## Why connected accounts are deliberately not account-owned

"Owned by an account" in the inventory means "swept by `sweepAccountOwned`", which every lock, deactivation and
end of access runs (`lib/end_users/revoke_access.ts`). The owner decided a lock **keeps** connected accounts: it is
reversible, and an unlock must not make a person connect everything again; the lock already destroys the grants,
and 118's exchange will check the person can sign in. So the store declares `unowned(...)` with that reason, and the
three deletions that must remove accounts do so by hand:

- the person deleted: `removeEndUser` (`lib/end_users/service.ts:331`), which the admin route, bulk delete and SCIM
  all go through;
- the service deleted: its admin route, accounts first while the service is still on the record their revocation
  reads;
- the project destroyed: `destroyClaimed` (`lib/admin/buckets/destroy.ts:226`).

`ConnectState`, by contrast, *is* account-owned: a lock should end a connect that has not come back.

**Gotcha:** a new path that deletes a person or a service must call `destroyConnectedAccountsOf` /
`destroyServiceAccounts` itself. No sweep will.

## The connect flow and what binds it

Started only by a same-origin POST from `/account/services` with the page's anti-forgery value and a sign-in no
older than fifteen minutes (`lib/account_page/services_routes.ts`). The callback (`services_routes.ts:375`) spends
the state first, then refuses unless the addressed project is the flow's, the browser's session digest
(`services_routes.ts:405`) and account are the ones that started it, the person can still sign in, the service
still exists and a keyring is in use. Then `iss` (RFC 9207, where the provider advertises it), then the code with
the flow's PKCE verifier.

**Gotcha:** the flow never sends `response_mode` and never inherits the sign-in catalogue's `returnMode`. The
binding rests on the person's session cookie, which is `SameSite=Lax` and reaches the callback only on a top-level
GET; a provider posting back (`form_post`, as Apple does for sign-in) would arrive without it and every connect
would be refused.

**Gotcha, found only in a browser:** `form-action` governs a form's whole redirect chain, so the connect
confirmation, which posts to itself and is answered with a redirect to the provider, must name the provider's
authorization origin (`handOffTo`, `lib/account_page/html.ts`, through `page()` in
`lib/interactions/plainPage.tsx`). With `'self'` alone Chrome blocks the person's own Continue and reports the
same-origin action as the violation, while every `elysia.handle` test passes. A spec now pins the policy.

## Provider differences are data

`lib/consts/connected_service_catalogue.ts` states each one as a field, never a branch: Google needs
`access_type=offline` and `prompt=consent` for a refresh token; Slack hands the person's token back under
`authed_user`, takes scopes in `user_scope` joined by commas, and **never** gets a code challenge (enabling PKCE
on a Slack app makes it public, one-way, with refresh tokens capped at 30 days); GitHub answers with comma-separated
scopes and is identified through `/user` `id`; Microsoft is keyed `tid:oid` because `sub` is pairwise per
application, and has no revocation at all. A plain OAuth 2.0 service must declare where its account id is (an
identity endpoint or the token answer), because without a key a second account cannot be told from a reconnect.

## Tokens are never plaintext

Unlike every 116 field, the connected-account store **throws** `KeyringRequired` on a write while no keyring is in
use (`lib/sealing/decorators.ts:705`, `:744`); the service layer refuses earlier with a message, and declaring or
editing a service is refused with 409 `keyring_required`. After a lost key the account reads as
`needs_reconnection`, is counted in the keyring status with its person, and a reconnect replaces it; the service's
own secret was lost too, so an administrator re-enters it first.

## Revocation: local first, provider best-effort

Every removal deletes the row, then asks the provider (`lib/connected_services/revoke.ts`): Google's revoke form
with the refresh token, GitHub's grant deletion with Basic client auth, Slack's `auth.revoke` with the user token,
RFC 7009 for a generic provider that has an endpoint, nothing for Microsoft (the person is linked to its consent
page). Four seconds per request, so a person's own disconnect answers within five; every cascade revokes in the
background, four at a time, never holding the request.

Known limit, carried to 118: GitHub and Slack revoke with the access token, and 117 never refreshes, so an expired
access token makes that revocation fail and the person is told to remove access at the provider.

## Not here

Issuing tokens, refresh (one at a time per account, because GitHub and Slack refresh tokens are single-use),
keep-alive, per-agent consent and the mail about a removed or broken account are spec 118.
