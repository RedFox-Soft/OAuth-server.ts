---
type: concept
title: 'Connected services: a person connects accounts at other services'
tags: [architecture, security, storage, decision, gotcha]
sources: [oauth-server-codebase]
created: 2026-11-02
updated: 2026-11-03
---

# Connected services

Spec 117, the floor of the token vault (spec 116 sealed stored secrets; 118 issues the stored tokens to agents by
token exchange, below; 119 puts a connect link for the person in the exchange's refusal, below; 120 lets a sign-in
through a linked provider connect the account, below). A project declares **connected services**
(Google, GitHub, Slack, Microsoft, an OpenID Connect issuer, or a plain OAuth 2.0 provider) with its own
registration at each provider. A person **connects** their account at one from their account page, and the
provider's tokens are stored sealed. Since spec 118 an agent the administrator and the person both allowed obtains
them by token exchange.

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
and 118's exchange checks the person can sign in. So the store declares `unowned(...)` with that reason, and the
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

Since spec 118, GitHub's and Slack's revocations, which authenticate with the access token, refresh an expired one
first (`revocableTokens`, `lib/connected_services/accounts.ts`): without a lease, because the record is already
deleted, and within one second for the person's own disconnect so the whole stays under five.

## Handing the tokens to agents (spec 118)

An agent exchanges a person's access token at `/token` by RFC 8693 with
`requested_token_type=urn:ietf:params:oauth:token-type:access_token`, `audience=<service id>` and, when the person
allowed several accounts there, `login_hint=<account label>` (Auth0 Token Vault's parameter for the same choice). The
answer is the stored upstream access token, never the refresh token. Everything is in
`lib/connected_services/upstream_exchange.ts:134`; the grant only routes there by token type
(`lib/actions/grants/token_exchange.ts`).

**Two consents, both checked on every exchange.** The administrator's: `ConnectedService.applications`, the
applications that may obtain that service's tokens, edited through the service's own PATCH. The person's: a
`connected` map on their Grant to the agent, keyed `account:<id>` (or `service:<id>` before they have an account
there), so it goes wherever the grant goes (`lib/connected_services/consent.ts`). Nobody among ten vendors asks the
person per agent; this is deliberate.

**Who may exchange.** The agent itself when it is confidential, or the application an administrator linked to an API
the agent's token was issued for (`ProtectedResource.exchangedBy`, the MCP server case, Auth0's "Custom API Client").
`whyCannotExchange` (`lib/connected_services/eligibility.ts:14`) is the one test for both and for the exchange: an
application of this project, created by an administrator, that authenticates and holds the token exchange grant.

**Gotcha: a JWT access token is not stored.** `BaseModel.save` writes only when the format yields a payload, and the
JWT format yields the value alone, so a JWT subject (an MCP server's, by default) has no record and names no grant.
`exchangeSubject` (`lib/connected_services/subject.ts:123`) verifies it as its API would (keys, issuer, `at+jwt`,
lifetime), takes the person from `sub` (refused for a pairwise agent) and reads the consent from the person's live
grants to the agent: removing the application's access leaves none, so the token is refused although it cannot itself
be revoked.

**Refusals carry a `reason`** beside RFC 6749's `error` (`UpstreamTokenRefused`, `lib/helpers/errors.ts`):
`not_permitted`, `consent_required`, `connect_required`, `account_selection_required`, `reconnect_required`,
`temporarily_unavailable`. A bad subject token is plain `invalid_grant` with none, so no answer says anything about the
person's accounts. Since spec 119 (2026-11-02) `account_selection_required` lists `accounts`, the labels of the
accounts the person allowed this agent and no others, and a scope the service does not declare is `not_permitted`
with `error=invalid_scope` (it was `reconnect_required`, which a reconnect asking only for the declared scopes could
never fix) (`assertScopes`, `lib/connected_services/upstream_exchange.ts:137`).

**The grant is always advertised.** `supportedGrantTypes` lists token exchange whatever `tokenExchange.enabled` says
(`lib/configs/discoverySupport.ts:92`); the setting now gates only ID-JAGs, and an ID-JAG request while it is off is
`invalid_request`, never `unsupported_grant_type`, because an advertised grant is never refused as unsupported (see
[[enterprise-managed-authorization]]).

## The person's connect link (spec 119)

Three refusals are the person's to fix, not the developer's: `connect_required`, `consent_required` and
`reconnect_required`. Each carries `connect_uri`, `connect_id`, `connect_expires_in` and `connect_message`, which map
one to one onto an MCP URL elicitation (`attachLink`, `lib/connected_services/upstream_exchange.ts:190`). The link is
attached only after the person is known, so a bad subject token still answers the same whatever anyone has; a link that
cannot be made leaves the refusal as it was.

**One slot per person, agent and service.** A link request is a `ConnectLink` model record keyed by SHA-256 of
(project, person, agent, service), found by its value through a unique `payload.uid` index as a session is
(`lib/consts/storage_inventory.ts:430`), thirty minutes, owned by account and client so a lock or the agent's deletion
ends it. A retry gets the same link while it is open and the act is unchanged; another act overwrites the slot, and the
old value then finds nothing (`issueLink`, `lib/connected_services/link.ts:59`). No counter: open links are bounded by
a person's agents times the project's services. No migration either: `db:setup` provisions the area and its index.

**The value is not a credential.** `/account/services/link/:link` (`lib/account_page/link_routes.ts`) acts only for
the person the agent's token named: unknown, expired, replaced and declined values read the same 404; nobody signed in
goes to sign in and back; another person gets 403 naming no one; a sign-in older than fifteen minutes signs in again;
only then does a used link say "already done" (`open`, `link_routes.ts:114`). Everything the exchange checked about the
agent and the administrator is checked again before the page offers anything, and the act already done on the account
page closes the link (`situation`, `link_routes.ts:180`). Every act is a button on a same-origin form with the page's
anti-forgery value, as on `/account/services`.

**Gotcha: a connect from a link carries the consent in its state.** `startConnect` stores `link` on the `ConnectState`,
and the provider's return (`finishLink`, `lib/account_page/services_routes.ts:330`) records the agent's consent for
the account just connected, after checking the allow-list and the agent's grant again, because thirty minutes and a
provider lie between the press and the answer. A reconnect writes no consent; reconnecting as another upstream account
connects that one as new and leaves the broken one. The link's done page is reached by `?done=` on the link itself,
read by whitelist.

**Gotcha: the memory adapter indexed `uid` for `Session` only.** MongoDB's and PostgreSQL's `findByUid` query any
collection's `payload.uid`; the memory adapter kept one global pointer for sessions. It now keeps one per model and
answers only while the record still holds the uid asked for, since a slot rewritten under a new uid left the old
pointer behind (`lib/adapters/memory/memoryAdapter.ts:112`). Found by the replaced-link test on 2026-11-02.

The agent learns the outcome by repeating the exchange, as MCP 2026-07-28 does for every out-of-band step; there is no
status endpoint and no redirect back to the agent. `account_selection_required` carries no link: the choice belongs in
the conversation, where the agent can ask with a form elicitation over `accounts`.

## Kept from sign-in (spec 120)

A service's optional `signInProviderId` names one sign-in provider of the project whose sign-ins also connect the
person's account at the service. Accepted only for the same provider and the **same client id**
(`signInMatch`, `lib/connected_services/link_signin.ts:34`): tokens belong to the registration that asked for them,
and the service refreshes and revokes with its own, so a kept account needs no second refresh path. Google, Microsoft
(same tenant), GitHub and OIDC by issuer match; Slack does not, since its user tokens come from `oauth.v2.access`
with `user_scope`, which its OIDC sign-in never calls. The link has one writer, the service's PATCH, as
`applications` does; a provider edit that would end the match is refused `linked_to_service` and a provider's
deletion clears the link (`assertLinkSurvives`, `lib/admin/federation/routes.ts:61`).

The sign-in start adds the service's scopes and offline access, and **never `prompt=consent`**
(`keepRequest`, `link_signin.ts:101`): every forced consent mints a new Google refresh token, and past 100 per
account and client Google silently invalidates the oldest, which may be an agent's. So a sign-in may bring no
refresh token; the store step then keeps the stored one (`storeConnectedAccount`,
`lib/connected_services/accounts.ts:349`), and a new account without one is marked broken `no_refresh_token` once
its access token is due (`lib/connected_services/refresh.ts:132`), which the exchange answers as
`reconnect_required` with 119's link. Only when due: keep-alive also visits accounts whose token never expires
(GitHub OAuth apps), which are not broken.

**Gotcha: tokens are kept only at leg three.** Leg two (`keptFromSignIn`, `accounts.ts:219`) names the upstream
account with 117's `identify`, not the sign-in's subject (Microsoft's sign-in `sub` is pairwise per registration
while accounts are keyed `tid:oid`), and carries the tokens in the handoff record, where `kept.tokens` is one sealed
JSON leaf (kind `signInTokenInTransit`, `sealedFederationStateAdapter`, `lib/sealing/decorators.ts:655`). Leg three
keeps them only on the path that sets the login result (`lib/interactions/index.ts:1807`); the password-link and
verification doors return first. Keeping at leg two would store a login-CSRF victim's tokens without the victim
signing in. A keep never fails a sign-in: every fault is a `connected_account.refused` event with a reason.

The person's own disconnect is remembered on their record, `connectionsDeclined`, at most 50 trimmed before the write
(`recordConnectionDeclined`, `lib/end_users/service.ts:581`), and cleared by their own connect; an administrator's
removal is not remembered. The list is barred from administrative reads by `presentUser`. A provider that refuses
the extra scopes (`invalid_scope`, `consent_required`, `interaction_required`, or Microsoft's `invalid_grant` with
`suberror=consent_required` at redemption) gets one retry without them (`lib/federation/routes.ts:118`);
`access_denied` is not retried, since it is also how a person's cancel returns. A provider that blocks the scopes on
its own page (Google Workspace `admin_policy_enforced`) never returns, so nothing can be retried.

## One refresh at a time

GitHub (expiring user tokens) and Slack (token rotation) spend a refresh token on use, so two concurrent refreshes
lose the account. `freshAccount` (`lib/connected_services/refresh.ts:59`) shares one in-process promise per account and
takes a 20-second lease written on the record itself (`claimRefresh` / `finishRefresh` / `releaseRefresh`, all three
backends); a waiter polls the record for at most 12 seconds; a holder that died is taken over when its lease runs out.
The new tokens are stored before anyone receives them; a refresh whose result could not be stored breaks the account
(`refresh_unsaved`), because the provider has already spent the old refresh token.

**Gotcha (found by the real-PostgreSQL verify):** dropping keys with `doc - ${array}::text[]` fails at runtime, since
Bun binds a bare JS array as comma-joined text. Use `handle.array(keys, 'text')`, as every other store does.

**Slack's refreshed user token** sits where the documentation does not say: its rotation guide shows the user case
only as a fragment with the `authed_user` members. The catalogue's `refreshTokenPath: 'authed_user'` tries there, then
the top level; the code exchange never falls back to the top level, where Slack puts the bot's token.

## Keep-alive and mail

An hourly pass (`lib/connected_services/keep_alive.ts:31`, started in `lib/index.ts`) refreshes, under the same lease,
every account with a refresh token that an agent may use and did use within twelve months, when it was not refreshed
for thirty days or its refresh token expires within a week. Thirty days sits inside Google's six idle months,
Microsoft's ninety days and GitHub's six months, with no per-provider table to keep right. A token nobody uses is left
to lapse.

A break (`markBroken`, atomic, `first` true once) mails the person once; a reconnect writes a record without `broken`,
which re-arms it. An administrator's disconnect and a service deletion mail too; the person's own disconnect and a
person's or project's deletion do not (`lib/connected_services/mail.ts`). Only to a verified address, only with mail
configured, in a background queue, never naming a token or an identifier.
