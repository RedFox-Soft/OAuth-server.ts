# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow
[Semantic Versioning](https://semver.org/). Spec numbers refer to the (untracked) `specs/`
directories; open work is tracked as GitHub issues; full retrospectives live in the git history of
the retired `TASKS.md` and in the knowledge base at `wiki/`.

## [Unreleased]

## [2.2.0] - 2026-11-27

Passkeys end to end: projects, applications, APIs, proxy paths and the administrators' console can sign in with and
require passkeys, including passwordless projects, recovery, enrollment links and adoption campaigns. Eight new storage
areas and five migrations (one adds `phishing_resistant` to a stored `acrValues` setting if present, four are fences):
run the usual setup and migrate steps.

### Added

- **Sign in with a passkey** (spec 139). A project can turn on **Passkeys** in its Sign-in tab (or `project_update`
  with `passkeyLogin`; off by default, refused at an IP-address `ISSUER`). People
  then sign in with a fingerprint, face or screen lock from the sign-in page's button or autofill, and add, rename and
  remove up to 20 passkeys on their account page, now named **Sign-in and security**; each new passkey is mailed with
  a "This wasn't me" link. A passkey works only at the host it was made for. **Changed:** a passkey sign-in reports
  the multi-factor `acr` and `amr` `pop user mfa`, so every requirement of a code (an app's, an API's, a proxy
  condition's) now accepts it, and the console and the agent's tools call them "two-step sign-in". Operators see a
  person's passkeys on their page and revoke one or all of them, which signs the person out everywhere and mails them
  (spec 140; agents get `project_user_passkey_list`, `_revoke` and `_revoke_all`). The Sign-in tab counts who has a
  passkey, and an address change that breaks passkeys says beforehand how many people lose them and who has no other
  way in. After a password sign-in people are offered a passkey (spec 141; `passkeyOffer`, on by default): after a
  password and a code it is two-step at once, after a password alone it works like the password until confirmed from
  its mail in the same browser, and any reset or "This wasn't me" removes it. The account page keeps the browser's
  passkey list current, and each project host serves `/.well-known/passkey-endpoints`. A full passkey now reaches a
  fourth `acr`, phishing-resistant (`phr` by default; spec 142): an app is told it only when it asks for it, and an app
  that names `acr` values is told the strongest of them the sign-in met, so one that asks for the multi-factor value
  keeps getting it. A sign-in confirmed with a device code or on a back channel never reaches it, and discovery lists
  it only for projects that accept passkeys. An app can **Require a passkey** (`requirePasskey`), previewed like
  "Require two-step sign-in"; people turned away can create a passkey on the spot. Declared APIs and MCP servers can
  also **Require a passkey** (`requirePasskey`, spec 143; enforced at sign-in, every grant, refresh before rotation,
  token exchange and the proxy check with `401 passkey_required`, and every access token and introspection answer for
  such an API always reports `acr = phr` even when the client did not ask for it), and apps behind your proxy can
  require a fresh passkey on **Ask to sign in again** and **From where** network-facts conditions (`withPasskey`).
  Turning passkeys off or moving a project to a new RP ID previews how many APIs and proxy paths require a passkey.
  **Administrators and the console** (spec 144): **Passkeys** can now be enabled on the **Administrators** project
  (`passkeyOffer` remains off); administrators manage their own passkeys from the console header account drawer, super
  administrators inspect and revoke colleagues' passkeys in **Administrators -> Accounts** and via MCP
  (`admin_passkey_list`, `admin_passkey_revoke`, `admin_passkey_revoke_all`), and a super administrator who signed in
  with a passkey can enable **Require a passkey to sign in to the console** (`consolePasskeyRequired`, with named
  preview, immediate enforcement on live console sessions and `/mcp` tokens, strict refusal page with no passkey
  creation, and console reachability protection across all lockout paths). **Passwordless passkeys, recovery,
  enrollment links and adoption** (spec 145): projects (including **Administrators** when a passkey-signed-in super
  administrator confirms with mail configured) can now turn off **Password sign-in** with **Passkeys** on and no IdP
  after a named preview of affected accounts; visitors register directly with a passkey after proving mailbox ownership
  (honouring `verificationMethod` `link` or `code`, with identical non-enumerating screens for taken addresses).
  Non-admin projects can opt in to self-service **Passkey recovery** (`passkeyRecovery`, off by default, browser-bound
  10-minute email link, mandatory TOTP gate whenever enrolled, no auto-sign-in, and a 72-hour `multi_factor` ACR cap
  lifted early by signing in with another full passkey), enable the **Ask everyone to create a passkey** adoption
  campaign (`passkeyRequired`, up to 3 skips in 14 days on passkey-capable devices, free continue on unsupported
  devices, Sign-in tab progress counts), or opt in to **Passkeys for provider-only users** (`passkeyForFederated`,
  off by default, mutually exclusive with SCIM). Operators and super administrators can email 24-hour single-use
  passkey setup links (`/account/passkey-setup`, `204` email-only with zero token leakage, 7-day email-change
  cooldown, mandatory TOTP gate when enrolled, and `high`-consequence MCP tools `project_user_passkey_link_send` and
  `admin_passkey_link_send`). Unlinked federated sign-ins in passwordless projects matching an existing passkey holder
  now require passkey confirmation before linking.
  **Upgrade note:** run `db:setup` (or `db:setup:pg`) for the new storage areas (including `PasskeyRegistrationChallenge`,
  `PasskeyRecoveryChallenge`, `PasskeyAdminLink`, and `PasskeyLinkThrottle`) and indexes, then `db:migrate` (five
  migrations: the passkeys fence, naming `phishing_resistant` in a stored `acrValues`, the
  `2026-11-26-passkey-api-proxy-fence` fence, the `2026-11-27-admin-passkeys-fence` fence, and the
  `2026-11-27-passwordless-passkeys-fence` fence; the server refuses to start until all have run).

### Fixed

- **"This wasn't me" links survive a sign-out everywhere.** The link in the mail about a new two-step factor
  (spec 126) or a sign-in from somewhere new (spec 138) stopped working once anyone signed the account out
  everywhere, so whoever had just turned the factor on or signed in could take away the owner's way back. The links
  now have their own storage area (`NotMeLink`; run `db:setup`) and go only with the person or the project; links
  mailed before the upgrade no longer work.
- **Unnamed applications in sign-in alerts and recent sign-ins.** An existing OAuth client with no `client_name` (or
  one that sanitises to empty) was reported as "An application that no longer exists" in new sign-in alert emails, on
  a person's Recent sign-ins page and in an administrator's own sign-ins. It now falls back to its first web redirect
  host, else its `client_id` (with a URL metadata-document `client_id` reduced to its host so emails never gain a
  second link), matching the consent screen and Connected apps; only a deleted client reads as gone.

## [2.1.0] - 2026-11-18

Super administrators can see where administrators sign in from, and an account is emailed about a sign-in from a
new network or browser. Two fence migrations and one new storage area: run the usual setup and migrate steps.

### Added

- **Where and how your administrators sign in.** Administrators' sign-ins and refused sign-ins of a known
  administrator are now kept like people's, for 90 days, with the address, its network owner and location, and the
  browser. A super administrator reads one administrator's under Administrators, Accounts, Sign-ins, everyone's at
  once under Administrators, Activity, or with the MCP tools `admin_activity_list` and `admin_activity_feed`; every
  read is recorded in the audit trail. Accounts shows each administrator's last sign-in and marks refusals since it. Each administrator sees their own last ten,
  without addresses, from their email at the top of the console (`own_sign_in_list`). **Upgrade note:** run
  `db:migrate` (one fence migration); recording of administrators starts at the upgrade, nothing earlier exists; their
  addresses are sent to FoxTrust's API like people's while address lookup is on.

- **An email about a sign-in from a new network or browser.** When an account signs in from a network (its owner,
  else its country) or a browser it has not used in 90 days, its owner is emailed when, where, how and with which
  browser, never the address, with a "This wasn't me" link that signs the account out everywhere; an administrator's
  also tells the other super administrators. On by default for administrators; for people, turn on "Email people about
  sign-ins from a new network or browser" in the project's Sign-in tab (`newSignInAlerts`). Proven addresses only, at
  most five a day; the sign-in row says the email was sent. **Upgrade note:** run `db:setup` (or `db:setup:pg`) for the
  new area and `db:migrate` for the fence; it needs mail set up and people's activity recording on.

### Fixed

- **A person's activity names the API that asked for a code.** A sign-in turned away because an API it asked for
  requires a code from an authenticator app was recorded as the application asking ("Claude Code asks for a code").
  It now reads "Signed in to Claude Code without a code; Files asks for one", as the sign-in page already said.

## [2.0.1] - 2026-11-17

A patch: Claude Code can sign in to an MCP server through its client metadata document. Nothing to set up or
migrate.

### Fixed

- **Claude Code signs in to an MCP server through its client metadata document.** Its document lists
  `http://localhost/callback` without a port and names no application type, and the default, web, kept the port
  exact, so the ephemeral port it binds at sign-in was refused as a redirect_uri mismatch. A document that names no
  type and offers only plain-http loopback targets is now read as a native client, whose loopback port may vary
  (RFC 8252 §7.3). Nothing to set up or migrate.

## [2.0.0] - 2026-11-17

The major number moves for one change: a client assertion whose `aud` is anything but the issuer is now refused, as
RFC 10070 requires (see Changed). Everything else adds to what was there. Each person has an Activity tab with their
sign-ins, refusals and what they used behind your proxy, and the network owner and place of each address; people see
their own recent sign-ins; an API can require a code or a recent sign-in, has a page of its own, and one MCP tool can
have conditions of its own; a path behind your proxy can keep out Tor, VPNs, hosting or countries with FoxTrust's
network facts. Sign-in addresses are now kept for 90 days, and sent to FoxTrust's API for their owner and place, by
default: read the upgrade notes. Six migrations, which cannot be undone, and new indexes: take a backup, then run the
usual setup and migrate steps.

### Added

- **Network owner and location of a person's addresses** (spec 136). Beside each address on a person's Activity tab
  and in `project_user_activity_list`: the AS number and name, region and city, looked up at FoxTrust's API with a
  key the server registers for itself about a week after its usage reports start carrying its instance key. Status
  under Settings → Integrations and `address_lookup_status_get`. **Upgrade note:** recorded addresses now go to
  FoxTrust's API by default, in batches, with nothing else about the person; FoxTrust keeps none and acts as your
  processor (https://foxtrust.dev/terms). Turn it off with **Look up network owner and location at FoxTrust**. Keep
  your keyring: it seals the instance key. Run `db:migrate`.
- **People see their own recent sign-ins** (spec 135) at `/account/sign-ins`: the last ten, with the app, time,
  method, browser and country, never the address, after a sign-in within 15 minutes. "Sign out everywhere" there ends
  every session, grant, token and app session behind the proxy without locking the account.
- **What a person uses, and who was refused recently** (spec 134). The Activity tab shows the apps and APIs behind
  your proxy a person used each day, the list of people gains "Last active", and an app's or an API's Access tab lists
  whom it refused in the last 24 hours (`behind_proxy_app_refusal_list`, `resource_refusal_list`). **Upgrade note:** a
  request your proxy lets through now counts as activity, so monthly active people rise. Re-run `db:setup` or
  `db:setup:pg`, then `db:migrate`.
- **A person's activity** (spec 133). Each person's page has an Activity tab: sign-ins with the full address, browser
  and FoxTrust's country and network kind, failed sign-ins where the account was found, and refusals behind your
  proxy. Agents read it with `project_user_activity_list`, audited once a day per reader and person. **Upgrade
  note:** every project now keeps full sign-in addresses for 90 days; tell your users, or turn it off with
  `personActivity.enabled`. Re-run `db:setup` or `db:setup:pg`, then `db:migrate`.
- **An API's own console page** (spec 132) with Connect, Access and Settings tabs, in place of the Edit… and Connect
  dialogs and the Access… drawer.
- **Conditions on one MCP tool** (spec 131): groups, networks and hours on top of the API's own conditions. A refused
  call is a plain 403, and apps too old to name their tool are refused once a tool has conditions. "Check access"
  answers with the proxy's own decision. Run `db:migrate`.
- **An API that requires a code or a recent sign-in** (spec 130). FoxAuth enforces it itself, since no MCP client
  handles step-up yet: at the sign-in, at every grant, at a refresh and at the proxy (RFC 9470
  `insufficient_user_authentication`). Introspection now reports `acr` and `auth_time`. Run `db:migrate`.
- **Network facts at your proxy** (spec 129). With "Network facts from FoxTrust" on, each process downloads FoxTrust's
  signed snapshot (about 13 MB a day), and "From where" can keep out Tor, commercial VPNs, hosting or countries,
  comparing the address in the server's own copy. Off, or more than 26 hours old, closes such a path. Run
  `db:migrate`.

### Changed

- **A client assertion's audience must be the issuer alone** (RFC 10070). `clientAuth.issuerOnlyAudience` is now on
  by default: an assertion whose `aud` is an endpoint's URL or several values gets `invalid_client` at every endpoint.
  **Upgrade note:** fix such clients; turning the setting off reopens CVE-2025-27370/27371. A stored `false` is kept.

### Fixed

- **An MCP header sent twice is refused** as `bad_mcp_header` at an API's tools table. It used to read as one joined
  value and let the call through without the tool's scopes.

## [1.7.0] - 2026-11-11

Two-step verification people turn on themselves, and authenticator codes required per application or proxy path.
Two irreversible migrations: back up, then run `db:setup` (or `db:setup:pg`) and `db:migrate`.

### Added

- **Self-service two-step verification** (spec 126) at `/account/security`; `totpSelfService` turns it off.
- **An authenticator code can be required** by an application (`requireCode`, spec 127) or a proxy path (spec 128).

### Changed

- **An expired sign-in shows a plain page in the person's language** instead of `interaction session not found`.

### Fixed

- **Switching accounts during a sign-in works on a project addressed by a path.**
- **Authenticator codes are accepted once**, and a password reset removes one set up before the address was proven.

## [1.6.0] - 2026-11-10

Your own proxy can put sign-in in front of a web app, check API tokens tool by tool and add conditions. A migration
makes rolling back impossible: back up, then run `db:setup` (or `db:setup:pg`) and `db:migrate`.

### Added

- **Sign-in in front of a web app, through your proxy** (spec 122), asked at `/verify/<appId>`.
- **Token checks for an API at your proxy, tool by tool** (spec 123), asked at `/verify/api/<checkId>`.
- **Conditions at your proxy** (spec 124); access tokens now carry `auth_time`, `acr` and `amr`.
- **Refusing password sign-ins from known password-guessing addresses** (spec 125), per project, from FoxTrust's list.

### Fixed

- **A DPoP proof without a usable `htu` is refused** with `invalid_dpop_proof` (spec 121).
- **Sign-in timing no longer tells which accounts exist.**

### Security

- **Elysia 1.4.31 and `@elysiajs/static` 1.4.12**, closing upstream routing, cookie and file-serving advisories.

## [1.5.0] - 2026-11-05

Connected accounts from sign-in, and a "What do you need?" setup guide. No migration.

### Added

- **Connected accounts from sign-in** (spec 120): a provider linked to a connected service connects there too.
- **"What do you need?" guide** in every project's console and on foxauth.dev.

### Fixed

- **Applications that skip consent sign in again after two weeks** instead of failing with `access_denied`.

## [1.4.0] - 2026-11-03

A token vault for agents and secrets encrypted at rest. Two migrations, the first irreversible: back up, check how the
server learns a caller's address, and note two FoxTrust reports on by default.

### Added

- **Connected services, and their tokens for agents** (spec 117, 118, 119), by token exchange (RFC 8693).
- **Encryption at rest for stored secrets** with a keyring (`KEYRING` or a file), backed up apart from the database.
- **Hourly attack reports and a daily usage report to FoxTrust**, on by default; off in Settings → Integrations.
- **Per-caller mail limit** (`mail.requestsPerCallerPerHour`), and `X-Robots-Tag: noindex, nofollow` everywhere.
- **IPSIE SL1 profile** (`ipsieSl1.enabled`); opt-in `clientAuth.issuerOnlyAudience` closes CVE-2025-27370/27371.

### Changed

- **RSA keys under 2048 bits are refused**, and every ID token carries `auth_time` and `acr`.

### Security

- **A caller can no longer choose its own address** (`clientAddress.source`); off Fly.io, check it after upgrading.
- **nodemailer 10.2.1 and zod 4.6.7** (GHSA-85x2-q946-cp5h, GHSA-8c8m-p3m8-cjg8, GHSA-m943-m63m-w62w,
  CVE-2023-54404, GHSA-mrhx-c7xc-m3w5).

## [1.3.0] - 2026-10-22

ID-JAG in both roles, and applications for the instance's administrators. No migration; run `db:setup`.

### Added

- **MCP enterprise-managed authorization (ID-JAG), in both roles** (`jwtBearer.enabled`, `tokenExchange.enabled`).
- **Applications in the Administrators project**, sign-in only, with `groups` naming the administrator's teams.

### Changed

- **Aligned with MCP 2026-07-28**: a client works only at its own project's token endpoint; check yours first.

### Fixed

- **Root introspection reports root tokens active again; console sign-out no longer disconnects an MCP agent.**

## [1.2.0] - 2026-10-21

A newcomer's path from sign-up to a first sign-in. No migration; `db:setup` provisions `ClientUsage`.

### Added

- **An application page, created from a situation**, and sign-in pages naming the project and the application.
- **Primary colour and `prompt=create`**: `primaryColor` paints an app's pages; `prompt=create` opens registration.

### Security

- **A public client with auth `none` gets no machine tokens** (`unauthorized_client`): give it a secret or a key.

### Fixed

- **Application secrets in the console, and project names in emails and authenticator apps.**

## [1.1.0] - 2026-10-16

Provider buttons fit any number of providers, and mail settings send a test. No migration.

### Added

- **Send test email** (`smtp_settings_test`) and provider warnings (`duplicate_brand`, `named_like_brand`).

### Changed

- **Provider buttons fit any number of providers**, folding past six under More sign-in options.

### Fixed

- **The console says why a provider is missing from the sign-in page; refused mail is logged with its reply.**

## [1.0.1] - 2026-10-16

A new instance tells applications the person's email address. No migration.

### Fixed

- **A new instance releases `email` and `email_verified` under the `email` scope**; a saved claims setting needs
  `"email": ["email", "email_verified"]` added under Settings → Claims.
- **`db:setup` no longer reports the instance's own projects as using reserved addresses.**

## [1.0.0] - 2026-10-16

First stable release, with Semantic Versioning from here on. Back up, then run `db:setup` (or `db:setup:pg`) and
`db:migrate` (five migrations, `2026-10-15` to `2026-10-19`, some irreversible).

### Added

- **Plans and Free-tier limits** (spec 102), off by default; a refusal is a 409 `plan_limit`.
- **A project can live on a subdomain of the instance** (spec 101), per `projects.addressForms`.

### Changed

- **`email_verified` is true only for an address that was proven** (spec 104).
- **Breaking renames, with no aliases** (spec 100, 101): buckets are projects and administrator groups teams in admin
  API paths, MCP tools and fields; `can.createHost` is `can.addressForms`.
- **The bucket is the only container** (specs 098, 099): an application or API belongs to one bucket for life; the
  old projects, their `/admin/api/projects` routes and `project_*` MCP tools are removed (`db:migrate`).

### Fixed

- **SCIM endpoint refused as a declared API at every address; teams read their provider changes in the audit trail.**

### Security

- **Tenant hardening before open administrator sign-up** (spec 103). Invitations no longer join another's account,
  and `db:migrate` closes administrators' sign-up where it was open without email verification.

## [0.12.0] - 2026-10-14

End-user pages are rebuilt. Run `db:setup` (or `db:setup:pg`) for `ClientLogo`; consent form posts need `accountId`.

### Added

- **End-user pages and emails in English, Russian and Simplified Chinese, in light or dark** (specs 096, 097).
- **`/account/apps`** (spec 095). People see and remove the access they gave applications.
- **Consent shows own apps' `logo`, `policyUri` and `tosUri`** (spec 094) **and can be partial** (`partialConsent`).

### Changed

- **Plain-language consent page** (spec 092, `scopeDescriptions`); it accepts only the account it was shown for.

## [0.11.0] - 2026-10-12

The admin console is rebuilt around addresses, pages and previews. Upgrade: back up, run `db:setup` (or
`db:setup:pg`), then `db:migrate`; administrators who enrolled an authenticator before this release re-enrol.

### Security

- **Administrators' TOTP secrets no longer leave the server**; `admin_update` is now high-consequence.
- **A password-reset link dies on an email change** (spec 089); **the federation callback checks RFC 9207 `iss`**.
- **Static SCIM tokens expire** (spec 088), old ones via irreversible migration `2026-10-12-static-token-expiry`.
- **A provider cannot be repointed under linked accounts**; linking an administrator asks for their password.
- **A 422 no longer echoes the request body**; host-addressed sign-out and device-code pages cannot be framed.

### Added

- **Sign-in preview** (spec 091) and **administrators' sign-in through an identity provider** (spec 080).
- **End-user support** (spec 089): invitations, manual verification, per-app sign-out, bulk actions on 100 users.

### Changed

- **Breaking: risky changes answer 409 with a preview** (specs 083, 084, 085); repeat with `confirm: true`, `expect`.
- **Breaking: the users list is paged** (spec 082), answering `{ users, totalResults }`.
- **Breaking: deleting a bucket schedules it** (spec 090); it can be restored for 30 days.
- **Keys rotate in one step and can be revoked at once** (specs 086, 087); SCIM credentials overlap (spec 088).
- **Every console screen has an address, every entity a page** (specs 079, 081, 084); Usage is open to every
  administrator (spec 091).
- **A user's profile wins over a stored claim of the same name** (spec 089); new buckets are closed to sign-up.

### Fixed

- Group audit visibility, invitation links, blank SCIM emails and `db:setup:pg` reserved-bucket slugs are fixed.

## [0.10.0] - 2026-10-10

Active users are counted per bucket, and buckets move between groups. Upgrade: back up, run `db:setup` (or
`db:setup:pg`), then `db:migrate`, which irreversibly leaves each personal group only its owner.

### Added

- **Active users per bucket and a Usage page** (specs 076, 077); **moving buckets between groups** (spec 075).
- **Breaking:** `admin_settings_read`/`admin_settings_update` are removed; edit the admins' bucket (spec 078).
- **foxauth.dev in Russian and Simplified Chinese** (spec 074), and a typed `eventBus` (`ServerEvents`).

### Changed

- **A personal group has one member** (spec 075): migration `2026-10-09-personal-groups-single-member`.
- **Startup refuses a stored setting of the wrong type** or a malformed `richAuthorizationRequests.types`.

### Fixed

- Concurrent registrations and `/session/end` with a `null` claims set no longer answer a server error.

### Security

- **A DPoP proof dated ahead of the server's clock can no longer be replayed** after five minutes (RFC 9449 §11.1).

## [0.9.0] - 2026-10-07

Upstream sign-out now reaches this server; run `db:setup` (or `db:setup:pg`) for the new `UpstreamSession` area.

### Added

- **Back-Channel Logout from Keycloak, Auth0 or Ping**, for providers opted in with `acceptsBackChannelLogout`.

### Fixed

- **Signing in through Keycloak completes**: unknown callback parameters such as `session_state` are ignored.
- **Compose upgrades run `db:migrate`** after `db:setup`, so pulling 0.7.0 or 0.8.0 no longer fails to start.

### Security

- **The image takes Alpine's security patches on every build again** (CVE-2026-85091, zlib shipped in 0.8.0).

## [0.8.0] - 2026-10-07

An enterprise directory can provision a bucket's users and groups over SCIM 2.0, roles become groups, and ending a
user's access ends their sessions and tokens at once. **Upgrading:** back up, then run `db:setup` and `db:migrate` in
that order (two irreversible migrations); refresh needs `offline_access` among supported scopes; `roles` writes become
memberships of Super administrators or of a bucket group.

### Added

- **SCIM 2.0 provisioning** (`scim.enabled`, off by default). Entra ID, Okta or any SCIM client manages a bucket's users
  at `<bucket issuer>/scim/v2`, targeting the IPSIE SCIM profile (AL1, AL2).
- **Mass-deprovisioning guard.** An optional per-connection threshold answers `429` until an administrator releases the
  hold. Re-run `bun run db:setup` / `db:setup:pg` for the new `DeprovisionSlot` area.
- **Groups replace roles.** Bucket groups, released in a `groups` scope and claim; SCIM gains `/Groups`; `super_admin`
  becomes Super administrators membership (`admin_super_grant`, `admin_super_withdraw`); `project_admin` is gone.
- **Okta Universal Logout** (`globalTokenRevocation.enabled`, off by default). An opted-in upstream provider ends a
  user's sessions and tokens; administrators get **Sign out everywhere** (`bucket_user_sign_out`).
- **Editable claims.** `claims` is a settings-catalog value, and an end user's claims can be set in the console or by an
  agent.
- **Full client registration in the console and MCP**, with `private_key_jwt`, `client_secret_jwt` and FAPI options.
- **Instance signing keys rotate without a restart** (`jwks_promote`, `jwks_retire`); `jwks_delete` is gone.
- **`POST /logout`** as RP-Initiated Logout requires; discovery lists introspection and revocation auth methods.

### Changed

- **The token endpoint accepts exactly the advertised grant types.** Without `offline_access`, refresh is
  `unsupported_grant_type`; `refreshToken.enabled` is removed.
- **Retiring a key needs `{ "confirm": "<kid>" }`**, and one key signs per algorithm rather than per key type.
- **Migration `2026-09-30-root-keys-lifecycle`** moves root keys into the bucket key store; startup refuses without it.

### Fixed

- **Deactivating, locking or deleting an end user ends their access at once** (spec 069), with an emergency lock.
- **Bucket addresses are honoured**: client registration, assertion `aud`, DPoP `htu` and request object `aud`.
- **ID tokens carry `amr`.** Behaviour change: password-only tokens gain `["pwd"]`; test for `otp` or `mfa` (#46).
- **Errors after sign-in reach the client** (#47); unvouched redirect URIs get the error on-page (RFC 9700 §4.11.2).
- **Device flow** can be approved by someone not yet signed in, and its failures reach the next poll.
- **Requested claim values are honoured** (OIDC Core §5.5.1); Request Objects follow RFC 9101.
- **Sign-out** returns to the relying party in Chrome, works at path-addressed buckets and on MongoDB, styled at once.
- **Federated sign-in** refuses an ID token without `iat` and follows an upstream key rotation.
- **Smaller fixes**: a new key algorithm is advertised without a restart, seven settings stop claiming one, and a
  refused registration reaches the console as `422`.

## [0.7.0] - 2026-09-29

Tenants are isolated: declared resources are unique per issuer, an addressed bucket signs with its own keys, and a
security audit's findings are fixed. **Upgrading:** back up, then `db:setup` and `db:migrate` (first, irreversible
migration); resource servers of addressed buckets verify against that bucket's `jwks_uri`; set
`mTLS.trustProxyCertificateHeader` to read forwarded client certificates.

### Security

- **A sign-in continues only in the browser that began it** (regression since `53341c6`).
- **An enrolment secret completes only the account it was offered to.**
- **Client metadata is snake_case only**, so wire input sets no internal keys; `PUT /reg/:id` keeps self-registration.
- **Federated sign-in no longer links to a password-only account** until that account's own sign-in completes.
- **An agent's token works on the management API only through `/mcp`.**
- **Client credentials for a declared resource** go only to that project's clients; consent skip only for its own group.
- **One egress boundary for every outbound request**, with a numeric address check that closes IPv6-mapped bypasses.
- **Single use under concurrency** for codes, rotating refresh tokens, pushed requests, `jti`s, setup, resets and
  invitations; attempt caps count atomically.
- **Forwarded client certificates** are read only with `mTLS.trustProxyCertificateHeader` (off by default).
- **No account enumeration or address leaks** through password reset or duplicate-key errors.
- **Bucket policy holds for clients in no project**; end-user passwords need eight characters server-side.
- **Personal groups are found by owner**, and the image excludes every `.env*`, `.git` and repository metadata.
- **Tenant isolation**: a resource is unique per issuer and only a super administrator declares at the root.

### Added

- **Per-bucket key rotation** in the console and MCP, and `resource_vouching_check` for RFC 9728 metadata.

### Fixed

- **The first schema migration now runs**; a significant trailing slash on a declared resource is kept.
- **Signed responses from a named bucket carry that bucket's issuer.**

## [0.6.0] - 2026-09-28

Every record read back from storage is checked against its schema, and the request context is typed from the
endpoints' schemas. **Upgrading:** extension functions receive the request context itself, not `{ oidc }` (no shim);
no schema migration is declared.

### Fixed

- **PostgreSQL** account updates and group-filtered audit reads work; **MongoDB** stores undefined members as absent.
- **Host-addressed buckets** keep their sign-ins and name their own issuer, also for device and CIBA.
- **Error codes follow RFC 6749 §5.2 and RFC 8707**; `ui_locales` and `claims_locales` are space-separated strings.
- **Breaking:** `GET /reg/:clientId` takes the registration access token only in the Authorization header.
- **Browser refresh-token chains** expire with their first token again; `ttl.*` now take `(token, client)`.
- **Smaller fixes**: `default_max_age: 0`, console client edits, CIBA `verifyUserCode`, device confirmation.

### Changed

- **Schema-checked storage**: a record that does not match fails as a server error the error store records.
- **Breaking:** extension functions, policy checks, registration policies and RAR validators take `oidc` directly.
- **Typed `OIDCContext`**: `oidc.client` and `oidc.session` throw when absent; `authenticatedClient` is gone.
- **A client is frozen data** written through `registerClient`; `clientAuthMethod` aliases are removed.
- **`authorization_details`** uses its RFC 9396 wire form, and a repeated parameter is refused.

## [0.5.0] - 2026-09-21

A user bucket can hold a hostname of its own, and Google, Microsoft, Apple and GitHub connect by name. **Upgrading**
signs administrators in once more; end users are unaffected and no schema migration is declared.

### Added

- **Hostname-addressed buckets** (spec 056): path or host, never both; only an instance administrator changes it.
- **Google, Microsoft, Apple and GitHub sign-in by name**, with branded buttons and the callback address shown.
- **Deleting projects and buckets from the console**, optionally with their contents, confirmed by typing `delete`.
- **site:** a blog, with inline SVG diagrams.

### Fixed

- **Console sign-in no longer fails** with `interaction session and authentication session mismatch`.
- **A client can no longer sign out a bucket it does not belong to.**
- **A lost race for a hostname answers 409**, not 500.
- **Federation binds the authorization code to its request** at every recognised upstream that supports it.
- **Console and login page fixes**: Apple key masked, dialogs not autofilled, provider buttons kept, reserved buckets
  undeletable.

## [0.4.0] - 2026-09-16

A user bucket is now a tenant with its own address, issuer and sign-in, while the default bucket keeps the bare issuer
and paths. **Upgrading signs end users in once**: a session cookie written before this release carries no bucket and is
expired on first use (accounts, grants, consent and refresh tokens are untouched).

### Added

- **Bucket as issuer**. A bucket given an address (e.g. `https://auth.example.com/acme`) serves every protocol endpoint
  and its own metadata, and mints tokens with itself as `iss`.

### Fixed

- **Sign-in to several buckets at once**. The session cookie is named per bucket, a sign-out ends only the addressed
  bucket's sign-in, and reaching a second bucket in one browser no longer answers `server_error`.
- **Sign-in started at a relying party**. `_interaction` and `_session` are now `SameSite=Lax`, ending the `422`.
- **A project's user bucket**. It can be changed and cleared (MCP `project_bucket_clear`), and the reserved
  administrators' bucket can no longer be assigned.
- **`settings_update` schema**. The MCP tool now publishes each setting's type, allowed values and description.
- **"Remember me"** (spec 049, issue #45). Declining now ends the sign-in when the browser closes.

## [0.3.0] - 2026-09-14

The server runs on PostgreSQL as well as MongoDB, behind a schema-migration layer, and a saved setting takes effect
without a restart. The first OpenID Foundation conformance runs found twelve defects, fixed here.

### Added

- **Settings apply on save**. A saved server setting takes effect without a restart.
- **Authentication context (`acr`)**. `acrValues` changes from a list to a map from password, second-factor and
  federated sign-in to the reported value; an unmeetable essential `acr` answers `unmet_authentication_requirements`.
- **`pkce.required`**. A super-admin setting, on by default, that lets a confidential client omit PKCE.
- **`CONFORMANCE.md`**. Records the OpenID Foundation suite results and the five defects still open.
- **PostgreSQL datastore**. Selected by `POSTGRES_URL` (setting `MONGODB_URI` too is refused), set up by `db:setup:pg`.
- **Schema migrations**. Applied by `bun run db:migrate` (`--plan` to gate a deploy); startup refuses a database that is
  behind, ahead or diverged. A deployment predating ownership groups must upgrade through an earlier release first.
- **`GET /ready`**. A readiness probe that checks the datastore, beside the `GET /health` liveness probe.
- **Fly configurations**. `fly.toml` and `fly.conformance.toml`; the release runs `db:migrate` after `db:setup`.
- **Release asset provenance**. `docs-export.json` and the shipped `CHANGELOG.md` carry a signed SLSA v1 statement.

### Fixed

- **Unknown request parameters**. `/auth`, `/par`, `/device/auth`, `/backchannel` and `/token` ignore extension
  parameters, as does a `claims` value with an unknown top-level member.
- **`400` for schema refusals**. The OAuth endpoints answer `400` instead of `422`; the admin API and `/mcp` keep `422`.
- **PKCE verifier alphabet**. A `code_verifier` containing `.` or `~` is accepted (RFC 7636 §4.1).
- **PAR**. A successful push answers `201` with a JSON content type, and a pushed `request_uri` can no longer be
  replayed once after a sign-in or consent.
- **Userinfo**. A request with no credentials gets `401` and a `WWW-Authenticate` challenge; a token may come in a form
  POST body.
- **Signing key algorithms**. Key generation offers every asymmetric algorithm, so FAPI 2.0 keys need no manual step.
- **Conformance findings**. `form_post` works without ES modules; a PAR's bad `redirect_uri` answers `invalid_request`.

## [0.2.0] - 2026-09-08

The server becomes an authorization server for third-party MCP servers, SECURITY.md gets evidence behind it, and RFC
8414 metadata lets a plain OAuth 2.1 client discover a deployment.

### Added

- **Authorization for MCP servers**. An administrator declares a third-party MCP server as a protected resource of a
  project, and the token endpoint mints audience-bound tokens for it with no restart.
- **Client ID Metadata Documents**. An https `client_id` resolves by retrieval (`clientIdMetadataDocument.enabled`).
- **Security evidence**. A threat model, an assurance page, a `Security` scanning workflow and OpenSSF Scorecard.
- **Signed container image**. Signed keylessly with `cosign`, with an SBOM and SLSA build provenance attached.
- **RFC 8414 metadata** (spec 038, issue #30). Served at `GET /.well-known/oauth-authorization-server`.
- **Site discoverability** (specs 036, 037). Build-enforced SEO, `llms.txt`, three new product comparisons.

### Fixed

- **Injection hardening**. `WWW-Authenticate` values, page titles and CSP tag matching are hardened; none was reachable.
- **Container OpenSSL**. The base image is pinned by digest and upgraded, removing `libssl3`/`libcrypto3` 3.5.7-r0.
- **Release workflow permissions**. Write access is granted only to the jobs that write.

### Security

- **Actions pinned to commit SHAs**. Every GitHub Action is pinned to a full SHA, kept current by Dependabot.

## [0.1.0] - 2026-09-03

The first tagged release: everything the server accumulated before a version number existed.

### Added

- **Fault reporting** (specs 034, 035). Optional reporting of recorded faults to the operator's Sentry
  (`sentry.enabled`, off by default), each carrying its code location.
- **Password brute-force protection** (issue #9, spec 032). Failed sign-ins lock the address for 15, 30, then 60 min.
- **Security headers** (issues #2, #10, specs 026, 029). HSTS, `Permissions-Policy`, `nosniff`, `Referrer-Policy` and a
  restrictive content policy on every non-page response, and `X-Frame-Options: DENY` on rendered pages.
- **Content-Security-Policy on pages** (specs 018/032). Derived per document, with hashed inline styles.
- **Rate limiting** (issue #1). An origin over its allowance gets `429` with `Retry-After`, tiered by route class.
- **TOTP second factor** (spec 027). `totpRequired` per bucket, the admin console included; operators can clear one.
- **CORS** (spec 011). Preflight, open CORS on discovery and JWKS, and per-project `corsOrigins` on the token family.
- **Administration** (specs 016, 024, 025). A readable admin audit trail, the admin MCP control plane at `POST /mcp`,
  and a durable error store.
- **Protocol and accounts** (specs 015, 020, 022). Rich Authorization Requests (RFC 9396), self-service password reset,
  and upstream OIDC federation per bucket.
- **`bun run db:setup`** (spec 012). Provisions every collection and index from a declared storage inventory.

### Changed

- **BREAKING: feature flags gate their endpoints** (spec 010). A disabled feature's routes answer 404.
- **BREAKING: deletion** (spec 019). Non-empty projects and buckets refuse deletion (409); client and user deletes
  cascade.
- **BREAKING: pairwise `sub`** (spec 023). Derived from stored state, so values change once, on first start of 0.1.0.
- **BREAKING: `richAuthorizationRequests.types`** (spec 015). Now a serializable descriptor map.
- **BREAKING: `authorization.allowOmittingSingleRegisteredRedirectUri`**. Moved into the Application Configuration and
  now disabled by default; enable it in the settings to restore the old behaviour.
- **Console groups**. The holding group is renamed **System** (by `db:setup`), personal groups leave the Groups table
  and other people's scope switcher, and a scope switch is no longer audited.
- **Documentation and interaction UI** (specs 021, 031). `README.md` lists the real endpoints; UI pages tidied.

### Removed

- **Unreferenced modules** (issue #19, spec 030). The legacy `lib/views/` templates and four unused helpers.

### Fixed

- **Admin console**. A super administrator's scope switch is honoured; an agent calling a withheld MCP tool is told why.
- **Boot and PKCE**. The server boots against MongoDB again, and PKCE accepts verifiers of 43 to 128 characters.
- **Sign-in and logout**. Native clients complete interactive sign-in, interaction pages hand off under the CSP, admin
  logout ends the provider session, and cookies are cleared at their own path.
- **Small fixes** (spec 018). Error pages carry the real status, and the unimplemented CIBA `push` mode is removed.

### Security

- **Admin bucket email verification**. The reserved admin bucket can no longer require it (it would lock admins out).
- **End-user cookies**. `_session` and `_interaction` carry `Secure`, and `/ui/*` responses set the full attribute set.
- **Admin id_token** (spec 017). The console verifies its signature, `nonce`, expiry and audience.
- **DPoP nonce secret** (spec 014). Provisioned at startup, so `requireNonce` can no longer answer 500.

[Unreleased]: https://github.com/RedFox-Soft/OAuth-server.ts/compare/v2.2.0...HEAD
[2.2.0]: https://github.com/RedFox-Soft/OAuth-server.ts/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/RedFox-Soft/OAuth-server.ts/compare/v2.0.1...v2.1.0
[2.0.1]: https://github.com/RedFox-Soft/OAuth-server.ts/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/RedFox-Soft/OAuth-server.ts/compare/v1.7.0...v2.0.0
[1.7.0]: https://github.com/RedFox-Soft/OAuth-server.ts/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/RedFox-Soft/OAuth-server.ts/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/RedFox-Soft/OAuth-server.ts/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/RedFox-Soft/OAuth-server.ts/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/RedFox-Soft/OAuth-server.ts/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/RedFox-Soft/OAuth-server.ts/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/RedFox-Soft/OAuth-server.ts/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/RedFox-Soft/OAuth-server.ts/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/RedFox-Soft/OAuth-server.ts/compare/v0.12.0...v1.0.0
[0.12.0]: https://github.com/RedFox-Soft/OAuth-server.ts/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/RedFox-Soft/OAuth-server.ts/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/RedFox-Soft/OAuth-server.ts/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/RedFox-Soft/OAuth-server.ts/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/RedFox-Soft/OAuth-server.ts/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/RedFox-Soft/OAuth-server.ts/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/RedFox-Soft/OAuth-server.ts/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/RedFox-Soft/OAuth-server.ts/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/RedFox-Soft/OAuth-server.ts/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/RedFox-Soft/OAuth-server.ts/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/RedFox-Soft/OAuth-server.ts/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/RedFox-Soft/OAuth-server.ts/releases/tag/v0.1.0
