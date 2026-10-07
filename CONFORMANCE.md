# Conformance

What the [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite) says
about this server, and what it takes to get an answer — because most of the cost of a conformance run
is not the run.

## Where it stands

### What passes

**Measured 2026-10-01 against the deployed `conformance.foxauth.dev` at `e61a5a1`**, with the suite
(`conformance-suite:latest`, built 2026-09-30) running locally and reaching the instance over the
internet — real TLS, a real hostname, no terminator of our own in between. Every client the suite
uses, its end user, the scope definitions and each profile switch were set up through the MCP control
plane, not by hand-written seed data, and each profile was switched on save, with no restart.

Eight plans test this server as an **OpenID Provider**. None of them reports a failure attributable to
it:

| Plan                                                | Conditions | Failures                     |
| --------------------------------------------------- | ---------- | ---------------------------- |
| `oidcc-config-certification-test-plan`              | 41         | **none**                     |
| `oidcc-basic-certification-test-plan`               | 1 855      | **none**, and no warnings    |
| `oidcc-formpost-basic-certification-test-plan`      | 2 007      | **none**, and no warnings    |
| `oidcc-rp-initiated-logout-certification-test-plan` | 551        | **none**                     |
| `oidcc-3rdparty-init-login-certification-test-plan` | 50         | **none**                     |
| `oidcc-dynamic-certification-test-plan`             | 852        | 12, none of them this server |
| `fapi2-security-profile-final-test-plan`            | 4 057      | 4, all needing a human       |
| `fapi2-message-signing-final-test-plan`             | 5 447      | 4, all needing a human       |

**14 860 conditions, and no server defect.** Every plan ran once, start to finish, with nothing re-run
by hand. Each remaining failure is explained under
[Failures that are not this server](#failures-that-are-not-this-server).

### At a named bucket

**Measured 2026-10-05 at `19e4bb8`** against two buckets with addresses of their own, one of each form:
`/named`, addressed by path (issuer `https://conformance.foxauth.dev/named`), and
`tenant.conformance.foxauth.dev`, addressed by hostname (issuer `https://tenant.conformance.foxauth.dev`,
a wildcard DNS name and a Fly certificate). Each has its own discovery document, endpoints and signing
key, and its own project, clients and end user, all set up through MCP. Both answer exactly as the root
does, condition for condition:

| Plan                                                | Conditions | Failures at `/named` and at `tenant.` |
| --------------------------------------------------- | ---------- | ------------------------------------- |
| `oidcc-config-certification-test-plan`              | 41         | **none**                              |
| `oidcc-basic-certification-test-plan`               | 1 855      | **none**                              |
| `oidcc-formpost-basic-certification-test-plan`      | 2 007      | **none**                              |
| `oidcc-rp-initiated-logout-certification-test-plan` | 551        | **none**                              |
| `oidcc-dynamic-certification-test-plan`             | 852        | 12 — the root's twelve (Dynamic)      |

Two Basic modules at `/named` were re-run alone after a network interruption between the suite and the
instance; both passed.

FAPI 2.0 at `/named`, at `f37bf2d`, with an ES256 signer promoted in the bucket and FAPI clients in its
own project, answers as the root does too:

| Plan                                     | Conditions | Failures at `/named`   |
| ---------------------------------------- | ---------- | ---------------------- |
| `fapi2-security-profile-final-test-plan` | 4 017      | 4, all needing a human |
| `fapi2-message-signing-final-test-plan`  | 5 407      | 4, all needing a human |

### In a real browser

**2026-10-05**: Basic, Formpost and RP-initiated logout were run in Chromium (Playwright,
`browser-plan.ts` in the rig) instead of the suite's HtmlUnit, one fresh browser profile per module.
No failure, and every REVIEW module now carries a real screenshot of the page it asks about. A
confirmed sign-out reaches the client's `post_logout_redirect_uri`, which is the hop a browser's
`form-action` enforcement decides and HtmlUnit does not check.

The failures the tables attribute to a missing person have been run by one, in the same browser:
`user-rejects-authentication` passes in both FAPI plans — signing in and pressing Cancel on the consent
page returns `access_denied` to both clients, as a signed JARM response in Message Signing — and
`oidcc-server-rotate-keys` passes with a key generated through MCP while the module waited.

### On the hosted suite

**2026-10-05, at `f37bf2d`**, on the suite at `www.certification.openid.net` (5.3.1), against the
deployed `conformance.foxauth.dev` — the plans that need this server to **call the suite**, which a
local suite cannot be:

| Plan                                                            | Result                                             |
| --------------------------------------------------------------- | -------------------------------------------------- |
| `oidcc-backchannel-rp-initiated-logout-certification-test-plan` | 101 conditions, **none failed**                    |
| `oidcc-dynamic-certification-test-plan`                         | 918 conditions, 6 failed, none of them this server |
| `oidcc-client-basic-certification-test-plan`                    | 14 modules, **every verdict right**                |
| `oidcc-client-config-certification-test-plan`                   | 6 modules, **every verdict right**                 |
| `oidcc-client-refreshtoken-test-plan`                           | 3 modules, no failure — subject not exercised      |

In Dynamic, the five the egress boundary caused locally — a client's `jwks_uri` at registration and on
RP key rotation, and `sector_identifier_uri` in both modules — **pass**. What is left is the implicit
demand (2), `request_uri` (3) and `rotate-keys` (1), each explained under
[Dynamic](#dynamic--12); the fourth `request_uri` failure counted locally was the scripted browser
timing out on the confirmation page, which the hosted config clicks through.

The three client plans test this server as a **Relying Party**, because `lib/federation/` makes it one
and no OP plan reaches that code. Each module ran at a provider on `/named` repointed at its own suite
alias; the verdicts are the RP's own answers (see [The client plans](#the-client-plans)):

- **Refused** — `invalid-iss`, `missing-sub`, `invalid-aud`, `missing-iat`, `kid-absent-multiple-jwks`,
  `invalid-sig-rs256`, `nonce-invalid`, and `idtoken-sig-none` in both plans (a refusal is one of the
  two answers that module accepts). `discovery-issuer-mismatch` is refused when the provider is
  written, before any sign-in: the discovery document names a different issuer.
- **Accepted** — `oidcc-client-test`, `client-secret-basic`, `idtoken-sig-rs256`,
  `kid-absent-single-jwks`, `discovery-jwks-uri-keys`, `signing-key-rotation-just-before-signing`, and
  `signing-key-rotation` across both of its sign-ins, the second after the suite rotated its key.
- **Not exercised** — `userinfo-invalid-sub`, `scope-userinfo-claims` and the three refresh-token
  modules, whose subject is a call this RP never makes; each first sign-in is accepted.

### Open defects

**None the suite has found.** Two results it will keep reporting are not defects: the Dynamic
profile's demand for the implicit flow, which this server refuses on purpose, and `request_uri` by
reference (RFC 9101), which it does not implement and refuses with the registered
`request_uri_not_supported`.

Nothing is known to be missing **outside** the suite either. An account claim whose value does not
match a requested `value`/`values`, compared as JSON values, is left out of the response (OIDC Core
§5.5.1). `sub`, `acr` and `amr` have rules of their own: a subject that matches
neither `value` nor `values` fails the authentication (§3.1.2.2), a voluntary `acr` is answered with
the session's current context (§5.5.1.1), and `amr` reports the methods actually used. All of it is
reachable only with `claimsParameter.enabled`, which ships off.

### What still has to run

In the order they are worth it:

| What              | Why       | What it needs                                                                                                                      |
| ----------------- | --------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| FAPI-CIBA ID1     | never run | a CIBA integration: how a person approves on their device is a deployment's to write (`lib/addon/ciba.ts`)                         |
| FAPI 1.0 Advanced | never run | mutual TLS end to end — Fly terminates TLS and does not pass the client certificate on — and its `jarm` variant to reach it at all |

Everything that needs this server to call the suite has run on the hosted one
([On the hosted suite](#on-the-hosted-suite)), which is also the one certification counts. Re-run those
plans there after a change to sign-out or to `lib/federation/`: a local suite cannot be reached from a
deployed instance, and a local instance refuses private addresses by design (the egress boundary,
`lib/shared/egress.ts`).

Repeat the real-browser pass after any change to a page this server renders. HtmlUnit enforces neither
CSP nor SameSite and draws nothing, so a page a browser blocks, or one that arrives unstyled, passes
the suite.

## Failures that are not this server

### FAPI 2.0 Message Signing — 4

Run as
`[openid=openid_connect][client_auth_type=private_key_jwt][sender_constrain=dpop][fapi_profile=plain_fapi][authorization_request_type=simple][fapi_request_method=signed_non_repudiation][fapi_response_mode=jarm][grant_management=disabled]`.

- All 4 (and 2 of the 3 warnings) are `user-rejects-authentication`, which needs a person to press
  Cancel — on this server, on the consent page that follows sign-in. The suite's script signs in and
  allows, so the module fails in an automated run and passes when a person declines (see
  [In a real browser](#in-a-real-browser)).
- 3 modules are **skipped**, correctly: the two `…-with-RS256-fails` modules apply only to a client
  whose key is RSA, and `refresh-token` warns that the server supports refresh tokens but issued none to
  this client — which asked for no `offline_access`, so none is due.
- `par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` ends in REVIEW. It needs the first
  visit to stop at the login page, because signing in there spends the pushed request the second visit
  reuses; the rig's config gives the module a browser script that screenshots the page and stops.

### FAPI 2.0 Security Profile — 4

The same as Message Signing: all 4 are `user-rejects-authentication`, the same two modules are skipped
for the same reasons, and `par-ensure-reused-request-uri…` ends in REVIEW with the same browser script.

### Dynamic — 12

**Dynamic OP certification is unreachable as the server stands, and for the same reason PKCE is the
default.** The profile requires `response_types_supported` to contain `code`, `id_token` and
`token id_token`, and `grant_types_supported` to contain `implicit`. This server offers `code` and
`none`, and no implicit grant — a deliberate OAuth 2.1 posture, so the profile is inapplicable rather
than unfinished. That is 2 of the 12.

- 4 are `request_uri` by reference (RFC 9101), which this server does not implement and refuses with the
  registered `request_uri_not_supported` — two of them the scripted browser waiting at the confirmation
  page described below.
- 5, in three modules, need this server to fetch a document **from the suite** — a client's
  `jwks_uri` (at registration and on RP key rotation, each answered `401` because the key cannot be
  fetched) and a `sector_identifier_uri` (answered `400`, three conditions). From a deployed instance
  a local suite is unreachable; from a local one the egress boundary refuses it. Both are the
  environment, not the rule: on the hosted suite all five pass.
- 1 is `oidcc-server-rotate-keys`, which fetches `/jwks`, waits for the operator to rotate the signing
  key, and fetches it again. Nobody rotates in an automated run. Run alone, with `jwks_generate` called
  through MCP while it waits, it passes: a generated key is in `/jwks` at once, and the old one stays.

**One module stops at a page of this server's, by design.** An authorization _error_ for a client whose
redirect URIs no operator vouched for — one created by dynamic registration, or resolved from a client
ID metadata document — is not redirected (RFC 9700 §4.11.2): the server answers with a confirmation
page of its own (the error's status, `frame-ancestors 'none'`, and a link that delivers the identical
answer when clicked). This plan registers every client dynamically, and the one module in it whose
authorization request is refused is `oidcc-request-uri-signed-rs256`, so the scripted browser stays on
`/auth` until it times out. Successful responses, and every client an administrator created, are
unaffected — which is why the Basic plan's `oidcc-prompt-none-not-logged-in`, run with static clients,
receives its `login_required` redirect.

The plan is still worth running: it is the only one that exercises dynamic registration. So is the
back-channel logout plan, which also registers dynamically and meets the same page after its sign-out —
a `prompt=none` request answered `login_required`. A browser script that clicks the page's link, as a
person would, gets the identical answer to the suite, and both plans pass.

## What an RP run does and does not prove

`lib/federation/` is a **login broker**, not a general-purpose OpenID client, and three of the plans'
assumptions do not hold against it. This is design, not omission, but it bounds what the result means.

- **It never calls `/userinfo`.** A client module that waits for that call never concludes, so nearly
  every one is stopped rather than finished; `userinfo-invalid-sub` and `scope-userinfo-claims` prove
  nothing.
- **It never uses a refresh token** and does not request `offline_access`, so the whole
  `oidcc-client-refreshtoken` plan runs clean without touching its subject.
- **It only ever runs a code flow**, which is why the hybrid, implicit, session-management and
  front-channel-logout client plans are inapplicable for the same reason their OP twins are.

What it _does_ prove is the verification: `iss`, `aud`, `exp`, the algorithm allowlist,
`alg: none`, a bad signature, a `kid` absent with several keys published, a mismatched `nonce`, a
missing `sub`, and a discovery document whose `issuer` disagrees with the URL it came from — each
refused. **The suite cannot see any of those refusals by itself**: its OP cannot observe whether the RP
rejected what it sent, so every negative client module reports PASSED either way. The verdict comes
from the runner, which records the HTTP status this server returned (see
[The client plans](#the-client-plans)).

## Configuring a conformance target

### Two instance profiles

The OIDC profiles and the FAPI profiles want opposite settings, so one instance serves one at a time:

|                            | OIDC plans | FAPI 2.0 Security | FAPI 2.0 Message Signing |
| -------------------------- | ---------- | ----------------- | ------------------------ |
| `pkce.required`            | `false`    | `true`            | `true`                   |
| `fapi.enabled`             | `false`    | `true`            | `true`                   |
| `requestObjects.enabled`   | `false`    | `false`           | **`true`**               |
| `responseMode.jwt.enabled` | `false`    | `false`           | **`true`**               |

Every one of these applies on save, so switching profiles is a `settings_update` through MCP (or the
console), not a redeploy. `pkce.required` is on by default, and with it on 34 of the Basic profile's 35
modules are refused before they test anything; FAPI mandates PKCE and fails the opposite way. Message
Signing is the Security Profile plus a signed request object (JAR) and a signed authorization response
(JARM), which is the whole of the difference in that column. The client plans need one setting of their
own: **`federation.enabled`**, off by default.

### Settings that read like defects

A run against a default instance fails for reasons that are settings, and **each one reads in the test
log exactly like a server defect**. That is the trap this section exists for.

- **`rateLimit.enabled: false`.** The loudest one. The suite drives several hundred `/auth` and
  `/token` requests from one address within a minute, far over `rateLimit.strict.max` (60 per 60 s).
  The refusal arrives as `temporarily_unavailable` on an HTML page, three consecutive modules are
  interrupted, and the runner aborts the whole plan reporting that the _server under test_ is
  unhealthy. Nothing in that chain names the rate limiter.
- **`fapi.enabled` for every FAPI plan.** With it off, three modules push a `client_assertion` whose
  `aud` is an array, the PAR endpoint URL or the token endpoint URL, are answered `201`, and read as an
  audience-confusion defect. It is not one: RFC 9126 §2 says an authorization server **MUST** accept
  its issuer, token endpoint URL **or** PAR endpoint URL as identifying it, and the narrow rule is FAPI
  2.0's alone, applied behind the flag (`lib/shared/token_jwt_auth.ts`). Note the opposite rule for a
  Request Object: an array `aud` naming this server **must** be accepted (RFC 7519 §4.1.3).
- **Claim-defined scopes** — `profile`, `email`, `address`, `phone` and their claims, in the `claims`
  setting, or the five `oidcc-scope-*` modules fail. The shipped default declares `openid` and
  `offline_access` only.
- **`claimsParameter.enabled` and `requestObjects.enabled`.** Off by default; with them off the `claims`
  parameter and by-value request objects are refused, and three modules fail.
- **An end user** in the bucket the clients resolve to, with profile, email, address and phone claims.
- **Two or three static clients.** The profile certifies both `client_secret_basic` and
  `client_secret_post`, and the suite reads the second from a block of its own. FAPI modules append
  `?dummy1=lorem&dummy2=ipsum` to the redirect URI to prove the match is exact, so that variant has to
  be registered too; so do `post_logout_redirect_uris`, for the logout plan.
- **`scope` in the suite's own client configuration**, for every FAPI plan. The suite omits the
  parameter when its config names none, a FAPI request always carries `nonce`, and this server refuses
  `nonce` without `openid` (`lib/actions/authorization/check_openid_scope.ts`) — on the first PAR push
  of every module.
- **`require_signed_request_object: true` on the client**, for Message Signing, or
  `ensure-unsigned-request-at-par-endpoint-fails` fails: an unsigned push is accepted with `201`. It is
  a per-client registration, and `fapi.enabled` does not imply it.

Register the clients through the console or MCP rather than writing records by hand. A stored client is
part camelCase and part wire-format, and a hand-seeded `postLogoutRedirectUris` is dropped silently by
validation — which surfaces as `400 post_logout_redirect_uri not registered`.

### Signing keys for a FAPI run

FAPI 2.0 forbids RS256, so the instance needs a signer in PS256 or ES256, and a FAPI client registers
for it. **A generated key does not sign until it is promoted**, and promotion is refused for the first
60 seconds, while every instance picks the key up. Registration checks a client's algorithm against the
keys that sign, so the order is: `jwks_generate` in ES256 (or PS256), wait out the window, `jwks_promote`,
then register the FAPI clients. There is one signer per algorithm, so promoting ES256 leaves the RS256
signer the OIDC clients use in place. A bucket with an address of its own has keys of its own, so the
same steps run against it with `bucket_key_generate` and `bucket_key_promote`.

Register the Message Signing clients while `responseMode.jwt.enabled` is on, or set their
`authorizationSignedResponseAlg` afterwards. The attribute is accepted only while JARM is enabled and
otherwise falls back to RS256, which FAPI 2.0 forbids: a client registered in the Security Profile's
settings signs every JARM response RS256, and nearly every Message Signing module fails
`FAPI2ValidateJarmSigningAlg`.

## Running the suite

### The rig

The suite runs locally from `docker-compose-prebuilt.yml` (prebuilt images, no Maven build). Against a
**local** server it needs an nginx TLS terminator the suite reaches as `https://oidcc-provider:3000`: the
end-user cookies are written `secure: true` unconditionally, so a plain-HTTP origin has the suite's
browser drop them and every login fails. Against the **deployed** instance there is no terminator —
point the configs' `discoveryUrl` at it.

Three properties of the rig cost a run each, and none announces itself:

- **Pin the terminator's upstream to IPv4.** Docker Desktop gives `host.docker.internal` both an A and an
  AAAA record; nginx alternates between them and every IPv6 attempt dies with `ENETUNREACH`. The suite
  reports `Socket closed` on a random endpoint, and `curl` never reproduces it because curl falls back to
  IPv4. Resolve the v4 address at container start and bake it in.
- **Run plans one at a time.** `run-test-plan.py` runs several plan/config pairs concurrently, they
  share one alias, and they fight over it — failures that are pure contention.
- **Make sure the previous run is gone.** A runner left waiting while the suite was down resumes when it
  comes back, and its modules interrupt the next run's for the same alias conflict: every module then
  reports `INTERRUPTED` with "Stopping test due to alias conflict". Check that no `run-test-plan.py` is
  still alive before starting a plan.
- **A path-addressed bucket's sign-in pages are not beneath its prefix.** Its `/auth`, `/token` and
  `/logout` are under `/<slug>`, but the interaction pages stay at the root `/ui/<uid>/login`. A browser
  script that matches `<issuer>/ui/*` never finds the login page and fails every module.

Two scripts in the rig do what `run-test-plan.py` cannot. `suite.py` creates one module without
starting it, so an operator step can happen in between (`create`, then `start` — how `rotate-keys` was
run), and uploads a screenshot to a REVIEW placeholder. `browser-plan.ts` runs a whole plan in Chromium
through Playwright from a config with its `browser` and `override` sections removed: it creates each
module, signs in, consents and confirms sign-out as a person would, photographs the page a REVIEW
module asks about, and fills the placeholder while the module waits for it.

**Nothing this server sends can reach a local suite.** Back-channel logout, a client's `jwks_uri`, a
`sector_identifier_uri` and every client plan need this server to call the suite. A deployed instance
cannot reach a laptop, and a local one refuses private addresses by design. Those plans run on the
hosted suite at `www.certification.openid.net`: `run-hosted.sh` is `run-plan.sh` pointed there, with an
API token created in that suite's own UI and an alias of its own (aliases there are shared by every
user). Its dynamic config adds one browser task, which clicks the link on this server's error
confirmation page (see [Dynamic](#dynamic--12)).

### The client plans

`run-test-plan.py` cannot drive these: it runs the suite's own sample RP or a nested OP plan, and
neither is `lib/federation/`. Each module is driven by replaying a federated sign-in through the
deployment — start at `/auth`, follow it to `/ui/:uid/login`, hit
`/ui/:uid/federation/:providerId/start`, follow that to the suite, and bring the callback back.

- **Give every module its own alias.** The suite mints a fresh signing key per module but serves the
  whole plan from one `jwks_uri`, while this RP caches discovery per issuer for ten minutes and holds one
  key set per `jwks_uri`. Behind a shared alias, module N verifies its token against module 1's key.
  Repoint the bucket's provider at the new issuer before each module.
- **Stop each module before creating the next.** A client test concludes only once the RP has done
  everything its script expects, and this one never calls `/userinfo`; creating the next module while
  one is `WAITING` makes the suite kill the earlier one as `INTERRUPTED`. `DELETE /api/runner/{id}` ends
  it cleanly.
- **Read the conditions, not the module status.** A finished negative module reports `PASSED` whether or
  not the RP rejected anything. Record the failed-condition list from `/api/log/{id}`, paired with the
  answer the RP itself gave at its callback.
- **An accepted assertion stops at "no email".** The suite's OP issues no `email` claim, so a sign-in
  whose ID token verified ends on the 400 page "Your identity provider sent no email address", and a
  refused one on the 400 page "Sign-in could not be completed". Read the page, not the status. No
  account has to be linked first.
- **Ask for `email` and `profile`.** With the provider's scopes at `openid` alone, the suite's OP
  refuses `scope-userinfo-claims`'s authorization request before any token is issued.

`client-plan.py` in the rig does the two scripted halves — `create` a plan and module under a fresh
alias, then `drive` the sign-in, record each hop and the module's conditions, and stop it — and the
provider is repointed through MCP in between. `discovery-openid-config` and `discovery-issuer-mismatch`
take no sign-in: the first concludes when writing the provider fetches discovery, and the second is
refused right there.

## Screenshots

Several modules end in `REVIEW` because they need a screenshot of a page the server rendered — the
second login page for `prompt=login` and `max_age=1`, and the error pages for a missing `response_type`
and an unregistered `redirect_uri`. The suite's scripted browser is HtmlUnit, which does not render, so
it stores the page's HTML rather than an image. **Certification requires real screenshots taken in a
real browser and uploaded by hand**, so those modules must be walked through manually once, whatever
else is automated. One captures nothing, correctly: for a missing `response_type` this server redirects
the error to the registered `redirect_uri` instead of rendering a page, and the module accepts either.

## SCIM provisioning (IPSIE AL SCIM profile)

Inbound SCIM 2.0 `/Users` and `/Groups` (RFC 7643/7644) are served per bucket at `<bucket issuer>/scim/v2`,
through a provisioning connection an administrator sets up on the bucket. The target is the
[OpenID IPSIE AL SCIM 2.0 Profile](https://openid.github.io/ipsie-scim-al/), draft 00 of 2026-09-08, at
AL1 and AL2, with the SCIM 2.0 Interoperability Profile (draft-zollner-scim-interop-profile-01) it builds
on.

**Microsoft's SCIM validator: passed.** Run on 2026-10-07 against the conformance deployment, with
`/Groups` (scimvalidator.microsoft.com, schema discovered from `/Schemas` — `displayName` as the group's
joining property, `externalId` — static token, default settings): 23 of 24 required tests and all 7
previews pass. All 12 group tests pass: get by id and filter by `displayName` excluding members, filter
existing, absent and in another letter case, create and a duplicate create, replace attributes, rename,
add and remove a member, delete; and the previews' multi-operation group PATCH and deleting an absent or
already-deleted group. The first run, on 2026-10-06 without groups, failed Add, Replace and Remove Manager,
which led to accepting the manager as a bare id (behind `scim.strict`, below).

The one failure, "Patch User - Replace Attributes", is the same in both runs and is counted as passed because the failure is the
validator's, not this server's. It reports `emails[primary eq true].value` and
`phoneNumbers[primary eq true].value` missing from the fetched resource, yet:

- the PATCH response it shows carries both replaced values, on the entries marked `primary: true`;
- a following `GET /Users/{id}` and a filtered `GET /Users?filter=userName eq …` return the same, so the change
  was stored, not only echoed;
- `primary` is a JSON boolean, as RFC 7643 §2.4 types it — the validator itself sends the string `"true"`,
  which this server reads as the boolean outside strict mode;
- the same test passes its path-less half in the same request (every other attribute it replaces is found),
  and the multi-operation previews that read the same resource pass;
- other implementations report this exact failure against correct responses, with no resolution from
  Microsoft ([Microsoft Q&A 5624709](https://learn.microsoft.com/en-us/answers/questions/5624709/scim-validator-failing-on-patch-user-replace-attri)).

**Okta's SCIM 2.0 Spec Test: passed.** Run on 2026-10-07 in BlazeMeter API Monitoring against the same
deployment, static token, with `/Groups`: all 11 required tests and the optional "Verify Groups endpoint"
pass — 12 of 12 steps, 53 of 53 assertions. An earlier run that day, before `/Groups`, failed only that
optional test (51 of 52). The first run also failed "Test Users
endpoint" and "Get Users/{id}", because the suite requires at least one user to exist beforehand and the
bucket was empty — a precondition of the suite, met by creating one. That run found a real defect too:
every unserved path, `/Groups` included, answered 404 with a `server_error` body; it now answers
`not_found`, and beneath an enabled SCIM base a SCIM 404. Okta's CRUD test, which needs an Okta org with
the integration installed, has not been run.

| Requirement (service provider)                                                                                       | Section      | Status                                                                                                                                                                                                                                                                                                                                          |
| -------------------------------------------------------------------------------------------------------------------- | ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| OAuth 2.0 `client_credentials` with JWT client authentication (RFC 7523 §2.2)                                        | §4.1, §10    | Met by the key credential. A client secret and a static token are also offered — deviations, below.                                                                                                                                                                                                                                             |
| Access token carries `scim` and nothing broader                                                                      | §4.1         | Met: a connection's token is `scim`-scoped, opaque, bound to its own bucket's SCIM URL as audience, and refused everywhere else.                                                                                                                                                                                                                |
| RFC 8414 metadata naming `token_endpoint`                                                                            | §4.1         | Met: each bucket's authorization-server metadata. The SCIM resource also publishes RFC 9728 metadata.                                                                                                                                                                                                                                           |
| Local modifications of provisioned users prohibited                                                                  | §4.2, §6     | Met for the profile and the active flag (409 to an administrator), except the local lock — deviation, below.                                                                                                                                                                                                                                    |
| Rate limits on every SCIM endpoint, 429; at least 25 requests a second                                               | §4.3         | Met: per connection, 50/s by default, a floor of 25/s enforced on save; `Retry-After` on 429.                                                                                                                                                                                                                                                   |
| `/Bulk`                                                                                                              | §4.3         | **Not met** — deviation, below.                                                                                                                                                                                                                                                                                                                 |
| PATCH with several attributes in one request                                                                         | §4.3         | Met, all or nothing.                                                                                                                                                                                                                                                                                                                            |
| `PATCH /Users/{id}` deactivates and reactivates; deactivation ends every access mechanism                            | §5.1         | Met: sessions, grants, refresh and opaque access tokens end at once, with back-channel logout. A JWT access token validated locally by a resource server lives to its expiry (1 h default); set a shorter `accessTokenTTL` on the resource for SL2's 15 minutes.                                                                                |
| `DELETE /Users/{id}`; the userName reusable afterwards                                                               | §5.2, §10    | Met.                                                                                                                                                                                                                                                                                                                                            |
| `GET /Users/{id}`; filters `userName eq`, `externalId eq`, `emails[value eq]`, `emails[type eq "work" and value eq]` | §5.3–5.4     | Met; `emails[type eq "work"].value eq` too. Anything else is 400 `invalidFilter`.                                                                                                                                                                                                                                                               |
| User schema with `userName`, `displayName`, `active`, `externalId`                                                   | §6.1.1       | Met.                                                                                                                                                                                                                                                                                                                                            |
| No `password` attribute; no credentials in custom schemas                                                            | §6.1.2       | Met in the schemas. A `password` sent anyway is ignored unless `scim.strict` is on — deviation, below.                                                                                                                                                                                                                                          |
| `POST`, `PATCH`, `GET /Users` (listing, ≤ 1,000 per page)                                                            | §6.1.3–6.1.5 | Met; index paging. Cursor paging is part 4 of the series.                                                                                                                                                                                                                                                                                       |
| Group schema: `displayName`, `members`, `externalId`; names unique                                                   | §6.2.1       | Met: `displayName` unique per bucket in any letter case (409 `uniqueness`), `externalId` per connection.                                                                                                                                                                                                                                        |
| `POST /Groups`, with zero members                                                                                    | §6.2.2       | Met. A body above the 256 KiB limit (about 5,500 members) answers 413; large groups are filled by PATCH, as Entra and Okta do.                                                                                                                                                                                                                  |
| `GET /Groups`, `excludedAttributes=members`                                                                          | §6.2.3       | Met; `attributes`/`excludedAttributes` are honoured for `members`.                                                                                                                                                                                                                                                                              |
| `GET /Groups/{id}`                                                                                                   | §6.2.4       | Met; the whole member list (SCIM has no paging of members).                                                                                                                                                                                                                                                                                     |
| Filters `displayName eq`, `externalId eq`, `members[value eq]`                                                       | §6.2.5       | Met; `id eq` and `members.value eq` too, so Entra's membership check works. Anything else is 400 `invalidFilter`.                                                                                                                                                                                                                               |
| `PATCH /Groups/{id}` with at least 50 member operations                                                              | §6.2.6       | Met: no ceiling but the body limit; every refusal changes nothing; answers 204. Measured 2026-10-07 by `database/verify_*`: a 50-member change into a group growing to 10,000 takes ~5–11 ms on PostgreSQL 17 (slowest 25 ms) and ~10 ms on a standalone MongoDB (slowest 29 ms), not growing with the group.                                   |
| Mapping the directory's groups to the application's roles                                                            | §6           | Met through the `groups` claim: relying parties receive the user's group names (built-in `groups` scope; above 200, an OpenID Connect distributed-claim reference to userinfo, which a resource server holding an audience-bound token cannot follow). Role management itself (AL3) is not claimed: its requirements are undefined in draft 00. |
| SCIM error format, nothing internal                                                                                  | §8           | Met.                                                                                                                                                                                                                                                                                                                                            |
| Every creating, changing or deleting request logged                                                                  | §8           | Met: the audit trail, actor `connection:<id>`, surface `scim`, attribute names never values.                                                                                                                                                                                                                                                    |

### Deviations, and the switch for each

| Deviation                                                                                                                                                   | Why                                                                                                                                                                                                                                                                                                                                                                             | Setting                            |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------- |
| Client-secret credential                                                                                                                                    | Microsoft Entra ID authenticates to a token endpoint only with a client secret (until workload identity federation)                                                                                                                                                                                                                                                             | `scim.secretCredentials` (on)      |
| Static bearer token                                                                                                                                         | Okta cannot use the client-credentials grant for SCIM                                                                                                                                                                                                                                                                                                                           | `scim.staticTokens` (on)           |
| Tolerant requests: a PATCH without `path`, `op` in any case, booleans as strings, `manager` as a bare id or `""`, unknown attributes and `password` ignored | Okta deactivates with a path-less PATCH and sends `password` on every create; Entra sends path-less multi-attribute replaces, `"False"`, capitalised operations, `addresses` by default, and `manager` as its bare id. The interop profile (§6.5.1.1) and IPSIE §6.1.2 require refusing them. `/ServiceProviderConfig` declares `interopProfileConformant` only in strict mode. | `scim.strict` (off)                |
| No `/Bulk`                                                                                                                                                  | None of Entra ID, Okta or OneLogin calls it; planned with asynchronous bulk in part 4                                                                                                                                                                                                                                                                                           | — (an absence)                     |
| An administrator's local lock on a provisioned user                                                                                                         | An incident response must not wait for the directory; it touches sign-in only, never the profile, and the directory cannot clear it                                                                                                                                                                                                                                             | — (an absence of the prohibition)  |
| On a standalone `mongod`, a group change interrupted by a database failure may be partly applied (RFC 7644 §3.5.2)                                          | A standalone `mongod` has no multi-document transaction. Every refusal is still decided before the first write; only a failure mid-request (answered 500) can leave part of a change, and the client's retry converges. PostgreSQL and MongoDB replica sets (Atlas) apply each change in one transaction. Declared as `bucket-group-change-atomicity`.                          | — (a failure mode of one topology) |

**§4.1 contradicts itself.** It requires "`client_credentials` … with JWT Client Authentication as defined
in [RFC7523] section 2.2", and a few lines later "HTTP Basic authentication in the Authorization request
header. Transmission of client credentials (e.g., `client_assertion`, `client_secret`) in the HTTP request
body is prohibited." No client can do both: RFC 7523 §2.2 carries the assertion in the body (RFC 7521 §4.2),
and Basic carries a shared secret. This server follows the JWT requirement, because §10 repeats it and §4.1
carries an editor's note that it "should be expanded" — so the key credential's assertion travels in the
body, as RFC 7521 defines, and that is not a violation of the second bullet in the sense its authors could
have meant.

## Scope

What is still to run is listed [above](#what-still-has-to-run). Certification itself has not been
applied for.

Inapplicable by design, not unfinished: Hybrid, Implicit and their form_post variants, because
`response_types_supported` is `code` and `none`; Dynamic, for the reason above; Session Management and
Front-Channel Logout, because there is no `check_session_iframe` and no front-channel logout; and their
client-side twins, because the RP runs a code flow only. Not implemented at all: OID4VCI and OID4VP, the
Shared Signals plans, AuthZEN, eKYC/IDA, OpenID Federation 1.0 (a different thing from
`lib/federation/`), and every `*-brazil-*` variant.
