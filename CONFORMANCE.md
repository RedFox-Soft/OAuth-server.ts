# Conformance

What the [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite) says
about this server, and what it takes to get an answer — because most of the cost of a conformance run
is not the run.

## Where it stands

### What passes

**Measured 2026-10-01 against the deployed `conformance.foxauth.dev` at `e61a5a1`**, the current
`main`, with the suite (`conformance-suite:latest`, built 2026-09-30) running locally and reaching the
instance over the internet — real TLS, a real hostname, no terminator of our own in between. Every
client the suite uses, its end user, the scope definitions and each profile switch were set up through
the MCP control plane, not by hand-written seed data, and each profile was switched on save, with no
restart.

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

This run covers the five commits that changed what these plans exercise after the 2026-09-30
measurement (at `7be92fc`): `7c8632a` and `7245d8f` (sign-out by `POST`, the confirmation's hand-off
to the relying party, introspection and revocation metadata, one source for `grant_types_supported`),
`a4d4382` (an error raised after an interaction is delivered to the client), `01f3d71` (an error for a
client no operator vouched for stops at a confirmation page — see [Dynamic](#dynamic--12)) and
`e61a5a1` (`amr` in every ID token and in `claims_supported`). The only difference any plan shows is
the one `01f3d71` intends.

Four plans were last measured on 2026-09-14 and not since, because each needs this server to
**call the suite** (see [What still has to run](#what-still-has-to-run)):

| Plan                                                            | Then                                |
| --------------------------------------------------------------- | ----------------------------------- |
| `oidcc-backchannel-rp-initiated-logout-certification-test-plan` | 101 conditions, none failed         |
| `oidcc-client-basic-certification-test-plan`                    | none — **and one wrong acceptance** |
| `oidcc-client-config-certification-test-plan`                   | 3, all of them the runner's         |
| `oidcc-client-refreshtoken-test-plan`                           | none — subject not exercised        |

The three client plans test this server as a **Relying Party**, because `lib/federation/` makes it one
and no OP plan reaches that code.

### Open defects

**None the suite has found.** Every defect it reported is fixed — see
[Defects found and fixed](#defects-found-and-fixed). Two results it will keep reporting are not
defects: the Dynamic profile's demand for the implicit flow, which this server refuses on purpose, and
`request_uri` by reference (RFC 9101), which it does not implement and refuses with the registered
`request_uri_not_supported`.

One gap is known **outside** the suite, and it is server-wide rather than one claim's. OIDC Core §5.5.1
says a claim whose value does not match a `value`/`values` in the `claims` request "is not included in
the response"; this server selects claims by name only and applies that rule to **no** claim (`sub` and
`acr`, which carry failure rules of their own, are enforced). It is reachable only with
`claimsParameter.enabled`, which ships off, and for an array-valued claim such as `amr` the equality
comparison the text prescribes is undefined.

### What still has to run

In the order they are worth it:

| What                                                                 | Why                                                                                            | What it needs                                                       |
| -------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| Back-channel logout                                                  | last run 2026-09-14, and the sign-out path has been rewritten since                            | a suite this server can reach                                       |
| The three client plans                                               | defects 4 and 5 are fixed and pinned by tests, but no run has confirmed either                 | a suite this server can reach                                       |
| A named bucket, at a path and at a hostname                          | its own issuer, well-known locations and keys — what these plans probe most, and never covered | a bucket with an address, and suite configs naming its issuer       |
| A real browser: `user-rejects-authentication`, screenshots, sign-out | HtmlUnit enforces neither CSP nor SameSite — `7245d8f` fixed a defect the suite passed         | a person and a real browser; certification requires it anyway       |
| `oidcc-server-rotate-keys` with an operator rotating                 | possible without a restart since `15ab771`, untried                                            | an operator running `jwks_generate` while the module waits          |
| FAPI-CIBA ID1                                                        | never run                                                                                      | `ciba.enabled` and the `poll` delivery mode                         |
| FAPI 1.0 Advanced                                                    | never run                                                                                      | client certificates through the rig; its `jarm` variant to reach it |

"A suite this server can reach" is the hosted one at `www.certification.openid.net`, which is also the
one certification counts: a deployed instance cannot call a suite on a laptop, and a local instance
refuses private addresses by design (the egress boundary, `lib/shared/egress.ts`, since 0.7.0).

## Defects found and fixed

| Found      | Defect                                                                                       | Fixed in  | Found by                     | Confirmed by a run |
| ---------- | -------------------------------------------------------------------------------------------- | --------- | ---------------------------- | ------------------ |
| 2026-09-30 | a confirmed sign-out never reached the relying party in a browser                            | `7245d8f` | Chromium, not the suite      | no — it cannot be  |
| 2026-09-30 | no `POST` end-session; introspection/revocation auth metadata missing; grant types disagreed | `7c8632a` | reading the specs (#7)       | passes; unseen     |
| 2026-09-30 | a sign-out without `id_token_hint` lost the session on MongoDB                               | `70f3598` | RP-initiated logout          | yes                |
| 2026-09-13 | an error raised after an interaction was rendered, not returned to the client (#47)          | `a4d4382` | reading the code             | needs a human      |
| 2026-09-13 | an ID token never carried `amr` (#46)                                                        | `e61a5a1` | reading the code             | no — not checked   |
| 2026-09-30 | too many refusals inside a Request Object answered `invalid_request_object`                  | `390cbda` | Message Signing              | yes                |
| 2026-09-14 | 1–3: a Request Object held to a client assertion's schema                                    | `f2b37e0` | Message Signing              | yes                |
| 2026-09-14 | 4: the relying party accepted an ID token with no `iat`                                      | `f2b37e0` | client Basic, and the runner | not yet            |
| 2026-09-14 | 5: the relying party could not follow an upstream key rotation                               | `f2b37e0` | client Config                | not yet            |
| earlier    | twelve, listed below                                                                         | below     | the OP plans                 | yes                |

"Passes; unseen" means the plans run clean with the fix, but no module exercises it: the suite signs
out by `GET` and never compares the grants it is told about with the grants `/token` accepts. "Needs
a human" means the module that would show it is `user-rejects-authentication`, which needs someone to
press cancel.

**The sign-out defect is the one to learn from.** The confirmation page carried `form-action 'self'`,
and `form-action` governs every hop of a submission's navigation, so Chrome blocked the 303 to the
client's `post_logout_redirect_uri` — after the session had already ended. The RP-initiated logout plan
passed throughout, because HtmlUnit does not enforce CSP. A browser-enforced property can only be shown
by a browser.

**`amr` (#46) was invisible to every plan.** The suite does not check the claim (`ValidateIdToken`:
"amr - not currently checked"), so no run could have found it and none can confirm the fix. A sign-in
recorded its methods and every hop carried them; the ID token dropped them because nothing in a default
request asks for `amr`. It is now written into every ID token from a sign-in and advertised in
`claims_supported` whatever the stored claims setting holds — see `wiki/concepts/amr-reporting.md`.

**1–3. One schema, three wrong answers about Request Objects.** The object was validated against the
schema of a **client assertion** (RFC 7523 §3), and every difference was wrong in the strict direction:
`jti` was demanded (RFC 9101 §4 makes it optional — and since every Message Signing module starts with
a signed PAR push, the whole plan died in its first block); `aud` could not be an array (RFC 7519
§4.1.3); and a refused object answered `invalid_request` rather than `invalid_request_object` (RFC 9101
§6.2). `390cbda` then narrowed that last rule: only the object's own registered claims, and a nested
`request`/`request_uri`, are refused as the object — `par-plain-pkce-rejected` expects
`invalid_request` for a `plain` `code_challenge_method` (RFC 7636 §4.4.1).

**4. The relying party accepted an ID token with no `iat`** (`lib/federation/verifyIdToken.ts`). The
value was checked, the presence was not, and jose does not require `iat` unless `maxTokenAge` is set;
OIDC Core §2 makes it REQUIRED. **The suite cannot see this defect, and that is the point.** Its OP
cannot observe whether the RP rejected what it sent, so every negative client module reports PASSED;
the runner here supplies the missing half by recording the HTTP status this server returned. Seven of
the eight negatives answered 400 and aborted the sign-in; this one answered 303 and finished it.

**5. The relying party could not follow an upstream key rotation** (`lib/federation/jwks.ts`). jose's
remote key set caches for ten minutes and forces a reload only on `JWKSNoMatchingKey`, and only after a
30-second cooldown. A second sign-in 3 s after a rotation was refused and one 45 s after it succeeded;
a new key with **no `kid`** never raises `JWKSNoMatchingKey` at all, so the lockout lasts the whole
ten-minute cache.

**The earlier twelve:** `830713b` (PAR content type), `1437341` (unknown request parameters, widened
from the one endpoint reported to six), `6cdb9ec` (`code_verifier` alphabet), `848c179` (schema refusals
answer 400, not 422), `dcc4c08` and `3589d48` (`/userinfo` challenge and POST body), `0353f4b`
(form_post reaches a module-less browser; PAR names its own error code), `b891075` (key generation for
any asymmetric signing algorithm), `87d44e8` (`pkce.required`), `a99c81a` (`acr`, which also closed an
interaction loop an essential `acr` claim could not escape), `2b83c91` (unknown members inside `claims`
are ignored; a pushed request is spent after a login, not only when no login was needed).

Setting the instance up through the MCP surface found four more gaps that no module would — each forced
a step outside the console and the agent's tools: scope claims were not a setting (`73b2d85`), an end
user's claims could not be set (`faa0ea8`), a key-authenticated or FAPI client could not be registered
(`7be92fc`), and a new signing algorithm needed a restart to be advertised (`bebc524`) or rotated
(`15ab771`) — see [Signing keys for a FAPI run](#signing-keys-for-a-fapi-run).

## Failures that are not this server

### FAPI 2.0 Message Signing — 4

Run as
`[openid=openid_connect][client_auth_type=private_key_jwt][sender_constrain=dpop][fapi_profile=plain_fapi][authorization_request_type=simple][fapi_request_method=signed_non_repudiation][fapi_response_mode=jarm][grant_management=disabled]`.

- All 4 (and 2 of the 3 warnings) are `user-rejects-authentication`, which needs a human to press
  cancel on the login page. It cannot be automated and is not meant to be.
- 3 modules are **skipped**, correctly: the two `…-with-RS256-fails` modules apply only to a client
  whose key is RSA, and `refresh-token` warns that the server supports refresh tokens but issued none to
  this client — which asked for no `offline_access`, so none is due.
- `par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` ends in REVIEW. It needs the first
  visit to stop at the login page, because signing in there spends the pushed request the second visit
  reuses; the rig's config gives the module a browser script that screenshots the page and stops.

The previous round's other failures are gone rather than explained away: the four
`RequireOnlyBCP195RecommendedCiphersForTLS12` failures tested the local nginx terminator, which a
deployed instance does not have, and the one unexplained `Socket closed` did not recur.

### FAPI 2.0 Security Profile — 4

All 4 are `user-rejects-authentication` again. `par-ensure-reused-request-uri…` ends in REVIEW with the
same browser override as in Message Signing; on 2026-09-30 it failed three conditions once, in the run
made before that override existed. The same two modules are skipped as in Message Signing, for the same
reasons.

One correction from an earlier run is preserved because the mistake is instructive. Three modules push
a `client_assertion` whose `aud` is an array, the PAR endpoint URL or the token endpoint URL, and each
was answered `201` where FAPI 2.0 requires refusal. It read as audience confusion — an assertion is a
bearer credential, so its accepted audiences are the places a captured one can be replayed — and it was
not a defect: RFC 9126 §2 says an authorization server **MUST** accept its issuer, token endpoint URL
**or** PAR endpoint URL as identifying it. The narrow rule is FAPI 2.0's alone, implemented behind
`fapi.enabled` (`lib/shared/token_jwt_auth.ts`) and held by three cases in `test/fapi/fapi2.spec.ts`;
with the flag on, those modules pass. **A run in the wrong instance profile does not report a
configuration problem; it reports a security defect that is not there.** Defect 2 above is the same
shape in the other direction — an array `aud` in a Request Object must be accepted — and the two are
worth reading together before touching either.

### Basic — none

No failure. `prompt-login` and `max-age-1` conclude in REVIEW — the screenshot of the second login page
(see [Screenshots](#screenshots)). On 2026-09-30 both had timed out once in the scripted browser
waiting for that page and passed when re-run alone; on 2026-10-01 neither did.

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
  the suite is unreachable; from a local one the egress boundary refuses it. Both are the environment,
  not the rule.
- 1 is `oidcc-server-rotate-keys`, which fetches `/jwks`, waits for the operator to rotate the signing
  key, and fetches it again. Nobody rotated. Since `15ab771` this can be done mid-run without a restart —
  `jwks_generate` publishes the new key in `/jwks` at once — but no run has tried it yet.

**One module now stops at a page of this server's, by design.** Since `01f3d71` (RFC 9700 §4.11.2),
an authorization _error_ for a client whose redirect URIs no operator vouched for — one created by
dynamic registration, or resolved from a client ID metadata document — is not redirected: the server
answers with a confirmation page of its own (the error's status, `frame-ancestors 'none'`, and a link
that delivers the identical answer when clicked). This plan registers every client dynamically, and
the one module in it whose authorization request is refused is `oidcc-request-uri-signed-rs256`: its
`request_uri_not_supported` used to arrive at the suite's callback, and since `01f3d71` the scripted
browser stays on `/auth` until it times out — one more failed condition, which is how the 11 of
2026-09-30 became the 12 of 2026-10-01. It is the third attack that section lists, closed on purpose,
and not a new failure class. Successful responses, and every client an administrator created, are
unaffected — which is why the Basic plan's `oidcc-prompt-none-not-logged-in`, run with static clients,
still receives its `login_required` redirect.

The plan is still worth running: it is the only one that exercises dynamic registration.

### The client plans — 3, all the runner's (2026-09-14)

All three are in `oidcc-client-config-certification-test-plan`, and all three are the runner driving a
module more times than the module expects: `idtoken-sig-none` and
`signing-key-rotation-just-before-signing` want one sign-in and got two, and `discovery-openid-config`
concludes as soon as the RP has fetched discovery, so the runner carried on into a finished test. The fix
is a per-module drive count; nothing about it reflects on the server.

## What an RP run does and does not prove

`lib/federation/` is a **login broker**, not a general-purpose OpenID client, and three of the plans'
assumptions do not hold against it. This is design, not omission, but it bounds what the result means.

- **It never calls `/userinfo`.** Six of the fourteen Basic client modules therefore never conclude and
  are stopped rather than finished; `userinfo-invalid-sub` and `scope-userinfo-claims` prove nothing.
- **It never uses a refresh token** and does not request `offline_access`, so the whole
  `oidcc-client-refreshtoken` plan runs clean without touching its subject.
- **It only ever runs a code flow**, which is why the hybrid, implicit, session-management and
  front-channel-logout client plans are inapplicable for the same reason their OP twins are.

What it _does_ prove is the verification: `iss`, `aud`, `exp`, the algorithm allowlist, `alg: none`, a
bad signature, a `kid` absent with several keys published, a mismatched `nonce`, a missing `sub`, and a
discovery document whose `issuer` disagrees with the URL it came from — each refused. Only `iat` got
through (defect 4, since fixed).

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
validation — which surfaced as `400 post_logout_redirect_uri not registered` and cost three runs.

### Signing keys for a FAPI run

FAPI 2.0 forbids RS256, so the instance needs a signer in PS256 or ES256, and a FAPI client registers
for it. **A generated key does not sign until it is promoted**, and promotion is refused for the first
60 seconds, while every instance picks the key up. Registration checks a client's algorithm against the
keys that sign, so the order is: `jwks_generate` in ES256 (or PS256), wait out the window, `jwks_promote`,
then register the FAPI clients. There is one signer per algorithm, so promoting ES256 leaves the RS256
signer the OIDC clients use in place.

## Running the suite

### The rig

The suite runs locally from `docker-compose-prebuilt.yml` (prebuilt images, no Maven build). Against a
**local** server it needs an nginx TLS terminator the suite reaches as `https://oidcc-provider:3000`: the
end-user cookies are written `secure: true` unconditionally, so a plain-HTTP origin has the suite's
browser drop them and every login fails. Against the **deployed** instance there is no terminator —
point the configs' `discoveryUrl` at it.

Two properties of the rig cost a run each, and neither announces itself:

- **Pin the terminator's upstream to IPv4.** Docker Desktop gives `host.docker.internal` both an A and an
  AAAA record; nginx alternates between them and every IPv6 attempt dies with `ENETUNREACH`. The suite
  reports `Socket closed` on a random endpoint, and `curl` never reproduces it because curl falls back to
  IPv4. Resolve the v4 address at container start and bake it in.
- **Run plans one at a time.** `run-test-plan.py` runs several plan/config pairs concurrently, they
  share one alias, and they fight over it — failures that are pure contention.

**Nothing this server sends can reach a local suite.** Back-channel logout, a client's `jwks_uri`, a
`sector_identifier_uri` and every client plan need this server to call the suite. A deployed instance
cannot reach a laptop, and a local one refuses private addresses by design. Those plans need a suite
the server can reach — the hosted one at `www.certification.openid.net`, which is also the one
certification counts.

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
  not the RP rejected anything (defect 4). Record the failed-condition list from `/api/log/{id}`, paired
  with the HTTP status the RP itself returned.
- **Link an account first.** The suite's OP issues no `email` claim, so the target bucket needs an
  account already linked to its subject (`user-subject-1234531`), or the sign-in stops at "your identity
  provider sent no email address" before any interesting check runs.

## Screenshots

Several modules end in `REVIEW` because they need a screenshot of a page the server rendered — the
second login page for `prompt=login` and `max_age=1`, and the error pages for a missing `response_type`
and an unregistered `redirect_uri`. The suite's scripted browser is HtmlUnit, which does not render, so
it stores the page's HTML rather than an image. **Certification requires real screenshots taken in a
real browser and uploaded by hand**, so those modules must be walked through manually once, whatever
else is automated. One captures nothing, correctly: for a missing `response_type` this server redirects
the error to the registered `redirect_uri` instead of rendering a page, and the module accepts either.

## Scope

What is still to run is listed [above](#what-still-has-to-run). Certification itself has not been
applied for.

Inapplicable by design, not unfinished: Hybrid, Implicit and their form_post variants, because
`response_types_supported` is `code` and `none`; Dynamic, for the reason above; Session Management and
Front-Channel Logout, because there is no `check_session_iframe` and no front-channel logout; and their
client-side twins, because the RP runs a code flow only. Not implemented at all: OID4VCI and OID4VP, the
Shared Signals plans, AuthZEN, eKYC/IDA, OpenID Federation 1.0 (a different thing from
`lib/federation/`), and every `*-brazil-*` variant.
