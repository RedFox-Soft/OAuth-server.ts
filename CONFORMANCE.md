# Conformance

What the [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite) says
about this server, and what it takes to get an answer.

`SECURITY.md` says the suite has never been run against a release. This file is the evidence that
replaces that sentence: the current result, what the remaining failures actually are, and the setup a
run needs — because most of the cost of a conformance run is not the run.

## Where it stands

**The measurement predates 0.4.0 and has not been repeated against it or against 0.5.0.** Those two
releases made a user bucket addressable — in the URL, then at a hostname of its own — and its own
issuer, which is the subject these plans probe most directly: the issuer identifier, the well-known
locations an issuer carrying a path has, and the `iss` in an authorization response. The numbers below
were taken against the default bucket, whose issuer and endpoints both releases deliberately leave
unchanged, so they still describe what a client integrated before them meets. They say nothing about a
_named_ bucket's metadata, at either kind of address, which no run has covered. A run for both
profiles is the open item.

Measured 2026-09-14, across two instance profiles (below). Twelve plans: nine testing this server as
an **OpenID Provider**, three testing it as a **Relying Party** — because `lib/federation/` makes it
one, and no OP plan reaches that code.

| Plan                                                            | Conditions | Failures                            |
| --------------------------------------------------------------- | ---------- | ----------------------------------- |
| `oidcc-config-certification-test-plan`                          | 41         | **none**                            |
| `oidcc-basic-certification-test-plan`                           | 1 855      | **none**, and no warnings           |
| `oidcc-formpost-basic-certification-test-plan`                  | 2 007      | **none**, and no warnings           |
| `oidcc-rp-initiated-logout-certification-test-plan`             | 551        | **none**                            |
| `oidcc-backchannel-rp-initiated-logout-certification-test-plan` | 101        | **none**                            |
| `oidcc-3rdparty-init-login-certification-test-plan`             | 50         | **none**                            |
| `oidcc-dynamic-certification-test-plan`                         | 883        | 11, none of them this server        |
| `fapi2-security-profile-final-test-plan`                        | 4 343      | 9, none of them this server         |
| `fapi2-message-signing-final-test-plan`                         | 5 693      | 13, **two of them this server**     |
| `oidcc-client-basic-certification-test-plan`                    | 655        | none — **and one wrong acceptance** |
| `oidcc-client-config-certification-test-plan`                   | 285        | 3, all of them the runner's         |
| `oidcc-client-refreshtoken-test-plan`                           | 216        | none — subject not exercised        |

**16 680 conditions. Five defects are open**, all found by the three plans run for the first time on
2026-09-14 (Message Signing and the client family); the nine plans above them are unchanged and still
carry no failure attributable to this server.

Twelve defects the suite found earlier have been fixed: `830713b` (PAR content type), `1437341`
(unknown request parameters, widened from the one endpoint reported to six), `6cdb9ec`
(`code_verifier` alphabet), `848c179` (schema refusals answer 400, not 422), `dcc4c08` and `3589d48`
(`/userinfo` challenge and POST body), `0353f4b` (form_post reaches a module-less browser; PAR names
its own error code), `b891075` (key generation for any asymmetric signing algorithm), `87d44e8`
(`pkce.required`), `a99c81a` (`acr`, which also closed an interaction loop an essential `acr` claim
could not escape), `2b83c91` (unknown members inside `claims` are ignored; a pushed request is spent
after a login, not only when no login was needed). The detail is in those commits.

## The five open defects

### 1–3. One schema, three wrong answers about Request Objects

[`lib/consts/param_list.ts`](lib/consts/param_list.ts) declares `JWTparameters` — `jti`, `iss`, `aud`
and `exp` all required, `aud` a single string. That shape is right for a **client assertion**
(RFC 7523 §3). [`lib/actions/authorization/authorization.ts`](lib/actions/authorization/authorization.ts)
spreads the same object into the schema a **Request Object** is validated against, where the rules are
different — and all three differences are wrong in the strict direction, so each one refuses a request
the specification permits.

**`jti` is demanded.** Every signed request object the suite pushes is answered
`400 invalid_request: Property 'jti' is missing`. RFC 9101 §4 and OIDC Core §6.1 make `jti` optional
in a Request Object, and FAPI 2.0 Message Signing requires only `aud`, `iss`, `exp` and `nbf`. This is
not one module's failure: with `fapi_request_method=signed_non_repudiation` every module in the plan
starts with a PAR push, so the whole plan died in the first block — 49 failed modules, each in 0.1
seconds. A temporary local patch making `jti` optional took the run from 49 failures to 15, which is
how the other two came into view.

**`aud` may not be an array.** `ensure-request-object-with-multiple-aud-succeeds` pushes
`"aud": ["https://oidcc-provider:3000", "https://other1.example.com", "invalid"]` and is answered
`400: Expected property 'aud' to be string`. RFC 7519 §4.1.3 allows either form, and the rule the
module tests is that the server's own identifier is _among_ the values — which it is.

**A refused Request Object names the wrong error.** `ensure-request-object-without-exp-fails` expects
`invalid_request_object`; it gets `invalid_request`. RFC 9101 §5 registers the former for exactly this
case. The cause is structural rather than a wrong string:
[`process_request_object.ts:128`](lib/actions/authorization/process_request_object.ts#L128) throws a
TypeBox `ValidationError`, which the shared error handler formats as `invalid_request`, while every
other check in that same file throws `InvalidRequestObject`
([`errors.ts:199`](lib/helpers/errors.ts#L199)) and answers correctly. It is also why the `jti`
refusal above arrived under the wrong code.

### 4. The relying party accepts an ID token with no `iat`

`oidcc-client-test-missing-iat` issues an ID token without `iat`; this server completes the sign-in.
OIDC Core §2 makes the claim REQUIRED. [`verifyIdToken.ts:162`](lib/federation/verifyIdToken.ts#L162)
reads

```ts
typeof payload.iat === 'number' && payload.iat > epochTime() + clockTolerance;
```

— so the _value_ is checked and the _presence_ is not, and jose does not require `iat` either unless
`maxTokenAge` is set. The comment above it explains why the future-check has to live there; absence
was simply not the case in view.

**The suite cannot see this, and that is the point.** Every negative client module reported PASSED,
including this one: the suite's OP has no way to observe whether the RP rejected what it sent, so a
human tester is supposed to confirm it did. The runner here supplies that half by recording the HTTP
status this server returned. Seven of the eight negatives answered 400 and aborted the sign-in; this
one answered 303 and finished it. Without that second half the plan reads as fourteen passes.

### 5. The relying party cannot follow an upstream key rotation

`oidcc-client-test-signing-key-rotation` signs in, rotates the OP's signing key, and signs in again.
The second sign-in is refused. [`jwks.ts:37`](lib/federation/jwks.ts#L37) calls
`createRemoteJWKSet(new URL(jwksUri))` with jose's defaults, and two of them decide this:
`cacheMaxAge` is 10 minutes, and the forced reload that rescues a rotation happens **only** on
`JWKSNoMatchingKey` and **only** once `cooldownDuration` — 30 seconds — has elapsed.

Measured directly, same module and same alias, changing nothing but the gap between the two sign-ins:

| Gap  | Second sign-in |
| ---- | -------------- |
| 3 s  | **refused**    |
| 45 s | succeeds       |

So there are two windows in which a rotation locks users out. Inside 30 seconds the reload is on
cooldown. And if the new key carries **no `kid`**, `JWKSNoMatchingKey` never occurs at all, so nothing
triggers a reload until the ten-minute cache expires — the failure then lasts twenty times longer than
the one that is measurable above. That second window is also what made
`oidcc-client-test-kid-absent-single-jwks` look like a defect on the first run, before every module got
its own alias.

## Failures that are not this server

### FAPI 2.0 Message Signing — 13

Run as
`[openid=openid_connect][client_auth_type=private_key_jwt][sender_constrain=dpop][fapi_profile=plain_fapi][authorization_request_type=simple][fapi_request_method=signed_non_repudiation][fapi_response_mode=jarm][grant_management=disabled]`.
64 of 71 modules pass. Two failures are defects 2 and 3 above. The rest:

- 4 are `RequireOnlyBCP195RecommendedCiphersForTLS12`, which tests the nginx terminator standing in
  for TLS in this rig, in `happy-flow` and `ensure-holder-of-key-required`.
- 2 (plus both warnings) are `user-rejects-authentication`, which needs a human to press cancel.
- 1 is `par-ensure-reused-request-uri-prior-to-auth-completion-succeeds`, which refuses to run when
  the browser arrives at the login page already authenticated — a session left by an earlier module,
  and the suite's own precondition rather than a result.
- 1 is `Socket closed` fetching `/jwks`, in `ensure-mismatched-dpop-jkt-fails`. **Unexplained.** The
  proxy's error log is empty for that run and so is the server's; it happened once in 5 693
  conditions. The identically-worded failure that plagued the earlier OIDC runs had a cause (below)
  and that cause is fixed, so this is not it, and nothing else is claimed.

### FAPI 2.0 Security Profile — 9

42 modules pass; the 9 failures are the same three classes: 2 `RequireOnlyBCP195Recommended…`, 3
`user-rejects-authentication`, and 1 exception inside the suite's own Java.

One correction is preserved here because the mistake is instructive. An earlier run reported that
**client assertion audiences are accepted too widely** — three modules push a `client_assertion` whose
`aud` is an array, the PAR endpoint URL, or the token endpoint URL, and each was answered `201` where
FAPI 2.0 requires refusal. Read as an audience-confusion defect, the reasoning was seductive: an
assertion is a bearer credential, so the set of accepted audiences is the set of places a captured one
can be replayed. It was wrong. RFC 9126 §2 anticipated that ambiguity and resolved it the other way —
an authorization server **MUST** accept its issuer identifier, token endpoint URL **or** PAR endpoint
URL as values identifying it, so narrowing that by default would make this server non-conforming. The
narrow rule is FAPI 2.0's alone, it is implemented behind `fapi.enabled`
([`lib/shared/token_jwt_auth.ts`](lib/shared/token_jwt_auth.ts)), held by three cases in
[`test/fapi/fapi2.spec.ts`](test/fapi/fapi2.spec.ts) — and with the flag on, as here, those three
modules pass. **A run in the wrong instance profile does not report a configuration problem; it
reports a security defect that is not there.**

Note that defect 2 above is the _same shape_ in the _other_ direction: an array `aud` in a Request
Object must be accepted, and is not. The two are worth reading together before touching either.

### Dynamic — 11

**Dynamic OP certification is unreachable as the server stands, and for the same reason PKCE is the
default.** The profile requires `response_types_supported` to contain `code`, `id_token` and
`token id_token`, and `grant_types_supported` to contain `implicit`. This server offers `code` and
`none`, and no implicit grant — a deliberate OAuth 2.1 posture, so the profile is inapplicable rather
than unfinished. That is 2 of the 11.

Of the rest: 3 are an exception inside the suite's own Java
(`runInBackground called after runFinalisationTaskInBackground()`); 1 is the key-rotation module the
suite's own `expected-failures-local.json` records as an expected failure; 3 are `request_uri` by
reference (RFC 9101), which this server does not implement and refuses with the registered
`request_uri_not_supported`; and 2 are `SocketTimeoutException: Read timed out` in the scripted
browser, which is HtmlUnit failing to finish a page, not an unanswered request.

The plan is still worth running: it is the only one that exercises dynamic registration.

### The client plans — 3 failures, all the runner's

All three are in `oidcc-client-config-certification-test-plan` and all three are the runner driving a
module more times than the module expects. `idtoken-sig-none` and
`signing-key-rotation-just-before-signing` want one sign-in and got two, so the suite reported
`Found existing client authentication` on the second token exchange; `discovery-openid-config`
concludes as soon as the RP has fetched the discovery document, and the runner carried on to the
authorization endpoint of a finished test. Fixing this means a per-module drive count; nothing about
it reflects on the server.

## What an RP run does and does not prove

`lib/federation/` is a **login broker**, not a general-purpose OpenID client, and three of the plans'
assumptions do not hold against it. This is design, not omission, but it bounds what the result means.

- **It never calls `/userinfo`.** Six of the fourteen Basic modules therefore never conclude — the
  module's script is still waiting for a call that is not coming — and are stopped rather than
  finished. Their conditions are clean and the sign-in completed; `userinfo-invalid-sub` and
  `scope-userinfo-claims` prove nothing at all.
- **It never uses a refresh token**, and does not request `offline_access`. The whole
  `oidcc-client-refreshtoken` plan therefore runs clean without touching its subject: 216 conditions,
  no failures, and three modules that only ever saw two ordinary sign-ins.
- **It only ever runs a code flow**, which is why the hybrid, implicit, session-management and
  front-channel-logout client plans are inapplicable for the same reason their OP twins are.

What it _does_ prove is the verification, and there the result is worth having: `iss`, `aud`, `exp`,
the algorithm allowlist, `alg: none`, a bad signature, a `kid` that is absent with several keys
published, a mismatched `nonce`, a missing `sub`, and a discovery document whose `issuer` disagrees
with the URL it came from — each refused, each correctly. Only `iat` gets through (defect 4).

## Two instance profiles

The OIDC profiles and the FAPI profiles want opposite settings, so one instance cannot serve both:

|                            | OIDC plans | FAPI 2.0 Security | FAPI 2.0 Message Signing |
| -------------------------- | ---------- | ----------------- | ------------------------ |
| `pkce.required`            | `false`    | `true`            | `true`                   |
| `fapi.enabled`             | `false`    | `true`            | `true`                   |
| `requestObjects.enabled`   | `false`    | `false`           | **`true`**               |
| `responseMode.jwt.enabled` | `false`    | `false`           | **`true`**               |

`pkce.required` is on by default, and with it on 34 of the Basic profile's 35 modules are refused
before they test anything — it relaxes the demand only for clients that authenticate at the token
endpoint, which is all a static-client run needs. FAPI mandates PKCE and fails the opposite way.
Message Signing is the Security Profile plus a signed request object (JAR) and a signed authorization
response (JARM), which is the whole of the difference in that column.

The client plans need one setting of their own: **`federation.enabled`**, off by default.

## What else a conformance target has to be configured with

A run against a default instance fails for reasons that are settings, and **each one reads in the test
log exactly like a server defect**. That is the trap this section exists for. The last two entries
were each mistaken for a defect during this round before being traced back to the seed.

- **`rateLimit.enabled: false`.** The loudest one. The suite drives several hundred `/auth` and
  `/token` requests from one address within a minute, far over `rateLimit.strict.max` (60 per 60s).
  The refusal arrives as `temporarily_unavailable` on an HTML page, three consecutive modules are
  interrupted, and the runner aborts the whole plan reporting that the _server under test_ is
  unhealthy. Nothing in that chain names the rate limiter.
- **Claim-defined scopes** — `profile`, `email`, `address`, `phone` and their claims, or the five
  `oidcc-scope-*` modules fail. The shipped default declares `openid` and `offline_access` only.
- **`claimsParameter.enabled` and `requestObjects.enabled`.** Off by default; with them off the
  `claims` parameter and by-value request objects are refused, and three modules fail.
- **An end-user account** in the bucket the client resolves to (`redfox` for a client belonging to no
  project), with profile, email, address and phone claims populated.
- **Two or three static clients.** The profile certifies both `client_secret_basic` and
  `client_secret_post`, and a static-client run needs a separate client for the second: the suite
  reads it from a `client_secret_post` block of its own. FAPI modules also append
  `?dummy1=lorem&dummy2=ipsum` to the redirect URI to prove the match is exact, so that variant has to
  be registered too.
- **`post_logout_redirect_uris` on the client**, for the logout plan — and spelled in _that_ case.
  Worth a warning of its own, because it cost three runs to find. A stored client record is part
  camelCase and part wire-format: only the keys in `BASE_METADATA_KEYS`
  ([`lib/models/client/validate.ts`](lib/models/client/validate.ts)) survive as camelCase, and
  `redirectUris` is one of them while `postLogoutRedirectUris` is not. Seed the latter in camelCase and
  validation **drops it silently** — no error, no warning, and the validated client reports an empty
  list. What surfaces is `400 post_logout_redirect_uri not registered` at logout, which reads as a
  server defect and is not one. `lib/admin/clients/service.ts` gets this right, so the console and DCR
  are unaffected; only hand-written seed data falls into it.
- **`scope` in the suite's own client configuration**, for every FAPI plan. The suite omits the
  parameter entirely when its config names none, a FAPI request always carries `nonce`, and this
  server refuses `nonce` without `openid` ([`check_openid_scope.ts`](lib/actions/authorization/check_openid_scope.ts)).
  The result is `400 openid scope must be requested when using the nonce parameter` on the first PAR
  push of every module — indistinguishable, in the log, from defect 1.
- **`require_signed_request_object: true` on the client**, for Message Signing. Without it
  `ensure-unsigned-request-at-par-endpoint-fails` fails, because an unsigned push is accepted with
  `201` and there is then no error for the authorization endpoint to return. It is a per-client
  registration and not a mode of the server, so `fapi.enabled` does not imply it.

## Running the OP plans

The suite runs locally from `docker-compose-prebuilt.yml` (prebuilt images, no Maven build) plus an
overlay adding an nginx TLS terminator the suite reaches as `https://oidcc-provider:3000`. The
terminator is not optional: the end-user cookies are written `secure: true` unconditionally, so a
plain-HTTP origin has the suite's browser drop them and every login fails for a reason that is not a
conformance defect.

Three properties of the rig cost a run each, and none of them announces itself:

- **Pin the proxy's upstream to IPv4.** Docker Desktop gives `host.docker.internal` both an A and an
  AAAA record; nginx alternates between them and every IPv6 attempt dies with `ENETUNREACH`. What the
  suite reports is `Socket closed` on a random endpoint, and `curl` never reproduces it because curl
  falls back to IPv4. One run carried **34** such upstream failures, six of which survived retries to
  become reported failures — and they were written off as unexplained flakiness for six runs before
  the proxy's own error log was read. Resolve the v4 address at container start and bake it in.
- **Run plans one at a time.** `run-test-plan.py` accepts several plan/config pairs and runs the
  _plans_ concurrently. Every plan here shares one alias, so a single invocation with seven pairs has
  them fight over it and die in seconds, reporting failures that are pure contention.
- **Trust the suite's certificate, or nothing the server _sends_ can be tested.** The local suite is
  self-signed, so every outbound call from this server to it fails verification. That silently
  swallowed back-channel logout and made `sector_identifier_uri` look like an SSRF refusal.

## Running the client plans

`run-test-plan.py` cannot drive these: it knows how to run the suite's own sample RP, or a nested OP
plan, and neither is `lib/federation/`. Each module has to be driven by replaying a federated sign-in
through the deployment — start an authorization at `/auth`, follow it to `/ui/:uid/login`, hit
`/ui/:uid/federation/:providerId/start`, follow that to the suite, and bring the callback back. Four
things about that are not obvious.

- **The driver has to run inside the suite's docker network.** The interaction cookie is written
  `secure`, so the flow only works over the TLS terminator, and `oidcc-provider:3000` resolves
  nowhere else. `docker exec` into the suite's own container, with `curl --resolve` for the suite's
  hostname, is enough — it needs a cookie jar and nothing more.
- **Give every module its own alias.** The suite mints a fresh signing key per module but serves the
  whole plan from one `jwks_uri`, while this RP caches discovery per issuer for ten minutes and holds
  one jose key set per `jwks_uri`. Behind a shared alias, module N verifies its token against module
  1's key. `kid-absent-single-jwks` failed for exactly that reason and for no other — it passes
  against a cold cache. Repoint the bucket's provider at the new issuer before each module.
- **Stop each module before creating the next.** A client test concludes on its own only once the RP
  has done everything its script expects, and this one never calls `/userinfo`. Creating the next
  module while one is still `WAITING` makes the suite kill the earlier one for an alias conflict,
  which reports `INTERRUPTED` and discards the verdict. `DELETE /api/runner/{id}` ends it cleanly.
- **Read the conditions, not the module status.** A stopped module has no `result`, and — far more
  importantly — a _finished_ one reports `PASSED` on every negative test whether or not the RP
  rejected anything (defect 4). The verdict worth recording is the failed-condition list from
  `/api/log/{id}`, paired with the HTTP status the RP itself returned.

The rig also needs an account in the target bucket already **linked** to the suite's subject
(`user-subject-1234531`): the suite's OP issues no `email` claim, and without an existing federated
identity the sign-in stops at "your identity provider sent no email address" before any of the
interesting checks run.

## Screenshots

Several modules per plan end in `REVIEW` because they need a screenshot of a page the server rendered
— the second login page for `prompt=login` and `max_age=1`, and the error pages for a missing
`response_type` and an unregistered `redirect_uri`.

An automated run cannot produce these. The suite's scripted browser is HtmlUnit, which does not render,
so `update-image-placeholder` stores the page's HTML source rather than an image and
`/api/log/{id}/images` stays empty. **Certification requires real screenshots taken in a real browser
and uploaded by hand**, so those modules must be walked through manually once, whatever else is
automated.

One of them captures nothing at all, and correctly: for a missing `response_type` this server returns
the error by redirecting to the registered `redirect_uri` rather than rendering a page, and the module
accepts either branch.

## Scope

Every applicable OP plan has been run, and the client family is now open rather than untouched.

Still to run, in the order they are worth it: **FAPI 2.0 Message Signing again once defects 1–3 are
fixed** (the plan has never completed without a local patch); the remaining client plans that a login
broker can satisfy; **FAPI-CIBA ID1**, which needs only `ciba.enabled` and the `poll` delivery mode;
and **FAPI 1.0 Advanced**, which is the expensive one — the profile requires certificate-bound access
tokens, so the rig needs client certificates plumbed through the nginx terminator, and the `jarm`
response-mode variant is what makes it reachable at all without `code id_token`.

Inapplicable by design, not unfinished: Hybrid, Implicit and their form_post variants, because
`response_types_supported` is `code` and `none`; Dynamic, for the reason above; Session Management and
Frontchannel Logout, because there is no `check_session_iframe` and no front-channel logout; and their
client-side twins, because the RP runs a code flow only. Not implemented at all, so not applicable:
OID4VCI and OID4VP, the Shared Signals plans, AuthZEN, eKYC/IDA, OpenID Federation 1.0 (which is a
different thing from `lib/federation/`), and every `*-brazil-*` variant, which needs that directory.

Everything here ran against a local instance rather than the deployed `conformance.foxauth.dev`. One
consequence is worth carrying forward: the end-user cookies are written `sameSite: 'strict'`
([`lib/consts/param_list.ts`](lib/consts/param_list.ts)), HtmlUnit does not enforce SameSite, and a real
browser will not send `_session` on a cross-site navigation from the suite to `/auth`. Whether that
breaks `prompt=none` against an established session is untested, and should be checked before any run
meant to count.
