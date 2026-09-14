# Conformance

What the [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite) says
about this server, and what it takes to get an answer.

`SECURITY.md` says the suite has never been run against a release. This file is the evidence that
replaces that sentence: the current result, what the remaining failures actually are, and the setup a
run needs — because most of the cost of a conformance run is not the run.

## Where it stands

Measured 2026-09-14 against an **unmodified working tree**, across two instance profiles (below).

| Plan                                                            | Conditions | Failures                                 |
| --------------------------------------------------------------- | ---------- | ---------------------------------------- |
| `oidcc-config-certification-test-plan`                          | 41         | **none**                                 |
| `oidcc-basic-certification-test-plan`                           | 1 855      | **none**, and no warnings                |
| `oidcc-formpost-basic-certification-test-plan`                  | 2 007      | **none**, and no warnings                |
| `oidcc-rp-initiated-logout-certification-test-plan`             | 551        | **none**                                 |
| `oidcc-backchannel-rp-initiated-logout-certification-test-plan` | 101        | **none**                                 |
| `oidcc-3rdparty-init-login-certification-test-plan`             | 50         | **none**                                 |
| `oidcc-dynamic-certification-test-plan`                         | 883        | 11, none of them this server — see below |
| `fapi2-security-profile-final-test-plan`                        | 4 343      | 9, none of them this server — see below  |

**9 831 conditions, and no failure left that is a defect in this server.** Six plans run clean
outright; the other two fail only on things that are the profile, the suite, or the test rig, each
enumerated below so the claim can be checked rather than taken.

Twelve defects the suite found have been fixed: `830713b` (PAR content type), `1437341` (unknown
request parameters, widened from the one endpoint reported to six), `6cdb9ec` (`code_verifier`
alphabet), `848c179` (schema refusals answer 400, not 422), `dcc4c08` and `3589d48` (`/userinfo`
challenge and POST body), `0353f4b` (form_post reaches a module-less browser; PAR names its own error
code), `b891075` (key generation for any asymmetric signing algorithm), `87d44e8` (`pkce.required`),
`a99c81a` (`acr`, which also closed an interaction loop an essential `acr` claim could not escape),
`2b83c91` (unknown members inside `claims` are ignored; a pushed request is spent after a login, not
only when no login was needed). The detail is in those commits.

## The two remaining plans, failure by failure

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

### FAPI 2.0 — 9

Run as
`[openid=openid_connect][client_auth_type=private_key_jwt][sender_constrain=dpop][fapi_profile=plain_fapi]`
against two purpose-seeded clients holding ES256 keys, in the FAPI instance profile. 42 modules pass,
9 await a screenshot.

All 9 failures are outside the server: 2 are `RequireOnlyBCP195RecommendedCiphersForTLS12`, which
tests the nginx terminator standing in for TLS in this rig; 3 (two failures and a warning) are
`user-rejects-authentication`, which requires a human to press cancel and cannot be satisfied by a
scripted browser that grants consent; and 1 is another exception inside the suite's Java.

**This is the profile worth pursuing**, because FAPI 2.0 requires PKCE, requires PAR and requires
sender-constrained tokens — the three things this server does by default and that make the OIDC Basic
profile awkward for it.

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

## Two instance profiles

The OIDC profiles and FAPI 2.0 want opposite settings, so one instance cannot serve both:

|                 | OIDC plans | FAPI 2.0 |
| --------------- | ---------- | -------- |
| `pkce.required` | `false`    | `true`   |
| `fapi.enabled`  | `false`    | `true`   |

`pkce.required` is on by default, and with it on 34 of the Basic profile's 35 modules are refused
before they test anything — it relaxes the demand only for clients that authenticate at the token
endpoint, which is all a static-client run needs. FAPI 2.0 mandates PKCE and fails the opposite way.

## What else a conformance target has to be configured with

A run against a default instance fails for reasons that are settings, and **each one reads in the test
log exactly like a server defect**. That is the trap this section exists for.

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

## Running it

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

Every applicable OP plan has been run. The rest of the FAPI family — FAPI 1.0 Advanced, FAPI 2.0
Message Signing and FAPI-CIBA — builds on the FAPI 2.0 result above and is the natural next step.

Inapplicable by design, not unfinished: Hybrid, Implicit and their form_post variants, because
`response_types_supported` is `code` and `none`; Dynamic, for the reason above; Session Management and
Frontchannel Logout, because there is no `check_session_iframe` and no front-channel logout.

Untouched so far: the suite's 32 **client** plans. They apply — `lib/federation/` makes this server a
relying party that fetches an upstream's discovery document, runs a code flow with PKCE and verifies
somebody else's ID token, and no run on this page reaches that code.

Everything here ran against a local instance rather than the deployed `conformance.foxauth.dev`. One
consequence is worth carrying forward: the end-user cookies are written `sameSite: 'strict'`
([`lib/consts/param_list.ts`](lib/consts/param_list.ts)), HtmlUnit does not enforce SameSite, and a real
browser will not send `_session` on a cross-site navigation from the suite to `/auth`. Whether that
breaks `prompt=none` against an established session is untested, and should be checked before any run
meant to count.
