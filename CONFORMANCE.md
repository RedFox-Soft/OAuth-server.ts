# Conformance

What the [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite) says
about this server, and what it takes to get an answer.

`SECURITY.md` says the suite has never been run against a release. This file is the evidence that
replaces that sentence: the current result, what still fails, and the setup a run needs — because
most of the cost of a conformance run is not the run.

## Where it stands

Measured 2026-09-14 against an **unmodified working tree**. Earlier runs needed patched source; none
do now.

| Plan                                                            | Conditions | Failures                         |
| --------------------------------------------------------------- | ---------- | -------------------------------- |
| `oidcc-config-certification-test-plan`                          | 41         | **none**                         |
| `oidcc-basic-certification-test-plan`                           | 1 831      | **none** — 31 passed, 4 review   |
| `oidcc-formpost-basic-certification-test-plan`                  | 2 007      | **none**, and no warnings        |
| `oidcc-rp-initiated-logout-certification-test-plan`             | 551        | **none**                         |
| `oidcc-backchannel-rp-initiated-logout-certification-test-plan` | 101        | **none**                         |
| `oidcc-3rdparty-init-login-certification-test-plan`             | 50         | **none**                         |
| `oidcc-dynamic-certification-test-plan`                         | 915        | 9, none a defect — see _Dynamic_ |
| `fapi2-security-profile-final-test-plan`                        | 4 239      | 18 — see _FAPI 2.0_              |

Seven of the eight run clean. "Review" is not a failure: those modules need a person to look at a
screenshot of a page the server rendered — see _Screenshots_.

Ten defects the suite found have been fixed: `830713b` (PAR content type), `1437341` (unknown request
parameters, widened from the one endpoint reported to six), `6cdb9ec` (`code_verifier` alphabet),
`848c179` (schema refusals answer 400, not 422), `dcc4c08` and `3589d48` (`/userinfo` challenge and
POST body), `0353f4b` (form_post reaches a module-less browser; PAR names its own error code),
`b891075` (key generation for any asymmetric signing algorithm), `87d44e8` (`pkce.required`),
`a99c81a` (`acr`). The detail is in those commits; what is left is below.

## What still fails

### An unknown member inside the `claims` object is refused, not ignored

> **Fixed, not yet re-measured.** The schema no longer closes the object and `checkClaims` deletes the
> members the server does not define, held by cases in [`test/claims/`](test/claims/) including a
> completeness case over every surface that accepts `claims`. The suite has not been re-run since, so
> the module below is not yet recorded as passing. What follows describes the defect as the run found
> it.

The same defect class as the request-parameter one fixed in `1437341`, one level deeper. `claims` is
declared `additionalProperties: false` in [`lib/consts/param_list.ts`](lib/consts/param_list.ts), so a
value carrying `id_token`, `userinfo` **and** a third member the server does not recognise is refused
outright — where OpenID Connect Core §5.5 says other members MAY be present and ones that are not
understood MUST be ignored. The refusal also misreports itself: it says the parameter "should be
object with userinfo or id_token properties" when both are present.

_Module: `fapi2-security-profile-final-test-claims-parameter-identity-claims`._

### One-time use of a `request_uri` holds on one path and not the other

> **Fixed, not yet re-measured.** The four payload reads described below are corrected, and
> [`test/pushed_authorization_requests/reuse.spec.ts`](test/pushed_authorization_requests/reuse.spec.ts)
> holds the invariant across no interaction, one, and two — the last being the case that fails if only
> `respond.ts` is repaired. The three weak `toHaveProperty('consumed')` assertions now assert the
> record is actually spent. The suite has not been re-run since. What follows describes the defect as
> measured against the unfixed tree.

`par-attempt-reuse-request_uri` expects a second authorization request carrying an already-used
`request_uri` to be refused; it is not. The suite grades this at SHOULD, so it reports a warning
rather than a failure.

**The feature is not missing, and saying it is would send the next reader looking for the wrong
thing.** One-time use is implemented, and implemented where it belongs:
[`respond.ts`](lib/actions/authorization/respond.ts) consumes the pushed request at the point an
authorization response is actually produced — not when the `request_uri` is first read — so a flow
that redirects to a login page does not burn the request the user has not finished using. It even
carries a second lookup for exactly that case: when the response is produced after an interaction the
pushed request is no longer in the request context, so it is re-found through the interaction's
`parJti`.

That second lookup is the part that does not hold. `Interaction` stores `parJti` in its payload and
exposes no accessor for it ([`lib/models/interaction.ts`](lib/models/interaction.ts) declares `uid`
and nothing else), so `oidc.entities.Interaction?.parJti` reads `undefined`, the fallback never
fires, and `consume()` is never reached. The same expression appears a second time in
[`interactions.ts`](lib/actions/authorization/interactions.ts), where a fresh interaction inherits
`parJti` from the previous one — so a login-then-consent chain loses the link at the first hand-off
as well. Both are the defect class of `Interaction.persist()`, whose guard reads `this.exp` where the
value is `this.payload.exp`: a payload field read as a top-level property, silently `undefined`,
failing open.

Measured against an unmodified tree:

| Step                                           | Result                                |
| ---------------------------------------------- | ------------------------------------- |
| One full authorization, through the login page | code issued; stored `consumed: false` |
| The same `request_uri` a second time           | a second code issued                  |
| A third time                                   | refused                               |

The third row is what identifies the branch. By the second attempt the user has a session and a
grant, so no interaction is needed, `respond` runs inside the original request with the pushed
request still in context, the working path is taken and the record is finally marked. **The mark is
set only when the authorization needed no interaction.** Since a first sign-in always needs one, the
practical shape is that a `request_uri` survives its own flow and stays good for one more
authorization — bounded by the 60-second lifetime a pushed request is given, and by whether the next
attempt is interactive too: one that also prompts leaves the record unmarked again.

**This is the attack RFC 9126 §7.3 is about**, and it is not what §4's exception covers. §7.3 —
_Request Object Replay_ — says an attacker could replay a request URI captured from a legitimate
authorization request, and that the server SHOULD make request URIs one-time use; it carries no
exception. §4 does carry one, permitting duplicates "due to a user reloading/refreshing their user
agent", but the second use here is not a reload of a finished page: it is a fresh authorization
request that mints a second authorization code. Nothing about it is idempotent.

Both clauses are SHOULD, so this is not a conformance failure and the suite is right to warn rather
than fail. It is worth fixing on its own terms — a server that adopted the SHOULD, built the
mechanism for it and then let one branch fail open is in a worse position than one that never claimed
it, because the gap is invisible to everything except the path nobody tested. Which is the other half
of the finding: the three existing assertions in
[`test/pushed_authorization_requests/`](test/pushed_authorization_requests/) check consumption with
`toHaveProperty('consumed')`, which passes on the `consumed: false` the constructor defaults, and all
three seed a session and a grant first — so the suite only ever exercised the path that works.

### FAPI 2.0 has not yet been measured as a FAPI deployment

Not a defect — an unfinished measurement, and the reason the FAPI 2.0 row above is worth less than its
size suggests. See below.

## Dynamic

**Dynamic OP certification is unreachable as the server stands, and for the same reason PKCE is the
default.** The profile requires `response_types_supported` to contain `code`, `id_token` and
`token id_token`, and `grant_types_supported` to contain `implicit`. This server offers `code` and
`none`, and no implicit grant. That is a deliberate OAuth 2.1 posture, so the profile is inapplicable
rather than unfinished.

Its nine failures decompose completely and leave nothing to fix: two are the profile's demand for
`implicit` and hybrid response types; three are an exception inside the suite's own Java
(`runInBackground called after runFinalisationTaskInBackground()`); one is the key-rotation module the
suite's own `expected-failures-local.json` records as an expected failure; and three are `request_uri`
by reference (RFC 9101), which this server does not implement and refuses with the registered
`request_uri_not_supported`.

The run is still worth having, because it is the only plan that exercises dynamic registration.

## FAPI 2.0

Run as
`[openid=openid_connect][client_auth_type=private_key_jwt][sender_constrain=dpop][fapi_profile=plain_fapi]`
against two purpose-seeded clients holding ES256 keys.

**This is the profile worth pursuing**, because FAPI 2.0 requires PKCE, requires PAR and requires
sender-constrained tokens — the three things this server does by default and that make the OIDC Basic
profile awkward for it.

**The measurement is incomplete, and knowing why matters more than the number.** The run had
`par.enabled`, `dpop.enabled` and `responseMode.jwt.enabled` on, but **not `fapi.enabled`** — so it
measured a general-purpose OAuth server driven by a FAPI plan. That produced one confident finding
that was simply wrong, and the shape of the mistake is worth keeping:

> Three modules push a `client_assertion` whose `aud` is an array, the PAR endpoint URL, or the token
> endpoint URL. FAPI 2.0 requires each to be refused; each was answered `201`. Read as a defect — an
> assertion is a bearer credential, so the set of accepted audiences is the set of places a captured
> one can be replayed — it looked like audience confusion.

It is the opposite. RFC 9126 §2 anticipated that ambiguity and resolved it the other way: an
authorization server **MUST** accept its issuer identifier, token endpoint URL **or** PAR endpoint URL
as values identifying it. Narrowing that by default would make this server non-conforming. The narrow
rule is FAPI 2.0's alone, it **is** implemented behind `fapi.enabled`
([`lib/shared/token_jwt_auth.ts`](lib/shared/token_jwt_auth.ts)), and three cases in
[`test/fapi/fapi2.spec.ts`](test/fapi/fapi2.spec.ts) hold it — array audience, PAR endpoint URL and
token endpoint URL, each answered `401 invalid_client`, all passing against unmodified code.

A second module, `par-ensure-pkce-required`, fails for the mirror-image reason: the instance is
configured `pkce.required: false` so the OIDC profiles can run at all, while FAPI 2.0 mandates PKCE.

**So FAPI 2.0 needs its own instance state** — `fapi.enabled` on and `pkce.required` left at its
default — and re-running it that way is the next thing worth doing here. The remaining failures are
not this server: the BCP195 cipher check tests the nginx terminator standing in for TLS, one module
needs a human to press cancel, and one aborts inside the suite's own Java.

## What a conformance target has to be configured with

A run against a default instance fails for reasons that are settings, and **each one reads in the test
log exactly like a server defect**. That is the trap this section exists for. The deployment needs all
of:

- **`pkce.required: false`** — for the OIDC profiles only. On by default, and with it on 34 of the
  Basic profile's 35 modules are refused before they test anything. It relaxes the demand for clients
  that authenticate at the token endpoint, which is all a static-client run needs. FAPI 2.0 wants the
  opposite; give it a separate instance state.
- **`fapi.enabled`, for the FAPI 2.0 plan.** Off by default, and with it off three modules measure a
  general-purpose server behaving correctly and report it as an audience-confusion defect. Nothing in
  the output names the switch. This one already cost this file a wrong finding.
- **`rateLimit.enabled: false`.** The loudest trap. The suite drives several hundred `/auth` and
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
  `client_secret_post`, and a static-client run needs a separate client for the second: the suite reads
  it from a `client_secret_post` block of its own. FAPI modules also append
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
  become reported failures — and they were written off as unexplained flakiness for six runs before the
  proxy's own error log was read. Resolve the v4 address at container start and bake it in.
- **Run plans one at a time.** `run-test-plan.py` accepts several plan/config pairs and runs the
  _plans_ concurrently. Every plan here shares one alias, so a single invocation with seven pairs has
  them fight over it and die in seconds, reporting failures that are pure contention.
- **Trust the suite's certificate, or nothing the server _sends_ can be tested.** The local suite is
  self-signed, so every outbound call from this server to it fails verification. That silently
  swallowed back-channel logout and made `sector_identifier_uri` look like an SSRF refusal.

## Screenshots

Three or four modules per plan end in `REVIEW` because they need a screenshot of a page the server
rendered — the second login page for `prompt=login` and `max_age=1`, and the error pages for a missing
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

Every applicable OP plan has been attempted except the rest of the FAPI family — FAPI 1.0 Advanced,
FAPI 2.0 Message Signing and FAPI-CIBA — which build on the FAPI 2.0 result above and are worth running
once it has been measured with `fapi.enabled`.

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
