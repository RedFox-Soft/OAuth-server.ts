# Conformance

What the [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite) says
about this server, and what it took to get an answer.

`SECURITY.md` states that the suite has never been run against a release. This file is the record of
the first run, so that claim can be replaced by evidence rather than by assertion.

## Runs of 2026-09-11

The suite was `registry.gitlab.com/openid/conformance-suite:latest`, run locally in Docker against a
local instance on the in-repo code, fronted by a TLS terminator so the suite reached it as
`https://oidcc-provider:3000`. Eight plans were run — every OP plan the suite publishes that this
server can be configured to attempt.

**Current state — every plan re-run after the fixes of 2026-09-11:**

| Plan                                                            | Conditions | Failures                                 |
| --------------------------------------------------------------- | ---------- | ---------------------------------------- |
| `oidcc-config-certification-test-plan`                          | 41         | **none**                                 |
| `oidcc-basic-certification-test-plan`                           | 1 850      | **none** (2 SHOULD-level warnings)       |
| `oidcc-formpost-basic-certification-test-plan`                  | 2 002      | **none** (2 SHOULD-level warnings)       |
| `oidcc-rp-initiated-logout-certification-test-plan`             | 551        | **none**                                 |
| `oidcc-backchannel-rp-initiated-logout-certification-test-plan` | 101        | **none**                                 |
| `oidcc-3rdparty-init-login-certification-test-plan`             | 50         | **none**                                 |
| `oidcc-dynamic-certification-test-plan`                         | 915        | 9, none of them a defect — see _Dynamic_ |
| `fapi2-security-profile-final-test-plan`                        | 4 280      | 18 — see _FAPI 2.0_                      |

Six of the eight plans now run clean. The two that do not are the two the server is not shaped for:
Dynamic, which the profile makes unreachable, and FAPI 2.0, which is the profile worth pursuing.

The Dynamic failures decompose completely and leave nothing to fix: two are the profile requiring
`implicit` and hybrid response types, three are an exception inside the suite's own Java, one is the
key-rotation module the suite's own CI records as an expected failure, and three are `request_uri`
by reference (RFC 9101), which this server does not implement and refuses with the registered
`request_uri_not_supported`.

The auto-submit change Form Post needed in order to run at all is now committed — see that finding
below.

**The original run, before any of it was fixed:**

| Plan                                                            | Result                                                                                     |
| --------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `oidcc-config-certification-test-plan`                          | **passed** — 35 conditions, no failures, no warnings                                       |
| `oidcc-rp-initiated-logout-certification-test-plan`             | **passed** — 547 conditions, no failures, no warnings (8 of 11 modules await a screenshot) |
| `oidcc-basic-certification-test-plan`                           | 27 passed, 4 review, 2 warning, **2 failed**, of 35                                        |
| `oidcc-formpost-basic-certification-test-plan`                  | 28 passed, 3 review, 2 warning, 2 skipped, **2 failed**, of 35                             |
| `oidcc-dynamic-certification-test-plan`                         | 816 conditions, **18 failed, 18 warnings**, of 23 modules — see _Dynamic_ below            |
| `oidcc-backchannel-rp-initiated-logout-certification-test-plan` | **passed** — 101 conditions, no failures, no warnings                                      |
| `oidcc-3rdparty-init-login-certification-test-plan`             | **passed** — 50 conditions, no failures, no warnings                                       |
| `fapi2-security-profile-final-test-plan`                        | 5 passed, 2 warning, **45 failed or interrupted**, of 52 run — see _FAPI 2.0_ below        |

Basic and Form Post ran with `server_metadata=discovery`, `client_registration=static_client`,
`response_type=code` and `client_auth_type=client_secret_basic` (plus one module on
`client_secret_post`). The Config plan checks only the discovery document and needed no conditions
relaxed — it passed against unmodified code.

Form Post failed on the same two defects as Basic and found no third: once its auto-submit page works
at all (see below), `form_post` is not a weaker path than `query`.

These are not certifications. They are local, unofficial runs whose value is the list below.

**Three conditions made those numbers honest at the time, and one of them has since become a property
of the release.** PKCE enforcement was disabled by a local patch that was not committed — see the
first finding for why nothing else could be measured otherwise. Form Post additionally needed the
auto-submit page's script moved, which was likewise uncommitted then and is committed now. And two
features off by default were turned on
(`claimsParameter.enabled`, `requestObjects.enabled`); with them off, three further modules fail for
a reason that is configuration rather than defect.

"Review" is not a failure. Those modules require a person to look at a screenshot of a page the
server rendered; the server behaved correctly in each. See _Screenshots_ below.

## What the runs found

### Mandatory PKCE makes the Basic profile unreachable

`authorizationPKCE` ([`lib/helpers/pkce.ts`](lib/helpers/pkce.ts)) is called unconditionally from
both authorization paths, and there is no setting for it in `ApplicationConfig` or in the admin
settings catalog. The Basic certification profile sends PKCE in exactly one of its 35 modules, so
against an unmodified build every other module is refused with `invalid_request` before it can test
anything.

This is a collision between an OAuth 2.1 position and an OpenID Connect profile, not a bug. Resolving
it is a product decision: certification for Basic OP requires a switch that makes PKCE optional.

### The authorization endpoint rejects unrecognized parameters

**Fixed in `1437341`**, and widened there from this one endpoint to six.

`AuthorizationParameters` ([`lib/consts/param_list.ts`](lib/consts/param_list.ts)) is a closed
TypeBox object, so an unknown query parameter is refused with
`invalid_request` / `Property '<name>' should not be provided`.

OpenID Connect Core §3.1.2.1 requires an OP to **ignore** request parameters it does not understand.
Any client that adds a parameter of its own to an authorization request is refused today.

_Module: `oidcc-ensure-request-with-unknown-parameter-succeeds`._

### `code_verifier` is validated against the wrong alphabet

**Fixed in `6cdb9ec`.**

The token endpoint's schema ([`lib/actions/grants/index.ts`](lib/actions/grants/index.ts)) requires
`^[A-Za-z0-9_-]{43,128}$` — the base64url alphabet. RFC 7636 §4.1 defines `code_verifier` over
`unreserved`, which also admits `.` and `~`. A conforming client whose verifier contains either
character is refused at the code exchange with `invalid_request`.

_Module: `oidcc-ensure-request-with-valid-pkce-succeeds`._

### The form_post auto-submit page needs a browser that runs ES modules

**Fixed.** The script is now a classic `<script>` at the end of `<body>`, after the form.

[`lib/html/formPost.tsx`](lib/html/formPost.tsx) returned a page whose only way forward was
`<script type="module">document.forms[0].submit();</script>` in `<head>`. The `module` type is
load-bearing there and not decoration: a module script is deferred, so it runs after the form has
been parsed. A plain `<script>` in the same position runs too early and fails with
`TypeError: Cannot call method "submit" of undefined`.

The fallback beside it — a "Continue" button — is inside `<noscript>`, so it only appears when
scripting is off entirely. That leaves one browser class with no path at all: **scripting enabled,
ES modules unsupported**. The conformance suite's scripted browser (HtmlUnit) is exactly that, and so
are some embedded webviews. The whole Form Post plan hangs on its first module, every test after it
aborts on an alias conflict, and nothing in the output names the cause.

Moving the classic script to the end of `<body>`, after the form, fixes it: with that one change the
plan ran to completion with the results in the table above — 2 002 conditions, no failures. `defer`
is not an alternative, whatever the first reading of this suggests: `defer` is ignored on an inline
script, so deferring one means `type="module"`, which is the defect.

That run was the change applied as a local patch. The change itself is now in the tree, and three
cases in [`test/form_post/`](test/form_post/form_post.spec.ts) hold it — one per browser class, plus
a count that refuses a second auto-submit script, since keeping the module beside a classic one would
post the response twice.

### `not_supported` is not a registered error code

**Fixed**: the Dynamic re-run now sees the registered `request_uri_not_supported`.

`NotSupportedError` ([`lib/helpers/errors.ts`](lib/helpers/errors.ts)) carries the code
`not_supported`, and [`lib/actions/authorization/featureVerification.ts`](lib/actions/authorization/featureVerification.ts)
raises it for six different refusals — claims parameter, resource indicators, RAR, DPoP thumbprint,
request object, request URI. No such code exists in the OAuth error registry.

The registered codes `request_not_supported` and `request_uri_not_supported` are already declared in
`lib/helpers/errors.ts` and are never used. The run did not fail on this only because the two
relevant features were switched on; every deployment running the defaults emits an unregistered
error code to real clients.

### Two SHOULD-level gaps

`/userinfo` does not accept the access token in a form-encoded POST body, which OpenID Connect Core
§5.3.1 describes alongside the header form. The header form works.
_Module: `oidcc-userinfo-post-body` (warning)._

No `acr` claim is returned when a request carries `acr_values`. This looks like a consequence of
`acrValues: []` in [`lib/configs/application.ts`](lib/configs/application.ts) — configuration rather
than code — but that has not been confirmed by a run with a value set.
_Module: `oidcc-ensure-request-with-acr-values-succeeds` (warning)._

## Dynamic

`oidcc-dynamic-certification-test-plan` was run with `registration.enabled`, which is what puts a
`registration_endpoint` in the discovery document. Its headline result is the same shape as Hybrid and
Implicit, and should be recorded before the detail:

**Dynamic OP certification is unreachable as the server stands, and for the same reason PKCE is
mandatory.** The profile requires `response_types_supported` to contain `code`, `id_token` and
`token id_token`, and `grant_types_supported` to contain `implicit`
(`OIDCCCheckDiscEndpointResponseTypesSupportedDynamic`,
`OIDCCCheckDiscEndpointGrantTypesSupportedDynamic`). This server offers `code` and `none`, and no
implicit grant. That is a deliberate OAuth 2.1 posture, so the profile is inapplicable rather than
unfinished.

The run is still worth having, because it is the only one that exercises dynamic registration, and
that surfaced things the other plans cannot reach:

- **A client may register `userinfo_signed_response_alg` and be ignored.** Registration is accepted
  with `RS256`, and `/userinfo` then answers `application/json` rather than `application/jwt`
  (`EnsureContentTypeApplicationJwt`, `ValidateUserInfoResponseSignature`,
  `ExtractSignedUserInfoFromUserInfoEndpointResponse`). Signed userinfo is behind
  `jwtUserinfo.enabled`, so the setting explains the behaviour — but accepting a registration value
  the server will not honour, rather than refusing it, is the part worth fixing.
- **Every module warns on client cleanup.** `UnregisterDynamicallyRegisteredClient` failed in 16 of
  23 modules: the RP cannot delete the client it registered, because `registrationManagement.enabled`
  is off and there is no usable `registration_client_uri`. Left as-is, a deployment with DCR on and
  registration management off accumulates clients nobody can remove through the protocol.
- **`sector_identifier_uri` cannot be validated against a local suite.** Registration was refused with
  `invalid_client_metadata` / "could not load sector_identifier_uri response". The cause is the
  local suite's **self-signed certificate**: every outbound HTTPS call from this server to
  `localhost.emobix.co.uk:8443` fails verification (`SEC_E_UNTRUSTED_ROOT`). The same cause silently
  swallowed back-channel logout until the run was repeated with TLS verification relaxed, after
  which that plan passed cleanly. Not a defect — but a local conformance target has to trust the
  suite's certificate or nothing the server _sends_ can be tested.
- **Refresh after an RP key rotation returns 401.** `oidcc-refresh-token-rp-key-rotation` rotates the
  client's own keys and then authenticates with `private_key_jwt`; the token endpoint answered 401.
  This is the one Dynamic finding that looks like a genuine defect — a client keystore that is not
  re-fetched after the RP publishes new keys at its `jwks_uri` — and it has not been confirmed
  outside the suite yet.

Three modules failed on a Java exception inside the suite itself
(`runInBackground called after runFinalisationTaskInBackground()`), and `oidcc-server-rotate-keys`
fails for the reason the suite's own CI records in `expected-failures-local.json` — neither says
anything about this server. Two more failures are `request_uri_parameter_supported` being false,
which is `par.enabled` rather than a gap.

## FAPI 2.0

`fapi2-security-profile-final-test-plan` was run as
`[openid=openid_connect][client_auth_type=private_key_jwt][sender_constrain=dpop][fapi_profile=plain_fapi]`,
against two purpose-seeded clients holding ES256 keys, with `par.enabled`, `dpop.enabled` and
`responseMode.jwt.enabled` on. 52 of 56 modules ran before the run was stopped.

**`fapi.enabled` was not among them, and it should have been.** Every number in this section is
therefore a measurement of a general-purpose OAuth server driven by a FAPI plan, not of a FAPI
deployment. It changes one finding materially — see the client assertion audience below — and the
settings list at the end of this file now names the switch.

This is the profile worth caring about most, because **FAPI 2.0 requires PKCE, requires PAR and
requires sender-constrained tokens** — the three things this server does by default and that make the
OIDC Basic profile awkward for it. The failures below are therefore not a mismatch of philosophy;
they are work.

### Re-run of 2026-09-11, after five fixes

`830713b` (PAR content type), `1437341` (unknown parameters), `6cdb9ec` (`code_verifier` alphabet),
`848c179` (schema refusals answer 400) and `dcc4c08` (`/userinfo` 401 + challenge) all landed. FAPI 2.0
was then run against **unmodified code** — it sends PKCE on every request, so it needs none of the
local patches the OIDC profiles do.

|                      | first run | after all five     |
| -------------------- | --------- | ------------------ |
| Modules passed       | 5         | **36** (+8 review) |
| Conditions succeeded | 1 819     | **4 280**          |
| Conditions failed    | 51        | **18**             |

Every defect this page reported against the token and authorization endpoints is confirmed gone from
the results, and the PAR content type directly:

```
$ curl -o /dev/null -w '%{http_code} %{content_type}\n' -u <client> -X POST /par ...
201 application/json;charset=utf-8
```

Two things that looked like defects turned out to be configuration, and both are worth keeping:

- **Signing algorithms.** 21 modules failed `FAPI2ValidateIdTokenSigningAlg` until an ES256 key was
  added; then all 21 passed. The signing path is sound. What is _not_ sound is that this could not be
  done through the product: `SUPPORTED_ALGS` in
  [`lib/admin/jwks/schema.ts`](lib/admin/jwks/schema.ts) is `['RS256','RS384','RS512']`, and
  `getAlgorithm` ([`lib/configs/verifyJWKs.ts`](lib/configs/verifyJWKs.ts)) advertises exactly the one
  `alg` stamped on each stored key. So ES256 cannot be generated at all, and PS256 is unreachable even
  though the RSA key already present can sign it. **A FAPI 2.0 deployment cannot be configured through
  this server's own console.** The key here was written straight to `jwksStore`.
- **Registered redirect URIs.** FAPI modules append `?dummy1=lorem&dummy2=ipsum` to prove the match is
  exact. A static client must register that variant too, and `authorization.requirePushedAuthorizationRequests`
  must be set, or four more modules fail for reasons that are the test config.

### What FAPI 2.0 still reports

**Client assertion audiences are accepted too widely** — reported as the one finding here that was
about security rather than shape, and **wrong**. It is a property of the run's configuration, and the
wide set is required. Three modules push a `client_assertion` whose `aud` is an array, the PAR
endpoint URL, or the token endpoint URL; FAPI 2.0 requires each to be refused, and each was answered
`201`.

The reasoning that made this look like a defect — an assertion is a bearer credential, so the set of
accepted audiences is the set of places a captured one can be replayed — is sound in general and does
not apply here, because RFC 9126 §2 anticipated exactly this ambiguity and resolved it the other way:

> To address that ambiguity, the issuer identifier URL of the authorization server according to
> [RFC8414] SHOULD be used as the value of the audience. In order to facilitate interoperability, the
> authorization server **MUST accept its issuer identifier, token endpoint URL, or pushed
> authorization request endpoint URL** as values that identify it as an intended audience.

So honouring a token-endpoint audience at the PAR endpoint is mandatory for a general-purpose
deployment, not a defect — narrowing it by default would make this server non-conforming. OIDC Core
§9 pushes the same way, telling clients the audience SHOULD be the token endpoint URL, and RFC 9126
§2 makes client authentication at the PAR endpoint follow the token endpoint's rules; so a conforming
OIDC client authenticating at `/par` routinely sends exactly the value the report wanted refused.

The narrow rule is FAPI 2.0's alone — the server "shall only accept its issuer identifier value … as
a string" — and it **is implemented**, gated on `fapi.enabled`
([`lib/shared/token_jwt_auth.ts`](lib/shared/token_jwt_auth.ts)), and covered by three cases in
[`test/fapi/fapi2.spec.ts`](test/fapi/fapi2.spec.ts): an array audience, the PAR endpoint URL and the
token endpoint URL, each answered `401 invalid_client`. All three pass against unmodified code.

What actually happened is in the run configuration above: this plan was run with `par.enabled`,
`dpop.enabled` and `responseMode.jwt.enabled`, and **not** `fapi.enabled`. The three modules measured
a general-purpose OAuth server behaving correctly. See the settings list at the end of this file,
which now names that switch.

`EnsurePARInvalidRequestOrInvalidRequestObjectError` saw `invalid_redirect_uri` where
`invalid_request` or `invalid_request_object` belongs — a dynamic-registration error code (RFC 7591)
used in a PAR response. **Fixed**; see _PAR refusals use the wrong status and the wrong code_ below.

Twice across roughly 170 modules, an outbound call from the suite died with `Socket closed` — once on
`/token`, once on `/jwks` — while the same endpoints answered in milliseconds by hand immediately
afterwards. Too rare to characterise from these runs and recorded only so a third occurrence is not
read as new.

The rest is not this server: the BCP195 cipher check tests the nginx terminator standing in for TLS
here, one module needs a human to press cancel, and one aborts inside the suite's own Java.

### Re-run of 2026-09-11, after two fixes

Commits `830713b` (PAR content type) and `1437341` (unknown parameters) landed, and FAPI 2.0 was run
again — this time against **unmodified code**, because FAPI 2.0 sends PKCE on every request and needs
none of the local patches the OIDC profiles do.

|                                       | before                  | after                   |
| ------------------------------------- | ----------------------- | ----------------------- |
| FAPI 2.0 modules passed               | 5                       | **12** (+2 review)      |
| FAPI 2.0 conditions succeeded         | 1 819                   | **2 929**               |
| `EnsureContentTypeJson` failures      | 39                      | **0**                   |
| `client_assertion` refused at `/auth` | 28                      | **0**                   |
| Basic OP                              | 27 passed, **2 failed** | **28 passed, 1 failed** |

Basic OP was re-run too, and `oidcc-ensure-request-with-unknown-parameter-succeeds` — the module that
found the second defect — now passes. One code defect remains in that plan, and it is the
`code_verifier` one below; the other three non-passing modules are the two SHOULD-level warnings and
the screenshot reviews.

Both fixes are confirmed gone from the results, and directly:

```
$ curl -o /dev/null -w '%{http_code} %{content_type}\n' -u <client> -X POST /par ...
201 application/json;charset=utf-8
```

**The top blocker is now the third defect on this page, not a new one.** `code_verifier` is rejected
in **22 modules** with `Expected string to match '^[A-Za-z0-9_-]{43,128}$'` — the suite generates
verifiers containing `~` and `.`, which RFC 7636 allows and that pattern does not. It was invisible
before only because those modules died earlier, at PAR. Fixing that regex is now worth more to this
profile than anything else on the list.

Behind it, in order: the 422-instead-of-400 status leak (now visible on the token endpoint too, not
just PAR), `invalid_redirect_uri` returned from PAR where `invalid_request` belongs, and the
PS256/ES256 signing algorithms FAPI 2.0 requires.

### The PAR success response has the wrong content type

**Fixed in `830713b`.**

`pushed_authorization_request_response.ts` builds its 201 with
`new Response(JSON.stringify(...), { status: 201 })` and no `content-type` header, so the response
goes out as **`application/octet-stream`** carrying a JSON body. RFC 9126 §2.2 requires
`application/json`.

This one line failed `EnsureContentTypeJson` in **39 of 52 modules** — by far the widest single cause
in any run on this page. Confirmed outside the suite:

```
$ curl -o /dev/null -w '%{content_type} %{http_code}\n' -u <client> -X POST /par -d ...
application/octet-stream 201
```

The route already declares `response: { 201: ParResponse }` and `status: 201`, so returning the
object instead of a hand-built `Response` would fix it and keep the declared schema meaningful.

### The closed authorization schema, a third time

`invalid_request` / `Property 'client_assertion' should not be provided` from the authorization
endpoint, in **28 modules**. This is the same defect as _The authorization endpoint rejects
unrecognized parameters_ above, reached from a different direction — and between the two it is now
the most expensive single issue across every plan run here.

### PAR refusals use the wrong status and the wrong code

**Both halves fixed** — the status in `848c179`, the code since.

An invalid pushed request answered **422**, not the 400 RFC 9126 requires
(`EnsurePARInvalidRequestError`, `EnsurePARInvalidRequestOrInvalidRequestObjectOrRequestUriNotSupportedError`,
and two more as warnings). 422 is the framework's validation status reaching the wire; the protocol
has no such code.

Separately, one refusal returned `invalid_redirect_uri` where `invalid_request` or
`invalid_request_object` is required. `invalid_redirect_uri` is a dynamic-registration error code
(RFC 7591) and does not belong in a PAR response.

[`check_redirect_uri.ts`](lib/actions/authorization/check_redirect_uri.ts) now picks the code from
the endpoint that refused: `invalid_request` on the PAR route, `invalid_request_object` where the
value arrived inside a request object — which RFC 9126 §2.3 licenses, since it permits "error codes
defined by the OAuth extension … when such an extension is involved". The authorization endpoint is
untouched and still answers `invalid_redirect_uri`, because RFC 6749 §4.1.2.1 forbids redirecting
that error at all and no specification defines a code for a refusal rendered as a page. So does
dynamic client registration, where RFC 7591 §3.2.2 is the code's home.

### `state` is lost on the PAR path

`CheckStateInAuthorizationResponse` failed in 5 modules: state was pushed to `/par` and is absent
from the authorization response. Worth confirming outside the suite, but if it holds it is a
correctness defect on the PAR path rather than a profile mismatch — a relying party's CSRF defence
depends on that echo.

### Signing algorithms are below what FAPI 2.0 requires

`id_token_signing_alg_values_supported` and `userinfo_signing_alg_values_supported` are
`['HS256', 'RS256']`; FAPI 2.0 requires PS256 or ES256. This is a real gap for this profile alone —
nothing in the OIDC profiles asks for it.

### Not this server

`RequireOnlyBCP195RecommendedCiphersForTLS12` fails against the nginx terminator standing in for TLS
in this setup, not against anything in the repository. `ExpectAccessDeniedErrorFromAuthorizationEndpointDueToUserRejectingRequest`
requires a human to press cancel; a scripted browser that grants consent cannot satisfy it, and the
suite says so in the failure text. One module aborted inside the suite's own Java code.

## What a conformance target has to be configured with

A run against a default instance fails for reasons that are settings, and each one reads in the test
log exactly like a server defect. The conformance deployment needs all of:

- **Claim-defined scopes.** `profile`, `email`, `address`, `phone` and their claims, or the five
  `oidcc-scope-*` modules fail. The shipped default declares `openid` and `offline_access` only.
- **`claimsParameter.enabled` and `requestObjects.enabled`.** Off by default; with them off the
  `claims` parameter and by-value request objects are refused, and three modules fail.
- **`fapi.enabled`, for the FAPI 2.0 plan.** The second trap of the same shape, and it cost this file
  a wrong finding before it was caught. Off by default, and with it off the server answers as a
  general-purpose OAuth server: three modules push a `client_assertion` whose `aud` is an array, the
  PAR endpoint URL or the token endpoint URL, and each is **accepted**, because RFC 9126 §2 requires
  a non-FAPI deployment to accept exactly those values. The modules report an accepted request and
  nothing in the output names the profile switch, so the result reads as an audience-confusion
  defect. It is not one — see _What FAPI 2.0 still reports_ above.
- **`rateLimit.enabled: false`.** This is the trap worth stating loudly. The suite drives several
  hundred `/auth` and `/token` requests from one address within a minute, far over
  `rateLimit.strict.max` (60 per 60s). The refusal arrives as `temporarily_unavailable` on an HTML
  page, three consecutive modules are interrupted, and the runner aborts the whole plan reporting
  that the _server under test_ is unhealthy. Nothing in that chain names the rate limiter.
- **An end-user account** in the bucket the client resolves to (`redfox` for a client that belongs to
  no project), with profile, email, address and phone claims populated.
- **Two or three static clients.** The profile certifies both `client_secret_basic` and
  `client_secret_post`, and a static-client run needs a separate client for the second: the suite
  reads it from a `client_secret_post` block of its own.
- **`post_logout_redirect_uris` on the client**, for the logout plan — and spelled in _that_ case.
  This one is worth a warning of its own, because it cost three runs to find. A stored client record
  is part camelCase and part wire-format: only the keys in `BASE_METADATA_KEYS`
  ([`lib/models/client/validate.ts`](lib/models/client/validate.ts)) survive as camelCase, and
  `redirectUris` is one of them while `postLogoutRedirectUris` is not. Seed the latter in camelCase
  and validation **drops it silently** — no error, no warning, and the validated client simply reports
  an empty list. What surfaces instead is `400 post_logout_redirect_uri not registered` at logout,
  which reads as a server defect and is not one. `lib/admin/clients/service.ts` gets this right
  (`toMetadata` writes `post_logout_redirect_uris`), so the console and DCR are unaffected; only
  hand-written seed data can fall into it.

## Screenshots

Three or four modules per plan end in `REVIEW` because they require a screenshot of a page the server
rendered — the second login page for `prompt=login` and `max_age=1`, and the error pages for a
missing `response_type` and an unregistered `redirect_uri`.

An automated run cannot produce these. The suite's scripted browser is HtmlUnit, which does not
render, so `update-image-placeholder` stores the page's HTML source rather than an image and the
`/api/log/{id}/images` endpoint stays empty. **Certification requires real screenshots taken in a
real browser and uploaded by hand**, so these four modules must be walked through manually once,
whatever else is automated.

One of the four captured nothing at all, and correctly: for a missing `response_type` this server
returns the error by redirecting to the registered `redirect_uri` rather than rendering a page. The
test module accepts either branch.

## Scope of these runs

Config, Basic OP, Form Post Basic, RP-Initiated Logout and Dynamic were exercised. Hybrid and
Implicit were not, and will not pass as the server stands — `response_types_supported` is `code` and
`none`, which is the same OAuth 2.1 posture that makes PKCE mandatory, so those two certifications
are inapplicable by design rather than unfinished, as is Dynamic for the reason above.

Every applicable OP plan in the suite has now been attempted except the rest of the FAPI family —
FAPI 1.0 Advanced, FAPI 2.0 Message Signing and FAPI-CIBA — which build on the FAPI 2.0 result above
and are worth running only once its findings are addressed. Session Management and Frontchannel
Logout are inapplicable: there is no `check_session_iframe` and no front-channel logout support.

Everything here ran against a local instance rather than the deployed `conformance.foxauth.dev`. One
consequence is worth carrying forward: the end-user cookies are written `sameSite: 'strict'`
([`lib/consts/param_list.ts`](lib/consts/param_list.ts)), HtmlUnit does not enforce SameSite, and a
real browser will not send `_session` on a cross-site navigation from the suite to `/auth`. Whether
that breaks `prompt=none` against an established session is untested and should be checked before any
run that is meant to count.
