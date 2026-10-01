---
type: concept
title: "Reporting the authentication methods a sign-in used"
tags: [oidc, contract, gotcha, config]
sources: [oauth-server-codebase]
created: 2026-10-01
updated: 2026-10-01
graph:
  node_type: concept
  relationships:
    - predicate: derived_from
      object: concept:authentication-context-reporting
      source: oauth-server-codebase
      evidence: "AMR_FOR_DISTINCTION: Record<AcrDistinction, readonly AmrValue[]>"
      confidence: high
      status: current
    - predicate: complements
      object: concept:totp-second-factor
      source: oauth-server-codebase
      evidence: "multi_factor: ['pwd', 'otp', 'mfa']"
      confidence: high
      status: current
---

# Reporting the authentication methods a sign-in used

`amr` (OIDC Core §2) is the factual record of *how* the end user authenticated, as RFC 8176 values;
`acr` ([[authentication-context-reporting]]) is the business-rule claim of *what context* that
satisfied. Every ID token issued from a sign-in carries `amr`, whether or not the request asked for it.

| Sign-in | `amr` |
| --- | --- |
| Password | `["pwd"]` |
| Password and a one-time code (verified, or enrolled during sign-in) | `["pwd", "otp", "mfa"]` |
| Upstream identity provider | none |
| Backchannel | what the deployment's integration passes to `backchannelResult`; none if nothing |

The values are declared once, keyed by the same distinction that yields `acr`
(`lib/consts/amr.ts`), so the two claims cannot disagree. They are not operator-renamable, unlike the
`acr` names: they are registered identifiers every relying party library knows. `mfa` sits beside the
individual methods as RFC 8176 §2 allows; order is fixed for reproducible tokens and means nothing.

## Declaring it was never going to be enough

Issue #46 read the defect as one missing entry: `amr` was absent from the `claims` setting, so
`Claims.result()` (`lib/helpers/claims.ts:45-55`) dropped it. There were **two** filters. A claim
survives only if it is in the supported set *and* in the mask built from the token's scope and the
`claims` request — and nothing in a default request names `amr`: no scope maps to it, and the `claims`
parameter ships disabled. Declaring it alone would have made it appear only for a request the default
configuration refuses. `acr` passes the second filter because `acr_values` adds it to the mask;
`amr` has no such parameter.

So `amr` takes the path `sid` and `nonce` already take: each ID-token grant site writes it with
`token.set` (`lib/actions/grants/authorization_code.ts`, `device_code.ts`, `ciba.ts`,
`refresh_token.ts`, next to `sid`), past both filters, and only when non-empty — a token never carries
`"amr": []`.

## Why it is supported whatever the claims setting says

`Object.assign(ApplicationConfig, await configStore.get())` (`lib/configs/application.ts`) replaces a
stored `claims` object whole. Adding `amr` to the shipped default would have reached no instance whose
operator ever saved that setting — the conformance instance among them — and those would emit a claim
they never advertised. Instead both mirrored derivations add it unconditionally
(`lib/configs/configuration.ts` after `collectClaims`, `lib/configs/discoverySupport.ts`
`deriveClaimsSupported`), the way `sub` is forced into `openid`. Listing or omitting `amr` in the
setting changes nothing, and the parity fixture passing with `amr` absent from its claims is the proof.
There is no switch to turn it off; nobody has asked for one.

## The two decisions the specifications leave open

Both decided by the owner on 2026-10-01, after the specifications and ten implementations were
compared.

- **A password-only sign-in reports `pwd`.** [[totp-second-factor]] originally left it with no `amr`,
  so its tokens stayed byte-identical and "contains `otp`" was the test. That made absence ambiguous —
  "password" and "this server says nothing" read the same. Okta, Duende, Zitadel and Entra all report
  `pwd`. The test for a second factor is still "contains `otp`", or now "contains `mfa`" — never
  "has `amr`".
- **A federated sign-in reports nothing.** Core defines `amr` as the methods used in the
  authentication, and this server used none of its own: it accepted a signed assertion. The upstream
  provider's `amr` is verified and discarded with the rest of its claims (`lib/federation/`). Rejected:
  the unregistered `fed` (Entra) / `external` (Duende) — it departs from the SHOULD that values be
  registered, describes the route the assertion took rather than a method, and adds nothing `acr`
  does not already say.

### Deferred, not rejected: forwarding a trusted provider's `amr`

Okta's model: an operator marks a provider trusted and its `amr` is carried into this server's tokens.
It is closest to the letter of §2 — those are the methods actually used — and NIST SP 800-63C permits
a proxy to copy upstream attributes. What it would need, so a future change starts here: a per-provider
trust flag on the federation provider record, with its console field, MCP argument and audit entry;
filtering to registered values, since providers send their own (Entra's `rsa`, `ngcmfa`); and a rule
for the weakest link, since 800-63C requires a proxy to report the lowest assurance on the path. It
composes with today's answer — an untrusted provider still yields no `amr`. No issue is open for it, by
decision.

## What `amr` deliberately does not do

- **Fail anything.** OIDC Core §5.5.1 gives only `sub` and `acr` a failure rule; an essential `amr`
  request, or one naming values the sign-in did not use, completes and is answered with the methods
  used. Core also says a claim whose value does not match a requested `value`/`values` "is not
  included" — this server applies that to **no** claim (selection is by key in `filter_claims.ts` and
  `Claims.result()`), and the equality comparison it prescribes is undefined for an array, so `amr`
  follows the server-wide behaviour. Recorded in `CONFORMANCE.md` as a server-wide gap.
- **Drive authorization.** Policy stays on `acr`; RFC 8176 warns that depending on specific methods
  makes brittle systems, and RFC 9470 step-up never mentions `amr`.
- **Appear anywhere but the ID token.** Not in userinfo (`amr` is a reserved name on the account
  record, so `account.claims()` can never yield one), introspection or JWT access tokens.
- **Rewrite history.** Sessions and refresh tokens recorded before the change emit what they recorded:
  `["pwd", "otp"]` without `mfa`, or no `amr` for a password sign-in. The next sign-in replaces it.

## Gotchas

- A two-factor sign-in followed by a password-only one on the same session is reachable only by a
  bucket change in between: the second factor is demanded by the bucket, not by enrolment.
- `test/totp/signin.spec.ts` used to assert `amr` on the session while its comment claimed that proved
  the ID token. It did not — the claim never got there. The cases now live in `test/amr/`, against the
  ID token.

## Related

- [[authentication-context-reporting]] — the distinctions `amr` is keyed on
- [[totp-second-factor]] — where `otp` comes from
- [[token-payload-access-contract]] — how `amr` is read off a stored artefact
