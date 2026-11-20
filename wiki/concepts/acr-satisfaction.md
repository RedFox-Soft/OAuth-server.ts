---
type: concept
title: "Which sign-in meets which context, and what a token is told"
tags: [oidc, contract, security, passkeys]
sources: [oauth-server-codebase]
created: 2026-11-20
updated: 2026-11-20
graph:
  node_type: concept
  relationships:
    - predicate: refines
      object: concept:authentication-context-reporting
      source: oauth-server-codebase
      evidence: "export const SATISFIED_BY: Readonly<"
      confidence: high
      status: current
    - predicate: complements
      object: concept:passkeys
      source: oauth-server-codebase
      evidence: "passkey: 'phishing_resistant',"
      confidence: high
      status: current
---

# Which sign-in meets which context, and what a token is told

Spec 142 (2026-11-20) added a fourth authentication context, `phishing_resistant` (default name `phr`, the OpenID EAP
ACR value), reached only by a sign-in with a full passkey. Three decisions came with it, each closing a way the
research found to break existing behaviour.

## Strength is a table, never an order

`SATISFIED_BY` (`lib/consts/acr.ts`) says which reached contexts meet a required one: the password context is met by
password, multi-factor and phishing-resistant; multi-factor by itself and phishing-resistant; phishing-resistant by
itself; federated by itself. An unknown name meets nothing. `lib/helpers/acr_satisfaction.ts` is the only reader:
`meets`, `satisfiesAny`, `strongestMet`. Every check that used to compare with `acrMap.multi_factor` goes through it
(the code requirements of an app, an API and the proxy, the essential `acr` checks, IPSIE SL1, `freshCode`, the
person's activity), so a passkey meets everything a code meets with no check written twice.

Why not positions in `ACR_DISTINCTIONS`: the list ended with `federated`, and comparing indexes would have ranked a
provider sign-in above a code and let it through every code requirement — the thing the code requirement forbids
(`11-critique-security` S8). The old comment "the order is documentation, not logic" was rewritten: there is no order.

## Two values: what the sign-in reached, what the app is told

The session keeps the reached context in `acr`. Every token artefact (the `stores_auth` mixin, the access token)
keeps the **reported** value in `acr` and the **reached** one in `signInAcr`, copied wherever `acr` is copied. Every
requirement reads `reachedAcr(payload) = signInAcr ?? acr`.

This way round on purpose: the reported value is always met by the reached one, so a copy site that forgets
`signInAcr` makes a check read something weaker and refuse — it fails closed. The other way round, a forgotten
emission site would have handed `phr` to an application that never asked for it.

A self-contained access token carries only `acr` and `amr`, never `signInAcr`. The proxy's API check therefore treats
`amr` containing `mfa` as "had a code" too (`lib/behind_proxy/api_check.ts`): `mfa` is present exactly when the
sign-in held two factors ([[amr-reporting]]).

## The reporting rule

`reportedAcr(reached, claims)` (Clarifications 2026-11-20, option B): the candidates are the request's `acr` claim
request, where `acr_values` and `default_acr_values` already arrive when no claim request exists
(`lib/actions/authorization/assign_claims.ts`); the token carries the strongest candidate the sign-in meets; with none
named or none met, the reached context with `phishing_resistant` lowered to the multi-factor name. So `phr` reaches
only an app that asked for it, an app comparing `acr === mfa` keeps working after a passkey, and an app that asked for
the password value is told that value. This is what Keycloak does (`AcrUtils.mapLoaToAcr`), and Okta's tokens reflect
the requested value. The essential checks use `satisfiesAny`, so an essential password request is no longer refused
for a stronger sign-in.

## A device code or a back channel never reaches phr

The browser that did the passkey ceremony is not the one that receives the tokens, so the passkey resisted no phishing
of the user code (`11-critique-security` S11). `capForOtherBrowser` lowers the reached context at the device code
(`device_user_flow_response.ts`) and at a CIBA result (`backchannel_result.ts`), and the login prompt judges a
device-flow interaction on the capped value (`judgedAcr`), so an essential `phr` fails at the verification page rather
than yielding a token that carries less.

## The stored names and the fence

A stored `acrValues` replaces the default whole, so one saved before spec 142 lacks the new key and validation would
refuse to boot. Migration `2026-11-20-acr-phishing-resistant` adds `phr`, or `urn:foxauth:acr:phr` when the operator
already uses `phr`, keeping every other name. Startup fills the same name in memory only
(`lib/configs/application.ts`), so the migration gate, not a `TypeError`, is what refuses a database that is behind.
The migration's record is also the fence that stops an older release from erasing `signIn.requirePasskey`.

## Requiring a passkey

`signIn.requirePasskey` is an operator base key like `signIn.requireCode`
([[client-registration-attributes]]), checked by `passkeyRequiredAndMissing` before the code requirement at the
sign-in (`app_passkey`) and at every grant for a person. It is refused (409 `passkeys_not_accepted`) while the project
does not accept passkeys; a project that later stops accepting them leaves the requirement in place and the app
refusing everyone. The refusal page leads to the goal: sign in with the passkey held, confirm a conditional one,
create one by the offer's rules, or ask the operators ([[passkeys]]).

`acr_values_supported` lists the phishing-resistant name only in the discovery document of a project that accepts
passkeys (`lib/actions/discovery.ts`): every project is its own issuer.
