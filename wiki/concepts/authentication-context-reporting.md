---
type: concept
title: "Reporting the authentication context a sign-in satisfied"
tags: [oidc, contract, gotcha, config]
sources: [oauth-server-codebase]
created: 2026-09-13
updated: 2026-09-13
graph:
  node_type: concept
  relationships:
    - predicate: constrained_by
      object: concept:token-payload-access-contract
      source: oauth-server-codebase
      evidence: "get acr() { return this.session.payload.acr; }"
      confidence: high
      status: current
    - predicate: complements
      object: concept:totp-second-factor
      source: oauth-server-codebase
      evidence: "amr: ['pwd', 'otp'], acr: configuration.acrMap.multi_factor"
      confidence: high
      status: current
---

# Reporting the authentication context a sign-in satisfied

The `acr` claim says which Authentication Context Class the authentication *performed* satisfied —
a statement of fact about the sign-in, never an echo of what was asked for. This server distinguishes
three: a password alone, a password with a second factor, and a sign-in delegated to an upstream
provider (`lib/consts/acr.ts`). Until commit `4101b93` it distinguished none of them, and an
**essential** `acr` request could therefore never be satisfied by anything.

## The server owns the distinctions, an operator owns the names

`acrValues` is a map from distinction to the string each is reported as, not a free-form list
(`lib/configs/application.ts`, validated by `toAcrValues` in `lib/configs/configuration.ts`). The
split is forced by the matching rule: comparing a requested context against a satisfied one is
**exact string comparison**, so a deployment whose relying parties expect `2` or
`urn:mace:incommon:iap:silver` must be able to say so, while nobody may invent a distinction the
server cannot make and then advertise it.

`acr_values_supported` and the `acr` entry in `claims_supported` are **derived** from the map's
values in both mirrored implementations (`lib/configs/configuration.ts`, `lib/configs/discoverySupport.ts`)
rather than stated beside them, so the advertised set and the producible set cannot disagree. The
conditional that used to drop `acr` when no values were configured is gone, because a complete map
is now a validation requirement: every distinction present, values unique, none of them `"0"` —
OIDC Core §2 reserves that for an authentication carrying no confidence that the same person is
there, which is not true of any sign-in here.

## It was two gaps, and the reported one was the lesser

`CONFORMANCE.md` diagnosed this as "nothing assigns an ACR, everything downstream is already wired".
The first half was right. The second was wrong by one hop, and the second hop is the one that made
the feature unreachable:

```ts
// before
get acr() { return this.session.acr; }
```

`Session` declares `acr` on its TypeBox payload and `BaseModel` proxies nothing, so `session.acr`
was `undefined` however the session was loaded — see [[token-payload-access-contract]], of which
this is the second recorded instance and the more expensive one. `amr` had the identical defect on
the next line. Assigning a context at sign-in without fixing the getter would have changed nothing
observable, which is the trap: the obvious repair looks complete and is inert.

Confirmed by construction rather than by reading, before anything was changed: a probe building a
`Session` with `acr` set printed `session.acr = undefined`, `session.payload.acr = "2"`, and no
accessor anywhere in the prototype chain.

## Where the refusal is raised, and why the resume route needs its own delivery

OIDC Core §5.5.1.1: an essential `acr` that cannot be met **MUST** be treated as a failed
authentication attempt. Before this, it was treated as a reason to show the login page again — every
time, forever, with no error and nothing logged.

Two mechanisms close it. Both ACR checks in `lib/helpers/interaction_policy/prompts/login.ts` now
declare `error: 'unmet_authentication_requirements'`, the registered code for exactly this case,
which already existed in `lib/helpers/errors.ts` with **zero call sites**. And a guard in
`lib/actions/authorization/interactions.ts`, immediately before the interaction is minted, refuses
when `oidc.result?.login` is present and the failing prompt's reasons name an ACR check.

`oidc.result.login` is the discriminator between *"has not tried yet"*, which must be shown a login
page, and *"tried, and it is still not enough"*. The `max_age` check and both consent checks already
read it for precisely that; the two ACR checks were the ones that did not.

**The delivery is the awkward part.** `lib/shared/authorization_error_handler.ts` redirects an error
to the client only when `route === routeNames.authorization`, and an interaction resumes on
`/ui/:uid/resume`. So a throw there renders to the browser instead of returning to the relying
party, and `resume()` has to deliver it itself — which it already did for an interaction `result.error`,
and now does for this too. That is the second hand-rolled workaround for one missing rule; widening
the handler's condition would change delivery for every error thrown during a resume, so it is filed
as issue #47 rather than done in passing.

## The backchannel breaks the same invariant from the other end

There is no login page on the CIBA path, so an unmet requirement produces no loop. It produces
something worse and quieter: a **token that should not exist**, carrying a context that does not
match what was required, or none at all. `backchannelResult` took the reported `acr` from the
deployment's authentication-device integration and assigned it without comparing it to anything.

It now records a failed transaction instead — at the moment the outcome becomes known rather than at
token issuance, because leaving the request marked successful would tell a ping-mode client to
collect a token that will never exist.

The code is CIBA §12's `transaction_failed`, and **not** `access_denied`, which the specification
reserves for *"the end-user denied the authorization request"*. The end user authenticated; they
denied nothing. A client that branches on a denial — to stop retrying, or to tell the person they
refused — would be misled by the obvious-looking choice.

The requested values already reach the integration (`params` and the assembled `claims` are both
stored on the request), so CIBA §8's "authenticate in line with the client's requests" was always
achievable by a deployment. What it lacked was documentation, now in the
`triggerAuthenticationDevice` contract: only the integration knows what the authentication was, and
this server will not invent a context it did not observe.

## The obligation and the defect appear together

`claimsParameter.enabled` ships **off** (`lib/configs/application.ts`), and §5.5.1.1 conditions its
MUST on exactly that support — *"and the implementation supports the claims parameter"*. With it off
no essential request can be expressed, so the loop was unreachable on default settings and the
conformance suite could only ever warn. This is worth knowing before estimating the blast radius of
a claims-parameter finding: see [[feature-flag-gating]] for the general shape.

## Gotchas

- **Two tests proved the opposite of what they claimed.** `test/claims/claims.spec.ts` built an
  interaction whose stored `params.claims` was the JSON **string** the request helper produces, so on
  resume `oidc.claims` was a string, `oidc.claims?.id_token` was `undefined`, and both ACR checks
  returned early without comparing anything. They asserted that a satisfied context yields a code and
  passed because the requirement was never evaluated. Re-anchored, then shown to have teeth by
  reverting the getter: 2 fail without it, 0 with it. In production the interaction stores `claims`
  as an object, which is why the real flow looped and the test did not.
- **A merge composed a requirement the client never expressed.** `assign_claims.ts` merged
  `acr_values` over an individual `acr` claim request, keeping `essential: true` from one form and
  taking `values` from the other. Since a client's `default_acr_values` arrive *as* `acr_values`, a
  registered default silently replaced what the request asked for — the opposite of what OIDC
  Registration §2 requires. The individual claim request is now authoritative. §5.5.1.1 leaves a
  client sending both forms explicitly *unspecified*, so what is owed there is determinism, not a
  particular winner.
- **A second factor is demanded by the bucket, not by the person.** `totpRequired` is a
  `UserBucket` flag; `user.totp` is consulted only inside that branch, to choose the verify page over
  the enrolment page. So an end user with an authenticator enrolled, in a bucket that does not require
  one, signs in with a password and reports the single-factor context — and a relying party requiring
  multi-factor is refused for them. The setting's own description says so, because it arrives as a
  support question whose remedy is a different setting.
- **A request that asks for nothing is unchanged.** §5.5.1.1 does not require the claim when it was
  not requested, and the mask reflects that, which is what keeps every existing deployment's tokens
  byte-identical.

## Related

- [[token-payload-access-contract]] — the contract the broken getter violated; this is its second
  recorded instance, and the one that cost a protocol feature rather than one delivery path.
- [[totp-second-factor]] — where the multi-factor distinction comes from, and the `amr` decision
  taken alongside it.
- [[feature-flag-gating]] — why a flag that is off by default can hide a conformance obligation.
- [[unknown-request-parameters]] — the other conformance finding whose scope widened once the
  governing text was read rather than the reported endpoint.
- [[per-origin-rate-limiting]] — the other page about `allow_redirect` and which errors reach a
  client's `redirect_uri`.

Verified against [[oauth-server-codebase]] at commit `4101b93`.
