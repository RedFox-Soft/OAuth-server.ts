---
type: concept
title: "Rich Authorization Requests and its conformance boundary"
tags: [oauth, config, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-07-31
updated: 2026-07-31
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:feature-flag-gating
      source: oauth-server-codebase
      evidence: "ApplicationConfig['richAuthorizationRequests.enabled'] gates checkRar and the shaping seams."
      confidence: high
      status: current
    - predicate: constrained_by
      object: concept:token-payload-access-contract
      source: oauth-server-codebase
      evidence: "introspectionAllowedPolicy read token.clientId instead of token.payload.clientId, refusing every public client."
      confidence: high
      status: current
---

# Rich Authorization Requests and its conformance boundary

`authorization_details` (RFC 9396) lets a client request structured, fine-grained permission instead of
or alongside a scope string. It is supported end to end on the **authorization-code and refresh-token
flows** only. That boundary is a decision, not an omission, and the deviations below are the useful part
of this page — a conformance claim is only meaningful next to its exceptions.

## Types are data, and at least one is required

`richAuthorizationRequests.types` maps an opaque type identifier to a serializable descriptor: a required
`label` (what the consent screen shows), optional per-field constraints over the five §2 common fields,
and `allowUnknownFields` (default `false`, because §5 requires refusing unknown fields). A `validate`
function may still be registered in an in-process bootstrap as an escape hatch, and a rejection from it
surfaces as `invalid_authorization_details` rather than a server fault.

Enabling the feature with an **empty** map fails validation, at boot and through the admin settings API,
because every request would otherwise be refused. `identifier` is single-valued, so a descriptor may mark
it required but cannot fix a permitted value set for it.

Per-client opt-in is mandatory: `authorization_details_types` defaults to `[]`, so a client that does not
list a type cannot use it (§10.5). That metadata is only *recognized* while the feature is enabled, which
means a client registered while it was off has no value at all — absent must read as "no types", never as
"all types".

## The parameter's declared shape is a runtime contract, not documentation

The single most expensive thing to know here. `lib/consts/param_list.ts` declares
`authorization_details` and Elysia coerces request values against that declaration **before any of our
code runs**:

| Declared member shape | A JSON query value arrives as |
|---|---|
| `t.Array(t.Object({}))` | `[{}]` — every member field stripped, silently |
| `t.Array(t.Object({}, { additionalProperties: true }))` | intact — the only correct shape |
| `t.Array(t.Unknown())` | the raw string split on its commas |

Form-encoded bodies do not coerce at all: a JSON string arrives as **one object per character**, status
200, no error. Since PAR is form-encoded, that corrupted every pushed rich request until
`parseJsonParams` (`lib/plugins/coerce_array_params.ts`) was mounted on the form routes. It is the
sibling of `coerceArrayParams`, which exists for the same class of quirk.

`checkRar` accepts the parameter as a JSON string *or* an already-parsed array, then **normalizes** it to
an array on `oidc.params`, so no consumer downstream re-parses it or needs to know which path a request
arrived by.

## Consent shows the not-yet-granted subset, and grants it wholesale

The `rar_prompt` check computes the requested details minus what the grant already holds, stashes that
subset on a module symbol exactly as `missingOIDCScope` does, and returns it as the prompt's details. One
determination serves both the decision to interrupt and the contents of the page, so a repeat
authorization for already-granted details does not re-prompt.

Approval records each presented detail with `Grant#addRar`, which is idempotent by **structural
identity**: object members are sorted before comparison, but string values are never transformed — §12
forbids trimming, case folding, and Unicode normalization. Two details differing only in member order are
the same detail; two differing in case are different details. `lib/helpers/rar_canonical.ts` is the one
implementation.

There is no per-detail selection: approval grants everything shown.

## Trusted grants are handled on the model, deliberately

A client with `consent.require: false` skips the consent prompt in its entirety, so nothing is ever
recorded on its grant. `Grant#getRarFiltered` therefore returns the requested details verbatim when the
grant is trusted — the same arm `getOIDCScopeFiltered`, `getResourceScopeFiltered` and
`getOIDCClaimsFiltered` already carry.

It lives on the model rather than inside the overridable `rarForAuthorizationCode` default **so that a
deployment shaping its own details cannot silently lose trusted clients**. Relatedly,
`loadExistingGrant` re-derives `trusted` from the client on every load: a grant created before the client
stopped requiring consent is persisted with `trusted: false`, and freezing that would under-grant every
returning user.

## Deviations, and the one that bites

- **Device authorization and CIBA refuse the parameter** (§3), and it is absent from the strict `/token`
  body schema (§6). The four grant-level §6 checks are therefore unreachable and still raise the wrong
  error code; they are kept as the seam that channel support plugs into.
- **Details reach a token only when a resource server resolves.** `at.payload.rar` is assigned only when
  `at.resourceServer` exists, and that needs a registered `getResourceServerInfo` override — whose
  default throws. A deployment without one grants details at consent that **no token ever carries**, with
  no error anywhere. This is the sharp edge; the guard for it belongs to the wider
  "features whose defaults throw" work.
- **A detail with unknown fields is granted whole but only its common fields are rendered**, so a field
  admitted by `allowUnknownFields` is approved without being individually shown.
- The feature requires `resourceIndicators.enabled`, which RFC 9396 does not.

The details field is **absent, never empty**: the shaping seam runs only when the parameter was sent, and
an empty result is omitted from the code, the tokens, the token response, the JWT claim and the
introspection response. An empty array would be a visible wire change for clients that never asked, and
the introspection guard tests truthiness — where `[]` is truthy.

## Related

- [[feature-flag-gating]] — how the enabling flag is read, and why config is boot-only.
- [[token-payload-access-contract]] — the contract whose violation made public-client introspection
  return `active: false` for every token.
- [[client-identity-from-database]] — where `authorization_details_types` is stored and validated.

Verified against [[oauth-server-codebase]] at commit `5ce224a` plus the `specs/015-rar-end-to-end`
implementation.
