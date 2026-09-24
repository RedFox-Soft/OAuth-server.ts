---
type: concept
title: "Ignoring request parameters the server does not define"
tags: [oauth, oidc, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-09-11
updated: 2026-09-24
graph:
  node_type: concept
  relationships:
    - predicate: implements
      object: subsystem:elysia-lifecycle
      source: oauth-server-codebase
      evidence: "export function ignoreUnknownParams(...schemas: TObject[]) { return new Elysia().onTransform({ as: 'scoped' }, ({ body, query }) => { ignoreUnknownIn(declared, body); ignoreUnknownIn(declared, query); }) }"
      confidence: high
      status: current
---

# Ignoring request parameters the server does not define

Every endpoint that takes authorization-request parameters must answer a request carrying a
parameter it does not recognize exactly as it answers the same request without it. This is what
makes the protocol extensible — a client may send what a later profile defines, and an older server
must still work — and it is a `MUST` in four separate specifications, not a courtesy.

`lib/consts/param_list.ts` declares these parameters as TypeBox objects, and the app is constructed
with `normalize: false` (`lib/index.ts:63`), so an undeclared key raises `invalid_request` with
`Property '<name>' should not be provided`. That was the behaviour until 2026-09-11.

## Where it is required, and by what

| Endpoint | Norm |
|---|---|
| `GET`/`POST /auth` | RFC 6749 §3.1 — "The authorization server MUST ignore unrecognized request parameters" |
| `POST /token` | RFC 6749 §3.2 — the identical sentence, in the token endpoint's own section |
| `POST /device/auth` | RFC 8628 §3.1 — the same sentence again |
| `POST /backchannel` | CIBA §7.1 — "OpenID Providers MUST ignore unrecognized request parameters" |
| `POST /par` | RFC 9126 §2.1 step 3 — "Validate the pushed request as it would an authorization request", which inherits §3.1 |
| JAR Request Object | RFC 9101 §4 — "The Request Object MAY include any extension parameters" |

OIDC Core §3.1.2.2 states it as a `SHOULD`, which is weaker than RFC 6749's `MUST` and does not
relax it. `POST /reg` is covered by RFC 7591 §2 and needs nothing: its body schema is already
`t.Record(t.String(), t.Unknown())` (`lib/actions/registration.ts:369`), and unknown metadata is
dropped by client validation. RFC 7009 and RFC 7662 say nothing, so introspection and revocation
keep their strict schemas.

## Absence from a schema now means "ignore", so a refusal has to be declared

This is the part that costs a debugging session. Before the change, "not in the schema" and "must be
rejected" produced the same 422, so several deliberate rejections were implemented by *omitting* the
parameter — `t.Omit(AuthorizationParameters, ['request_uri', ...])`. The moment undeclared keys are
dropped instead, every one of those rejections silently becomes an acceptance.

`refusedParam(name)` in `lib/consts/param_list.ts` is the counter-declaration: an optional member
typed `t.Undefined`, present in the schema precisely so it can fail. Four places need it, each for a
different specification:

- **`request_uri` at `/par`** — RFC 9126 §2.1 step 2 rejects a pushed request carrying it.
- **`request` and `request_uri` *inside* a Request Object** — OIDC Core §6.1 forbids inception.
  Declared on `authorizationRequest`, `DeviceRequest` and `BacckchannelRequest`.
- **`authorization_details` at `/token`** — RFC 9396 §7 defines it there as a way for a client to
  *narrow* the grant being exchanged. This server does not implement that, and ignoring it would
  hand back a token broader than the one the client asked for without saying so. See
  [[rich-authorization-requests]].
- **`registration`** — already declared this way (OIDC Core §7.2.1), and the precedent the others
  follow.

CIBA's `request_uri`/`registration` are a fifth case with a different mechanism: they are declared as
real strings and refused in the handler, because CIBA specifies the named error codes
`request_uri_not_supported` / `registration_not_supported` rather than a generic refusal
(`lib/actions/authorization/device.ts:165-176`).

## The Request Object is not a route, so a framework-level answer cannot reach it

`processRequestObject` validates the decoded JWT payload with a direct
`getSchemaValidator(schema).Check(payload)` call (`lib/actions/authorization/process_request_object.ts`),
outside Elysia's route pipeline entirely. Nothing configured on the app — no hook, no flag — applies
there. It calls `ignoreUnknownIn(declaredParams(schema), payload)` itself, which is why the filter is
exported as a pure function and not only as a plugin.

## Why not Elysia's `normalize: true`

The framework already has a feature that looks like the answer, and it is not. Both reasons below
were measured on 2026-09-11 by flipping the flag on a clean tree and running the suite: 14 failures
against 10 for the scoped plugin, and two of them are live features breaking rather than test shape.

**`normalize` cleans headers too.** Elysia normalizes against the route's `headers` schema as well
as body and query, and this server reads a header no schema can enumerate — the client certificate,
which `getCertificate` (`lib/addon/mtls.ts`) reads under a name a deployment may change. Since
2026-09-24 the route schemas declare the default, `x-client-cert`, so the typed client can send it;
a deployment whose proxy forwards `x-ssl-client-cert` overrides the addon, and under the flag that
header is stripped before the addon can read it, so a certificate-bound access token presented
**with** its matching certificate answers 401 instead of 200. The same trap sits on `/token`, where
that header is mTLS client authentication. Enumerating every header a deployment might use in every
route schema would undo the seam the addon layer exists to provide.

**`normalize` repairs the input; the requirement is only to ignore it.** It coerces a value to fit
the schema recursively, so a malformed `claims` parameter stops being refused and is silently
emptied instead — the client asks for claims, receives none, and is told nothing. Dropping
undeclared keys leaves every declared-but-malformed value to normal validation, which is the
behaviour the four specifications above actually ask for.

The flag also saves less work than it appears to: once "absent means ignore" holds anywhere, the
four `refusedParam` declarations are needed either way, and the Request Object still needs its own
call.

## What this does not close

`ignoreUnknownParams` is mounted per endpoint. A seventh endpoint taking authorization-request
parameters will not inherit it, and nothing fails if its author forgets — the cost of choosing the
scoped answer over the global flag. `test/unknown_parameters/` covers the six that exist by sending
each endpoint's own request twice, with and without an extra parameter, and comparing the two
answers; it is a table, not a guard enumerated from the running system, so it grows only when
somebody adds a row.

Comparing *status alone* is not enough there and the first draft of that spec was wrong for it: the
authorization endpoint delivers a refusal by redirecting to the client's `redirect_uri`, so a
refused request and an honoured one are both a `303` and differ only in the query. Both `/auth`
cases passed against the reintroduced defect until the comparison included the error code.

## The same rule applies one level in, inside a parameter's value

Added 2026-09-14 (spec 047). "Absence from a schema means ignore" was stated for request
*parameters*; it holds for the members of a parameter's **value** too, and the `claims` object was
the case where it did not.

`claims` was declared `additionalProperties: false`, so a value carrying `id_token`, `userinfo` and
a third member the server does not define was refused outright — where OIDC Core §5.5 says other
members MAY be present and ones that are not understood MUST be ignored. It is the defect fixed in
`1437341`, one level deeper, and the conformance suite found it the same way. The refusal also
misreported itself: the object's single `error` string fired for *every* object-level failure, so
the answer said the parameter "should be object with userinfo or id_token properties" while both of
those members were present.

The fix has the same shape as the parameter-level one and reuses its function. The schema no longer
closes the object, and `checkClaims` calls `ignoreUnknownIn` with the member set exported from
`param_list.ts` beside the schema built from it, so the two cannot drift. **Deleted, not merely
tolerated** — for the reason `ignoreUnknownIn`'s own comment gives: PAR serialises `oidc.params`
into the request object it stores and the interaction record copies them again, so a member carried
rather than dropped is a member a client can make this server keep.

`checkClaims` is the one place all five surfaces converge before anything persists their parameters,
which is why the deletion sits there rather than at the transform stage — where `claims` is still a
JSON *string*, since `t.ObjectString` parses it during validation.

## Related

- [[elysia-lifecycle]] — the plugin family this joins, and the argument for each lifecycle stage.
- [[rich-authorization-requests]] — the declared shape of `authorization_details` as a runtime
  coercion contract, and why the token endpoint refuses it.
- [[test-admission-rule]] — why the spec above is a behavioural table rather than a completeness
  guard.
