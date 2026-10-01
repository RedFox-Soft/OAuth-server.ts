---
type: concept
title: 'Interaction error delivery'
tags: [architecture, contract, oauth]
sources: [oauth-server-codebase]
created: 2026-10-01
updated: 2026-10-01
---

# Interaction error delivery

An authorization request can end in two places: at the authorization endpoint, or after the end user
was handed to the interaction pages and the stored request is resumed. RFC 6749 §4.1.2.1 and OIDC Core
§3.1.2.6 require either kind of failure to reach the client's redirect URI. Until spec 065 (issue #47)
only the first did — the shared `onError` redirected on the authorization route alone — so an error
raised while resuming was rendered to the browser, the client never heard, and the end user was left on
this server's page. Two places hand-rolled a redirect to compensate; consent refusal had none and
answered `400`.

## One module, two callers

`lib/shared/authorization_error_delivery.ts` owns the whole rule: whether an error may be redirected
(`refusesRedirect`, `:110` — an `allow_redirect === false` error never is), the delivered body and its
`error_description` character set (`restrictDescription`, `:99`), the response mode, and the fault record
(`deliverAuthorizationError`, `:133`). Its callers differ only in where the request comes from:

- the shared handler, for `/auth`, addressing the error from the request it received
  (`lib/shared/authorization_error_handler.ts:360`, `:506`);
- `resume()` (`lib/interactions/index.ts:173`), addressing it from the stored request, through
  `deliverToClient` (`:135`).

The module imports neither the interaction pages nor the shared handler — both import it, and the
handler is loaded by the root app before the interaction routes are mounted. `getObjFromError` and
`getFirstError` moved into it for the same reason.

## The boundary is the restored request, not a list of errors

Inside `resume()`, everything after `getResume()` restores the stored request runs in one `try`
(`lib/interactions/index.ts:214`), and its `catch` delivers (`:261`). Nothing before that line is
delivered.

That boundary is what makes the untrusted-interaction rule structural. Every way an interaction can fail
to belong to this browser, this address or this session is raised before it: the route guard's
`SessionNotFound`s run before the handler at all, and `getResume`'s session mismatch
(`lib/actions/authorization/resume.ts:26`) is raised before the stored parameters are assigned. Before
the line there is also no redirect URI to deliver to. Redirecting those would hand the original
request's `state` to whoever presented the uid, and RFC 9700 §4.11.2 requires the user to be
authenticated before any redirect.

After the line, an error nobody anticipated is delivered as surely as one somebody did. Rejected
alternatives: widening the handler's route condition (it holds a route pattern, not the interaction, and
`resume()` is reached from six routes — a list someone forgets), and an Elysia-scoped `onError` reading
the resolved interaction (correct only if the framework hands resolved values to `onError` at every throw
site; the failure mode when it does not is the original defect, silently).

## Re-checked at delivery, for a code as much as for an error

The stored request passed redirect-URI validation when it began; delivery goes to the registration as
it stands now. `deliverToClient` re-reads the client and tests `redirectUriAllowed` before an error
(`lib/interactions/index.ts:135`); the success path tests it after `checkClient` (`:238`). A client
deleted, or a redirect URI withdrawn, while the end user was signing in gets this server's own
`invalid_client` / `invalid_redirect_uri` page and no redirect.

The success-path check closed a defect found while testing this: a redirect URI deregistered
mid-sign-in still received an **authorization code**, because the resume step trusted the stored check.

Re-reading the client also sets the client entity, which a JWT response mode needs to sign
(`lib/response_modes/jwt.ts:23`). Before this the interaction-result branch ran ahead of `checkClient`,
so an error under `response_mode=jwt` could not be delivered at all.

## Consent refusal is an interaction result

*Cancel* records `result.error = 'access_denied'` and calls `resume()`, as *Allow* records
`result.consent` and does (`lib/interactions/index.ts:1291`). The throw it replaced left the interaction
standing: after a cancel, the same uid could still be resumed — or consent submitted again — into a code.
As a result it is consumed like any other (`lib/actions/authorization/resume.ts:82` destroys it) and
delivered by the same rule.

## A delivered fault is still recorded

A fault answered by redirect never reached the handler's `captureFault`, so a fault at `/auth` was
announced on `server_error` and never stored. The module records it after the response-mode handler has
returned (`lib/shared/authorization_error_delivery.ts:174`) — a delivery that fails goes back to the
handler, which records it there, so it is one record either way — filed at status 500, and the reference
is not put in the redirect. See [[error-store-capture-sites]].

## Not covered

- The device flow's resume step stays on-page: RFC 8628 delivers a denial through polling.
- Recoverable interaction-page errors (wrong password, wrong code, an upstream sign-in that did not
  complete) never reach `resume()`.
- The authorization endpoint itself still redirects request errors before the user is authenticated,
  which RFC 9700 §4.11.2 does not allow; that is the endpoint's question, not this rule's.

## Related

- [[authentication-context-reporting]] — the second workaround this replaced (`unmet_authentication_requirements`)
- [[error-store-capture-sites]] — where faults are recorded, now including a delivered one
- [[form-action-redirect-chain]] — why a 303 off a form post must be named in `form-action`; the consent page already hands off
- [[per-origin-rate-limiting]] — the other `allow_redirect = false` error, raised before routing
