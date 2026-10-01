---
type: concept
title: 'Untrusted redirect confirmation'
tags: [oauth, contract, architecture]
sources: [oauth-server-codebase]
created: 2026-10-01
updated: 2026-10-01
---

# Untrusted redirect confirmation

An authorization server's address is trusted, which makes it a phishing springboard. RFC 9700 §4.11.2
(repeated in OAuth 2.1 draft-16 §7.13.2) names three ways an attacker who **registers a client of their
own** can make the server forward a user to the attacker's redirect URI: a deliberately malformed request
(an invalid scope), a valid request the user declines, and a silent `prompt=none` request. It requires
the server to "take precautions" and to "only automatically redirect the user agent if it trusts the
redirection URI"; for an untrusted one it "MAY inform the user and rely on the user". Since spec 066 this
server does exactly that: for such a client, an authorization **error** is offered on a confirmation page
instead of redirected. Successful responses, and every client an operator created, are unchanged.

## Trust is provenance

`redirectUrisVouchedFor` (`lib/models/client/provenance.ts:23`) answers one question: did an operator put
these redirect URIs here? **No** for a client created by dynamic registration (`registeredDynamically`,
written by the endpoint, unsettable by the registrant) and for a client resolved from a metadata document
(stored nowhere — so "no stored record" is its definition). **Yes** for everything else, including an
operator-created client whose id is a URL: the shape of the id is not the test, the same reason
`tryFindClient` reads the store before trying a document.

This is not a local interpretation. The section's history (draft-ietf-oauth-security-topics -05 → -06,
2018) replaced an absolute ban with the trust-based SHOULD after Lodderstedt wrote that "open dynamic
client registration collides with" RFC 6749's assumption that every configured client is legit; and in
December 2025 an OAuth 2.1 editor stated the intent as: don't automatically redirect "to a redirect URI that
has been registered via unauthenticated DCR (or CIMD from an untrusted domain)". The literal "MUST always
authenticate the user first … before redirecting" read alone would forbid redirecting *any* pre-sign-in
error, which OAuth 2.1 §4.1.2.1 and OIDC Core §3.1.2.6 contradict. Of the servers surveyed
(node-oidc-provider, Keycloak, Hydra, Spring, Duende), none distinguishes these clients at the
authorization endpoint; Microsoft reported live campaigns abusing exactly this in March 2026.

## One decision point, one answer

The decision sits in `deliverAuthorizationError` (`lib/shared/authorization_error_delivery.ts:175`),
which every authorization error has passed through since spec 065 — `/auth`, `prompt=none`, a declined
consent, any terminal error on resume. The response modes **describe** an answer as well as send it
(`lib/response_modes/describe.ts`; `responseModes.describe`, `lib/response_modes/index.ts:75`): navigate
to a URL, or post fields. Sent, that is a 303 or the auto-submit page; offered, it is a link or a
button-submitted form on `confirmationPage` (`lib/interactions/confirmationPage.tsx:22`). One description,
two exits — so the confirmed answer cannot drift from the redirect's.

## The page

Plain family, no script, the error's status (as a form-post error answer has). It shows the destination
**host** and the error code — never the client's name, logo or the error description, all of which are
registrant-chosen text. A query answer is a link, not a GET form (a GET form would replace a query the
registered redirect URI may carry). It **denies framing** even though its form posts off-origin —
`denyFraming` in `htmlResponse`, see [[html-response-security-policy]] — because a framed "return" button
is a clickjacking target and a hidden-frame silent request is what it exists to stop answering.

Consequences accepted: a hidden-iframe `prompt=none` for such a client times out instead of reading
`login_required`; a JWT answer (120 s) may expire while the page is open; the OpenID conformance Dynamic
plan's `oidcc-prompt-none-not-logged-in` sees the page instead of a redirect.

## Not here

No operator "trust this document host" list (the editors' "CIMD from an untrusted domain" implies one
could exist); no reputation checks or first-use warnings, which the standard mentions as options.

## Related

- [[interaction-error-delivery]] — the single delivery rule this branches inside
- [[html-response-security-policy]] — `denyFraming`, and the one page that stays framable
- [[interaction-page-families]] — why this is a plain page
