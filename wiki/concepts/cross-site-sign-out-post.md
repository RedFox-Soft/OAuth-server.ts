---
type: concept
title: "A cross-site sign-out post is bounced once, because Lax withholds the cookie"
tags: [oidc, gotcha, contract]
sources: [oauth-server-codebase]
created: 2026-09-30
updated: 2026-09-30
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:end-user-cookie-attributes
      source: oauth-server-codebase
      evidence: "A relying party's sign-out form is a cross-site POST, and the sign-in cookie is `SameSite=Lax`, so the browser withholds it"
      confidence: high
      status: current
---

# A cross-site sign-out post is bounced once, because Lax withholds the cookie

OpenID Connect RP-Initiated Logout 1.0 §2 requires the end-session endpoint to accept POST as well as
GET. `POST /logout` exists since spec 064 (`lib/actions/end_session.ts:233`), and it is **not** the GET
handler mounted for a second method. It cannot be, and the reason is the cookie.

## Why the obvious implementation signs people out wrongly

The end-user session cookie is `SameSite=Lax` ([[end-user-cookie-attributes]]). `Lax` sends the cookie
on a cross-site top-level **GET** and withholds it on a cross-site **POST** — and a relying party's
sign-out form is a cross-site POST by definition. Handled directly, such a post:

1. arrives with no session cookie, so `sessionHandler` (`lib/shared/session.ts:55`) starts an empty
   session;
2. writes the sign-out state onto it, which marks it touched;
3. saves it and sets the session cookie to the **new, empty** session — a `Set-Cookie` on the
   response is honoured whatever site the request came from, so this overwrites the real one;
4. finds no account on it and answers "You have been signed out".

The user is told they are signed out; the browser has lost its sign-in; nothing happened on the server:
the real session still exists, no back-channel logout was sent, no grant was revoked. A suite that
drives sign-out by GET never sees any of it, which is how the missing method went unnoticed.

## What the endpoint does instead

A POST carrying **no session cookie for the addressed bucket** and no `_resubmitted` marker is
answered with the `form_post` self-submitting page (`lib/html/formPost.tsx`), re-posting the same
fields plus `_resubmitted=1` to the same address (`lib/actions/end_session.ts:263`). That second post is
initiated by a page on this server's own origin, so it is same-site and the browser sends the `Lax`
cookie with it; from there it is handled exactly as the GET is (`endSession`,
`lib/actions/end_session.ts:81`). Nothing about the session is read or written on the first leg.

A resubmission that still carries no cookie has genuinely no sign-in and proceeds as a sign-out with
no session — the outcome a GET without a session already had.

## The choices that were rejected, and why they will look tempting again

- **303 from the POST to `GET /logout?…`.** A top-level GET carries `Lax` cookies even cross-site, so
  it works — and puts `id_token_hint` back into the URL: history, proxy and server logs, URL length.
  Keeping the hint out of the URL is the main reason a relying party posts at all.
- **`SameSite=None` on the session cookie.** Removes the CSRF boundary `Lax` carries.
- **`Sec-Fetch-Site` as the loop guard.** The browser reports `cross-site` on the first leg and
  `same-origin` on the resubmission, but a browser that does not send the header would bounce
  forever. The body marker bounds the exchange to one round trip whatever the browser does, and makes
  the header unnecessary.
- **Adding the POST to `logoutAction`.** That instance's `noQueryDup` derive and query guard apply to
  every route registered after them, so the POST would validate a query string it never reads. It is
  its own instance (`logoutPostAction`), mounted beside the GET at both addresses in `lib/index.ts`.

## Two details that are easy to undo

- `parse: 'urlencoded'` *forces* the form decoder on any body, so the handler checks the media type
  itself; without that a `text/plain` body shaped like a form is accepted.
- `_resubmitted` is declared in the POST's body schema, because the schema is closed: undeclared, the
  resubmission itself would be refused as an unexpected property.

Proved by `test/end_session/end_session_post.spec.ts`, the "when the browser withholds the sign-in
cookie" group in particular.
