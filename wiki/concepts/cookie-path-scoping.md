---
type: concept
title: "A cookie's Path is part of its identity"
tags: [contract, gotcha, architecture]
sources: [oauth-server-codebase]
created: 2026-08-27
updated: 2026-08-27
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:admin-console-signin
      source: oauth-server-codebase
      evidence: "The console's sign-out cleared _admin_session from /admin/api, whose default-path is /admin/api, while the live cookie was stored under Path=/admin."
      confidence: high
      status: current
---

# A cookie's Path is part of its identity

`(name, domain, path)` identifies a cookie, not `name` alone. A `Set-Cookie` that expires a name
under one path leaves an identically-named cookie under another path completely untouched — and the
browser keeps sending the survivor. Nothing reports this: the response looks correct, the store row
is genuinely gone, and only the browser knows the cookie is still there.

## `remove()` never names the path the cookie was set with

Elysia's `cookie.remove()` passes only `value`, `expires` and `maxAge` to `set()`
(`node_modules/elysia/dist/cookies.mjs`), so the path comes from whatever the route's cookie
*schema* supplies — never from the cookie being cleared. Measured on elysia 1.4.29, two ways:

- a route **with** a cookie schema (options or not) emits `Path=/`, because the compiled cookie
  options default it (`node_modules/elysia/dist/compose.mjs` — `get("path", "/")`);
- a route with **no** schema at all also emitted `Path=/` in this version, rather than leaving the
  attribute off for the browser to fill in from RFC 6265's default-path.

Either way the path a clearing cookie lands on has nothing to do with which cookie is being cleared.
(An earlier revision of this note blamed the browser's default-path; the observable outcome — a
clear that names a different cookie — is the same, the mechanism is not.)

That is the whole defect, and it has now bitten three times:

- **`_admin_session`** is set with `path: '/admin'` (`lib/admin/auth/session.ts`) but was cleared from
  `POST /admin/api/logout`, whose default-path is `/admin/api`. Different cookie; the live one
  survived every sign-out.
- **`_session`** was written with **no** explicit path at all (`lib/shared/session.ts`), so it landed
  on `/` when written from `/auth` and on `/logout` when written from `/logout/confirm` — one name,
  two cookies, and end-session's `cookie._session.remove()` cleared whichever one its own path named.

- **`_interaction`** is set with `path: /ui/${uid}` (`lib/actions/authorization/interactions.ts`) and
  was cleared with `remove()` from `resume()` and `device_resume` (`lib/interactions/index.ts`) — so
  every clear went out as `Path=/` and the real cookie survived login, consent, and the device flow.
  It survived this note's first writing, which is the argument for the rule below being mechanical
  rather than remembered.

The neighbouring `admin_oauth` cookie is removed from `/admin/callback` and happens not to matter:
it is a short-lived leg-one cookie whose value is single-use, so a survivor buys nothing.

## The fix is to name the path on both ends, from one constant

`lib/shared/session.ts` now exports `SESSION_COOKIE_PATH` and an `expiredSessionCookie()` derived
from it; `lib/admin/auth/session.ts` derives `expiredSessionCookieAttributes()` by spreading
`sessionCookieAttributes()`. Deriving the clearing attributes from the setting attributes is the
point — the two cannot drift apart again, which a second hand-written literal guarantees they
eventually would.

`lib/actions/authorization/interactions.ts` now owns the interaction cookie's identity the same way:
`interactionCookiePath(uid)` is used to set the cookie and `expiredInteractionCookie(uid)` to clear
it, so the two cannot name different cookies.

**Never clear a cookie with `remove()` in this codebase.** Set an expired cookie carrying the same
attributes it was created with, derived from the same constant that set it.

## Why the existing test could not see it

`test/admin/login_flow.spec.ts` asserted that `/admin/api/me` answered 401 after logout — but it
re-sent the *same* cookie string by hand on every request. A hand-driven cookie string is not a
cookie jar: it cannot observe a `Set-Cookie` that fails to apply, so a test can pass while the
browser stays signed in. Asserting on the response's `Set-Cookie` attributes directly is what closes
that gap, and the same blindness applies to any spec that threads cookies through headers manually.

## Related

- [[admin-console-signin]] — the sign-out this broke, and why the console must end two sessions.
- [[form-action-redirect-chain]] — the other defect only a real browser's rules make visible; the
  same lesson about headless fetch scripts standing in for browsers.
- [[end-user-cookie-attributes]] — the other half of a cookie's definition, and the second schema
  that was quietly writing `_session` with no attributes at all.
- [[html-response-security-policy]] — the neighbouring per-response policy derived from one owner.
