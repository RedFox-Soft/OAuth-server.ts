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

## `remove()` omits `Path`, so the browser invents one

Elysia's `cookie.remove()` emits only `value`, `expires` and `maxAge` (`node_modules/elysia/dist/cookies.mjs`).
With no `Path` attribute and no global `cookie` option on the root instance
(`lib/index.ts` — `new Elysia({ strictPath: true, normalize: false })`), the browser falls back to
**RFC 6265 default-path: the directory of the request URI**. So the path a clearing cookie lands on
is decided by *which route ran*, not by which cookie was being cleared.

That is the whole defect, and it bit twice:

- **`_admin_session`** is set with `path: '/admin'` (`lib/admin/auth/session.ts`) but was cleared from
  `POST /admin/api/logout`, whose default-path is `/admin/api`. Different cookie; the live one
  survived every sign-out.
- **`_session`** was written with **no** explicit path at all (`lib/shared/session.ts`), so it landed
  on `/` when written from `/auth` and on `/logout` when written from `/logout/confirm` — one name,
  two cookies, and end-session's `cookie._session.remove()` cleared whichever one its own path named.

The neighbouring `admin_oauth` cookie was never affected, and only by luck: it is removed from
`/admin/callback`, whose default-path *is* `/admin` — the path it was set with.

## The fix is to name the path on both ends, from one constant

`lib/shared/session.ts` now exports `SESSION_COOKIE_PATH` and an `expiredSessionCookie()` derived
from it; `lib/admin/auth/session.ts` derives `expiredSessionCookieAttributes()` by spreading
`sessionCookieAttributes()`. Deriving the clearing attributes from the setting attributes is the
point — the two cannot drift apart again, which a second hand-written literal guarantees they
eventually would.

**Never clear a cookie with `remove()` in this codebase.** Set an expired cookie carrying the same
attributes it was created with.

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
- [[html-response-security-policy]] — the neighbouring per-response policy derived from one owner.
