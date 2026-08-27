---
type: concept
title: "One owner per cookie family, because two schemas can name one cookie"
tags: [contract, gotcha, architecture]
sources: [oauth-server-codebase]
created: 2026-08-27
updated: 2026-08-27
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:cookie-path-scoping
      source: oauth-server-codebase
      evidence: "A cookie's Path and its attribute set are both part of what has to be restated at every write; both drifted through a second, option-less schema naming the same cookie."
      confidence: high
      status: current
---

# One owner per cookie family, because two schemas can name one cookie

A cookie's attributes are not written where the cookie's *name* is declared — they come from the
**cookie schema of the route that happens to be running**. Elysia compiles a schema's option object
into the per-request cookie jar, and `Cookie.set()` merges it under whatever the call site passes:

```js
set(config) { this.setCookie = Object.assign({ ...this.initial, value: this.value }, config) }
```

(`node_modules/elysia/dist/cookies.mjs`; `initial` is built from `validator.cookie.config` merged
with the app-level `cookie` option — `dist/compose.mjs`.) So `cookie._session.set({ value, path })`
inherits `HttpOnly`/`SameSite`/`Secure` from the schema and nothing else. **The weakest schema that
names a cookie decides what the browser stores for it.**

## Two schemas named `_session`, and only one carried attributes

- `lib/consts/param_list.ts` — `AuthorizationCookies`, guarding `/auth`, `/logout`,
  `/logout/confirm`, `/device`. Carried `httpOnly + sameSite: 'strict'`; `secure` was missing.
- `lib/interactions/index.ts` — the `/ui/*` guard, declared with **no options at all**. And this is
  the schema that matters most: `resume()` runs `sessionHandler` on *this* jar
  (`lib/interactions/index.ts` — `ctx.oidc.cookie = cookie`), so the login POST — where the
  authenticated `_session` is first issued — emitted it with no `HttpOnly`, no `SameSite` and no
  `Secure`. Every existing spec re-sent `set-cookie` by hand as a request header, so none could see
  it.

Both now build from one exported `endUserCookieAttributes` (`lib/consts/param_list.ts`), and
`expiredSessionCookie()` (`lib/shared/session.ts`) spreads it too — that clear is also issued from
the admin console's sign-out (`lib/admin/auth/login.ts`), whose jar has none of these defaults.

## Why `secure` is not the proxy's job

`fly.toml` sets `force_https = true`, which redirects a cleartext request at the edge. That is a
mitigation, not the control: without the attribute the browser is still willing to *put the cookie
on the wire* first. The admin cookie always had it (`lib/admin/auth/session.ts`), which is the
posture the end-user cookies now match. Local development is unaffected — `http://localhost` is a
trustworthy origin, so browsers store `Secure` cookies from it; a non-TLS deployment on a real
hostname is the only configuration this closes off, deliberately.

## The rule

Every cookie family gets **one** module that owns its attributes, and every write and clear derives
from it. A second literal is a second policy, and the drift is silent: the response looks correct,
the flow works end to end, and only the browser knows which attributes it kept.

Assert it on the response header, never through a hand-threaded cookie string —
`test/interaction_ui/cookie_attributes.spec.ts` and `test/admin/login_flow.spec.ts` do.

## Related

- [[cookie-path-scoping]] — the other half of a cookie's definition, same failure shape: a value
  restated at a second call site instead of derived from one owner.
- [[admin-console-signin]] — why an admin sign-out writes an end-user cookie at all.
- [[interaction-page-families]] — the `/ui/*` route family whose guard this fixes.
