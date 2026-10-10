---
type: concept
title: "The admin console frame: addresses, stated rights, one confirmation ladder"
tags: [architecture, contract, admin]
sources: [oauth-server-codebase]
created: 2026-10-11
updated: 2026-10-11
---

# The admin console frame: addresses, stated rights, one confirmation ladder

Until spec 079 the console was one page. `Layout.tsx` kept the current screen in `useState<PageKey>`,
drill-downs swapped a subtree, and a group switch called `window.location.reload()`. So no screen could be
linked to, Back left the console, a reload or a group switch dropped the operator on Projects, and sign-in
always landed on `/admin`. Every page also reported outcomes its own way, confirmed destruction its own
way, and offered buttons the server then refused with 403.

Spec 079 is the frame the later console phases build on. The panels inside it moved to addresses but
otherwise kept their content.

## Every screen has an address

One pure route table, `ROUTES` (`lib/admin/ui/frame/routes.ts:57`), is read by both sides:

- **The server.** `GET /admin/*` (`lib/admin/index.ts:54`, handler at `:62`) renders the console at the
  requested path. It answers 404 for an address no route matches, redirects a signed-out request to
  `/admin/login?next=<address>`, and serves the one public page, `/admin/accept-invitation`, without a
  session. A mistyped `/admin/api/*` path stays a JSON 404 and is never rendered as a page. `REDIRECTS`
  (`routes.ts:156`) send `/admin` to `/admin/projects`, and an entity's bare address to its first tab.
- **The client.** The path goes into `window.PROPS.path` and becomes the server snapshot of an in-house
  history router (`frame/router.tsx:74`). It is `useSyncExternalStore` over `pushState`/`popstate`, so the
  first client render matches the HTML.

The router is about a page of code, not react-router: about thirty addresses, no loaders, and only one
feature worth a library, which is blocking navigation while a form is dirty (`useLeaveGuard`,
`router.tsx:223`). A value only the browser has, such as Usage's stored view, is read after hydration
(`frame/hydrated.ts`) so the first frame matches the HTML.

**Sign-in returns to the address.** `safeNext` (`lib/admin/auth/next.ts:15`) admits only `/admin` or a
path under it. It refuses `//`, backslashes, control characters, dot segments (including `%2e`) and the
`/admin/api`, `/admin/login` and `/admin/callback` subtrees; anything else becomes `/admin`. It runs twice,
because the value travels through the provider in the `admin_oauth` cookie: once when `/admin/login`
stores it (`login.ts:48`) and again when the callback redirects to it (`login.ts:148`).

**A group switch keeps the section.** The switcher re-reads `/admin/api/me` and replaces the address
with the current section's list. The page subtree is keyed by `activeGroupId`, so every list remounts.
An entity page gives way to its list, because the entity may belong to the group just left.

## The server states the rights

Bucket and project responses carry `can` and `blockers`, and `GET /admin/api/me` carries `can`. The
predicates live in `lib/admin/auth/can.ts` (`bucketCan` `:113`, `projectCan` `:196`, `meCan` `:213`).
The route loaders decide through them, so there is one source: a route refuses with 403 exactly when the
stated flag is false. `test/admin/can_routes.spec.ts` checks this from both directions. Every mounted
bucket and project route is declared against a flag or a recorded exclusion, and the generated cases (five
callers × several buckets or projects) check that 403 ⇔ flag false. A 409 is a state refusal, not a
rights refusal.

`can` never depends on `viaClientId`, so an agent at `/mcp` is told the same rights as the console (the
console-parity rule, [[admin-mcp-control-plane]]). `blockers.usedByProjects` lists only projects the caller
can reach, so another tenant's project names never leak.

The console has two answers (`frame/rights.tsx`):

- **No right:** the control is hidden.
- **The right, but state blocks it:** the control is disabled and the reason is written beside it. For
  example, "Moves with its bucket" or the projects using a bucket. A tooltip alone is not enough.

`frame/can.ts` reads a missing flag as allowed. The server still refuses, so a gap costs a 403, never a
hidden control.

## One confirmation ladder

`ACTIONS` (`frame/actions.ts:29`) classifies every act the console takes:

| Class | When | Mechanism |
|---|---|---|
| C0 | Creating, editing, enabling | Nothing |
| C1 | Small, reversible | A plain question (`useConfirm`) |
| C2 | Ends access, revokes, replaces, or is irreversible for one object | A danger question with Cancel focused and the consequences listed |
| C3 | Destroys an unbounded set, or a key | `ConfirmDestruction` with a typed word: `delete`, `retire` or `release` |
| C4 | Only the server knows the full list | `PreviewConfirm`: preview first, then commit (a move, the faults purge) |

The table is the product decision; the components are mechanics. `useConfirm` refuses C3 and C4 ids, and
answers no while another confirmation is open, so a double click cannot stack two dialogs.

## One feedback model

Outcomes go through antd's `App` context (`useFeedback`, `frame/feedback.tsx:36`). `ConsoleRoot`
(`frame/ConsoleRoot.tsx:17`) mounts it once for the server render and the hydrate.

- **Success:** one past-tense sentence naming the object.
- **Refusal:** the server's message, verbatim. If the body names a `field` and a form is passed, the message
  lands on that field.
- **Fault (5xx):** a notification that stays until dismissed, with the error reference copyable.

`request()` (`frame/request.ts`) is the single fetch helper. It never throws, and a 401 sends the browser to
sign-in with `next`. A rejection nobody awaited is reported through the same channel by the bridge in
`adminClient.tsx`.

The static `message`/`notification` imports and `Modal.confirm/info/success/error/warning` are lint errors
under `lib/admin/ui/**` (`eslint.config.ts:114`). They render outside the console's theme and, under the
zeroRuntime build, generate runtime CSS that the strict style policy keeps out.

## The 422 no longer echoes the submission

The admin plane's validation handler used to return Elysia's serialised error, including `found`, the
whole submitted body. A rejected `POST /admin/api/admins` sent the typed password back. Elysia's own
summary also quotes the offending value ("but found: …"). The handler (`lib/admin/routes.ts:43`) now answers
`{ error: 'invalid_request', message, field }` from the first violation in TypeBox's wording. See
[[admin-plane-error-shape]].

## The invitation page

Invitation emails linked to `/admin/accept-invitation`, which did not exist (404). It is now the console's
one public page. A related bug was fixed in the accept route: it claimed the single-use token *before*
checking whether a new account needs a password. A new invitee who submitted without one spent the
invitation on the refusal. The check now runs first (`lib/admin/groups/accept.ts:49`).

## Related

- [[admin-plane-error-shape]] — the error body, now with `field`
- [[group-ownership]] — membership as the only grant, now stated as `can`
- [[container-ownership-transfer]] — the two move routes, C4 in the console
- [[admin-mcp-control-plane]] — why `can` must not depend on the calling client
