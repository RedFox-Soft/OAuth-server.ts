---
type: concept
title: "The admin console frame: addresses, stated rights, one confirmation ladder"
tags: [architecture, contract, admin]
sources: [oauth-server-codebase]
created: 2026-10-11
updated: 2026-10-15
---

# The admin console frame: addresses, stated rights, one confirmation ladder

Since spec 100 the console names a stored bucket (`UserBucket`) a **project**, an administrator group
(`Group`) a **team**, and a bucket group (`BucketGroup`) a project's **group** of end users; the code, its
route keys (`bucket.*`, `groups`, `group`) and its page components keep the stored names. Before spec 099
the console also had a Projects page for a different thing, the old Project entity, now called a retired
project.

Until spec 079 the console was one page. `Layout.tsx` kept the current screen in `useState<PageKey>`,
drill-downs swapped a subtree, and a group switch (now a team switch) called `window.location.reload()`. So
no screen could be linked to, Back left the console, a reload or a group switch dropped the operator on the
retired projects' page, and sign-in always landed on `/admin`. Every page also reported outcomes its own way, confirmed destruction its own
way, and offered buttons the server then refused with 403.

Spec 079 is the frame the later console phases build on. The panels inside it moved to addresses but
otherwise kept their content.

## Every screen has an address

One pure route table, `ROUTES` (`lib/admin/ui/frame/routes.ts:74`), is read by both sides:

- **The server.** `GET /admin/*` (`lib/admin/index.ts:55`, handler at `:63`) renders the console at the
  requested path. It answers 404 for an address no route matches, redirects a signed-out request to
  `/admin/login?next=<address>`, and serves the one public page, `/admin/accept-invitation`, without a
  session. A mistyped `/admin/api/*` path stays a JSON 404 and is never rendered as a page.
- **Projects and teams.** A project lives at `/admin/projects/:project` and its tabs below it, its groups
  at `/admin/projects/:project/groups[/:group]`, a team at `/admin/teams[/:team]`, and a deleted project's
  history at `/admin/usage/projects/:project`; the navigation reads Projects and Teams (`SECTION_LABELS`,
  `routes.ts:476-486`). A project's applications and APIs are its tabs, route keys `bucket.applications`
  and `bucket.apis` (`routes.ts:87-98`). A project's bare address is a page of its own since spec 081, its
  Overview ([[project-workspace]]).
- **`REDIRECTS`** (`routes.ts:390-406`) send `/admin` to `/admin/projects`, and every address a page had
  before spec 100 to its new one with a 302: `/admin/buckets/…` to `/admin/projects/…`,
  `/admin/buckets/:b/user-groups[/:g]` to `/admin/projects/:b/groups[/:g]`, `/admin/groups[/:g]` to
  `/admin/teams[/:g]` and `/admin/usage/buckets/:b` to `/admin/usage/projects/:b`. The old addresses are
  derived from the table rather than listed (`formerPattern`, `routes.ts:361-375`), so no page can gain an
  address its old one misses; they must keep working because held-deprovisioning emails already sent link
  `/admin/buckets/:id/provisioning/:conn`. Between spec 099 and spec 100 `/admin` led to `/admin/buckets`;
  before spec 099, `/admin/projects` was the retired projects' page. Since spec 083 every address of the
  administrators' project, under either spelling, redirects to the matching tab of `/admin/administrators`
  (`administratorsRedirects`, `routes.ts:326-354`; [[project-sign-in-policy]]).
- **The client.** The path goes into `window.PROPS.path` and becomes the server snapshot of an in-house
  history router (`frame/router.tsx:74`). It is `useSyncExternalStore` over `pushState`/`popstate`, so the
  first client render matches the HTML.

The router is about a page of code, not react-router: about thirty addresses, no loaders, and only one
feature worth a library, which is blocking navigation while a form is dirty (`useLeaveGuard`,
`router.tsx:223`). A value only the browser has, such as Usage's stored view, is read after hydration
(`frame/hydrated.ts`) so the first frame matches the HTML.

**Sign-in returns to the address.** `safeNext` (`lib/admin/auth/next.ts:15`) admits only `/admin` or a
path under it. It refuses `//`, backslashes, control characters, dot segments (including `%2e`) and the
`/admin/api`, `/admin/login`, `/admin/signup` and `/admin/callback` subtrees (`/admin/signup` since 2026-10-20); anything else becomes `/admin`. It runs twice,
because the value travels through the provider in the `admin_oauth` cookie: once when `/admin/login`
stores it (`startSignIn` in `login.ts`) and again when the callback redirects to it (`/admin/callback` in `login.ts`).

**A team switch keeps the section.** The switcher re-reads `/admin/api/me` and replaces the address
with the current section's list. The page subtree is keyed by `activeTeamId` (`pages/Layout.tsx:346`), so
every list remounts. An entity page gives way to its list, because the entity may belong to the team just
left.

`/admin/api/me` and the shell's `window.PROPS.me` carry the same edge view, built by `meView`
(`lib/admin/me_view.ts:19-30`): `projectId`, `memberships[].teamId` and `activeTeamId`. The `AdminContext`
it is built from keeps the stored names (`bucketId`, `memberships[].groupId`, `activeGroupId`), so a
server-side reader of the context and a reader of the response see different field names for the same
facts.

**The switcher is named by what it does** (spec 085, `pages/ScopeSwitcher.tsx`):
- A member of several teams sees "Team" ("Group" until spec 100). A super administrator sees "Create in"
  with an explanation: their lists show the whole instance whatever is chosen, so the control only decides
  where new things land.
- With one team it is plain text.
- The operator's own personal team reads "Personal · Only you".
- The New project dialog chooses its team with `GroupField` (`frame/CreateDestination.tsx`, spec 087;
  labelled "Team", writing `teamId`), the header's team preselected. The retired projects' New project
  dialog, which also chose a bucket there, went with them in spec 099.

## The server states the rights

Project responses carry `can` and `blockers`, and `GET /admin/api/me` carries `can` (`createProject`,
`createTeam` since spec 100, `createBucket` and `createGroup` before; `addressForms`, an ordered list of the
address forms the caller may give a project, since spec 101, which replaced the boolean `createHost` —
[[subdomain-project-addresses]]). The predicates live in
`lib/admin/auth/can.ts` (`bucketCan` `:195`, `meCan` `:234`). Retired-project responses carried them
through `projectCan` until spec 099 removed that entity; a project's `edit` flag now also governs its
applications and APIs.
The route loaders decide through them, so there is one source: a route refuses with 403 exactly when the
stated flag is false. `test/admin/can_routes.spec.ts` checks this from both directions. Every mounted
project route is declared against a flag or a recorded exclusion, and the generated cases (five
callers × several projects) check that 403 ⇔ flag false. A 409 is a state refusal, not a
rights refusal.

`can` never depends on `viaClientId`, so an agent at `/mcp` is told the same rights as the console (the
console-parity rule, [[admin-mcp-control-plane]]). `blockers` carries counts, never names
(`withRights`, `lib/admin/buckets/routes.ts:494-523`): `addressable`, `dependents` (applications, identity providers and
provisioning connections) and `accounts`, each null where it could not change this caller's answer. Until
spec 099 `blockers.usedByProjects` named the retired projects using a bucket, filtered to those the caller
could reach so another tenant's project names never leaked.

The console has two answers (`frame/rights.tsx`):

- **No right:** the control is hidden.
- **The right, but state blocks it:** the control is disabled and the reason is written beside it. For
  example, the applications, providers and connections that keep an owner from changing a project's address.
  A tooltip alone is not enough.

`frame/can.ts` reads a missing flag as allowed. The server still refuses, so a gap costs a 403, never a
hidden control.

## One confirmation ladder

`ACTIONS` (`frame/actions.ts:29`) classifies every act the console takes:

| Class | When | Mechanism |
|---|---|---|
| C0 | Creating, editing, enabling | Nothing |
| C1 | Small, reversible | A plain question (`useConfirm`) |
| C2 | Ends access, revokes, replaces, or is irreversible for one object | A danger question with Cancel focused and the consequences listed |
| C3 | Destroys an unbounded set, or a key | `ConfirmDestruction` with a typed word: `delete`, `retire` or `release` (plus, since spec 084, an optional `acknowledgement` checkbox the release uses) |
| C4 | Only the server knows the full list | `PreviewConfirm`: preview first, then commit (a project's move or address change, the faults purge; a retired project's bucket change from spec 085 until 099) |

The table is the product decision; the components are mechanics. `useConfirm` refuses C3 and C4 ids, and
answers no while another confirmation is open, so a double click cannot stack two dialogs.
`test/admin/console_frame.spec.ts` keeps the table and the screens in step: every C1 and C2 id must be asked
somewhere under `lib/admin/ui/`. Since spec 084 that includes `.ts` files, because the provider and connection
action hooks are plain TypeScript.

A value the server returns only once (a client secret, a provisioning secret or token) is shown through
`frame/SecretReveal.tsx`. It is masked until asked for, offers one Copy, and holds its surface until the
operator ticks that it is stored. It always sits inside the surface that produced it, never in a window
stacked on another ([[provider-connection-group-pages]]).

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
- [[team-ownership]] — membership as the only grant, now stated as `can`
- [[container-ownership-transfer]] — the two move routes, C4 in the console
- [[admin-mcp-control-plane]] — why `can` must not depend on the calling client
