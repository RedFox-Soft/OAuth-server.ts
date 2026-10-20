---
type: concept
title: 'The application page: creating an application from a situation and connecting it'
tags: [architecture, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-10-20
updated: 2026-10-20
graph:
  node_type: concept
  relationships:
    - predicate: relates_to
      object: concept:admin-console-frame
    - predicate: relates_to
      object: concept:mcp-server-authorization
    - predicate: relates_to
      object: concept:admin-mcp-control-plane
    - predicate: relates_to
      object: concept:prompt-create
---

# The application page: creating an application from a situation and connecting it

Spec 107 (2026-10-20) replaced the console's protocol-raw "New client" modal with a choice of situation and gave
every application a page of its own. It came out of a walk of the FoxAuth Cloud path as a newcomer: the form asked
for grant types and an auth method, the only thing after creation was a "Client created." toast, the issuer lived on
another tab, there was no sign-out redirect field, and a new project — closed to sign-ups and empty (specs/083) —
had nobody to sign in. Market research and four critiques are in `specs/app-connect-research/` (not tracked).

## Situations live in the console only

`lib/admin/ui/pages/applications/situations.ts` declares the situations — web app with a server, single-page app,
mobile/desktop/CLI, device without a keyboard, service calling your API, "My MCP server or API", and "Configure
everything yourself". A situation only **expands into the existing create-route fields** (`expand(devAddress)`); the
server never learns which one was chosen and nothing stores it. Rejected alternative: a `template` input on the admin
route/MCP tool — a later change to a template's defaults would silently change what scripts and agents create, and a
second creation path is what broke Zitadel's and authentik's consoles. The page describes an application from its
stored settings (`describe()` in `blocks.ts`), because one an agent created has no situation.

Defaults worth knowing: a single-page app stays `applicationType: web` (the public-client refresh cap reads the
type); a native app registers `http://127.0.0.1/callback`, accepted on any port (RFC 8252 §7.3) — `localhost` is a
different address; templates add `refresh_token`, but a refresh token is issued only when `offline_access` is
requested with consent, which the Connect tab says. "My MCP server or API" creates no application: an MCP server is a
declared resource and the agent host gets its own identity (CIMD). It opens the APIs tab with `?declare=1`.
`test/applications/situations.spec.ts` proves every expansion is accepted by the real route and stored as promised.

## One page, one edit surface

Routes `bucket.application` (`/admin/projects/:project/applications/:client`, Connect) and
`bucket.application.settings` (`…/settings`) in `lib/admin/ui/frame/routes.ts`, dispatched through `APPLICATION_TABS`
in `Layout.tsx`. `ApplicationPage.tsx` follows the provisioning connection page (spec 084). **The edit modal is
gone**: Settings (`SettingsTab.tsx` over `ClientFormFields.tsx`) is the only place an application's settings are
edited, and the list only finds, creates, rotates and deletes. `clientForm.ts` (lowercase) holds the form model;
the component file is `ClientFormFields.tsx` because Windows treats `ClientForm.tsx` and `clientForm.ts` as one name.

The one-time secret travels from the creation step to the page in `handOff.ts`: in this tab's memory, never in the
address or storage. It is **peeked in a state initialiser and forgotten in an effect** — the console runs in
`StrictMode`, which calls an initialiser twice in development, so a read that also deleted would hand the page nothing.

## What the server states

- `connection` on client create, get and patch (`lib/admin/clients/connection.ts`): issuer, discovery address,
  endpoints (the `*_endpoint` members and `jwks_uri` of the project's **served** discovery document —
  `openidConfiguration`, exported from `lib/actions/discovery.ts`, so gating and operator overrides apply),
  `signInPageUrl` (the project's account page, spec 095 — its real sign-in page, with no authorization run for the
  application), and `lastUsed`. All issuer-derived values are null for a project without an address
  (`addressing()`, now in `lib/configs/issuer.ts`). MCP tools re-dispatch these routes, so an agent gets the same
  object (`test/mcp/client_connection.spec.ts` for path, subdomain and hostname projects).
- `hasSecret: Boolean(client.clientSecret)` — the auth method answered wrongly both ways (`none` with a symmetric
  algorithm holds a secret; `private_key_jwt` does not). Rotate is offered only when it is true.
- A PATCH that gives an application a secret returns it once as `secret`, like the create does.
- `agentClients` on the project (`lib/admin/buckets/agent_clients.ts`) and `connection` on each declared resource
  (`lib/resources/connection.ts`: issuer, exact audience, RFC 9728 metadata, metadata URL, challenge). Computed on the
  server because the console's CSP is `connect-src 'self'`: it cannot read a subdomain or hostname project's
  discovery. The values are public anyway, so stating them to a tenant leaks no instance setting.

## Last used: `ClientUsage`

A model area keyed by client (`lib/models/client/usage.ts`): `{ clientId, firstUsedAt, lastUsedAt }` and nothing
about the person. `noteClientUse` is called beside `noteActivity` in `executeGrant`, **never awaited**, for every
grant including `client_credentials`; a per-instance LRU skips a client written in the last 60 s, so the database cost
grows with applications, not traffic. Written **only for a stored, operator-created client** — self-registered and URL
(CIMD) clients would be an unbounded set nobody has a page for, and the RFC 7592 delete path does not sweep
client-owned areas. Client-owned, so the admin delete cascade removes it; permanent (no ttl). Grants were rejected as
the source (they expire and the status would flip back), as were activity marks (they carry no client).

## Who can sign in

`WhoCanSignIn.tsx` reads the project and its summary and, when nobody can sign in, offers **Add a test user** (the
existing users route with `invite: true` to the caller's own address) and **Open sign-ups** (the project PATCH through
`useSignInSave`, extracted from the Sign-in tab so both share the preview-and-confirm). No new route, so no new MCP
tool, audit action or rights row.

## What the Connect tab will not do

No library code (it rots — openid-client v5 → v6 was a rewrite; code lives in the three-language docs), no console
"try sign-in" that runs an authorization for the real client (a code the console's PKCE verifier holds proves
nothing the app does, and accepting codes it never asked for would be a login-CSRF hole), and no secret in the agent
copy block or under a `NEXT_PUBLIC_`/`VITE_`-style name (`test/applications/blocks.spec.ts`).
