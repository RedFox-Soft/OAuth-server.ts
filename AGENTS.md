# OAuth-server.ts — Agent Guide

This file holds the rules. The reasons, the history and the traps behind them live in the wiki at
`wiki/` — each rule below names the page to read **before changing** that area.

## What this project is

A standards-compliant OAuth 2.1 / OpenID Connect authorization server written in TypeScript, running on [Bun](https://bun.sh/) + [Elysia](https://elysiajs.com/). Downstream apps import the `elysia` app and mount it; there is no init step — importing is what boots it.

It is three surfaces on one core, and knowing which one you are in matters more than anything else in this file:

1. **The protocol surface** — the OAuth/OIDC endpoints. Implemented: Authorization Code + PKCE, Client Credentials, Refresh Token, Device Flow, CIBA, PAR (RFC 9126), DPoP (RFC 9449), Resource Indicators (RFC 8707), token introspection/revocation, dynamic client registration, OIDC Core 1.0.
2. **The administrative control plane** (`lib/admin/`) — a management API and a server-rendered console for projects, OAuth clients, administrators, user buckets, end-users, upstream federation providers, settings, SMTP, signing keys and an immutable audit trail. Reachable at `/admin`, authenticated by an OIDC flow against this server's own issuer.
3. **The MCP control plane** (`lib/mcp/`) — the same management API, served to an AI agent at `POST /mcp` as an OAuth 2.1 protected resource. Off by default (`mcp.enabled`).

A fourth thing follows from the first: the server is also an authorization server **for other people's MCP servers**. An administrator declares a third-party MCP server as a protected resource of a project (`lib/resources/`, `lib/admin/resources/`) and this server mints audience-bound tokens for it — data, not code, so no source change and no restart. See `wiki/concepts/mcp-server-authorization.md`.

The third exists because the constitution requires an agent to be able to do what a human operator can, with no privileged back door. It is built as a _consumer_ of the second: a tool rebuilds the HTTP request the console would have sent and dispatches it into the real admin routes in-process, so the permission checks, validation, invariants and audit write are the console's own code rather than a copy kept in step by review. If you are adding an administrative operation, add it to the admin routes; the parity guard will then tell you to publish it, exclude it, or explain yourself.

---

## Runtime & toolchain

| Tool                       | Version    | Purpose                                              |
| -------------------------- | ---------- | ---------------------------------------------------- |
| Bun                        | latest     | Runtime, package manager, test runner, bundler       |
| TypeScript                 | 6.x        | Strict mode; `paths` aliases `lib/` and `test/`      |
| Elysia                     | 1.4.x      | HTTP framework                                       |
| ESLint + typescript-eslint | 10.x / 8.x | Linting (`bun run format` applies fixes)             |
| Prettier                   | 3.x        | Formatting — tabs, single quotes, no trailing commas |

---

## Common commands

```sh
bun start               # start server (port 3000)
bun test                # run all tests
bun run format          # lint + auto-fix (eslint --fix)
bun run build           # bundle React login client → public/
bun run watch           # watch-mode bundle for loginClient.tsx
bun run db:setup        # provision MongoDB (idempotent)
bun run db:setup:pg     # provision PostgreSQL (idempotent; --check reports only)
bun run db:migrate      # apply declared schema migrations (--plan to gate a deploy)
```

`bun test` never touches a real database: it runs on the in-memory adapter, and the two verification
scripts under `database/` are scripts, not specs, precisely so the default run cannot reach them.

---

## Environment variables

| Variable        | Required       | Description                                                |
| --------------- | -------------- | ---------------------------------------------------------- |
| `ISSUER`        | yes            | Canonical server URL (e.g. `https://auth.example.com`)     |
| `MONGODB_URI`   | one of the two | MongoDB connection string — and what selects MongoDB       |
| `DATABASE_NAME` | with MongoDB   | MongoDB database name                                      |
| `POSTGRES_URL`  | one of the two | PostgreSQL connection string — and what selects PostgreSQL |
| `NODE_ENV`      | test only      | Set to `test` to use in-memory adapter                     |

- **Exactly one connection string may be set**; both is refused at startup, neither selects the
  in-memory adapter (`lib/adapters/selectBackend.ts`). Bun loads `.env` and `.env.local` on its own, so
  a script that must run hermetically deletes all three datastore variables. The test suite loads
  `.env.test`. → `wiki/concepts/postgresql-backend.md`
- **Signing keys are not an environment variable.** They live in `jwksStore`, provisioned by
  `db:setup`/`db:setup:pg`. → `wiki/concepts/signing-keys.md`
- **Nothing is seeded at boot.** The console's records come from the provisioning scripts, which must be
  re-run after an upgrade; seeded values are declared once in `lib/consts/admin_seed.ts`.
  → `wiki/concepts/admin-provisioning.md`

---

## Architecture

```
lib/
  index.ts              ← library entry: exports elysia, errors, eventBus, interactionPolicy
  actions/              ← per-endpoint request handlers (operate on `oidc`, the OIDCContext)
    authorization/      ← authorization endpoint pipeline (validate → interact → respond)
    grants/             ← grant type handlers (auth_code, refresh_token, device, ciba)
  models/               ← AccessToken, RefreshToken, IdToken, Grant, Session, …
    client/             ← validate, register, projection, types, checks, secret, sector, keys, schema
  addon/                ← overridable behaviour functions; index.ts is the single import seam
  helpers/              ← JWT, crypto, claims, validation utilities; errors.ts
  plugins/              ← Elysia plugins: noCache, noQueryDup, auth, feature gate, rate limit, …
  response_modes/       ← query, fragment, form_post, JWT response modes
  adapters/             ← mongodb/, postgres/, memory/ behind one contract; selectBackend.ts chooses
  migrations/           ← schema-migration state, runner, lease, startup gate (both backends)
  configs/              ← application.ts (ApplicationConfig), clientBase.ts, keys, algorithm lists
  consts/               ← import-free declarations: storage inventory, migrations, client attributes, …
  interactions/         ← login/consent/registration UI endpoints (React + Ant Design)
  shared/               ← session, the shared onError, token auth, client notifications, resource validation
  resources/            ← declared protected resources: canonical form, matching, descriptors
  client_metadata_document/ ← a client_id that is a URL: form rules, SSRF-bounded fetch, cache
  admin/                ← the administrative control plane
    routes.ts           ← THE admin API route set; mounted by the console and by lib/mcp/dispatch.ts
    auth/rbac.ts        ← session cookie OR an MCP-audience bearer token → one AdminContext
    audit/              ← append-only trail; written before the mutation, inside the handler
  mcp/                  ← catalogue.ts (published tools), dispatch.ts, confirm.ts (two-call gate)
  error_store/          ← the one place a fault becomes a record (capture.ts is the choke point)
  sentry/               ← optional outbound reporting; registers NO Elysia hook
database/               ← provisioning (mongodb.ts, postgres.ts), migrate.ts, real-DB verify scripts
test/                   ← test_helper.ts bootstrap; one dir per feature with *.config.ts + *.spec.ts
```

### Rules by area

Each rule is the part that is easy to break. Read the named page before changing the area.

- **Action pipeline** — handlers take `OIDCContext` directly as `oidc` and **return** their response;
  there is no `{ oidc }` wrapper anywhere. Every extension function, interaction-policy check and
  request-scoped event receives the context itself, first. → `entities/addon-registry.md`,
  `entities/event-bus.md`
- **Errors** — throw an `OIDCProviderError` subclass (`lib/helpers/errors.ts`); one shared `onError`
  (`lib/shared/authorization_error_handler.ts`) formats every one. → `admin-plane-error-shape.md`
- **Configuration** — every setting lives on exactly one of three surfaces: `ApplicationConfig`
  (flat dotted keys, applied to the running process on save), `ClientDefaults` (camelCase only), or
  `lib/addon/*` (behaviour). Import `configuration` from `lib/configs/application.ts`, never off the
  provider. A module that caches something derived from a setting registers an invalidator with
  `onSettingsApplied`. → `feature-flag-gating.md`, `settings-console-descriptor.md`
- **Behaviour functions** — import the accessor from `lib/addon/index.ts`, never the implementation;
  override through `addons.override`. An empty addon body is an extension seam, not dead code.
  → `entities/addon-registry.md`, `override-seams-vs-dead-code.md`
- **Storage** — all persistence goes through the adapter contract; declare every area in
  `lib/consts/storage_inventory.ts` and every intended backend difference in
  `lib/consts/storage_divergences.ts`. Importing `lib/adapters/postgres/` opens no connection, and a
  jsonb column is written as an object, never `JSON.stringify(...)`. → `postgresql-backend.md`,
  `mongodb-test-fidelity.md`
- **Schema migrations** — declared in `lib/consts/migrations.ts`, applied by `bun run db:migrate`;
  startup refuses a database that is behind, ahead or diverged, and never migrates it itself. A
  migration must be safe to apply twice. → `postgresql-backend.md`
- **Persisted models** — only the keys a model's TypeBox schema declares are stored; add the field to
  the schema. Read model fields through `.payload`. Use `tryFind` where absence is handled and `find`
  where it is not. → `token-payload-access-contract.md`
- **Signing keys** — import `keystore`/`publicJWKS` from `lib/configs/keystore.ts`, which stays a leaf
  module. → `signing-keys.md`, `model-graph-import-order.md`
- **Clients** — a client is a validated plain object read from `adapter('Client')` on every
  resolution; there is no boot-time `clients` option. A URL `client_id` may resolve to a metadata
  document, and that branch must stay after the adapter read. Registration attributes are declared once,
  in `lib/consts/client_attributes.ts`, and kept flat. A resolved client is frozen data: use the functions
  in `lib/models/client.ts`, read key material through `clientKeys(client)`, write only through
  `registerClient`, and in a test change the stored record (`changeClient`), never the object.
  → `client-identity-from-database.md`,
  `client-registration-attributes.md`, `mcp-server-authorization.md`
- **Buckets** — a bucket is addressed by a path segment or a hostname, never both, and is its own
  issuer. The request host is read only by `hostOfRequest`, never from `X-Forwarded-Host`. Which bucket
  a sign-in uses is `resolveBucketForRequest`, and every caller passes the resource it has.
  → `bucket-is-an-issuer.md`, `cookie-path-scoping.md`, `account-resolution.md`
- **Ownership** — a group owns every project and bucket, and membership is the only grant of access;
  instance-wide things stay super-admin-only. → `group-ownership.md`
- **Audit** — a mutating admin route records audit-first, after authorization, inside the handler.
  → `admin-audit-trail.md`
- **Error store** — only defects (5xx) are recorded, from two capture sites; recording never blocks a
  request; the read surface is not flag-gated. → `error-store-capture-sites.md`,
  `error-store-is-not-flag-gated.md`
- **Sentry** — reporting is off the request path: `lib/sentry/` mounts nothing into Elysia, and
  `@sentry/elysia` is deliberately not a dependency. → `sentry-plugin-not-used.md`
- **Interaction screens** — a page is either the antd shell (inside an interaction) or plain and
  self-contained (opened from an email, no script); which one is not a style choice.
  → `interaction-page-families.md`, `end-user-onboarding.md`

Pages are under `wiki/concepts/` unless the path says otherwise.

---

## Testing

**Read [`test/RULES.md`](test/RULES.md) before adding a test, and use its checklist when reviewing
one.** In one line: a test proves a User Case or a Security Invariant, never that the code is the code
it is — and a test that proves neither is deleted, not reviewed. That file also holds the mechanics:
Bun matchers with Sinon (no Chai), the `*.config.ts` named exports, `bootstrap(import.meta.url)`, and
what `test/preload.ts` guarantees for every spec (a 20 s bound, no real network).

---

## Adding a new grant type

1. Create `lib/actions/grants/<name>.ts` implementing the handler.
2. Register it in `lib/actions/token.ts` grant dispatch map.
3. Add a feature flag in `lib/configs/` if it should be opt-in.
4. Declare a storage area in `lib/consts/storage_inventory.ts` if the grant needs persistence — both provisioning scripts read it, and the drift guard fails until it is there.
5. Write tests under `test/<name>/` with a matching `*.config.ts`.
6. Correct any wiki page the grant falsifies, and add one if it carries a decision worth keeping. No guard fails for this — see **LLM Wiki** below.

## Adding an administrative operation

The admin routes are the definition; the MCP surface follows from them. Read
`wiki/concepts/admin-mcp-control-plane.md` before changing anything in `lib/mcp/`.

1. Add the route to a group under `lib/admin/<group>/routes.ts`, with its body schema in the group's
   `schema.ts` — **not** inline, because `lib/mcp/catalogue.ts` imports schema modules and must never
   import a route module (a route module reaches a db module that connects at import time).
2. If it mutates, add it to `lib/consts/admin_audit_routes.ts` and call `recordAdminAudit` inside the
   handler, after authorization. The only escape is `excludedAdminRoutes`, for a route that changes the
   caller's own session and no managed entity.
3. Publish it as a tool in `lib/mcp/catalogue.ts`, or name it in `excludedConsoleOperations` with the
   reason.
4. Classify a destructive or instance-wide operation as `high`; it is then gated automatically.
5. Run `bun test test/mcp/ test/admin/` — the parity, audit-classification, argument-collision and
   secrecy guards will tell you what you missed.
6. Correct any wiki page the operation falsifies. Nothing fails if you skip it.

## Adding a new endpoint

1. Create `lib/actions/<name>.ts` with an action pipeline.
2. Mount the route in the Elysia app in `lib/index.ts`.
3. Expose it in the OIDC discovery document (`lib/actions/discovery.ts`).
4. Protect it with the `auth` plugin if it requires client authentication.
5. If it takes authorization-request parameters, mount `ignoreUnknownParams(<its body/query schema>)`
   and add it to the table in `test/unknown_parameters/`; a parameter you mean to **refuse** must be
   declared with `refusedParam(name)`. Nothing fails if you forget.
   → `wiki/concepts/unknown-request-parameters.md`
6. Correct any wiki page the endpoint falsifies, and add one if it carries a decision worth keeping.

## The website

`website/` is the public site (foxauth.dev), an independent Astro project with no test suite by
decision. **Read [`website/README.md`](website/README.md) before changing it.** Two rules reach back
into this repository: reference pages are generated — document a setting in
`lib/admin/settings/catalog.ts` and a route in `lib/consts/route_classification.ts`, never on the site —
and the site build drives the real admin API, so a server change can break the site while `bun test`
stays green. Verify with `cd website && bun run check && bun run build`.

---

## Code style rules

- Tabs for indentation, single quotes, no trailing commas (Prettier enforces).
- Unused variables must be prefixed with `_` (ESLint enforces).
- No `any` — use proper types or `unknown` with narrowing.
- No comments explaining _what_ — only _why_ when non-obvious.
- `bun run format` must pass before committing.

---

## LLM Wiki

`wiki/` is an LLM-curated wiki (Karpathy's "LLM Wiki" pattern). `wiki/SCHEMA.md` holds its
conventions and is authoritative.

- **Read it before changing a subsystem, not only before answering a question about one.** Start at
  `wiki/index.md`; the pages most worth reading before a change are the ones the change is most likely
  to falsify. If the index surfaces nothing, `python wiki/bin/wiki.py search "terms" --json`.
- **A change that falsifies a wiki claim corrects it in the same change.** Before finishing,
  `grep -rn "\bterm\b" wiki/ --include=*.md` for the names you touched and fix what is now false — a
  surgical `str_replace` that says what changed and at which commit. A stale page is worse than a
  missing one.
- **New knowledge goes to the wiki, not here.** A decision worth keeping gets a page (frontmatter,
  `file:line` citations, an index entry, a `wiki/log.md` line); this file gets at most a one-line rule
  pointing to it. Wiki pages never cite `specs/`.
- Run every wiki script through `wiki/bin/wiki.py` (`search`, `lint`, `graph-query`, …); calling the
  plugin scripts with bare `python` silently downgrades search and breaks the graph scripts.

<!-- SPECKIT START -->

For additional context about technologies to be used, project structure,
shell commands, and other important information, read the current plan
<!-- SPECKIT END -->
