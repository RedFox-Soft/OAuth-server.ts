# OAuth-server.ts — Agent Guide

## What this project is

A standards-compliant OAuth 2.1 / OpenID Connect authorization server written in TypeScript, running on [Bun](https://bun.sh/) + [Elysia](https://elysiajs.com/). Downstream apps import the `elysia` app and mount it; there is no init step — importing is what boots it.

It is three surfaces on one core, and knowing which one you are in matters more than anything else in this file:

1. **The protocol surface** — the OAuth/OIDC endpoints. Implemented: Authorization Code + PKCE, Client Credentials, Refresh Token, Device Flow, CIBA, PAR (RFC 9126), DPoP (RFC 9449), Resource Indicators (RFC 8707), token introspection/revocation, dynamic client registration, OIDC Core 1.0.
2. **The administrative control plane** (`lib/admin/`) — a management API and a server-rendered console for projects, OAuth clients, administrators, user buckets, end-users, upstream federation providers, settings, SMTP, signing keys and an immutable audit trail. Reachable at `/admin`, authenticated by an OIDC flow against this server's own issuer.
3. **The MCP control plane** (`lib/mcp/`) — the same management API, served to an AI agent at `POST /mcp` as an OAuth 2.1 protected resource. Off by default (`mcp.enabled`).

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
```

---

## Environment variables

| Variable        | Required  | Description                                            |
| --------------- | --------- | ------------------------------------------------------ |
| `ISSUER`        | yes       | Canonical server URL (e.g. `https://auth.example.com`) |
| `MONGODB_URI`   | yes       | MongoDB connection string                              |
| `DATABASE_NAME` | yes       | MongoDB database name                                  |
| `NODE_ENV`      | test only | Set to `test` to use in-memory adapter                 |

Signing/decryption keys are **not** an environment variable: they are stored via the `jwksStore`
adapter and loaded once at startup. The initial RS256 key is provisioned during schema creation
(`bun run db:setup` → `database/mongodb.ts`); the loader (`lib/configs/keys.ts`) also auto-generates
and persists one if it finds an empty store (in-memory adapter, un-provisioned store). In tests,
keys are seeded into the in-memory `jwksStore` by `test/preload.ts`.

The same `bun run db:setup` step seeds the admin panel (reserved admin project + "Administrators"
bucket + the first-party `admin-panel` OAuth client) via `database/mongodb.ts`. It is idempotent and
must be re-run after upgrading an existing install. `lib/admin/seed.ts` (`ensureAdminSeed`) is the
app-side equivalent used by tests; there is **no** boot-time seeding, so admin login requires a
Mongo-backed, `db:setup`-provisioned deployment.

Super-admins manage the running instance through the admin control plane (`lib/admin/`, mounted under
`/admin/api/*`): projects, clients, buckets, end-users, server settings, and **signing keys**
(`lib/admin/jwks/` — view/generate/delete over `jwksStore`, persist-then-restart like settings; RSA
generation only, private key material never returned; status is drift between `jwksStore` and the
boot-time `JWKS_KEYS`). Every state-changing key action is written to an **append-only admin audit
trail** (`adminAuditStore`, collection `adminAudit`, via `lib/admin/audit/record.ts`, audit-first
before the mutation) capturing actor, action, target, and timestamp; the store exposes no
update/delete so entries cannot be altered.

**Ownership is by group, not by named manager.** Every project and user bucket carries `ownerGroupId`, and belonging to that group is the only thing that grants access to it — there is no per-container `managedBy` list, and no second ownership mechanism. Each administrator gets a `personal` group with their account (the console labels it "Personal", or "Personal — owner@email" for somebody else's, via `lib/admin/ui/groupLabel.ts`, and the Groups table does not list personal groups at all); a `regular` group is a company or team; the reserved `unassigned` system group, displayed as "System", holds containers no administrator managed. Within a group, `owner` and `member` are properties of the _membership_, not roles on the account: `assertGroupOwner` gates who is in the group and whether it may be deleted, while `assertRole` still gates the instance. `contextFor` resolves memberships on every request, so a removal takes effect on the next call. The console's active scope lives on the session (`AdminSession.activeGroupId`) and is re-validated against live membership each request; a super administrator may switch into any group _except_ another administrator's personal group, and their choice is honoured without a membership so it survives the next request. A project administrator creates projects, buckets and groups, invites people by email, and reads the audit trail for their own groups; the instance itself — settings, keys, SMTP, administrator accounts, the error store — stays super-admin-only. See `wiki/concepts/group-ownership.md`.

Unexpected internal faults are recorded to a **server error store** (`lib/error_store/`, area
`errorStore`, read at `/admin/api/errors`, super-admin only). Only defects are recorded — routine client
rejections are correct behaviour and never appear. Three things about it are load-bearing and easy to
get wrong: there are **two capture sites** (the global handler stands aside on the `adminPlane` marker,
so `adminApp`'s own `onError` records 5xx `AdminError`s); recording never blocks a response and never
fails a request, so a store failure degrades to the console and a full queue is _counted_; and the read
surface is deliberately **not** flag-gated, because the admin operation set is invariant under capability
switches — `errorStore.enabled` governs writes and is reported as `recording` in the payload. Agent
purging is withheld outright for the same reason; `error_purge_preview` is published instead.

End-user onboarding is bucket-scoped. Each `UserBucket` carries `registrationOpen`,
`emailVerificationRequired`, and `verificationMethod` (`'link' | 'code'`); defaults are open +
verification-off, except the reserved admin bucket which seeds `registrationOpen: false` (set in
**both** `lib/admin/seed.ts` and `database/mongodb.ts`). `POST ui/:uid/registration` resolves the
bucket from the interaction's client (`resolveBucketForClient`), rejects when registration is
closed, and — when verification is required — creates the user unverified and issues a challenge;
`POST ui/:uid/login` refuses an unverified user in such a bucket. Email verification lives in
`lib/verification/` (challenge issue/verify/resend over `adapter('VerificationChallenge')` +
`adapter('VerificationResend')` with TTLs; link tokens are single-use, codes are 6 digits hashed
at rest with an attempt cap, resends are cooldown + daily-capped) and `lib/mail/` (Nodemailer
transport read live from a runtime `SmtpSettingsStore`, plus the standard template; under
`NODE_ENV=test` the transport captures messages in memory instead of sending). The public,
cookie-less verification endpoints (`GET /verify-email`, `GET|POST /verify-email/code`,
`POST /verify-email/resend`) are a standalone group in `lib/routes/verification.ts`. SMTP transport
is a super-admin runtime setting (`/admin/api/settings/smtp`, password write-only/masked, audited)
— deliberately **not** in the boot-only `ApplicationConfig`, so changes apply without a restart.

The test suite loads `.env.test` automatically via Bun.

---

## Architecture

```
lib/
  index.ts              ← library entry: exports elysia, errors, eventBus, interactionPolicy
  event_bus.ts          ← the process-wide EventEmitter (default export of index.ts)
  actions/              ← per-endpoint request handlers (operate on `oidc`, the OIDCContext)
    authorization/      ← authorization endpoint pipeline (validate → interact → respond)
    grants/             ← grant type handlers (auth_code, refresh_token, device, ciba)
  models/               ← AccessToken, RefreshToken, IdToken, Grant, Session, …
    client.ts           ← façade: validated plain-object client + pure-function exports
    client/             ← checks, secret, sector, keystore, backchannel, validate, schema
  addon/                ← overridable behaviour functions (CORS, mTLS, claims, tokens, …); index.ts is the single import seam + override registry
  helpers/              ← JWT, crypto, claims, validation utilities
  adapters/             ← MongoDB adapter; TestAdapter (in-memory) for tests
  plugins/              ← Elysia plugins: noCache, noQueryDup, auth
  interactions/         ← Login/consent UI endpoints (React + Ant Design)
  response_modes/       ← query, fragment, form_post, JWT response modes
  shared/               ← session, authorization_error_handler (shared onError), token auth, resource validation
  configs/              ← application.ts (single source of config DATA), algorithm lists, token lifetimes, env
  admin/                ← the administrative control plane
    routes.ts           ← THE admin API route set; mounted by both the console and lib/mcp/dispatch.ts
    index.ts            ← the console: routes.ts plus the HTML shell (imports React/antd — expensive)
    auth/rbac.ts        ← resolveAdmin: session cookie OR an MCP-audience bearer token → one AdminContext
    audit/              ← append-only trail; written before the mutation, inside the handler
  mcp/                  ← the MCP control plane (agent-facing)
    catalogue.ts        ← THE published tool set: load-bearing table, drift-guarded both ways
    dispatch.ts         ← rebuilds the admin HTTP request and handles it in-process
    confirm.ts          ← the two-call gate on high-consequence operations
  error_store/          ← the one place a fault becomes a record (capture.ts is the choke point)
  sentry/               ← optional outbound reporting; registers NO Elysia hook (see below)
database/               ← MongoDB collection definitions + TTL index setup
test/
  test_helper.ts        ← bootstrap: loads *.config.ts per feature, wires adapter + provider
  oauth/                ← core flow tests
  …                     ← feature-specific test dirs, each with *.config.ts + *.spec.ts
```

### Key patterns

**Sentry reporting is off the request path** — `lib/sentry/` mounts nothing into Elysia: no plugin, no lifecycle hook, no `wrap`. A fault reaches it after the fact, from the single call inside `captureFault`'s record continuation in `lib/error_store/capture.ts`, which runs only once the fault is already classified as a defect (its callers gate on `status >= 500`) and already accepted for local recording. That shape is load-bearing, not stylistic: it is what keeps responses byte-identical, adds no latency, and stops routine protocol rejections being reported as faults. The official `@sentry/elysia` plugin does the opposite on all three counts and is deliberately not a dependency — `wiki/concepts/sentry-plugin-not-used.md` records why, and four specs in `test/sentry/` hold it.

**Action pipeline** — Each endpoint is a composed sequence of async functions that take the typed `OIDCContext` **directly as `oidc`** (the former `ctx = { oidc }` wrapper is gone). Helpers have `(oidc)` signatures and read `oidc.params`/`oidc.client`/`oidc.entities`/`oidc.cookie`/etc.; handlers **return** their typed response value (no `ctx.body`/`ctx.status` mutation). User-overridable config callbacks (findAccount, resourceIndicators.\*, interaction-policy `check(ctx)`, response-mode handlers) keep a `{ oidc }`-shaped argument as a public-API boundary; callers pass `{ oidc }` there. Event payloads that tests inspect (`authorization.success`, `registration_create.success`, `device_authorization.success`) stay `{ oidc }`-shaped.

**Config** — every setting lives on exactly one of **three** surfaces, and there is no `lib/helpers/defaults.ts` and no `globalConfiguration.ts`:

1. `lib/configs/application.ts` (`ApplicationConfig`) — **single source of truth for all server-wide flag/option DATA** (flat dotted feature keys plus `scopes`, `claims`, `acrValues`, `clientAuthMethods`, `conformIdTokenClaims`, `discovery`), each with an inline description. Boot-only: persisted via `configStore`, applied at module load, needs a restart.
2. `lib/configs/clientBase.ts` (`ClientDefaults`) — what a client gets when it does not specify, in **camelCase only**. Consumers working in wire-format (snake_case) metadata names translate at their own seam (see the map in `lib/models/client/schema.ts`).
3. `lib/addon/*` — overridable behavior, resolved through the override registry at call time, **including the interaction policy** (`interactionPolicy()` plus an `interactionPolicyControl` add/reset surface).

`lib/configs/configuration.ts` (`validateConfiguration`) is a **pure function of a config object**: it runs the validation and collection passes and returns the derived values (`scopes`, `claims`, `grantTypes`, `claimsSupported`, …). `application.ts` calls it at the point the settings finish loading and exports the result as `configuration`, so an unrunnable config fails at startup and nothing can observe an unvalidated one; `reloadConfiguration()` re-derives in place after a test mutates `ApplicationConfig`. Because it takes the config as an argument, the admin settings API validates a **candidate** config with the very same rules instead of mirroring them.

**Behaviour functions** — Overridable server behaviour (CORS, token issuance/rotation, resource-server info, CIBA/mTLS/RAR/registration helpers, …) is **single-sourced through `lib/addon/index.ts`**. Each function's default lives in its addon module; the index exposes a dynamic call-time accessor per function plus an `addons.override(partial)` / `addons.reset()` registry (`lib/addon/registry.ts`). Source modules import the accessor from the index — never off the merged configuration. Deployments and tests override via the registry (the test harness resets it after every test via `test/preload.ts`; `test/addon_baseline.ts` bridges a `*.config.ts`'s behaviour-fn overrides into a per-spec baseline). `findAccount` / `assertJwtClientAuthClaimsAndHeader` keep their existing direct imports.

**Adapter pattern** — All persistence goes through a `StorageAdapter` interface. Swap implementations without touching business logic. Use `TestAdapter` (in-memory) for unit/integration tests.

**Storage contract** — Every persisted model (all `BaseModel`/`BaseToken` subclasses: tokens, `Grant`, `Session`, `Interaction`, `ReplayDetection`) filters its stored payload by its TypeBox schema: `Opaque.getValueAndPayload()` persists only the top-level keys declared in `this.model` and copies each value verbatim (a **shallow** projection — never `Value.Clean`, so freeform fields like `claims`/`rar`/`params`/`session.state` are preserved). A field must be declared in the model's schema to be persisted; there is no whole-payload fallback. When adding a field a model must persist, add it to that model's TypeBox schema.

**Model lookup** — Every `BaseModel`/`BaseToken` subclass (and the `Client` namespace) exposes two static lookups. `tryFind(id, opts?)` returns the item or `undefined` — use it where absence is a valid, handled outcome. `find(id, opts?)` returns the item or **throws** — use it where the item is required, so no `undefined` check or non-null assertion is needed at the call site. `find` accepts an optional pre-constructed `{ error }` to throw on miss; without it, each model throws its own `static notFoundError` default (token hierarchy → `InvalidToken`, `Client` → `InvalidClient`). `find` delegates to `tryFind`, so both share identical verification/expiration/session-binding/policy semantics — only the not-found outcome differs. In tests, `spyOn(Model, 'tryFind')` to simulate a miss (mocking `find` would bypass the throw path).

**Provider singleton** — the provider has **no init step and no configuration of its own**; constructing it only opens the internals map the request path writes to. Server settings are validated and derived where they load (`configuration` from `lib/configs/application.ts`) — import that directly, never `instance(provider).configuration`. Signing keys are **not** part of it: `lib/configs/keystore.ts` exports the live `keystore` (sign/verify/encrypt/decrypt) and `publicJWKS` (what `/jwks` serves) as module state, loaded from the `jwksStore` adapter by `lib/configs/keys.ts` — the same "module state, single-sourced from a store" shape as `ApplicationConfig`. Import them directly; never reach for them through `instance(provider)`. Both are mutated **in place** and never reassigned, so a held reference always sees current keys (the admin API relies on this to hot-apply a generated key). `keystore.ts` deliberately imports nothing that reaches the adapters, `ApplicationConfig` or the models — keeping the key-loading `await` out of the model import graph, where it reorders module evaluation and trips the `base_model → provider → models` cycle. `provider.Client` is a **namespace** (`find`/`tryFind`/`validate`/`needsSecret`/`validateClient`/`adapter`), not a class.

**Client model** — A client is a TypeBox `ClientSchema`-validated **plain object** (`validateClient(metadata)`), not a class instance. Behaviour lives in pure functions under `lib/models/client/` (`checks`, `secret`, `sector`, `keystore`, `backchannel`); `lib/models/client.ts` re-exports them. The object exposes the historical method/getter surface (delegating to those functions) for call-site/test compatibility.

**Client provisioning** — Clients are **single-sourced from `adapter('Client')`**; there is no boot-time `clients` option (a stray one is silently ignored) and no in-memory static/dynamic client store. `tryFindClient` reads the adapter on every resolution (so updates/deletes are always current) and validates at resolution time, backed only by a size-bounded validated-object memo. Every client is uniformly manageable through the admin control plane and DCR (no `noManage` class). Provision clients via the admin API / DCR / DB seed; tests seed them with the harness's `seedClient`.

**Interaction system** — Login/consent are served under `/ui/:uid/*` (`lib/interactions/index.ts`; `/ui` is an `alwaysAvailablePrefixes` entry, so the surface is unconditional). Screens belong to one of two families and which one is not a style choice: the **antd shell** pages (login, registration, consent) hydrate React and are reached inside an interaction with the `_interaction` cookie, while the **plain self-contained** pages (`/verify-email/*`, `/reset-password`, the device/registration notices) carry no script and must work in a different browser opened from an email. Interaction result is POSTed back; the server resumes the authorization flow.

**Error convention** — Throw an `OIDCProviderError` subclass (`lib/helpers/errors.ts`). The subclasses are registered with the Elysia app via `.error({...})` in `lib/index.ts`; a single shared app-level `onError` (`lib/shared/authorization_error_handler.ts`) formats every one (RFC 6749 §5.2 body, `WWW-Authenticate`, `DPoP-Nonce`, response-mode/JARM delivery, HTML variant) and endpoints declare per-route `response` schemas. The legacy Koa-style `shared/error_handler.ts` has been removed.

---

## Testing

Tests use **Bun's native test runner** with **Chai** assertions and **Sinon** stubs/spies.

Each feature area has:

- `*.config.ts` — per-feature test settings, expressed entirely as **named exports** the harness applies (nothing is passed to the provider): `ApplicationConfig` (feature flags and collection options incl. `claims` — omit it to get the shared test claim set, `claims: {}` to opt out), `ClientDefaults`, `addons` (behavior overrides incl. `interactionPolicy`), `jwks` (per-instance keys), and `clients` / `client` which are seeded into the `Client` store. Configs that clone another config must re-export its `clients`.
- `*.spec.ts` — test cases using the Eden type-safe HTTP client

`test_helper.ts` bootstraps the provider with the right config before each suite. Use `bootstrap(import.meta)` at the top of a spec file.

Time-sensitive tests use Bun's `setSystemTime` (from `bun:test`) to travel time; call `setSystemTime()` with no argument to reset.

---

## Adding a new grant type

1. Create `lib/actions/grants/<name>.ts` implementing the handler.
2. Register it in `lib/actions/token.ts` grant dispatch map.
3. Add a feature flag in `lib/configs/` if it should be opt-in.
4. Add a MongoDB collection (with TTL index) in `database/` if the grant needs persistence.
5. Write tests under `test/<name>/` with a matching `*.config.ts`.

## Adding an administrative operation

The admin routes are the definition; the MCP surface follows from them.

1. Add the route to a group under `lib/admin/<group>/routes.ts`, with its body schema in the group's
   `schema.ts` — **not** inline, because `lib/mcp/catalogue.ts` imports schema modules and must never
   import a route module (a route module reaches the adapters and from there a db module that connects
   at import time).
2. If it mutates, add it to `lib/consts/admin_audit_routes.ts` and call `recordAdminAudit` inside the
   handler, after authorization. `test/admin/audit_route_classification.spec.ts` fails otherwise. The
   only escape is `excludedAdminRoutes`, and it is narrow: a route that changes the caller's own session
   and no managed entity (logout, the scope switch). Anything that touches a managed entity is audited.
3. Decide the agent's access and record it in `lib/mcp/catalogue.ts`: publish it as a tool, or name it
   in `excludedConsoleOperations` with the reason. `test/mcp/catalogue_drift.spec.ts` fails until you do
   one or the other — that is the point of the table.
4. Classify a destructive or instance-wide operation as `high`, and it is gated automatically.
   `test/mcp/confirmation_matrix.spec.ts` covers it the moment it is classified.
5. Run `bun test test/mcp/ test/admin/`. The guards that will complain at you — parity, audit
   classification, argument-name collisions, the secrecy sweep — are doing the job they were written for.

See `wiki/concepts/admin-mcp-control-plane.md` before changing anything in `lib/mcp/`; it records four
traps that each cost a debugging session.

## Adding a new endpoint

1. Create `lib/actions/<name>.ts` with an action pipeline.
2. Mount the route in the Elysia app in `lib/index.ts`.
3. Expose it in the OIDC discovery document (`lib/actions/discovery.ts`).
4. Protect it with the `auth` plugin if it requires client authentication.

---

## Code style rules

- Tabs for indentation, single quotes, no trailing commas (Prettier enforces).
- Unused variables must be prefixed with `_` (ESLint enforces).
- No `any` — use proper types or `unknown` with narrowing.
- No comments explaining _what_ — only _why_ when non-obvious.
- `bun run format` must pass before committing.

---

## LLM Wiki

This project maintains an LLM-curated wiki at `wiki/` following Andrej Karpathy's "LLM Wiki" pattern (https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f).

Before answering questions that rely on knowledge accumulated in this project, read `wiki/index.md` (or the relevant shard under `wiki/indexes/` if the wiki has been sharded) and use its one-line summaries to find the pages you need. Cite with `[[wikilinks]]`. If the index does not surface good candidates, fall back to hybrid retrieval:

```bash
python wiki/bin/wiki.py search "query terms" --json   # add --no-embed for lexical-only BM25
```

Run every wiki script through `wiki/bin/wiki.py` (`search`, `lint`, `stats`, `setup`, `graph-extract`, `graph-lint`, `graph-query`) — it resolves the plugin's versioned script path, supplies the wiki directory, and forces UTF-8. Calling the plugin scripts directly with bare `python` silently downgrades search to lexical and breaks the graph scripts.

Relational questions — what links to what, which pages depend on a subsystem, the path between two pages — can consult the compiled graph instead of reading pages: `python wiki/bin/wiki.py graph-query neighbors --node concept:<slug>` (also `edges`, `facts`, `path`). Rebuild it with `graph-extract` after an ingest that adds typed `graph.relationships`.

To add a new source, follow the `llm-wiki` skill's ingest workflow: decide placement under `wiki/sources/`, `wiki/entities/`, `wiki/concepts/`, or `wiki/synthesis/`; identify touched pages and make surgical `str_replace` updates rather than rewrites; update the index; append a one-line entry to `wiki/log.md`.

Scaling discipline: atomic pages (400-line soft cap, 800-line hard cap), sharded indexes past ~150 pages or 300 index lines, required YAML frontmatter on every page, `[[wikilinks]]` for every cross-reference.

Full conventions live in `wiki/SCHEMA.md`. Treat it as authoritative when it disagrees with this summary.

<!-- SPECKIT START -->

For additional context about technologies to be used, project structure,
shell commands, and other important information, read the current plan
<!-- SPECKIT END -->
