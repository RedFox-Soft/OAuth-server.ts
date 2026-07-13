# OAuth-server.ts — Agent Guide

## What this project is

A standards-compliant OAuth 2.0 / OpenID Connect authorization server written in TypeScript, running on [Bun](https://bun.sh/) + [Elysia](https://elysiajs.com/). It is designed as a library: downstream apps call `provider.init(config)` and mount the returned Elysia app.

Implemented specs: Authorization Code + PKCE, Client Credentials, Refresh Token, Device Flow, CIBA, PAR (RFC 9126), DPoP (RFC 9449), token introspection/revocation, dynamic client registration, OIDC Core 1.0.

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

The test suite loads `.env.test` automatically via Bun.

---

## Architecture

```
lib/
  index.ts              ← library entry: exports provider, elysia, errors
  provider.ts           ← ProviderClass (EventEmitter); holds config, models, key store
  actions/              ← per-endpoint request handlers (operate on `oidc`, the OIDCContext)
    authorization/      ← authorization endpoint pipeline (validate → interact → respond)
    grants/             ← grant type handlers (auth_code, refresh_token, device, ciba)
  models/               ← AccessToken, RefreshToken, IdToken, Grant, Session, …
    client.ts           ← façade: validated plain-object client + pure-function exports
    client/             ← checks, secret, sector, keystore, backchannel, validate, schema
  addon/                ← behavioural config-default functions (CORS, mTLS, claims, findAccount, …)
  helpers/              ← JWT, crypto, claims, validation utilities
  adapters/             ← MongoDB adapter; TestAdapter (in-memory) for tests
  plugins/              ← Elysia plugins: noCache, noQueryDup, auth
  interactions/         ← Login/consent UI endpoints (React + Ant Design)
  views/                ← React components rendered server-side for interaction pages
  response_modes/       ← query, fragment, form_post, JWT response modes
  shared/               ← CORS, session, authorization_error_handler (shared onError), resource validation
  configs/              ← application.ts (single source of config DATA), algorithm lists, token lifetimes, env
database/               ← MongoDB collection definitions + TTL index setup
test/
  test_helper.ts        ← bootstrap: loads *.config.ts per feature, wires adapter + provider
  oauth/                ← core flow tests
  …                     ← feature-specific test dirs, each with *.config.ts + *.spec.ts
```

### Key patterns

**Action pipeline** — Each endpoint is a composed sequence of async functions that take the typed `OIDCContext` **directly as `oidc`** (the former `ctx = { oidc }` wrapper is gone). Helpers have `(oidc)` signatures and read `oidc.params`/`oidc.client`/`oidc.entities`/`oidc.cookie`/etc.; handlers **return** their typed response value (no `ctx.body`/`ctx.status` mutation). User-overridable config callbacks (findAccount, resourceIndicators.\*, interaction-policy `check(ctx)`, response-mode handlers) keep a `{ oidc }`-shaped argument as a public-API boundary; callers pass `{ oidc }` there. Event payloads that tests inspect (`authorization.success`, `registration_create.success`, `device_authorization.success`) stay `{ oidc }`-shaped.

**Config** — `lib/configs/application.ts` is the **single source of truth for all flag/option DATA** (flat dotted keys, each with an inline description). Behavioural function defaults live in `lib/addon/`. `lib/helpers/configuration.ts` (`Configuration`) expands the flat data into the nested `features.*` shape, runs the validation/collection passes, and **owns** the resolved object `provider.ts` reads — there is no `globalConfiguration.ts`.

**Adapter pattern** — All persistence goes through a `StorageAdapter` interface. Swap implementations without touching business logic. Use `TestAdapter` (in-memory) for unit/integration tests.

**Storage contract** — Every persisted model (all `BaseModel`/`BaseToken` subclasses: tokens, `Grant`, `Session`, `Interaction`, `ReplayDetection`) filters its stored payload by its TypeBox schema: `Opaque.getValueAndPayload()` persists only the top-level keys declared in `this.model` and copies each value verbatim (a **shallow** projection — never `Value.Clean`, so freeform fields like `claims`/`rar`/`params`/`session.state` are preserved). A field must be declared in the model's schema to be persisted; there is no whole-payload fallback. When adding a field a model must persist, add it to that model's TypeBox schema.

**Provider singleton** — `provider.init(config)` resolves config via `Configuration`. After init, models are accessed as `provider.Grant`, etc. `provider.Client` is a **namespace** (`find`/`validate`/`needsSecret`/`validateClient`/`adapter`), not a class.

**Client model** — A client is a TypeBox `ClientSchema`-validated **plain object** (`validateClient(metadata)`), not a class instance. Behaviour lives in pure functions under `lib/models/client/` (`checks`, `secret`, `sector`, `keystore`, `backchannel`); `lib/models/client.ts` re-exports them. The object exposes the historical method/getter surface (delegating to those functions) for call-site/test compatibility.

**Interaction system** — Login/consent are React pages served by `/interaction/*` routes. Interaction result is POSTed back; the server resumes the authorization flow.

**Error convention** — Throw an `OIDCProviderError` subclass (`lib/helpers/errors.ts`). The subclasses are registered with the Elysia app via `.error({...})` in `lib/index.ts`; a single shared app-level `onError` (`lib/shared/authorization_error_handler.ts`) formats every one (RFC 6749 §5.2 body, `WWW-Authenticate`, `DPoP-Nonce`, response-mode/JARM delivery, HTML variant) and endpoints declare per-route `response` schemas. The legacy Koa-style `shared/error_handler.ts` has been removed.

---

## Testing

Tests use **Bun's native test runner** with **Chai** assertions and **Sinon** stubs/spies.

Each feature area has:

- `*.config.ts` — provider config for that feature (clients, scopes, features flags)
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
