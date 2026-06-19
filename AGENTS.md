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
| `JWKS`          | yes       | JSON stringified JWKS with private RS256 keys          |
| `MONGODB_URI`   | yes       | MongoDB connection string                              |
| `DATABASE_NAME` | yes       | MongoDB database name                                  |
| `NODE_ENV`      | test only | Set to `test` to use in-memory adapter                 |

The test suite loads `.env.test` automatically via Bun.

---

## Architecture

```
lib/
  index.ts              ← library entry: exports provider, elysia, errors
  provider.ts           ← ProviderClass (EventEmitter); holds config, models, key store
  actions/              ← per-endpoint request handlers
    authorization/      ← authorization endpoint pipeline (validate → interact → respond)
    grants/             ← grant type handlers (auth_code, refresh_token, device, ciba)
  models/               ← AccessToken, RefreshToken, IdToken, Grant, Client, Session, …
  helpers/              ← JWT, crypto, claims, validation utilities
  adapters/             ← MongoDB adapter; TestAdapter (in-memory) for tests
  plugins/              ← Elysia plugins: noCache, noQueryDup, auth
  interactions/         ← Login/consent UI endpoints (React + Ant Design)
  views/                ← React components rendered server-side for interaction pages
  response_modes/       ← query, fragment, form_post, JWT response modes
  shared/               ← CORS, session, error handler, resource validation middleware
  configs/              ← algorithm lists, token lifetimes, env parsing
database/               ← MongoDB collection definitions + TTL index setup
test/
  test_helper.ts        ← bootstrap: loads *.config.ts per feature, wires adapter + provider
  oauth/                ← core flow tests
  …                     ← feature-specific test dirs, each with *.config.ts + *.spec.ts
```

### Key patterns

**Action pipeline** — Each endpoint is a composed sequence of async actions that receive and mutate an `OIDCContext`. Add a new step by inserting a function in the relevant pipeline array.

**Adapter pattern** — All persistence goes through a `StorageAdapter` interface. Swap implementations without touching business logic. Use `TestAdapter` (in-memory) for unit/integration tests.

**Provider singleton** — `provider.init(config)` merges user config with `globalConfiguration`. After init, models are accessed as `provider.Client`, `provider.Grant`, etc.

**Interaction system** — Login/consent are React pages served by `/interaction/*` routes. Interaction result is POSTed back; the server resumes the authorization flow.

**Error convention** — Throw `OIDCProviderError(code, description)`. The shared error handler converts it to an RFC-compliant JSON response.

---

## Testing

Tests use **Bun's native test runner** with **Chai** assertions and **Sinon** stubs/spies.

Each feature area has:

- `*.config.ts` — provider config for that feature (clients, scopes, features flags)
- `*.spec.ts` — test cases using the Eden type-safe HTTP client

`test_helper.ts` bootstraps the provider with the right config before each suite. Use `bootstrap(import.meta)` at the top of a spec file.

Time-sensitive tests use `timekeeper` to freeze/travel time.

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
