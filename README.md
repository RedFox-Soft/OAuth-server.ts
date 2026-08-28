<div align="center">
  <img src="public/logo.svg" alt="OAuth-server.ts logo" width="120" />
  <h1>OAuth-server.ts</h1>
  <p><strong>Open-source OAuth 2.0 and OpenID Connect authorization server — built with Bun and TypeScript.</strong></p>

  <p>
    <a href="https://github.com/RedFox-Soft/OAuth-server.ts/actions/workflows/ci.yml">
      <img src="https://github.com/RedFox-Soft/OAuth-server.ts/actions/workflows/ci.yml/badge.svg" alt="CI status" />
    </a>
    <a href="https://codecov.io/gh/RedFox-Soft/OAuth-server.ts">
      <img src="https://codecov.io/gh/RedFox-Soft/OAuth-server.ts/branch/main/graph/badge.svg" alt="Coverage status" />
    </a>
  </p>

  <p>
    <a href="https://datatracker.ietf.org/doc/html/rfc6749">OAuth 2.0</a> ·
    <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect</a> ·
    <a href="https://bun.sh/">Bun</a> ·
    <a href="LICENSE">MIT License</a>
  </p>
</div>

---

OAuth-server.ts is a fully open-source, standards-compliant authorization server written in TypeScript and powered by [Bun](https://bun.sh/) and [Elysia](https://elysiajs.com/). It implements OAuth 2.0 and OpenID Connect from the ground up, giving you complete control over your identity infrastructure — with no vendor lock-in.

## Features

- **OAuth 2.0 flows** — Authorization Code, Client Credentials, and Refresh Token, including PKCE for public clients
- **OpenID Connect** — Full OIDC Core 1.0 support with ID tokens, UserInfo endpoint, and discovery
- **DPoP** — Sender-constrained access tokens via Demonstration of Proof-of-Possession ([RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449))
- **JWT tokens** — RS256-signed access and ID tokens with JWKS endpoint and key rotation; signing keys are stored in the database and auto-generated on first run
- **Token introspection & revocation** — RFC 7662 and RFC 7009 compliant endpoints
- **Pushed Authorization Requests (PAR)** — RFC 9126 support
- **Client registration** — Static and dynamic client registration with metadata validation
- **MongoDB storage** — Pluggable adapter architecture with built-in MongoDB and in-memory adapters
- **Consent & login UI** — Built-in user authentication and consent screens (React + Ant Design)
- **Scope-based access control** — Fine-grained, per-client scope enforcement
- **Extensible** — Middleware hooks for custom validation, logging, and policy

## Quick Start

**Prerequisites:** [Bun](https://bun.sh/) v1.3+ and a running MongoDB instance.

```bash
# Clone the repository
git clone https://github.com/your-org/oauth-server-ts.git
cd oauth-server-ts

# Install dependencies
bun install

# Create .env — set MONGODB_URI, DATABASE_NAME, and ISSUER

# Provision the database schema (creates collections + an initial RS256 signing key)
bun run db:setup

# Start the server
bun start
```

The server starts on `http://localhost:3000` by default. Schema provisioning creates the initial
signing key, so no key configuration is required. If the server ever starts against an empty key
store it also generates and persists one automatically.

### Admin panel provisioning

`bun run db:setup` also provisions the admin panel: the reserved admin project, its "Administrators"
user bucket, and the first-party `admin-panel` OAuth client. The seed is idempotent — **re-run
`bun run db:setup` after upgrading an existing install** so the admin client/project/bucket exist.
On first visit to `/admin`, a one-time setup screen creates the initial `super_admin`; the setup
route is closed once any super_admin exists. The admin panel requires a MongoDB-backed deployment
(the in-memory adapter does not persist seeded data across restarts).

## Configuration

| Variable        | Description                                | Example                     |
| --------------- | ------------------------------------------ | --------------------------- |
| `MONGODB_URI`   | MongoDB connection string                  | `mongodb://localhost:27017` |
| `DATABASE_NAME` | Name of the database to use                | `OAuth`                     |
| `ISSUER`        | Canonical URL of your authorization server | `https://auth.example.com`  |

### Signing keys

Signing and decryption keys are stored in the database via the `jwksStore` adapter, not in an
environment variable. The initial RS256 signing key is created when you provision the schema
(`bun run db:setup`); the server also generates and persists one automatically if it starts against
an empty store. On subsequent restarts the existing keys are reused. Keys are loaded once at startup
— to rotate, update the store and reload the server. Additional keys (for example encryption keys)
can be provisioned by populating the store.

### Rate limiting

Requests are counted per calling origin and refused with `429` once an origin exceeds its allowance
inside a window. The refusal happens before the endpoint does any work, and carries `Retry-After`
with the seconds remaining; the body is the standard OAuth error shape, the admin plane's own shape,
or an HTML page, depending on which surface was addressed. No `RateLimit-*` headers are emitted —
they would tell a caller probing for the threshold exactly where it is.

Allowances are tiered by route class rather than being one blanket number, because a limit tight
enough to protect the token endpoint would refuse the console's asset burst:

| Class      | Applies to                                                                                                                         | Default       |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------- | ------------- |
| `strict`   | Token, authorization, dynamic registration, PAR, device, CIBA, and every end-user door that checks a secret or sends mail          | 60 / 60s      |
| `ordinary` | Everything not otherwise classified — userinfo, introspection, revocation, the admin API, MCP, the rest of the interaction screens | 300 / 60s     |
| `public`   | Static assets, discovery metadata, the key set, and every cross-origin preflight                                                   | 1200 / 60s    |
| exempt     | `GET /health` only — a refused liveness probe would take the machine out of the load balancer                                      | never counted |

All of it is settable from the admin console under **Settings → Rate limiting**, or directly on
`ApplicationConfig`. Changes apply at the next restart, like every other server setting.

| Setting                       | Default | Notes                                    |
| ----------------------------- | ------- | ---------------------------------------- |
| `rateLimit.enabled`           | `true`  | Incident kill switch                     |
| `rateLimit.trustedProxy`      | `true`  | See below — no universally safe value    |
| `rateLimit.maxTrackedOrigins` | `10000` | Per class; caps the limiter's own memory |
| `rateLimit.strict.max`        | `60`    | With `.windowSeconds`, default `60`      |
| `rateLimit.ordinary.max`      | `300`   | With `.windowSeconds`, default `60`      |
| `rateLimit.public.max`        | `1200`  | With `.windowSeconds`, default `60`      |

The server refuses to start if any of these is not a positive integer, rather than serving with
limiting silently absent or silently total.

**`rateLimit.trustedProxy` is the one setting with a wrong answer in each direction.** Leave it on
when anything sits in front of this server (the shipped `fly.toml` does): with it off, every caller
arrives as the proxy's own address, so the whole internet shares one allowance and all traffic is
refused within seconds. Turn it off when the server is directly exposed: with it on, any caller can
set `Fly-Client-IP` to a fresh value per request and is never limited.

**Two properties to know before relying on this.** Counting is per instance and held in memory, so
with N machines serving concurrently the effective allowance is N times the configured value, and an
instance restart clears every counter. This is a resource protection — it bounds what one source can
cost the server — and not a security boundary. The limits that must hold absolutely are the
per-identity throttles: verification codes cap at five attempts, and resends and password-reset
requests are cooldown- and daily-capped, independently of anything here.

**Tuning.** Raise `strict.max` if a legitimate server-to-server integration behind one address, or
many users behind one corporate NAT, start seeing refusals. Raise `public.max` if the admin console
stutters while loading. Lower `maxTrackedOrigins` under memory pressure. Set `rateLimit.enabled` to
`false` and restart to switch the whole thing off during an incident.

## Docker

```bash
docker build -t oauth-server-ts .
docker run -p 3000:3000 --env-file .env oauth-server-ts
```

## Endpoints

| Endpoint                                 | Description                              |
| ---------------------------------------- | ---------------------------------------- |
| `GET  /.well-known/openid-configuration` | OpenID Connect discovery document        |
| `GET  /jwks`                             | JSON Web Key Set                         |
| `GET/POST /authorize`                    | Authorization endpoint                   |
| `POST /token`                            | Token endpoint                           |
| `GET  /userinfo`                         | UserInfo endpoint                        |
| `POST /introspect`                       | Token introspection                      |
| `POST /revoke`                           | Token revocation                         |
| `POST /register`                         | Dynamic client registration              |
| `GET/POST /session/end`                  | End session (logout)                     |
| `POST /device/auth`                      | Device authorization                     |
| `POST /request`                          | Pushed Authorization Requests (PAR)      |
| `GET  /admin`                            | Administration console                   |
| `POST /mcp`                              | Administration over MCP (off by default) |

## Administration

The server administers itself. `GET /admin` is a console for projects, OAuth clients,
administrators, user buckets, end-users, upstream identity providers, settings, signing keys and an
append-only audit trail. Administrators sign in through an OpenID Connect flow against this server's
own issuer, so there is no second password store.

### Administration from an AI agent (MCP)

The same management API is available to an AI agent over the Model Context Protocol, as an OAuth 2.1
protected resource of this server. It is **off by default** — the capability hands an agent the
authority of the administrator who authorized it, so a deployment should switch it on deliberately:

1. In the console, **Settings → Administration → Enable the administrative MCP control plane**, then
   restart (settings apply at boot).
2. Point your MCP client at `https://your-server/mcp` with client id **`admin-mcp`** and resource
   `https://your-server/mcp`.

An agent then acts as the administrator who signed in, with exactly that account's permissions. Every
change it makes runs through the same routes, the same checks and the same audit trail as the console's,
and each audit entry names both the operator and the agent.

Two things it deliberately cannot do: **delete a project** and **delete a user bucket**. Those destroy a
container of clients or of accounts with nothing left afterwards to inspect, so they stay console-only.
Everything else destructive takes two steps — the agent describes what would change and you confirm that
specific operation.

> **Compatibility note.** The `client_id` above is not optional. An administrator's account lives in the
> reserved admin bucket, and a dynamically registered client is not routed there — so an MCP client that
> only supports Dynamic Client Registration, with no way to configure a `client_id`, cannot use this
> surface yet.

## Implemented Standards

| Specification                                                                    | Description                         |
| -------------------------------------------------------------------------------- | ----------------------------------- |
| [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)                        | OAuth 2.0 Authorization Framework   |
| [RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009)                        | OAuth 2.0 Token Revocation          |
| [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)                        | JSON Web Token (JWT)                |
| [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)                        | JSON Web Key (JWK)                  |
| [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)                        | PKCE                                |
| [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662)                        | OAuth 2.0 Token Introspection       |
| [RFC 9126](https://datatracker.ietf.org/doc/html/rfc9126)                        | Pushed Authorization Requests (PAR) |
| [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)                        | DPoP                                |
| [OIDC Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)           | OpenID Connect Core                 |
| [OIDC Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) | OpenID Connect Discovery            |

## Contributing

Contributions are welcome! Please open an issue or pull request. For significant changes, open an issue first to discuss your proposal.

## License

[MIT](LICENSE)
