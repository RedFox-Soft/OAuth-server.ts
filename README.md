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
