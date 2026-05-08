<div align="center">
  <img src="public/logo.svg" alt="OAuth-server.ts logo" width="120" />
  <h1>OAuth-server.ts</h1>
  <p><strong>Open-source OAuth 2.0 and OpenID Connect authorization server — built with Bun and TypeScript.</strong></p>

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
- **JWT tokens** — RS256-signed access and ID tokens with JWKS endpoint and key rotation
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

# Create .env — set MONGODB_URI, DATABASE_NAME, ISSUER, and JWKS

# Start the server
bun start
```

The server starts on `http://localhost:3000` by default.

## Configuration

| Variable        | Description                                     | Example                     |
| --------------- | ----------------------------------------------- | --------------------------- |
| `MONGODB_URI`   | MongoDB connection string                       | `mongodb://localhost:27017` |
| `DATABASE_NAME` | Name of the database to use                     | `OAuth`                     |
| `ISSUER`        | Canonical URL of your authorization server      | `https://auth.example.com`  |
| `JWKS`          | JSON Web Key Set (RS256) used for token signing | `{"keys": [...]}`           |

## Docker

```bash
docker build -t oauth-server-ts .
docker run -p 3000:3000 --env-file .env oauth-server-ts
```

## Endpoints

| Endpoint                                 | Description                         |
| ---------------------------------------- | ----------------------------------- |
| `GET  /.well-known/openid-configuration` | OpenID Connect discovery document   |
| `GET  /jwks`                             | JSON Web Key Set                    |
| `GET/POST /authorize`                    | Authorization endpoint              |
| `POST /token`                            | Token endpoint                      |
| `GET  /userinfo`                         | UserInfo endpoint                   |
| `POST /introspect`                       | Token introspection                 |
| `POST /revoke`                           | Token revocation                    |
| `POST /register`                         | Dynamic client registration         |
| `GET/POST /session/end`                  | End session (logout)                |
| `POST /device/auth`                      | Device authorization                |
| `POST /request`                          | Pushed Authorization Requests (PAR) |

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
