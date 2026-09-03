<div align="center">
  <img src="public/logo.svg" alt="OAuth-server.ts logo" width="120" />
  <h1>OAuth-server.ts</h1>
  <p><strong>Source-available OAuth 2.0 and OpenID Connect authorization server — built with Bun and TypeScript.</strong></p>

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
    <a href="LICENSE">FSL-1.1-ALv2 License</a>
  </p>
</div>

---

OAuth-server.ts is a source-available (FSL-1.1-ALv2), standards-compliant authorization server written in TypeScript and powered by [Bun](https://bun.sh/) and [Elysia](https://elysiajs.com/). It implements OAuth 2.0 and OpenID Connect from the ground up, giving you complete control over your identity infrastructure — with no vendor lock-in.

## Features

Most protocol capabilities are governed by a named feature flag, and **a flag that is off means the
capability's endpoint is not served at all**. So this list is split by what you get on a default
install versus what you switch on deliberately — the distinction is load-bearing, not editorial.

### Out of the box

- **Authorization Code flow with PKCE** — PKCE is mandatory for every client, public or confidential, per OAuth 2.1
- **OpenID Connect** — OIDC Core 1.0 with ID tokens, UserInfo endpoint, and discovery
- **Authorization-response issuer identification** — `iss` on every authorization response ([RFC 9207](https://datatracker.ietf.org/doc/html/rfc9207))
- **Resource Indicators** — audience-restricted tokens via `resource` ([RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707))
- **RP-initiated logout** — with a confirmation step
- **JWT tokens** — access and ID tokens signed with the algorithms your key store holds; `bun run db:setup` provisions an initial RS256 key, and ES256 and EdDSA keys are supported. Keys live in the database, are generated on first run, and are published at `/jwks`
- **Database-backed clients** — clients live in this server's own store and are created through the admin API, dynamic registration, or `bun run db:setup`. There is no static client configuration file
- **Administration console** — projects, OAuth clients, administrators, user buckets, end-users, upstream identity providers, settings, SMTP, signing keys and an append-only audit trail
- **End-user self-service** — email verification and password reset, each with per-identity attempt and cooldown caps
- **TOTP second factor** — per-bucket, optionally enforced for the admin console ([RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238))
- **Pairwise subject identifiers** — per-sector `sub` values, salted from the database
- **Per-origin rate limiting** — tiered by route class, on by default
- **Sign-in brute-force throttle** — persisted per-address failure counters with escalating lockouts, and no way to tell a throttled refusal from a wrong password
- **Security headers** — HSTS, `Permissions-Policy`, framing and content-type protections
- **CORS closed by data** — an origin is readable only if it is listed on the project owning the calling client
- **Pluggable storage** — adapter architecture with MongoDB and in-memory implementations
- **Consent & login UI** — built-in authentication and consent screens (React + Ant Design)
- **Scope-based access control** — fine-grained, per-client scope enforcement
- **Extensible** — 31 named behaviour seams (account lookup, interaction policy, refresh-token rotation, resource resolution, pairwise identifiers, RAR handling and more) replaced at call time via `addons.override()`

### Opt-in capabilities

Implemented, and off until the flag is set. Set them in the console under **Settings** or on
`ApplicationConfig`; they apply at the next restart.

| Capability                                                                                                          | Flag                                |
| ------------------------------------------------------------------------------------------------------------------- | ----------------------------------- |
| Client Credentials grant                                                                                            | `clientCredentials.enabled`         |
| Refresh Token grant                                                                                                 | `refreshToken.enabled`              |
| **DPoP** — sender-constrained tokens, including nonces ([RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449))  | `dpop.enabled`                      |
| **Pushed Authorization Requests** ([RFC 9126](https://datatracker.ietf.org/doc/html/rfc9126))                       | `par.enabled`                       |
| Token introspection ([RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662))                                     | `introspection.enabled`             |
| Token revocation ([RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009))                                        | `revocation.enabled`                |
| JWT-response introspection ([RFC 9701](https://datatracker.ietf.org/doc/html/rfc9701))                              | `jwtIntrospection.enabled`          |
| Signed UserInfo responses                                                                                           | `jwtUserinfo.enabled`               |
| Dynamic client registration ([RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591))                             | `registration.enabled`              |
| Registration management ([RFC 7592](https://datatracker.ietf.org/doc/html/rfc7592))                                 | `registrationManagement.enabled`    |
| Device Authorization Grant ([RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628))                              | `deviceFlow.enabled`                |
| CIBA — backchannel authentication                                                                                   | `ciba.enabled`                      |
| JARM — JWT-secured authorization response                                                                           | `responseMode.jwt.enabled`          |
| Request objects (`request` / `request_uri`)                                                                         | `requestObjects.enabled`            |
| Rich Authorization Requests ([RFC 9396](https://datatracker.ietf.org/doc/html/rfc9396))                             | `richAuthorizationRequests.enabled` |
| mTLS client authentication and certificate-bound tokens ([RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705)) | `mTLS.enabled`                      |
| FAPI profile behaviours                                                                                             | `fapi.enabled`                      |
| Backchannel logout                                                                                                  | `backchannelLogout.enabled`         |
| The `claims` request parameter                                                                                      | `claimsParameter.enabled`           |
| Token and response encryption                                                                                       | `encryption.enabled`                |
| Upstream OIDC federation — sign in via an external provider                                                         | `federation.enabled`                |
| Administration over MCP — the same management API, served to an AI agent                                            | `mcp.enabled`                       |
| Error-store recording (its read surface is always served, deliberately)                                             | `errorStore.enabled`                |

## Quick Start

### With Docker Compose

**Prerequisites:** Docker with Compose v2.

```bash
curl -O https://raw.githubusercontent.com/RedFox-Soft/OAuth-server.ts/main/docker-compose.yml
docker compose up
```

That starts MongoDB, provisions the schema and the admin panel (an idempotent one-shot step), and
serves the server at `http://localhost:3000`. Open `http://localhost:3000/admin` — the first visit
shows a one-time setup screen that creates the initial super administrator. Discovery is at
`http://localhost:3000/.well-known/openid-configuration`. Set `ISSUER` in `docker-compose.yml` to its
final public URL before this first `docker compose up`: the seeded admin client's redirect URI is
derived from it once, and a later change is not repaired by re-running setup.

Images are published to `ghcr.io/redfox-soft/oauth-server-ts` on every release, tagged with the
version and `latest`. To upgrade, pull and run `docker compose up` again; the setup step re-runs and
is safe to repeat.

### From source

**Prerequisites:** [Bun](https://bun.sh/) v1.3+ and a running MongoDB instance.

```bash
git clone https://github.com/RedFox-Soft/OAuth-server.ts.git
cd OAuth-server.ts
bun install

# Create .env — set MONGODB_URI, DATABASE_NAME, and ISSUER (see Configuration)

bun run db:setup   # collections, indexes, initial RS256 signing key, admin panel seed
bun run build      # bundles the console and sign-in screens into public/
bun start          # http://localhost:3000
```

Schema provisioning creates the initial signing key, so no key configuration is required. If the
server ever starts against an empty key store it also generates and persists one automatically.

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
per-identity throttles: verification codes cap at five attempts, resends and password-reset requests
are cooldown- and daily-capped, and the password sign-in door has the brute-force throttle below —
all independently of anything here.

**Tuning.** Raise `strict.max` if a legitimate server-to-server integration behind one address, or
many users behind one corporate NAT, start seeing refusals. Raise `public.max` if the admin console
stutters while loading. Lower `maxTrackedOrigins` under memory pressure. Set `rateLimit.enabled` to
`false` and restart to switch the whole thing off during an incident.

### Sign-in brute-force throttle

Failed password attempts are counted per bucket and address. Once an address reaches the cap, the
sign-in door is shut for that address and refuses every further attempt — **including one carrying
the correct password** — until the window ends. Each further exhaustion shuts it for longer, doubling
to the ceiling: 15 → 30 → 60 minutes by default, which holds a sustained attack to roughly 120
guesses a day. The counter is forgotten after 24 hours without a failure.

The refusal is the ordinary "invalid username or password" page. It never says that a throttle
exists, how many attempts remain, or when the door reopens, because saying any of it would tell an
attacker that the address they are guessing is real. For the same reason attempts are counted for
addresses that have no account at all — a counter's existence means somebody typed that address,
nothing more. And because the refusal happens before the account lookup, a refused attempt costs no
password hashing: a flood against one address stops being a CPU cost as well as stopping being a
guessing opportunity.

Unlike the per-origin limiter above, these counters are **persisted**, so the limit holds across
restarts and across every machine serving concurrently. That is what makes this a security boundary
rather than a resource protection — and why there is deliberately no switch to turn it off.

| Setting                              | Default | Notes                                                  |
| ------------------------------------ | ------- | ------------------------------------------------------ |
| `loginThrottle.failureCap`           | `5`     | Attempts per window; at most `100`                     |
| `loginThrottle.windowSeconds`        | `900`   | First lockout, and the base the curve doubles from     |
| `loginThrottle.windowCeilingSeconds` | `3600`  | Longest lockout; never below the first, never over 24h |

Two counters are cleared immediately rather than waiting out the window: a password that verifies,
and a **completed** password reset. The second is the escape hatch — consuming the emailed secret
proves control of the address, which is exactly what an attacker guessing passwords does not have —
so a locked-out user is never stuck waiting. Merely _requesting_ a reset clears nothing.

**A bucket that requires a one-time code stays at the first window** however often it is tripped: a
guessed password there does not sign anyone in, so the deeper lockouts buy little. This matters most
for the reserved administrator bucket, whose operators sign in through this same door and have no
self-service reset to escape with — their worst case is a 15-minute wait, and the way to make that
door properly hard is to require the second factor on it (**Settings → Administrators**).

## Docker

Published image:

```bash
docker pull ghcr.io/redfox-soft/oauth-server-ts:latest
docker run -p 3000:3000 --env-file .env ghcr.io/redfox-soft/oauth-server-ts:latest
```

Run `bun run db:setup` against the same database once before the first start (the Compose file
above does this for you). To build locally instead:

```bash
docker build -t oauth-server-ts .
docker run -p 3000:3000 --env-file .env oauth-server-ts
```

## Endpoints

**Most endpoints are governed by a feature flag, and a flag that is off means the endpoint is not
served at all** — not merely that discovery stops advertising it. The refusal is deliberately
indistinguishable from a path the server does not have, so if a request below returns `404`, check the
flag before suspecting a defect. Flags are set in the admin console under **Settings**, or directly on
`ApplicationConfig`, and apply at the next restart.

### Always available

| Endpoint                                 | Description                                                               |
| ---------------------------------------- | ------------------------------------------------------------------------- |
| `GET  /health`                           | Liveness probe                                                            |
| `GET  /.well-known/openid-configuration` | OpenID Connect discovery document (contents reflect enabled capabilities) |
| `GET  /.well-known/security.txt`         | Security contact and disclosure policy (RFC 9116)                         |
| `GET  /jwks`                             | JSON Web Key Set                                                          |
| `GET, POST /auth`                        | Authorization endpoint                                                    |
| `POST /token`                            | Token endpoint                                                            |

### Enabled by default

Flag-governed, but on unless you turn them off.

| Endpoint               | Description         | Flag                        |
| ---------------------- | ------------------- | --------------------------- |
| `GET, POST /userinfo`  | UserInfo endpoint   | `userinfo.enabled`          |
| `GET  /logout`         | RP-initiated logout | `rpInitiatedLogout.enabled` |
| `POST /logout/confirm` | Logout confirmation | `rpInitiatedLogout.enabled` |

### Opt-in

Absent from a default install until the flag is set.

| Endpoint                                         | Description                                        | Flag                             |
| ------------------------------------------------ | -------------------------------------------------- | -------------------------------- |
| `POST /par`                                      | Pushed Authorization Requests (RFC 9126)           | `par.enabled`                    |
| `POST /token/introspect`                         | Token introspection (RFC 7662)                     | `introspection.enabled`          |
| `POST /token/revocation`                         | Token revocation (RFC 7009)                        | `revocation.enabled`             |
| `POST /reg`                                      | Dynamic client registration (RFC 7591)             | `registration.enabled`           |
| `GET  /reg/:clientId`                            | Read a client's own registration                   | `registration.enabled`           |
| `PUT, DELETE /reg/:clientId`                     | Update / delete a registration (RFC 7592)          | `registrationManagement.enabled` |
| `POST /device/auth`                              | Device authorization (RFC 8628)                    | `deviceFlow.enabled`             |
| `GET, POST /device`                              | User-code entry page for the device flow           | `deviceFlow.enabled`             |
| `POST /backchannel`                              | Client-Initiated Backchannel Authentication (CIBA) | `ciba.enabled`                   |
| `POST, GET /mcp`                                 | Administration over MCP                            | `mcp.enabled`                    |
| `GET  /.well-known/oauth-protected-resource/mcp` | Protected resource metadata for `/mcp` (RFC 9728)  | `mcp.enabled`                    |
| `GET  /federation/callback`                      | Upstream identity provider callback                | `federation.enabled`             |

Reading your own registration follows `registration.enabled` rather than
`registrationManagement.enabled`: the registration response hands the client that URI, so refusing the
read while registration is on would break the capability that issued it. Only the mutating methods
need the management flag.

### Route families

Reached by redirect or through the console rather than called directly, so these are described as
families rather than enumerated.

| Family                       | Entry point            | Description                                                                                                                                                       |
| ---------------------------- | ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| End-user interaction screens | `/ui/:uid/…`           | Login, consent, registration, TOTP challenge and enrolment, forgot-password, flow resume. The federation legs (`/ui/:uid/federation/…`) need `federation.enabled` |
| Email verification           | `/verify-email`        | Verify, code entry, resend                                                                                                                                        |
| Password reset               | `/reset-password`      | Self-service reset                                                                                                                                                |
| Administration console + API | `/admin`, `/admin/api` | Projects, clients, administrators, user buckets, end-users, federation providers, settings, SMTP, signing keys, audit trail, error store                          |
| Static assets                | `/public/…`            | Console assets                                                                                                                                                    |

The interaction and self-service families are unconditional by design — a user locked out of their
account cannot be asked to wait for a capability toggle. The console is unconditional too, even though
`/mcp` is gated: switching MCP off must not take the console with it.

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

The **Flag** column names the capability's governing flag; `—` means always on. See
[Features](#features) for defaults.

| Specification                                                                                     | Description                                                                                                          | Flag                                |
| ------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- | ----------------------------------- |
| [OAuth 2.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1)                          | The profile targeted: PKCE for all clients, exact redirect-URI matching, refresh-token rotation, no Implicit or ROPC | —                                   |
| [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)                                         | OAuth 2.0 Authorization Framework                                                                                    | —                                   |
| [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)                                         | PKCE                                                                                                                 | —                                   |
| [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)                                         | JSON Web Token (JWT)                                                                                                 | —                                   |
| [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)                                         | JSON Web Key (JWK)                                                                                                   | —                                   |
| [OIDC Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)                            | OpenID Connect Core                                                                                                  | —                                   |
| [OIDC Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)                  | OpenID Connect Discovery                                                                                             | —                                   |
| [RFC 9207](https://datatracker.ietf.org/doc/html/rfc9207)                                         | Authorization Server Issuer Identification                                                                           | —                                   |
| [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707)                                         | Resource Indicators                                                                                                  | `resourceIndicators.enabled`        |
| [RFC 7009](https://datatracker.ietf.org/doc/html/rfc7009)                                         | OAuth 2.0 Token Revocation                                                                                           | `revocation.enabled`                |
| [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662)                                         | OAuth 2.0 Token Introspection                                                                                        | `introspection.enabled`             |
| [RFC 9701](https://datatracker.ietf.org/doc/html/rfc9701)                                         | JWT Response for OAuth Token Introspection                                                                           | `jwtIntrospection.enabled`          |
| [RFC 9126](https://datatracker.ietf.org/doc/html/rfc9126)                                         | Pushed Authorization Requests (PAR)                                                                                  | `par.enabled`                       |
| [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)                                         | DPoP, including nonces                                                                                               | `dpop.enabled`                      |
| [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591)                                         | Dynamic Client Registration                                                                                          | `registration.enabled`              |
| [RFC 7592](https://datatracker.ietf.org/doc/html/rfc7592)                                         | Dynamic Client Registration Management                                                                               | `registrationManagement.enabled`    |
| [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628)                                         | Device Authorization Grant                                                                                           | `deviceFlow.enabled`                |
| [RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705)                                         | mTLS Client Authentication and Certificate-Bound Tokens                                                              | `mTLS.enabled`                      |
| [RFC 9396](https://datatracker.ietf.org/doc/html/rfc9396)                                         | Rich Authorization Requests                                                                                          | `richAuthorizationRequests.enabled` |
| [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728)                                         | OAuth 2.0 Protected Resource Metadata                                                                                | `mcp.enabled`                       |
| [CIBA](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html) | Client-Initiated Backchannel Authentication                                                                          | `ciba.enabled`                      |
| [JARM](https://openid.net/specs/oauth-v2-jarm.html)                                               | JWT-Secured Authorization Response Mode                                                                              | `responseMode.jwt.enabled`          |

## Contributing

Contributions are welcome! Please open an issue or pull request. For significant changes, open an issue first to discuss your proposal.

## License

OAuth-server.ts is licensed under the [Functional Source License, Version 1.1, ALv2 Future
License](LICENSE) (`FSL-1.1-ALv2`) — the same license Sentry uses. In short: you may use, modify,
self-host and redistribute it for any purpose except offering it to others as a competing hosted
service, and each version converts to the Apache License 2.0 two years after its release.

This project began in April 2025 as a fork of [node-oidc-provider](https://github.com/panva/node-oidc-provider)
by Filip Skokan, distributed under the MIT License. Its notice is preserved in [NOTICE](NOTICE).
