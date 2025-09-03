# OAuth-server.ts

A lightweight OAuth 2.0 and OpenID Connect server built with [Bun](https://bun.sh/) and TypeScript.

## Specifications to Implement

This project implements the following official specifications:

- [OAuth 2.0 Authorization Framework (RFC 6749)](https://datatracker.ietf.org/doc/html/rfc6749)
- [OAuth 2.0 Token Revocation (RFC 7009)](https://datatracker.ietf.org/doc/html/rfc7009)
- [OAuth 2.0 Proof Key for Code Exchange (PKCE, RFC 7636)](https://datatracker.ietf.org/doc/html/rfc7636)
- [OAuth 2.0 Demonstration of Proof-of-Possession (DPoP, RFC 9449)](https://datatracker.ietf.org/doc/html/rfc9449)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [JSON Web Token (JWT, RFC 7519)](https://datatracker.ietf.org/doc/html/rfc7519)
- [JSON Web Key Set (JWKS, RFC 7517)](https://datatracker.ietf.org/doc/html/rfc7517)
- [OAuth 2.0 Token Introspection (RFC 7662)](https://datatracker.ietf.org/doc/html/rfc7662)

### Implemented Specification Details

- OAuth 2.0 flows: Authorization Code, Client Credentials, Refresh Token, with PKCE for public clients
- DPoP support for proof-of-possession access tokens
- Secure redirect URI validation and access token expiration/refresh logic
- OpenID Connect: ID token issuance/validation, claims (`sub`, `aud`, `iss`, `exp`, `iat`, `nonce`), UserInfo endpoint
- JWT access and ID tokens (RS256), JWKS endpoint, token introspection
- Configurable client registration (dynamic/static), metadata validation
- Secure/encrypted storage for secrets and tokens, rotating signing keys
- Scope-based access control and enforcement
- Token revocation endpoint (RFC 7009)
- Well-known discovery endpoint (`/.well-known/openid-configuration`)
- User authentication and consent screens, session management
- Extensible middleware for custom validation/logging
- Error handling per OAuth and OIDC standards
