# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). No release has
been cut yet — everything below is unreleased. Spec numbers refer to the (untracked) `specs/`
directories; full retrospectives live in `TASKS.md`'s git history and the knowledge base at
`wiki/`.

## [Unreleased]

### Added

- CORS support: preflight handling, open CORS on discovery/JWKS, client-based CORS on the token
  family driven by a per-project `corsOrigins` allow-list, `cors.enabled` setting (spec 011)
- Hardening headers on every response that is not a rendered page — `nosniff`, `no-referrer`, and a
  content policy of `default-src 'none'` plus `frame-ancestors 'none'` — across the protocol
  endpoints, the admin API, MCP and the static surface, including responses built by the error
  pipeline. Rendered pages keep their own derived policy (spec 026)
- Content-Security-Policy on every rendered page, derived per document — `script-src 'none'` on
  script-free pages, hashed inline styles; hydrated pages use precompiled antd CSS under
  `zeroRuntime` (specs 018/032, `74cc208`, `1a4628d`)
- Admin audit trail covers all 23 mutating admin routes and became readable:
  `GET /admin/api/audit` + an Audit page in the console (spec 016)
- Rich Authorization Requests (RFC 9396) work end to end on the code and refresh flows: consent
  display, grant persistence, working hook defaults, per-client `authorizationDetailsTypes` via
  the admin API (spec 015)
- Self-service end-user password reset, bucket-scoped, with throttling (spec 020)
- Upstream OIDC federation per bucket — end users sign in through their own identity provider;
  admin management plane included (spec 022)
- Admin MCP control plane: administer the instance from an AI agent at `POST /mcp`, served as an
  OAuth 2.1 protected resource of the server itself (spec 024)
- Durable server error store an operator can read — internal faults no longer vanish with the
  console (spec 025)
- `bun run db:setup` provisions every collection and index from a declared storage inventory under
  a drift guard, including TTLs for verification areas and unique per-bucket email indexes
  (spec 012)

### Changed

- **BREAKING:** feature flags now gate their endpoints — a disabled feature's routes answer 404
  instead of staying silently live (spec 010)
- **BREAKING:** deletion means what it reads as — projects/buckets refuse deletion while non-empty
  (409 with machine-readable blockers); deleting a client or end-user cascades to their sessions,
  grants and tokens (spec 019)
- **BREAKING:** pairwise `sub` values derive from stored server state instead of `os.hostname()`.
  They change exactly once, on first start of this version, for clients registered
  `subjectType: 'pairwise'` — then never again across restarts and scale-out (spec 023)
- **BREAKING:** `richAuthorizationRequests.types` is now a serializable descriptor map (`label`,
  per-common-field constraints, `allowUnknownFields`) editable in the admin settings; enabling the
  feature with an empty map fails validation. A code-registered `validate` remains an optional
  escape hatch (spec 015)
- **BREAKING:** `allowOmittingSingleRegisteredRedirectUri` moved into the Application
  Configuration (`authorization.allowOmittingSingleRegisteredRedirectUri`) and now defaults to
  **disabled**; enable it in the admin settings and restart to restore the old behavior
- Interaction UI: post-registration "check your inbox" notice renders, registration refusals are
  styled pages, consent permissions carry headings and friendly labels, decorative Google button
  removed (spec 021)

### Fixed

- The server could not boot against MongoDB: the DPoP nonce secret came back from the driver as a
  BSON `Binary` and failed its own round-trip check (`71d9b53`)
- PKCE accepts the full RFC 7636 verifier length range (43–128), not only 43 (`6dce3f7`)
- Native clients can complete an interactive sign-in (`ba5629d`)
- Interaction pages can hand off to a foreign callback under the CSP (`271d518`)
- The settings audit records only the fields a save actually changed (`b630c73`)
- Logging out of the admin console actually signs the operator out: it now ends the provider
  session as well as the console's own, and clears both cookies with the `Path` they were set with
  (Elysia's `cookie.remove()` omits `Path`, so the browser defaulted it to the request's directory
  and cleared a different cookie)
- Small-batch fixes: duplicate first-run admin setup surface removed, error pages carry the real
  status and illustration, stale `interaction.returnTo` corrected, unimplemented CIBA `push` mode
  removed from the admin schema (spec 018)

### Security

- The admin console verifies its id_token's signature (plus `nonce`, expiry, audience) against the
  live keystore before trusting it — previously a documented decode-only shortcut (spec 017)
- The DPoP nonce secret is self-provisioned at startup, making the requireNonce-without-secret 500
  state unrepresentable (spec 014)
