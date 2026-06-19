<!--
SYNC IMPACT REPORT
==================
Version change: 2.0.0 → 2.1.0 (MINOR — Principle I & II expanded, Security expanded)
Modified principles:
  I. Standards Compliance — expanded scope from OAuth 2.0 to OAuth 2.1 (mandatory PKCE
    for all clients, no Implicit or Resource Owner Password grants, exact redirect-URI
    matching, refresh-token rotation).
  II. Multi-Mode Deployment & MCP Integration — clarified MCP as an administrative
    CONTROL PLANE: AI agents manage the instance (create/modify clients, users, scopes,
    settings) via MCP, not merely authenticate through it.
Added sections: none (Security Requirements expanded with admin-plane controls)
Removed sections: none
Templates requiring updates:
  ✅ plan-template.md — no structural change needed; Constitution Check defers to this file.
  ✅ spec-template.md — aligned.
  ✅ tasks-template.md — aligned.
Follow-up TODOs:
  ⚠ AGENTS.md — describes the project as a "library" (OAuth 2.0) and omits the admin
    control plane + MCP; MUST be updated to match Principles I & II (per Governance §3).
-->

# OAuth-server.ts Constitution

## Core Principles

### I. Standards Compliance (NON-NEGOTIABLE)

The server targets **OAuth 2.1** and OpenID Connect. Implementations MUST conform exactly
to their governing specifications: the OAuth 2.1 draft consolidation, plus RFCs 7009,
7519, 7517, 7636, 7662, 9126, 9449, and OIDC Core/Discovery 1.0. Per OAuth 2.1, the
following are mandatory: PKCE for **all** clients (not only public), exact redirect-URI
string matching, refresh-token rotation, and the **removal** of the Implicit and Resource
Owner Password Credentials grants. Non-standard extensions MUST be documented and MUST NOT
break spec-compliant clients. Any deviation from a specification MUST be isolated behind a
named feature flag and justified with an inline comment referencing the relevant section.

### II. Multi-Mode Deployment & MCP Control Plane

The server MUST support two first-class deployment modes that share the same OAuth/OIDC
core: **self-hosted** (enterprises run their own instance) and **cloud-managed** (SaaS,
operated by the project team). Both modes MUST expose an identical API surface; behavioural
differences MUST be driven by configuration or adapter, never by conditional branches in
business logic.

The server MUST provide an **administrative control plane** for managing the instance —
clients, users, scopes, keys, and settings — exposed as a versioned management API. The
**MCP (Model Context Protocol) layer is a first-class consumer of that control plane**: an
AI agent, driven from chat, MUST be able to perform the same administrative operations a
human operator can (e.g. create a client, provision a user, change a setting) without a
human visiting the admin UI. MCP MUST NOT have a privileged back door — every MCP-initiated
action MUST flow through the same management API, authorization checks, validation, and
audit trail as a human-initiated action. The set of operations exposed to MCP MUST be an
explicit allow-list, never the entire internal surface.

### III. Adapter Pattern for Persistence

All storage access MUST go through the `StorageAdapter` interface. Business logic MUST
NOT reference MongoDB, SQL, or any specific database technology. New storage requirements
MUST be expressed as new adapter interface methods. The in-memory `TestAdapter` MUST be
the sole adapter used in automated tests — no real database calls in the test suite.

### IV. Type Safety

TypeScript strict mode is non-negotiable. `any` is forbidden; use typed interfaces or
`unknown` with explicit type narrowing. All public API surfaces MUST carry explicit types.
Type assertions (`as SomeType`) MUST be accompanied by a comment explaining why the type
system cannot express the constraint statically.

### V. Integration-First Testing

Every grant flow and endpoint MUST have integration tests exercising the real HTTP layer
via the Eden client against the in-memory adapter. The canonical pattern is a paired
`*.config.ts` (provider bootstrap with feature flags) and `*.spec.ts` (test cases).
Unit tests are permitted but MUST NOT substitute for integration coverage. When adding a
new grant flow or endpoint, tests MUST be written and confirmed failing before
implementation begins.

### VI. Security-First

PKCE is mandatory for all public clients; the server MUST reject authorization requests
from public clients that omit a code challenge. DPoP binding MUST be validated on every
request when a token is DPoP-bound. JWT access and ID tokens MUST be RS256-signed from
the configured JWKS. Introspection and revocation endpoints MUST require authentication.
Key rotation MUST NOT invalidate currently valid tokens.

### VII. Code Discipline

All code MUST be formatted with `bun run format` before merging (Prettier config: tabs,
single quotes, no trailing commas). Comments MUST explain WHY, never WHAT — block
comments describing what the code does are prohibited. Unused variables MUST be prefixed
with `_`. Backwards-compatibility shims and feature flags are not permitted unless
explicitly required by a specification or a documented migration plan.

## Security Requirements

- All token and authorization endpoints MUST be served over HTTPS in production;
  the `ISSUER` environment variable MUST be an `https://` URL.
- Client secrets MUST be stored hashed; they MUST NOT appear in logs, error responses,
  or token payloads.
- Access tokens and refresh tokens MUST carry an explicit `exp` claim; unbounded token
  lifetimes are forbidden.
- The `redirect_uri` MUST be validated against pre-registered values on every
  authorization and token request.
- CSRF protection via the `state` parameter or PKCE is REQUIRED for all Authorization
  Code flows.
- Error responses MUST conform to RFC 6749 §5.2; internal stack traces MUST NOT be
  included in responses returned to OAuth clients.
- The administrative control plane MUST require authenticated, authorized access; admin
  privileges MUST be scoped (least privilege) and MUST NOT be granted implicitly.
- Every state-changing administrative action — whether initiated by a human or by an AI
  agent via MCP — MUST be recorded in an immutable audit log capturing actor, action,
  target, and timestamp. AI-agent actions MUST be attributable to the agent and the
  authorizing principal.
- Operations that MCP may invoke MUST be an explicit allow-list; destructive or
  irreversible operations exposed to MCP MUST require an additional confirmation or
  policy gate.

## Development Workflow

- **Branch naming**: `###-kebab-feature-name` (e.g., `042-dpop-binding`).
- **Commits**: Conventional Commits format (`feat:`, `fix:`, `refact:`, `docs:`,
  `test:`).
- **Adding a grant type**: Create a handler in `lib/actions/grants/`, register it in
  the token dispatch table, add a feature flag in `lib/configs/`, provision the MongoDB
  collection, and write integration tests before implementation.
- **Adding an endpoint**: Create the action pipeline, mount it in the Elysia app, expose
  it in the discovery document, and protect it with the auth plugin when authentication
  is required.
- **Merge gate**: Both `bun run format` and `bun test` MUST pass with no failures.
- **Architectural changes**: `AGENTS.md` MUST be updated whenever architectural patterns
  or the action pipeline contract change.

## Governance

This constitution supersedes all other development practices for this repository.
Amendments require:

1. A written rationale for the change.
2. A version increment following semantic versioning:
   - MAJOR — principle removal or redefinition that is backward-incompatible.
   - MINOR — new principle or section added, or materially expanded guidance.
   - PATCH — clarification, wording fix, or non-semantic refinement.
3. A propagation check across all `.specify/templates/` files and `AGENTS.md`.
4. An update to `Last Amended` date (ISO format).

All pull requests MUST be reviewed for compliance with this constitution. When a feature
requires deviating from a principle, the deviation MUST be documented in the PR
description and, if the exception is long-lived, reflected as an amendment here.
Runtime development guidance is maintained in `AGENTS.md`.

**Version**: 2.1.0 | **Ratified**: 2026-06-19 | **Last Amended**: 2026-06-19
