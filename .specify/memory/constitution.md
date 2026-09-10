<!--
SYNC IMPACT REPORT
==================
Version change: 2.2.0 → 3.0.0 (MAJOR — Principle V redefined, backward-incompatible)
                3.0.0 → 3.0.1 (PATCH — completeness template widened to admit property-based tests)
  The PATCH was found by applying the rule rather than by reading it. Classifying
  test/properties/invariants.spec.ts, the first batch under the new principle, showed that its
  seven cases fit NEITHER template as first written: a property-based test has no trigger, so the
  behavioural form does not fit, and its input space is generated rather than "enumerable", so the
  completeness form excluded it on a word chosen to stop a guard hardcoding a copy of the set it
  checks. Taken literally the rule deleted seven exemplary security invariants — header injection,
  CSP tag matching, HTML escaping — each of which the file records as having survived three rounds
  of example-based fixes. The template now names both shapes of set explicitly. Recorded here
  because the near-miss is the argument for classifying case by case rather than reasoning about
  the rule in the abstract.
Modified principles:
  V. Integration-First Testing → V. Tests Prove User Cases or Security Invariants. The
    principle is rewritten rather than supplemented. Integration-first survives inside it as a
    consequence of the rule; the clause "Unit tests are permitted but MUST NOT substitute for
    integration coverage" is gone.
Rationale (Governance §1):
  The suite had reached 285 spec files, 2,835 test cases and 75,020 lines — larger than several
  of the subsystems it covers — and it grew monotonically because nothing written down said what
  a test had to be ABOUT. The old Principle V required integration coverage and then permitted
  unit tests without bounding them, so an assertion about any function was admissible and no test
  could be removed without an argument nobody had the standing to make. Two costs came due.
  Refactoring internals broke tests that never described a behaviour anyone depended on, which
  taught contributors that internal structure was frozen; and a reviewer facing a new test had no
  criterion with which to say no. The shape of the problem is visible in the numbers: 263 of 285
  spec files import lib internals directly while 80 exercise the HTTP layer, and only 35% of case
  names state the condition their outcome depends on.
  Two findings shaped the rule and are recorded because they were not obvious. First, the guards
  that looked like structure tests — catalogue drift, audit route classification, inventory drift,
  backend parity — enumerate the MOUNTED ROUTE TABLE of the constructed application, not the text
  of source files. They were never structure tests in the sense the testing literature condemns,
  and they close a claim about ABSENCE that no example-based test can close. They are admitted
  under the completeness template rather than exempted, and no third category was created for
  them. Second, two assertions sitting inside one of those same guards — that the published tool
  list has 65 entries and the exclusion list 12 — fit no template at all: they name no set and no
  property, fire identically on a legitimate addition and on a mistake, and are always repaired by
  updating the number. That one file contains both kinds is why classification is per test case
  rather than per file.
  MAJOR because the governance clause reserves it for "principle removal or redefinition that is
  backward-incompatible", and this is exactly that: tests compliant under 2.2.0 are non-compliant
  under 3.0.0. Deleting them is the intended consequence, not a side effect.
Added sections: none
Removed sections: none
Templates requiring updates:
  ✅ .specify/templates/plan-template.md — Constitution Check defers to this file; no structural
    change needed, and its gate now reaches the rule through Principle V.
  ✅ .specify/templates/spec-template.md — aligned; its acceptance scenarios are already
    Given/When/Then, which is where the three-slot form belongs.
  ✅ .specify/templates/tasks-template.md — aligned; its "Tests are OPTIONAL" note is unchanged,
    because the rule governs what a test must be, not whether one is written.
  ✅ AGENTS.md §Testing — rewritten so a contributor reading only that file writes admissible
    tests. The same edit corrects a standing inaccuracy: it instructed `bootstrap(import.meta)`
    while every spec calls `bootstrap(import.meta.url)`.
Follow-up TODOs:
  ✅ The existing suite was classified case by case (2,766 of them) and refactored: 8 spec files
    deleted, ~400 cases re-anchored or renamed. There is deliberately **no mechanical
    enforcement** — a guard requiring each spec to declare its intent was built and then withdrawn,
    because it failed this principle's own second question: no audience outside the code depends on
    whether a spec file declares itself. So the principle is applied by **review**, against
    test/RULES.md, which carries its working form and a pull-request checklist.
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
MUST be expressed as new adapter interface methods.

The **default test run** — `bun test`, which is the merge gate — MUST use the in-memory
`TestAdapter` as its sole adapter and MUST make no real database calls.

A **storage-fidelity suite** MAY use a real database, under three binding conditions. It
MUST be invoked separately and MUST NOT be reachable from the default run. It MUST be
confined to properties an in-memory double cannot exhibit — server-side value encoding,
index constraints, expiry, concurrency, and the provisioned collection set; coverage a
database-free test can provide MUST NOT be moved into it. And every behavioural divergence
it finds between two adapters MUST be resolved either by converging them or by declaring
the difference with a written reason, never by tolerating it silently.

### IV. Type Safety

TypeScript strict mode is non-negotiable. `any` is forbidden; use typed interfaces or
`unknown` with explicit type narrowing. All public API surfaces MUST carry explicit types.
Type assertions (`as SomeType`) MUST be accompanied by a comment explaining why the type
system cannot express the constraint statically.

### V. Tests Prove User Cases or Security Invariants (NON-NEGOTIABLE)

Every test in the suite exists to prove either a **User Case** or a **Security Invariant**.
A test that proves neither MUST be removed. Citing this principle is sufficient
justification for its removal; no further argument is required, and none may be demanded.

**User Case** — an outcome an identifiable audience depends on, stated from outside the
system: what someone tried to do, and what they observed. This server has four such
audiences and all of them count equally: the **end user** authenticating, the **client
application** integrating, the **administrator** operating the instance, and the **AI
agent** acting through the management surface. A refusal, an error response and a correct
degradation are outcomes exactly as success is — in this product the error responses are
normative protocol surface (the RFC 6749 §5.2 shapes, the specific error codes, the
`authorization_pending` and `slow_down` polling semantics), so proving the right refusal
for the right reason is a first-class user case and not an edge case admitted by exception.

**Security Invariant** — a property that MUST hold regardless of what a caller does, most
often a refusal: the request that must not succeed, the secret that must not appear, the
token that must not be accepted. Distinguished from a user case by being adversary-facing
rather than audience-facing. An invariant MAY be proved below the public surface where that
is the only place it is observable — a constant-time comparison is the standing example —
and MUST NOT be removed merely for being tested close to where it lives.

**How a test states its intent.** Every test MUST be expressible in one of two sentence
templates, and there are two rather than one because a test that enumerates a surface has
no trigger, and forcing behavioural prose onto it would delete it:

- behavioural — *`<outcome>` when `<condition>`*, with the shared context carried by the
  enclosing group;
- completeness — *for every `<member of a set>`, `<property>`*, where the set is either
  **enumerated from the running system** and the property checked against a declaration, or
  **generated over an input domain** and the property checked directly. The first form is the
  drift guard; the second is the property-based test. Both close a claim no example can close,
  and neither has a trigger.

A test fitting neither template proves code. An assertion that a list has a particular
length fits neither: it names no set and no property, it fires identically on a legitimate
addition and on a mistake, and its repair is always to update the number.

**A completeness guard is not a third category.** It is a User Case when its audience is
the operator and a Security Invariant when its audience is the attacker, and it is
admissible because an example-based test cannot prove an absence: a behavioural test proves
that a given route is audited, never that no route is unaudited, because the defect is the
route someone forgot. "User Case" MUST NOT be read as "an HTTP request".

**Admission** is decided by a two-part test, and both parts MUST hold:

1. the intent can be stated in one of the templates **without naming a function, class,
   module or file of the implementation in the trigger**; and
2. the outcome matters to one of the four audiences, or to an attacker.

Worked example: *"a public client that omits a code challenge is refused"* — a Security
Invariant; the trigger names an actor and an action, and an attacker is the audience.
Counter-example: *"the escaping helper returns `'false'` for `false`"* — the trigger can
only be written as "when the helper is called", so part 1 fails. Second counter-example,
which passes part 1 and still fails: *"a console notice is prefixed `oidc-provider NOTICE:`"*
— articulable, but no audience outside the system depends on a log prefix.

**Disposing of an existing test.** A test that proves nothing as written, but whose subject
matter is real, MUST be re-anchored to the surface where the behaviour is observable rather
than deleted. Deletion is admissible on exactly two grounds: the test proves nothing
observable at all, or it is a demonstrated duplicate of a named surviving test. **Effort is
not a ground** — a test that is expensive to re-anchor is re-anchored.

**Shape.** A test case MUST exercise one action; two triggers means two cases. Its name
MUST state the outcome in the present tense, and its condition wherever the outcome is
conditional — the connective is free (`when`, `while`, `after`, `unless`, `with`, `without`,
`for`, `on`) and the word "should" is neither required nor forbidden. Neither the name nor
the enclosing group may name a symbol of the implementation, where that is decided by
whether the word appears in the governing specification or in an operator's vocabulary: a
protocol field name is domain language, an internal identifier is not. Given/When/Then is a
discipline of formulation for specification documents; no BDD tooling, Gherkin syntax or
feature file is introduced.

**What follows for integration coverage.** An outcome observable from outside is usually
observable at the HTTP boundary, so most admissible tests are integration tests exercising
the real HTTP layer via the Eden client against the in-memory adapter, in the canonical
paired `*.config.ts` / `*.spec.ts` form. That is a consequence of the rule, not a second
instruction competing with it. When adding a new grant flow or endpoint, tests MUST be
written and confirmed failing before implementation begins.

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

**Version**: 3.0.1 | **Ratified**: 2026-06-19 | **Last Amended**: 2026-09-10
