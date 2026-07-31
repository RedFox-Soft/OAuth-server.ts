# Implementation Gap Backlog

Derived from the code-level gap analysis of 2026-07-28 (all specs 001–009 and admin SP-1..5 are
implemented; these tasks close the gaps found in the code itself). Health baseline at the time of
analysis: `bun test` green (1981 pass / 0 fail), `bun run typecheck` red (2633 errors: 836 lib,
1797 test).

**How to work this list.** Each task is sized for one Spec Kit cycle: feed the task body to
`/speckit-specify`, then clarify → plan → tasks → implement. Tasks marked **Investigate** exist
because the expected result is a product/design decision that must be made first — their
deliverable is a written decision (a research note under `specs/` or an update to this file) that
becomes the "Expected result" of the follow-up implementation task. Do not start an implementation
task whose dependency is unresolved. Check a task off only after the full suite passes.

Evidence pointers are given as `path:line` at the time of analysis; re-verify before relying on
exact line numbers.

---

## P0 — Functional holes in live paths

### 1. Enforce feature flags on protocol endpoints — ✅ Implemented

- **Delivered by** `specs/010-feature-flag-gating` (branch `010-feature-flag-gating`). Mechanism: a
  single `onRequest` gate (`lib/plugins/featureGate.ts`) driven by a declarative table
  (`lib/consts/route_classification.ts`) that classifies all 74 mounted routes as gated-by-flag (15)
  or explicitly always-available (59); a two-way drift guard fails the suite if any route is
  unclassified. Per-request flag evaluation, not boot-time mounting — the test suite drives one
  long-lived instance and flips settings between cases.
- **Findings worth carrying forward** (belong in `docs/wiki/` as a troubleshooting note once task 29
  initializes it):
  1. `POST /token` is always available while `POST /token/introspect` and `POST /token/revocation`
     are gated. Any prefix-style match on `/token` takes down every grant flow, and it presents as a
     token bug rather than a gate bug. Matching must be exact on (method, path).
  2. An HTML-preferring request to an unserved path used to answer **HTTP 200** with a page titled
     `200`, because `getErrorHtmlResponse` built its `Response` without a status. Corrected here for
     gated and unserved paths alike — see the note on task 14 item 4 below.
  3. A gate placed on `onRequest` must be mounted **after** the `nocache` plugin: `onRequest` hooks
     run in registration order and a throw short-circuits the chain, so gating first omits the
     `Cache-Control: no-store` every other response carries — a one-header fingerprint separating
     "disabled" from "absent".
  4. `test/fapi/fapi2.config.ts` drove `POST /par` without enabling `par.enabled`; it passed only
     because of this very defect. FAPI 2.0 mandates PAR, so the omission was always wrong.
- **Context:** Every route is mounted unconditionally (`lib/index.ts:77-97`) and no handler checks
  its own flag. With default (`false`) flags, these stay fully functional and only vanish from
  discovery: `POST /par` (`par.enabled` — its only check keys off `request_uri`, which the PAR body
  schema omits, so it is unreachable), `POST /token/introspect` (`introspection.enabled`),
  `POST /token/revocation` (`revocation.enabled` — never read on the request path), `POST /reg`
  (`registration.enabled` — **open client registration on a default deployment**), `PUT/DELETE
/reg/:clientId` (`registrationManagement.enabled`), `GET /logout` + `POST /logout/confirm`
  (`rpInitiatedLogout.enabled`), `GET/POST /userinfo` (`userinfo.enabled`). Device flow and CIBA
  front-channel (`lib/actions/authorization/device.ts:89,169`, `lib/actions/code_verification.ts`)
  check only client metadata, never `deviceFlow.enabled` / `ciba.enabled`.
- **Expected result:** A request to any endpoint whose governing flag is `false` is rejected the
  same way a nonexistent route is (HTTP 404; config is boot-only, so conditional mounting at boot
  is acceptable — the plan phase picks the mechanism). Device/CIBA front-channel endpoints check
  the server flag before client metadata. Discovery output is unchanged (already correct). Every
  flag listed above gets a spec test proving: flag off → endpoint unavailable; flag on → previous
  behavior intact. Full suite stays green.

### 2. CORS policy design — Investigate — **RESOLVED 2026-07-30**

- **Context:** The server emits no `Access-Control-*` header and mounts no `OPTIONS` route on any
  endpoint. `lib/shared/cors.ts` is dead code (zero importers, Koa-shaped, references an undefined
  `cors` identifier — it would throw if called). The `clientBasedCORS` addon (`lib/addon/cors.ts`,
  default deny-all) is unreachable. Browser-based clients therefore cannot call `/token`,
  `/userinfo`, `/jwks`, or discovery cross-origin. Both CORS test suites are ignored in
  `bunfig.toml`, so zero CORS assertions run.
- **Deliverable — done:** `docs/superpowers/specs/2026-07-30-cors-policy-design.md`. It records what
  the specs actually require (OIDC Discovery §3/§4 SHOULD; the browser-based-apps BCP MUST, which
  also forbids CORS on the authorization endpoint; RFC 9449 §7.1/§8 requiring `WWW-Authenticate`
  **and** `DPoP-Nonce` in `Access-Control-Expose-Headers`) and the seven product decisions: route
  classes (open / client-based / none), origins stored per **Project** as `corsOrigins`, a disallowed
  origin loses the header without the request being rejected, hand-rolled Elysia plugins (no new
  dependency), the `clientBasedCORS` addon deleted, a single `cors.enabled` config key, and an
  admin surface of entity + stores + create/patch + one minimal SPA editor. It also amends tasks 4,
  12, 21, 24 and 27 — see "Backlog impact" in the note.

### 3. CORS implementation — ✅ Implemented

- **Delivered by** `specs/011-cors-support`. All ten acceptance items below are in place: the
  `corsRoutes` table under a two-way drift guard (74 routes → 2 open / 6 client-based / 66 none), the
  three plugins in `lib/plugins/cors.ts`, the flag-aware preflight, the header contract,
  `Project.corsOrigins` with one shared validator, both client-identification paths, `cors.enabled`,
  the admin surface, and every removal. Suite: 2210 pass / 0 fail (was 1981).
- **Findings worth carrying forward** (belong in the wiki alongside task 1's notes):
  1. **The design note's `onBeforeHandle` was wrong**, and the plan corrected it to `onTransform`.
     `AuthPlugin` authenticates in a `derive`, which runs in the transform queue and throws
     `invalid_client` from there; body-schema 422s also precede `beforeHandle`. A header written at
     `beforeHandle` would be missing from exactly the two responses a misconfigured browser app hits
     most. Measured, not reasoned: `POST /token` with no body 401s from that derive.
  2. `set.headers` **does** merge into a raw `Response` returned by a handler *and* into one returned
     from an `onRequest` short-circuit. That is what lets `corsOpen` work on `jwks` (which builds its
     own `Response`) and lets the preflight 204 inherit `no-store` from `nocache` with no duplicated
     constant.
  3. `OPTIONS` on a mounted path already 404s identically to an unrouted path, `no-store` included —
     so the fall-through half of the no-leak contract held before any code was written.
  4. `POST /admin/api/projects` forwarded only four fields to `store.create()`, silently dropping
     `clientIds`. A schema-only addition would have accepted `corsOrigins` and discarded it. Fixed for
     `corsOrigins`; the `clientIds` drop is still there (nothing sends it).
  5. The in-memory project store is a process-wide singleton and `findByClientId` returns the *first*
     match, so a project left behind by an earlier test inverts a later filtered-origin assertion into
     a false pass. The suite tracks and destroys what it creates.
- **Source of truth:** `docs/superpowers/specs/2026-07-30-cors-policy-design.md`. The summary below
  is the acceptance surface; the note carries the rationale and the exact header contract.
- **Expected result:**
  1. **Classification.** A `corsRoutes` table in `lib/consts/route_classification.ts`, in Elysia
     declaration form, classifying every mounted route as open (`GET
/.well-known/openid-configuration`, `GET /jwks`), client-based (`POST /token`, `GET+POST
/userinfo`, `POST /token/revocation`, `POST /par`, `POST /device/auth`) or none (everything
     else, including `/auth`, `/reg*`, `/token/introspect`, `/backchannel`, `/logout*`, `/device`,
     `/ui/*`, `/admin/*`, `/health`, `/public/*`).
     `test/feature_gate/route_classification.spec.ts` is extended so an unclassified mounted route
     fails the drift guard in both directions.
  2. **Mechanism.** One new `lib/plugins/cors.ts`: `corsPreflight` (function plugin on `onRequest`,
     mounted in `lib/index.ts` directly after `featureGate`), `corsOpen` (mounted inside `discovery`
     and `jwks`), `corsClientBased(extractClientId)` (mounted inside `token`, `userinfo`,
     `revocation`, `par`, `deviceAuth`, running in `onBeforeHandle` so the header survives onto
     error responses). No new dependency — `@elysiajs/cors` is deliberately not adopted.
  3. **Preflight must not leak flag state.** `corsPreflight` resolves the governing flag via
     `gatedFlagForRequest(<Access-Control-Request-Method>, path)` and falls through to the ordinary
     404 when it is off, because that helper matches exactly on `(method, path)` and would never
     match an `OPTIONS`. A 204 on an endpoint that 404s every real request is the fingerprint
     `lib/plugins/featureGate.ts:44-49` exists to prevent. The 204 carries the same
     `Cache-Control: no-store` headers as every other response.
  4. **Headers.** `Vary: Origin` on every touched response; echoed `Access-Control-Allow-Origin`
     when allowed (never `*`, never `Access-Control-Allow-Credentials`); client-based responses also
     carry `Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce`; preflight returns 204 with
     the route's real methods, an echo of `Access-Control-Request-Headers`, and `Max-Age: 3600` (a
     module constant, not config — see D6a in the note). An `OPTIONS` without
     `Access-Control-Request-Method` is not a preflight and falls through to 404. Routes in the
     "none" class get no `Vary: Origin` either.
  5. **Allow-list.** `Project.corsOrigins: string[]` in `lib/adapters/types.ts` and both project
     stores (default `[]`, patchable). One shared validator: `new URL(v)` parses, protocol is
     `http:`/`https:`, `url.origin === v`, no wildcard/`*`/`null`, host lowercased, deduped;
     matching is exact string equality. `projectStore.findByClientId` resolves the client's project;
     Mongo gains an index on `projects.clientIds` (extends task 4).
  6. **Client identification.** `body.client_id` → `Basic` username for the form endpoints; access
     token → `payload.clientId` for `/userinfo`. `client_assertion`-only clients are not decoded
     (documented). No identifiable client → no header, request unaffected.
  7. **Config.** One key: `cors.enabled` (default `true`) in `ApplicationConfig` and the settings
     catalog, read flat per request like `featureGate` does. `cors.enabled: false` suppresses all
     emission and makes preflight fall through to 404. `cors.maxAge` is deliberately **not** a key
     (it would be the first numeric one and the catalog has no `number` type — D6a).
  8. **Admin.** `corsOrigins` accepted by `POST /admin/api/projects` and the existing `PATCH
/admin/api/projects/:id` with the shared validation and the existing RBAC/admin-project guards,
     plus one origins editor on `lib/admin/ui/pages/Projects.tsx`. Full project edit stays task 19;
     auditing project mutations stays task 8.
  9. **Removals.** `lib/shared/cors.ts`; `lib/addon/cors.ts` plus its `AddonImplementations` entry
     and `lib/addon/index.ts` re-export; `test/cors/cors.config.ts`;
     `test/cors/custom_cors.spec.ts` (**deleted, not migrated** — it asserts that a Koa `cors()`
     middleware injected via `provider.use()` overrides the built-in handling, and neither exists);
     both `test/cors/*` entries in `bunfig.toml`.
  10. **Tests.** `test/cors/cors.spec.ts` rewritten for bun:test covering the 16 cases listed in the
      design note — including the disallowed-origin case succeeding without a header, the
      `/userinfo` DPoP-nonce 401 exposing both header names, the flag-off preflight 404, the
      negative sweep over every "none"-class route, and `cors.enabled: false`. Plus the drift-guard
      extension, a storage-contract round-trip for `corsOrigins` in both adapters, and admin route
      validation/RBAC tests. Full suite green.

### 4. Complete `db:setup` provisioning — Implement

- **Context:** Verified empirically on a throwaway DB: after `bun run db:setup`, the collections
  `VerificationChallenge`, `VerificationResend`, and `serviceConfig` do not exist — they
  auto-create on first write **without TTL indexes**, so expired verification challenges and
  resend rate-limit records are never reaped in production (`lib/verification/challenge.ts:24,28`,
  `lib/adapters/mongodb/configStore.ts:13`). Per-bucket `user_<bucket>` collections have **no
  unique index on `email`** (duplicate check in `lib/adapters/mongodb/userStore.ts:35-38` is racy;
  `findByEmail` is an unindexed scan on every login). Also: `database/collections.ts` lists
  `DeviceCode` and `BackchannelAuthenticationRequest` twice (harmless — MongoDB tolerates
  re-create, verified — but fix the hygiene), and the TTL-index `else` branch applies `expiresAt`
  TTLs to collections that never carry that field (audit the per-collection index mapping).
- **Expected result:** `bun run db:setup` provisions every collection the code uses, with correct
  per-collection indexes: TTL on `VerificationChallenge`/`VerificationResend`, no TTL on
  `serviceConfig`/`Client`/`projects`/`userBuckets`, unique `email` index created for user
  collections (including a hook so newly created buckets get it — bucket creation happens at
  runtime via the admin API, so index creation must live where user collections are created, not
  only in the setup script). Duplicate list entries removed. Script stays idempotent (re-run
  succeeds). A test or documented manual verification proves the collection/index inventory.
- **Amended by task 2's decision note:** the inventory must also create an index on
  `projects.clientIds` (no TTL) — `projectStore.findByClientId` becomes a per-request lookup on five
  endpoints once client-based CORS lands.

### 5. DPoP nonce configuration safety — Implement

- **Context:** `dpop.requireNonce` is in the admin settings catalog but `dpop.nonceSecret` is not
  (`lib/admin/settings/catalog.ts:68-74`), and `validateConfiguration` neither cross-checks the
  pair nor enforces the documented "32-byte Buffer" constraint (`lib/configs/application.ts:46`).
  Result: an admin can enable `requireNonce` with no secret; every DPoP request then throws a bare
  `Error` → 500 (`lib/helpers/validate_dpop.ts:48-50,156`).
- **Expected result:** `validateConfiguration` rejects `dpop.requireNonce: true` (and
  `dpop.allowReplay` if it needs the secret) when `dpop.nonceSecret` is absent/invalid, and
  validates the 32-byte constraint — so both boot and the admin `PUT /admin/api/settings` (which
  validates candidates with the same function) refuse the broken combination with a clear message.
  Decide during planning how the secret is supplied (env, generated-and-persisted like signing
  keys, or write-only catalog entry like the SMTP password) and implement it. No request path can
  reach the bare-`Error` throw. Tests cover: invalid combo rejected at boot and via admin PUT;
  valid combo → nonce flow works.

### 6. Rich Authorization Requests product scope — Investigate

- **Context:** RAR is enable-able from the admin UI but cannot work end-to-end: the consent page
  drops `authorization_details` (`lib/interactions/consentView.ts:26-30` omits the `rar` key the
  consent prompt emits), `grant.addRar` has zero callers (`lib/models/grant.ts:289-292`), all four
  addon hooks throw 'not implemented' (`lib/addon/rar.ts`), and `richAuthorizationRequests.types`
  is function-valued so it cannot be configured via the admin API (empty `{}` → every
  `authorization_details` value rejected at `lib/shared/check_rar.ts:62`). The only RAR-rendering
  code in the repo is in the dead legacy template `lib/views/interaction.ts:42-46`.
- **Deliverable (defines Expected result of task 7):** Decide: (a) is RAR a supported product
  feature (implement consent rendering + grant persistence + workable default hooks + a
  serializable type-config format) or a code-extension-only feature (then hide/guard the admin
  toggle per task 12 and document the extension contract); (b) if supported, define the
  `authorization_details` type-configuration format an admin can express, and the consent-screen
  UX for displaying details.

### 7. Rich Authorization Requests end-to-end — Implement (depends on task 6)

- **Expected result:** Whatever task 6 decides, made true in code and proven by functional tests
  that send `authorization_details` through the authorization-code flow (today zero tests do).
  Definition of done if "supported": consent page displays details, approved details persist on
  the Grant via `addRar`, token issuance honors them, admin can configure types. Definition of
  done if "extension-only": toggle guarded, contract documented, dead paths removed.

---

## P1 — Security & conformance

### 8. Admin audit completeness and readability — Implement

- **Context:** The constitution note (`lib/admin/audit/record.ts:5-8`) promises an immutable audit
  log for **every** admin action, but `recordAdminAudit` has exactly 5 call sites (bucket policy
  branch, JWKS ×2, settings, SMTP). Unaudited: project create/update/delete/bucket-assign, client
  create/update/delete/secret-rotate, admin create/update/deactivate, end-user
  create/update/password-reset/delete, bucket create/delete, first-run setup. The trail is also
  write-only: `adminAuditStore.list()` exists in both adapters (`lib/adapters/types.ts:124-127`)
  but no route or UI reads it.
- **Expected result:** Every state-changing admin route writes an audit record (audit-first, as
  the existing call sites do) capturing actor, action, target, timestamp. A read surface exists:
  `GET /admin/api/audit` (paginated, filterable by actor/action/target, super-admin only) plus an
  admin SPA page listing it. Tests assert an audit record for each mutating route and cover the
  read API's authz.

### 9. Deletion integrity semantics — Investigate

- **Context:** No cascade or guard exists on any delete: project delete leaves its clients in the
  DB **still able to authenticate at `/token`** (`lib/admin/projects/routes.ts:87`); client delete
  revokes no grants/sessions/tokens (`lib/admin/clients/service.ts:193-195`); end-user delete
  keeps their sessions/grants/tokens (`lib/admin/users-end/routes.ts:100`); bucket delete leaves
  the `user_<bucket>` collection behind.
- **Deliverable (defines Expected result of task 10):** For each entity (project, client, bucket,
  end-user), decide: block deletion while dependents exist vs cascade (and exactly what cascades:
  clients? grants? sessions? tokens? collections?), and what the admin UI shows (confirmation
  listing consequences). Note the token model: revocation by grantId exists
  (`lib/helpers/revoke.ts`), and mind the memory-vs-mongo `revokeByGrantId` divergence
  (`lib/adapters/memory/memoryAdapter.ts:93-122` global vs `lib/adapters/mongodb/mongoAdapter.ts:66-68`
  per-collection) — the decision doc must say which semantics is correct so task 10 can align both.

### 10. Deletion integrity implementation — Implement (depends on task 9)

- **Expected result:** The decided semantics implemented for all four entities; the
  `revokeByGrantId` adapter divergence resolved to the decided behavior with a storage-contract
  test pinning it; no deleted principal can authenticate or use existing tokens afterward
  (negative tests: deleted project's client at `/token`, deleted user's refresh token, etc.).

### 11. Verify the admin BFF id_token signature — Implement

- **Context:** `lib/admin/auth/login.ts:86-96` base64-decodes the id_token payload without
  signature verification — a documented first-party shortcut with an explicit "MUST be replaced
  with full signature verification" comment. The local JWKS is available in-process
  (`lib/configs/keystore.ts`).
- **Expected result:** The callback verifies the id_token signature (and `iss`, `aud`, `exp`,
  `nonce` if present) against the live local keystore before trusting `sub`. Invalid/tampered
  tokens → 401, no admin session created. Tests cover: valid token logs in; tampered
  payload/signature rejected; token signed by a foreign key rejected.

### 12. Guard feature toggles that require code overrides — Implement

- **Context:** The admin settings catalog exposes toggles whose default addon hooks throw or
  misbehave, so a super-admin can 500 the server from the UI: `ciba.enabled` (5 hooks throw,
  `lib/addon/ciba.ts`), `richAuthorizationRequests.enabled` (4 hooks throw, `lib/addon/rar.ts`),
  `resourceIndicators.enabled` (default `getResourceServerInfo` throws `InvalidTarget`,
  `lib/addon/resources.ts:27-31` — and it defaults to **true**), `mTLS.*`
  (`certificateAuthorized`/`certificateSubjectMatches` throw, `lib/addon/mtls.ts:22-40`). The
  override registry (`lib/addon/registry.ts`) is code-only.
- **Expected result:** Enabling any feature whose required hooks are still the throwing defaults
  fails validation (boot and admin PUT) with a message naming the missing hooks — or, where a
  sensible default is implementable (planning decision per feature), the default is implemented
  instead. The catalog marks such settings so the UI can explain why they are locked. Tests: each
  guarded flag rejected without overrides, accepted with overrides registered.
- **Amended by task 2's decision note:** `clientBasedCORS` is not among the hooks needing a guard —
  task 3 deletes the addon and replaces it with project-scoped origin data.

### 13. Protocol conformance batch — Implement

- **Context / Expected results (one spec, several verified fixes):**
  1. **POST end-session:** OIDC RP-Initiated Logout requires GET and POST on the same endpoint;
     only `GET /logout` exists (`lib/actions/end_session.ts:40`). → `POST /logout` accepts
     form-encoded logout requests identically to GET.
  2. **RFC 8414 metadata:** discovery never emits
     `introspection/revocation_endpoint_auth_methods_supported` (+ `_auth_signing_alg_values_supported`)
     although both endpoints require client auth. → advertised when the endpoints are enabled.
  3. **`grant_types_supported` parity:** `lib/configs/discoverySupport.ts:47-62` and
     `lib/configs/configuration.ts:118` disagree when `refreshToken.enabled` is set without
     `offline_access`. Decide the fate of the otherwise-dead `refreshToken.enabled` flag (its only
     read is that one line) — either make it real (gate the grant, advertise it, catalog it) or
     remove it; both sides must derive from one source afterward, with a parity test stronger than
     the current single-fixture check.
  4. **`registrationManagement.enabled`:** currently affects nothing (task 1 gives it endpoint
     gating; this item makes sure discovery/`registration_client_uri` behavior matches the flag).
- **Expected result:** All four items fixed with spec tests; discovery baseline fixtures updated.

### 14. Small verified bug-fix batch — Implement

- **Context / Expected results (one spec, independent one-to-few-line fixes, each with a test):**
  1. `GET /admin/setup` references `/admin.js`; the bundle is served at `/public/admin.js`
     (`lib/admin/auth/setup.ts:16`) → setup page actually hydrates.
  2. `interaction.returnTo` persists an unmounted URL `/auth/{uid}`
     (`lib/helpers/oidc_context.ts:57-63`); the real resume route is `/ui/:uid/resume` → stored
     value matches a mounted route (or the dead field is removed — nothing reads it today).
  3. `form_post` response mode ships an inline `<script>` with the CSP-hash call commented out
     (`lib/html/formPost.tsx:36`, `lib/helpers/script_src_sha.ts` otherwise dead) → hash emitted
     in CSP header, or the helper deleted with a decided CSP story.
  4. Error page shows the 403 illustration for every non-500 status (`lib/html/error.tsx:10`) →
     status-appropriate rendering. **Partly done by task 1:** the response now carries the real
     status (it defaulted to 200, so every HTML-rendered error answered `200 OK`), and
     `errorHandler` assigns 404 for `NOT_FOUND`. What remains for this item is only the
     _illustration_ choice — `renderError` still passes `'403'` for every non-500 status. Verified
     no existing test asserted the old 200.
  5. Admin client schema offers CIBA delivery mode `'push'` which config validation rejects and
     nothing implements (`lib/admin/clients/schema.ts:32,53`) → option removed.

### 15. Pairwise identifier salt — Implement

- **Context:** `pairwiseIdentifier` salts with `os.hostname()` (`lib/addon/tokens.ts:30-41`); its
  own warning says dev-only. Hostname changes (container reschedules, horizontal scaling) silently
  change every pairwise `sub`, breaking RP account linkage.
- **Expected result:** The salt comes from persistent server state (generated once and stored,
  like signing keys/`serviceConfig` — planning picks the store) so pairwise subs are stable across
  restarts and hosts. Existing-deployment migration note written (subs WILL change once when
  moving off hostname — call it out in CHANGELOG). Test: two provider boots produce identical
  pairwise subs for the same account+client.

---

## P2 — Incomplete product surfaces

### 16. End-user password reset — Implement

- **Context:** No route, page, template, token store, or admin-independent path exists; the login
  page's "Forgot password" is a dead `href=""` (`lib/interactions/loginPage.tsx:114`). The email
  infrastructure (SMTP settings, `lib/mail/`, verification-challenge patterns with TTL + attempt
  caps + resend cooldowns in `lib/verification/`) is a ready template.
- **Expected result:** Self-service reset: request form (from the login page link) → single-use,
  TTL'd, hashed-at-rest token emailed via the existing mail transport → reset form → password
  updated, sessions for that user invalidated (coordinate with task 9/10 semantics), audit-free
  (user-initiated) but rate-limited like verification resends. Bucket-scoped (respects
  `resolveBucketForClient`). New collection provisioned with TTL (extends task 4 inventory).
  Tests cover the happy path, expiry, reuse, rate limits, and unverified/inactive users.

### 17. Interaction UI fixes batch — Implement

- **Context / Expected results (one spec):**
  1. Post-registration redirect `/ui/:uid/login?notice=verify` is never rendered — the GET login
     route ignores the query and `loginServer` only accepts an error message
     (`lib/interactions/index.ts:252,157`, `serverRender.tsx:10`) → user sees a "check your inbox"
     notice after registering into a verification-required bucket.
  2. Registration failures return bare `text/plain` (403 closed / 400 password mismatch / 502)
     (`lib/interactions/index.ts:217-258`) → styled pages or inline form errors, consistent with
     the login page's error rendering.
  3. `registrationServer` never substitutes `<!--app-props-->` (`serverRender.tsx:37-52`), unlike
     login/consent → hydration props injected the same way as the other pages.
  4. The decorative "Sign in with Google" button and the dead "Forgot password" link are removed
     until their features exist (tasks 18 and 16 respectively re-add them for real).
  5. Consent page is all-or-nothing scope display — verify (and test) that `missingOIDCClaims`
     and `missingResourceScopes` actually render; RAR display is task 7's scope.

### 18. Social login / federation — Investigate

- **Context:** No federation code exists anywhere in `lib/` (the Google button was decorative).
  Spec 001 explicitly declared social login out of scope, so this needs a product decision, not
  just code. `UserBucket.authMethods` exists but is never read (`lib/adapters/types.ts:182`).
- **Deliverable:** Decide whether federation enters the roadmap; if yes, define providers (OIDC
  generic? Google first?), the account-linking model (federated identity ↔ bucket user), per-bucket
  enablement via `authMethods`, and the interaction-UI flow. That document becomes the spec input
  for a future implementation task.

### 19. Admin UI completion — Implement

- **Context:** Backend routes exist with no UI reaching them, creating dead ends:
  `PATCH/DELETE /admin/api/projects/:id` and `PUT /admin/api/projects/:id/bucket` are unreachable
  (`lib/admin/ui/pages/Projects.tsx` lists/creates only) — and since the "Users" button is
  `disabled={!row.bucketId}`, **a newly created project can never be given a bucket through the
  UI**; admins page is list+create only (no roles/deactivate UI, and no password change for admins
  at all — `UpdateAdminBody` lacks `password` while end-users have a reset route);
  `DELETE /admin/api/buckets/:id` has no UI; bucket `managedBy` accepted by API but not editable;
  `restartRequired` is displayed but no restart action exists anywhere.
- **Expected result:** Project edit/delete/bucket-assign flows in the SPA (unblocking the Users
  dead end); admin management UI (roles, deactivate, guarded by the existing last-super-admin
  rule) plus an admin password-change path (self-service at minimum — schema + route + UI);
  bucket delete and `managedBy` editing in the UI. For restart: this task only adds an explicit
  "restart required" affordance explaining the manual step — an actual restart trigger is
  deployment-specific and stays out of scope unless a later investigation adds it. UI changes
  covered by route-level tests; SPA pages at least smoke-rendered.

### 20. Admin client-management schema expansion — Implement

- **Context:** `lib/admin/clients/schema.ts:20-56` exposes a fraction of
  `lib/configs/clientSchema.ts`: no `jwks`/`jwksUri`, `sectorIdentifierUri`, `subjectType`,
  `backchannelLogoutUri`/`backchannelLogoutSessionRequired`, `responseTypes`,
  `idTokenSignedResponseAlg`, `dpopBoundAccessTokens`, `tlsClientAuth*`,
  `logoUri`/`policyUri`/`tosUri`; auth methods capped at
  `none|client_secret_basic|client_secret_post` while the server supports
  `client_secret_jwt`/`private_key_jwt`. Net effect: mTLS, JWT client auth, DPoP-bound clients,
  and back-channel logout can be enabled server-side but **no client can be configured to use
  them** through the admin plane.
- **Expected result:** Admin client create/update covers the full client schema surface (validated
  by the same `validateClient` the server uses), the SPA form exposes the fields grouped sensibly,
  and misconfigurations surface the schema's own error messages. Tests: create/update a
  `private_key_jwt` client with `jwks`, a back-channel-logout client, and a cert-bound client via
  the admin API and verify they function at the protocol endpoints.

### 21. Settings catalog completeness — Implement

- **Context:** Catalog covers 39 of 58 `ApplicationConfig` keys. Functional omissions:
  `registration.initialAccessToken` (the only lever that closes open registration once task 1
  lands — and it is a prerequisite for `registration.policies` per
  `lib/configs/configuration.ts:202-210`) and `claims` (drives `claims_supported` and
  claim-backed scopes; omitted without the documented-intentional note `discovery` has).
  `dpop.nonceSecret` is task 5. Function-valued keys (`registration.policies`,
  `richAuthorizationRequests.types`) are legitimately non-serializable — document why they are
  absent instead of leaving it implicit.
- **Expected result:** `registration.initialAccessToken` (write-only/masked like the SMTP
  password if a string secret) and `claims` are editable via the settings API/UI with proper
  validation; intentionally-omitted keys carry an explanatory note in the catalog module; a test
  pins the catalog-vs-ApplicationConfig key diff so future keys must be classified explicitly.
- **Amended by task 2's decision note:** task 3 adds `cors.enabled` (catalogued there), so the
  key-diff test must account for it. `cors.maxAge` was dropped because the catalog has no `number`
  `SettingType`; if this task adds one, that key becomes a viable follow-up.

### 22. Admin session/grant/token visibility and revocation — Implement

- **Context:** `lib/admin/` has zero references to `Grant`, `Session`, `AccessToken`,
  `RefreshToken`, or `helpers/revoke`. No admin can see or revoke an end-user's sessions, grants,
  or tokens; `AdminSessionStoreInstance` has no list-by-user, so admins can't manage their own
  other sessions either.
- **Expected result:** Per end-user: list active sessions and grants (with client, scopes,
  timestamps) and revoke them (grant revocation cascades to its tokens via the task-9/10-aligned
  semantics). Per admin: list own sessions, revoke others ("sign out everywhere"). Store
  interfaces gain the needed list methods in **both** adapters with storage-contract tests. All
  mutations audited (task 8 pattern).

### 23. JWKS management: non-RSA keys — Implement

- **Context:** Admin key generation is RSA-only (`lib/admin/jwks/service.ts:15`), while the
  configured algorithm surface and test keystore include ES256/EdDSA. No encryption-use keys can
  be provisioned via the admin API.
- **Expected result:** Admin JWKS API can generate EC (ES256) and OKP (EdDSA) signing keys, and
  the key list/status/delete/audit behavior covers them identically to RSA. Planning decides
  whether encryption-use keys are in scope now or documented as follow-up. Tests mirror the
  existing RSA route specs for each new type.

---

## P3 — Debt, coverage, docs

### 24. Migrate ignored and skipped test suites — Implement

- **Context:** `bunfig.toml` ignores `test/cors/cors.spec.ts`, `test/cors/custom_cors.spec.ts`
  (both handled by task 3) and `test/helpers/attention.spec.ts` (uses Mocha's `context()`).
  Additionally never running: `test/provider/provider_instance.spec.ts` (whole file
  `describe.skip`, targets a removed constructor API — likely delete or rewrite),
  `test/configuration/secure.spec.ts` (`describe.skip`, obsolete `x-forwarded-proto` trust —
  decide delete vs revive), one intentional skip in `test/signatures/signatures.spec.ts` (HS256,
  keep). Dead orphan configs: `test/cors/cors.config.ts` (task 3), `test/routing/routing.config.ts`
  (no spec at all), `test/provider/set_session.config.ts`.
- **Expected result:** `bunfig.toml` ignore list contains only entries with a written
  justification (target: empty apart from anything task 3 hasn't absorbed); each skipped file is
  migrated, rewritten against current APIs, or deleted with rationale in the commit message;
  orphan configs deleted or given specs. Suite count reflects reality (no silently-dead specs).
- **Amended by task 2's decision note:** task 3 absorbs all three `test/cors/*` items —
  `cors.spec.ts` rewritten, `custom_cors.spec.ts` deleted (its `provider.use()` + Koa `cors()`
  premise no longer exists), `cors.config.ts` deleted. Only `test/helpers/attention.spec.ts` remains
  here from the ignore list.

### 25. MongoDB adapter test strategy — Investigate

- **Context:** The production storage backend (`lib/adapters/mongodb/`, all 11 files) has zero
  test coverage — tests always run the in-memory adapter (`lib/adapters/index.ts:58-60`;
  `MONGODB_URI` never set under test). Known behavioral divergences already found:
  `revokeByGrantId` scope (see task 9), email lowercasing on insert (mongo) vs as-supplied
  (memory), `upsert` never `$unset`s a stale `expiresAt`.
- **Deliverable:** A decision note: how mongo-backed tests run (real local mongod in CI /
  testcontainers / a dedicated `bun test` project with `MONGODB_URI` + cleanup strategy), which
  suites run against it (minimum: the existing `test/storage_contract/` round-trips + the store
  specs, parameterized over both adapters), and how divergences get pinned. Produces the spec
  input for the implementation task it defines.

### 26. Typecheck remediation strategy — Investigate

- **Context:** `bun run typecheck` (`tsc --noEmit`) fails with 2633 errors: 836 in `lib/`
  (overwhelmingly implicit-`any` — known accepted debt from the non-aggressive typing approach),
  1797 in `test/`. Worst offenders: `lib/models/client/schema.ts` (89),
  `test/configuration/client_metadata.spec.ts` (243). Because the command fails wholesale, it
  gates nothing and new type errors land unnoticed.
- **Deliverable:** A decision note choosing the path to a _useful_ typecheck signal: e.g. a
  ratchet (error-count budget file enforced in CI), a scoped `tsconfig.typecheck.json` that is
  green today and grows, or a phased burn-down plan with per-directory milestones. Includes the
  measured baseline per directory and defines the follow-up implementation task(s).

### 27. Dead code removal — Implement

- **Context (verified zero importers / unreachable):** entire `lib/views/` directory (3 legacy
  template files — note `interaction.ts:42-46` is the repo's only RAR rendering; coordinate with
  task 7 before deleting), `lib/admin/ui/pages/Stub.tsx`, `lib/helpers/params.ts`,
  `lib/helpers/set_www_authenticate.ts` (superseded by inline code in
  `authorization_error_handler.ts`), `lib/helpers/_/pick_by.ts`, `lib/helpers/script_src_sha.ts`
  (only call commented out — task 14 item 3 decides its fate first), `provider.urlFor/pathFor`
  (`lib/provider.ts:33-45` — reads never-assigned fields, would throw if called),
  `lib/models/grant.ts` `addRar` (task 7 decides), empty-body addon asserts
  (`lib/addon/claims.ts:9-13` `assertClaimsParameter`, `lib/addon/default.ts:13-22` — verify
  whether empty-by-design as override seams; if so, document instead of delete).
- **Expected result:** Each listed item deleted, or kept with a written reason (override-seam
  documentation counts). Zero importers re-verified at deletion time (tasks 7/14 may have changed
  things). Full suite and lint green afterward.
- **Amended by task 2's decision note:** `lib/shared/cors.ts` and `lib/addon/cors.ts` (plus its
  `AddonImplementations` entry and `lib/addon/index.ts` re-export) are removed by task 3, not here.

### 28. Documentation sync — Implement

- **Context:** `README.md` endpoint table has 6 of 11 rows wrong (real paths: `/auth`, `/par`,
  `/reg`, `/token/introspect`, `/token/revocation`, `/logout`; userinfo is GET+POST); Features
  claims "Static and dynamic client registration" (static clients were removed — clients are
  DB-backed via admin API/DCR/seed); Features/Standards omit implemented capabilities (Device
  Flow RFC 8628, CIBA, JARM, RAR RFC 9396, mTLS RFC 8705, Resource Indicators RFC 8707,
  RFC 8414, RFC 9207 `iss`, RFC 7592) and the admin control plane. `AGENTS.md:140` says
  interaction routes are `/interaction/*`; they are `/ui/:uid/*`. Housekeeping: check off the 24
  stale checkboxes in `specs/004-findaccount-direct-db/tasks.md` (work landed in `ab8eb01`,
  `88e3ae5`).
- **Expected result:** README endpoint table matches mounted routes exactly (source of truth:
  `lib/consts/param_list.ts`); Features/Standards list what is actually implemented, with
  flag-gated features marked as opt-in; AGENTS.md route reference corrected; spec-004 checkboxes
  checked. No code changes.

### 29. Initialize the `docs/wiki/` knowledge base — Implement

- **Context:** The org standard requires a git-tracked `docs/wiki/`; it does not exist. Spec
  tasks 005-T017 and 006-T018 already called for capturing the redirect_uri-omission business
  rule and the DB-single-sourced-clients architecture there.
- **Expected result:** `docs/README.md` + `docs/wiki/` + `Index.md` scaffolded per the docs-wiki
  skill conventions (frontmatter, naming, wikilinks, `## Related` sections), seeded with at
  minimum: the config three-surface architecture note, the clients-from-DB note, the
  redirect_uri-omission business rule, the addon override-registry contract (including which
  hooks throw by default — feeds task 12), and a troubleshooting note for the CORS/flag-gating
  findings of this analysis. Every note linked from `Index.md`.

### 30. Missing OIDC surfaces roadmap — Investigate

- **Context:** Entirely absent, with traces suggesting past intent: OIDC Session Management /
  `check_session_iframe` (stale docstring at `lib/actions/authorization/respond.ts:10-11`
  references an OP iframe cookie that is never written) and Front-Channel Logout (no discovery
  keys, no client metadata). `request_uri`-by-reference is deliberately unsupported and correctly
  advertised — leave it.
- **Deliverable:** A decision note: implement, or explicitly declare unsupported. If declared
  unsupported: remove the stale docstring and record the decision in `docs/wiki/` (task 29). If
  implementing: a spec input defining scope (front-channel logout is the likelier candidate;
  session management is legacy — modern guidance leans on back-channel logout, which already
  works).

---

## Suggested order

Quick wins first: **14** (bug batch) → ~~**1** (flag gating)~~ → **4** (db provisioning) → **5**
(DPoP safety) → **11** (id_token verification). Then the investigation pair-ups: ~~**3** (CORS)~~,
**9→10** (deletion), **6→7** (RAR). Then P1 remainder (**8**, **12**, **13**, **15**), P2 product
work (**16**–**23**), and P3 (**24**–**30**) as capacity allows. Tasks 28 and 29 are safe to do
anytime.
