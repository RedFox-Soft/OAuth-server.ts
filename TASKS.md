# Implementation Gap Backlog

Derived from the code-level gap analysis of 2026-07-28 (all specs 001–009 and admin SP-1..5 were
implemented; these tasks close the gaps found in the code itself).

**Status verified against the code on 2026-08-23.** Completed entries below are compressed to a
delivered-by record plus what still matters (outstanding debts, decisions that bind open tasks,
findings not filed elsewhere); their full retrospectives live in this file's git history and, where
noted, in the tracked knowledge base at `wiki/` (read `wiki/SCHEMA.md` first). `specs/` and
`docs/superpowers/` are **gitignored**, so where a design note is cited by path, the decisions
restated here are the committed record.

**How to work this list.** Each open task is sized for one Spec Kit cycle: feed the task body to
`/speckit-specify`, then clarify → plan → tasks → implement. Tasks marked **Investigate** exist
because the expected result is a product/design decision that must be made first — their
deliverable is a written decision that becomes the "Expected result" of the follow-up
implementation task. Do not start an implementation task whose dependency is unresolved. Check a
task off only after the full suite passes.

Evidence pointers are given as `path:line` at the time of analysis; re-verify before relying on
exact line numbers. Numbering is append-only — a new task takes the next free number regardless of
its priority band, so references stay valid.

Health baseline 2026-08-23: `bun test` 2757 pass / 3 skip / 0 fail (167 files); `bun run typecheck`
red by design (~2601 errors — task 26 owns the strategy; `lib/` contributes none of the 14 added by
task 15, which are all in new spec files and of the classes that task already owns).

---

## P0 — Functional holes in live paths

### 1. Enforce feature flags on protocol endpoints — ✅ Implemented

- **Delivered by** `specs/010-feature-flag-gating`. One `onRequest` gate
  (`lib/plugins/featureGate.ts`) driven by a declarative route table
  (`lib/consts/route_classification.ts`, all 74 routes classified, two-way drift guard). Per-request
  flag evaluation, exact `(method, path)` matching.
- **Findings (one-liners):** matching must be exact — a prefix match on `/token` takes down every
  grant flow; HTML error responses used to answer 200 (fixed for gated and unserved paths); the gate
  must mount **after** `nocache` or disabled paths lose the `no-store` fingerprint;
  `test/fapi/fapi2.config.ts` drove `/par` without `par.enabled` and passed only because of this
  defect. Knowledge base: `wiki/concepts/feature-flag-gating.md`.

### 2. CORS policy design — Investigate — **RESOLVED 2026-07-30**

- **Deliverable:** `docs/superpowers/specs/2026-07-30-cors-policy-design.md` (gitignored; decisions
  restated in task 3's record). Route classes open / client-based / none; origins stored per
  **Project** as `corsOrigins`; a disallowed origin loses the header without the request being
  rejected; hand-rolled Elysia plugins; the `clientBasedCORS` addon deleted; one `cors.enabled`
  config key; admin surface of entity + stores + create/patch + one minimal SPA editor. Amendments
  were applied to tasks 4, 12, 21, 24, 27.

### 3. CORS implementation — ✅ Implemented

- **Delivered by** `specs/011-cors-support`. `corsRoutes` table under the two-way drift guard
  (74 routes → 2 open / 6 client-based / 66 none); three plugins in `lib/plugins/cors.ts`
  (`corsPreflight` on `onRequest`, `corsOpen`, `corsClientBased` — header written at `onTransform`);
  flag-aware preflight that falls through to 404 rather than leaking flag state; `Vary: Origin`,
  echoed origin (never `*`, no credentials), `Access-Control-Expose-Headers: WWW-Authenticate,
DPoP-Nonce` on client-based routes; `Project.corsOrigins` with one shared validator in both
  stores; `cors.enabled` catalogued; `lib/shared/cors.ts` / `lib/addon/cors.ts` /
  `test/cors/custom_cors.spec.ts` deleted, `test/cors/cors.spec.ts` rewritten and un-ignored.
  Suite: 2210 pass (was 1981).
- **Findings (not filed in the wiki — this is the record):** the design's `onBeforeHandle` was
  wrong, corrected to `onTransform` — `AuthPlugin` authenticates in a `derive` (transform queue) and
  body-schema 422s precede `beforeHandle`, so the header would have been missing from exactly the
  two responses a misconfigured browser app hits most; `set.headers` merges into a raw `Response`
  returned by a handler and from an `onRequest` short-circuit (what lets `corsOpen` work on `jwks`
  and the preflight 204 inherit `no-store`); `OPTIONS` on a mounted path already 404'd identically
  to an unrouted one, so the no-leak fall-through held before any code was written;
  `POST /admin/api/projects` forwarded only four fields to `store.create()` and silently dropped
  `clientIds` — fixed for `corsOrigins`, **the `clientIds` drop is still there** (nothing sends it;
  candidate for task 19); the in-memory project store is a process-wide singleton and
  `findByClientId` returns the first match, so suites must destroy what they create.

### 4. Complete `db:setup` provisioning — ✅ Implemented

- **Delivered by** `specs/012-db-setup-provisioning`. A declared inventory
  (`lib/consts/storage_inventory.ts`) every consumer reads — the operator routine provisions from
  it, the seven Mongo store classes take collection names from it, `KnownModelName` derives from it,
  and `test/storage_contract/inventory_drift.spec.ts` fails on any disagreement. Provisioned areas
  19 → 24 on a fresh database; decisions live in pure helpers (`database/reconcile.ts`). Suite:
  2251 pass.
- **Findings (not filed in the wiki — this is the record):** MongoDB's `create` is idempotent when
  options match, so existence must be asked via `listCollections`, not deduced from the absence of a
  throw; the wrong TTL indexes were inert, not live bugs (Mongo never expires a document lacking the
  indexed field) but were dropped because a future `expiresAt` write would silently delete clients;
  index dropping is scoped by capability — only expiry rules are safe to remove, operator-added
  ordinary indexes survive; the runtime drift guard scans `adapter('X')` literals and dynamically
  imports `lib/models/*.ts` because `ModelPayloadByName` is a type; `lib/adapters/mongodb/db.ts`
  connects at module scope and throws without `MONGODB_URI`, which dictates that the inventory lives
  in `lib/consts/` and imports nothing; seed before per-bucket provisioning or a fresh deployment
  ends with zero user collections while exiting 0.
- **Verification debt:** the MongoDB path itself has no automated test (Principle III keeps the
  suite off real datastores); verified by hand per `specs/012-db-setup-provisioning/quickstart.md`.
  Four structural-only guarantees are recorded in task 25, which owns the class.

### 5. DPoP nonce configuration safety — ✅ Implemented

- **Delivered by** `specs/014-dpop-nonce-safety` (commit `670c7f2`). The server **provisions its own
  32-byte secret** at startup, unconditionally, before serving traffic — the broken
  requireNonce-without-secret state is unrepresentable rather than detected. One resolver
  (`lib/configs/nonceSecret.ts`), a store class per adapter over the existing `serviceConfig` area,
  two never-firing-on-healthy-boot validator invariants retained as tripwires, four bare-`Error`
  sites removed. An unusable stored secret is replaced, not refused (deliberately asymmetric with
  signing keys — the admin plane is served by the same process, so a server that will not boot
  cannot be repaired); conditional write, first writer wins, so concurrent instances converge.
- **Outstanding note, closed 2026-08-23:** the entry originally recorded that the MongoDB store
  class was verified by reading only and quickstart step 3 (the driver's binary round trip) was
  never executed. **That exact failure materialized:** the driver returned a BSON `Binary` the
  resolver rejects, so the server could not boot against MongoDB at all — found by task 32's browser
  verification, recorded as task 35, fixed in `71d9b53`. An adapter-level automated test is still
  missing; task 25 owns the class. Knowledge base: the concurrent-provisioning race also exists for
  signing keys, where divergence is worse — recorded as a scoping decision, not an oversight.

### 6. Rich Authorization Requests product scope — Investigate — **RESOLVED 2026-07-31**

- **Deliverable:** `docs/superpowers/specs/2026-07-31-rar-conformance-design.md` (gitignored;
  §-by-§ audit against final RFC 9396). Nine decisions, the binding ones: RAR is a **supported**
  feature (D1) scoped to the authorization-code and refresh-token flows (D2);
  `richAuthorizationRequests.types` becomes a serializable per-type descriptor with the
  code-registered `validate` as an optional escape hatch (D3); enabling the flag with zero types
  fails validation (D4); consent displays all requested details and grants them wholesale (D6); the
  four addon hooks get working generic defaults (D7); the `resourceIndicators` coupling is kept and
  documented (D8). Also found: the old implementation tracked a draft, not the RFC; RAR over PAR or
  a signed request object always failed; the `rar` model schemas disagreed. Amendments were applied
  to tasks 12, 21, 27; task 31 was added for the remaining channels.

### 7. Rich Authorization Requests end-to-end — ✅ Implemented

- **Delivered by** `specs/015-rar-end-to-end` (commit `c9a70dd`). Descriptor-as-data configuration
  behind a new `json` catalog `SettingType`, §5-conformant validation with normalization (string and
  array shapes both accepted — fixes the PAR/JAR bug), consent rendering (`'rar-detail'` groups)
  plus idempotent `grant.addRar` persistence, working defaults for all four hooks, and `test/rar/`
  — the first suite anywhere to send `authorization_details`. Suite: 2366 pass.
- **Findings:** filed in `wiki/concepts/rich-authorization-requests.md` — including the two that
  generalize: a declared TypeBox shape on a request parameter is a runtime **coercion contract**
  (Elysia stripped every detail to `{}` before validation ran), and form-encoded bodies do not
  coerce JSON at all (PAR bodies arrived as one object per character; fixed by `parseJsonParams` in
  `lib/plugins/coerce_array_params.ts`). Two live bugs found outside RAR by the new tests: public
  clients introspecting their own token got `active: false` (stale `token.clientId` read), and
  `loadExistingGrant` froze `trusted` at grant-creation time.
- **Operational hole, deliberate:** details reach a token only when a resource server resolves,
  which needs a `getResourceServerInfo` override whose default throws — pinned by a test; the guard
  belongs to task 12.

### 35. The server cannot boot against MongoDB — ✅ Implemented

- (P0; found 2026-08-05 during task 32's browser verification, recorded as task 35.)
- **Delivered by** commit `71d9b53` (2026-08-23). BSON has no Buffer type, so the 32-byte nonce
  secret written by `lib/configs/nonceSecret.ts` came back as a driver `Binary` — the one shape the
  resolver rejects — and every boot against MongoDB died in `roundTripFailure`. Fixed by unwrapping
  in `lib/adapters/mongodb/dpopNonceSecretStore.ts`'s `read()`, where the driver's representation
  choice belongs; the resolver's guard stays a check on the material. It is the only binary writer
  in the Mongo adapter, so no sibling store shares the defect.
- **Residual:** the expected result asked for an adapter-level automated round-trip test; that is
  impossible under the current no-datastore test policy and is owned by task 25 (this incident is
  that task's first hard evidence). The fix itself was verified by hand against a real MongoDB.

---

## P1 — Security & conformance

### 8. Admin audit completeness and readability — ✅ Implemented

- **Delivered by** `specs/016-admin-audit-completeness`. A load-bearing declarative table
  (`lib/consts/admin_audit_routes.ts`, 23 of 23 mutating admin routes + one deliberate exclusion)
  with a two-way drift guard; `recordAdminAudit` takes an `AuditAction` typed from the table; read
  surface `GET /admin/api/audit` (super-admin, filterable, offset-paged) plus an `Audit` SPA page.
  Coverage went 4 routes (+1 conditional) → 23/23. Suite: 2446 pass.
- **Findings:** filed in `wiki/concepts/admin-audit-trail.md` — the binding ones: audit-first and
  authorization-first are both required, so the write stays inside the handler (a route-level plugin
  would record unauthenticated callers into permanent storage); an entry means "an authorized actor
  reached the point of applying this change", not "the change took effect"; Elysia strips undeclared
  query parameters before validation, so refusing one means reading the raw URL; field names, never
  values.
- **Verification debt:** the MongoDB `adminAuditStore` rewrite (filters, sort/skip/limit, six
  indexes) has no automated coverage; contract pinned against the in-memory adapter; manual
  procedure `specs/016-admin-audit-completeness/quickstart.md` § 4 was **not executed**. Task 25
  owns the class.

### 9. Deletion integrity semantics — Investigate — **RESOLVED 2026-08-04**

- **Deliverable:** `docs/superpowers/specs/2026-08-04-deletion-integrity-design.md` (gitignored —
  the decisions here are the committed record). Six decisions:
  1. **D1 — containers guard, principals cascade.** Project and bucket refuse deletion with 409
     while they hold clients / users; client and end-user cascade. The line is visibility.
  2. **D2 — ownership is declared in `lib/consts/storage_inventory.ts`**; one engine reads the
     table; no call site names an area.
  3. **D3 — `revokeByGrantId` is per-collection** (Mongo's semantics) on both adapters, and
     `revoke()` stops filtering by `client.grantTypeAllowed` — always sweeps all five grantable
     areas.
  4. **D4 — order is audit → destroy the principal → cascade**, partial-failure cost accepted and
     bounded.
  5. **D5 — deliberately left behind:** `Session.authorizations[clientId]`, admin sessions
     (task 22 owns them), bucket-scoping of the account sweep.
  6. **D6 — operator surface:** machine-readable 409 body + the existing confirmation dialogs; no
     new audit actions.
- **Findings:** filed in `wiki/concepts/deletion-and-revocation.md` — including: client deletion
  already took effect immediately while every issued token kept working (the visible half fixed,
  the invisible half not); `ClientCredentials` carries no `grantId` and `RegistrationAccessToken`
  may never expire, which is why owner-field sweeps beat grant walks; protocol revocation
  deliberately does not destroy the `Grant` record (consent ≠ tokens).

### 10. Deletion integrity implementation — ✅ Implemented

- **Delivered by** `specs/019-deletion-integrity` (commit `84da0e2`). Ownership as an `owners`
  block per inventory entry; one cascade engine (`lib/helpers/cascade.ts`); `destroyByOwner(field,
value)` on both adapters with owner indexes derived from the same declaration; per-collection
  `revokeByGrantId` on both adapters; guards (project 409 while `clientIds` resolve, bucket 409
  while any user exists, then drops `user_<bucket>`); cascades for client and end-user deletes.
  Knowledge filed in `wiki/concepts/` deletion-and-revocation, model-graph-import-order,
  admin-plane-error-shape.
- **Contract that task 19 consumes:** 409 bodies carry `blockers: [{ kind, count, ids? }]`
  (`kind` `'client'` lists ids; `'enduser'` reports count only) beside the `AdminError` shape;
  successful cascades return per-area `destroyed` counts; partial failures answer 500 with
  `failedAreas`.
- **Findings beyond the wiki notes:** the admin plane's own error shape never reached callers in
  the composed server (root `onError` won; fixed with an `adminPlane` marker and pinned against the
  composed app); `lib/models/` has an import cycle that throws a TDZ `ReferenceError` on a cold
  entry — documented, not fixed; `DATABASE_NAME`, not the URI path, selects the Mongo database.
- **Verification:** the MongoDB half was exercised directly against a local server in a scratch
  database; only the HTTP-level walkthrough (`quickstart.md` §§ 4.2–4.5) remains manual. Task 25
  owns the class.

### 11. Verify the admin BFF id_token signature — ✅ Implemented

- **Delivered by** `specs/017-admin-idtoken-verification` (commit `e7da8c1`). One module
  (`lib/admin/auth/verifyIdToken.ts`) proving the token against the live keystore before any claim
  is read, returning only `sub`; signature/registered-claim work delegated to `verify()` in
  `lib/helpers/jwt.ts` with the algorithm pinned to the admin client's registered
  `idTokenSignedResponseAlg`; four relying-party checks added (`azp` on multi-audience, future
  `iat`, presence/shape, per-sign-in `nonce`); every failure answers one identical
  `401 invalid_id_token`, the reason goes to a new `admin.login.error` event. Fail-first check run:
  with the old code, forged tokens got HTTP 302 + admin session. Suite: 2473 pass. No verification
  debt — nothing touches a MongoDB path.
- **Findings:** filed in `wiki/concepts/admin-console-signin.md` — including: `assertPayload` skips
  the future-`iat` check on any token carrying `exp` (so every relying party must make it itself),
  and `idTokenSigningAlgValues` is not an allow-list (contains HS256, and goes stale when the admin
  JWKS API hot-applies a new key type — read the client's registered alg instead).
- **Deviations, argued in the spec's research.md:** repo-wide `clockTolerance` instead of FR-006's
  zero-skew; FR-003's "algorithms this server supports" narrowed to the client's registered one.

### 12. Guard feature toggles that require code overrides — Implement

- **Context:** The admin settings catalog exposes toggles whose default addon hooks throw or
  misbehave, so a super-admin can 500 the server from the UI: `ciba.enabled` (5 hooks throw,
  `lib/addon/ciba.ts`), `resourceIndicators.enabled` (default `getResourceServerInfo` throws
  `InvalidTarget`, `lib/addon/resources.ts:27-31` — and it defaults to **true**), `mTLS.*`
  (`certificateAuthorized`/`certificateSubjectMatches` throw, `lib/addon/mtls.ts:22-40`). The
  override registry (`lib/addon/registry.ts`) is code-only.
- **Expected result:** Enabling any feature whose required hooks are still the throwing defaults
  fails validation (boot and admin PUT) with a message naming the missing hooks — or, where a
  sensible default is implementable (planning decision per feature), the default is implemented
  instead. The catalog marks such settings so the UI can explain why they are locked. Tests: each
  guarded flag rejected without overrides, accepted with overrides registered.
- **Amended by task 2's decision note:** `clientBasedCORS` is not among the hooks needing a guard —
  task 3 deleted the addon and replaced it with project-scoped origin data.
- **Amended by task 6's decision note:** `richAuthorizationRequests.enabled` is not among the flags
  needing a hook-presence guard either — task 7 gave all four `lib/addon/rar.ts` hooks working
  defaults (D7) and delivered its different guard (empty `types` map fails validation, D4).
  Remaining flags for this task: `ciba.enabled`, `resourceIndicators.enabled`, `mTLS.*`. Task 7
  also pinned the operational hole this task's `resourceIndicators` guard closes: details granted at
  consent silently reach no token when `getResourceServerInfo` is the throwing default.

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
  4. **`registrationManagement.enabled`:** currently affects nothing beyond task 1's endpoint
     gating (this item makes sure discovery/`registration_client_uri` behavior matches the flag).
- **Expected result:** All four items fixed with spec tests; discovery baseline fixtures updated.

### 14. Small verified bug-fix batch — ✅ Implemented

- **Delivered by** `specs/018-small-bugfix-batch` (commit `74cc208`). Suite: 2506 pass. Two items
  were not what they looked like: `GET /admin/setup` was a duplicate surface, not a broken link —
  deleted (`GET /admin` already server-renders the same screen properly); and the commented-out CSP
  hash call grew into the feature — the server emitted **no** `Content-Security-Policy` anywhere, so
  it became a server-wide policy through a single HTML response constructor (`lib/html/csp.ts`,
  all nine construction sites, two-way drift guard) that derives the policy from the document it is
  handed. The other items: `interaction.returnTo` fixed, error page status/illustration fixed,
  CIBA `'push'` removed from the admin schema.
- **Findings:** filed in `wiki/concepts/html-response-security-policy.md` and
  `first-run-setup-had-two-surfaces.md` — the binding one: a CSP lifecycle plugin was built,
  measured and rejected (`mapResponse({ as: 'global' })` never fires for an `onError`-built
  response nor the named `adminApp`, and fails silently with a perfect page and no policy — see
  spec 018 research.md M9); the single-constructor + drift-guard shape is deliberate. There is
  exactly one inline event handler in the whole server (device user-code `onfocus`), authorized via
  `'unsafe-hashes'`.
- **Verification debt, since closed:** the browser pass (quickstart § 4) was run as part of
  task 32's verification on 2026-08-05 — which is also what found task 35.

### 15. Pairwise identifier salt — ✅ Implemented

- **Delivered by** `specs/023-pairwise-identifier-salt` (branch `023-pairwise-identifier-salt`).
  The salt is 32 bytes of server state resolved once at startup (`lib/configs/pairwiseSalt.ts`),
  stored as a fourth singleton in the existing `serviceConfig` area. `os.hostname()` and the
  dev-only `mustChange` warning are gone. Suite 2722 → 2757 pass, 0 fail.
- **Two decisions that bind future work:**
  1. **Fail closed, narrowly — never replace.** An unusable stored salt is left exactly as found;
     the server starts, serves every non-pairwise client, and refuses requests needing a pairwise
     `sub` with `temporarily_unavailable` (thrown from the default `pairwiseIdentifier`, so all four
     emit sites are covered by one guard). This deliberately splits task 5's behaviour: keep "always
     start" (the admin plane is served by this same process), drop "replace" (a replaced nonce
     secret costs one client retry; a replaced salt permanently breaks every RP's account linkage,
     and task 35's defect class recurs on _every_ read — so a replacing resolver would reassign
     every pairwise identifier on every restart while reporting a healthy boot).
  2. **Module state, not an `ApplicationConfig` key.** The nonce secret is a config key only because
     the validator cross-checks it against `dpop.requireNonce`; nothing cross-checks the salt, so a
     key would buy nothing and cost the catalogue exclusion, the settings-merge exclusion and a test
     pinning its absence. Resolution is _driven_ from `configs/application.ts` (store passed in)
     because the consumer, `addon/tokens.ts`, is a leaf the model graph imports — a store import
     there closes a cycle into a module still evaluating.
- **One store class per adapter, two instances.** `DPoPNonceSecretStore` became
  `SingletonSecretStore`, parameterized by document name (`'dpopNonceSecret'` / `'pairwiseSalt'`,
  derived into the `_id` exactly as before, so no existing deployment's nonce secret moves). Rather
  than copy ~90 lines of non-obvious mechanics — duplicate-key-as-conflict-signal, conditional
  replace, and task 35's `Binary` unwrap — per document per adapter. Task 5's resolver and
  storage-contract specs passed **with zero assertion changes**, which is what makes the refactor
  defensible; only imports and type names moved.
- **Migration note for existing deployments** (deliberately _not_ in `CHANGELOG.md` — no release
  exists yet; move it there when one does): **pairwise `sub` values change exactly once**, when this
  version first starts. Only clients registered `subjectType: 'pairwise'` are affected; `public`
  clients are untouched. Affected relying parties will treat returning users as new accounts unless
  they re-link, so coordinate with any that key durable data off `sub`. After that one change the
  identifiers never move again — including across restarts, reschedules and scale-out, which is what
  was broken. **The salt now lives in the datastore**, so losing the datastore permanently loses
  every pairwise identifier, the same exposure the signing keys already carry.
- **Two findings from implementation, both worth keeping:**
  1. **The back-channel logout "defect" was not one.** Clarification recorded that logout tokens
     carry the raw account id to pairwise clients, from reading `end_session.ts:163` plus a grep of
     `id_token.ts` that found no derivation. Wrong: `IdToken.payload()` builds claims through
     `Claims.result()`, which derives the pairwise `sub`. The pseudonym has always gone out. Grepping
     the file where a behaviour _should_ live and reading silence as absence is the mistake; a
     regression test now pins it (`test/pairwise/pairwise_logout.spec.ts`), since the derivation
     sitting a layer away is exactly what made it look missing.
  2. **The refusal lands at the token endpoint, not the authorization endpoint.** The authorization
     endpoint issues a code without needing a subject identifier, so it succeeds; refusing there
     would mean deriving an identifier nobody asked for just to fail early.
- **Residual:** the live MongoDB restart check (quickstart §5) was **not** run — it needs writes to a
  real datastore. What _was_ verified without one: the BSON round trip that produced task 35
  (a `Buffer` deserialises as `Binary`, fails the predicate, and `read()`'s unwrap restores
  byte-identical usable material). The remaining gap is boot → record `sub` → restart → same `sub`
  against a real deployment. Task 25 owns the class.

### 31. RAR on the device, CIBA and token-endpoint channels — Implement

- (P1; added by task 6's decision note; task 7 landed, so unblocked.)
- **Context:** Task 7 deliberately scopes RAR to the authorization-code and refresh-token flows
  (decision D2), leaving two documented gaps against final RFC 9396. §3 says
  `authorization_details` "can be used to specify authorization requirements in all places where the
  `scope` parameter is used", naming device authorization (RFC 8628) and backchannel authentication
  (CIBA) explicitly, but `unsupportedRar` (`lib/actions/authorization/unsupported_rar.ts`, mounted at
  `lib/actions/authorization/device.ts:20`) and `lib/actions/grants/ciba.ts:25-28` refuse both. §6
  defines the parameter on the **token request** — the AS checks that the underlying grant
  (`authorization_code`, `refresh_token`) or, for `client_credentials`, the client's policy permits
  the requested details, and otherwise refuses with `invalid_authorization_details` — but the
  parameter is absent from the `/token` body schema (`lib/actions/token.ts:45-59`), so the four
  grant-level checks are unreachable and each raises `invalid_request` rather than the code §6
  mandates.
- **Expected result:** `authorization_details` is carried end to end on the device-authorization and
  CIBA channels, reusing task 7's descriptor validation, consent view model and grant persistence
  across those channels' own consent surfaces (device code verification, CIBA's backchannel
  authorization). `authorization_details` is accepted on the `/token` request for
  `authorization_code`, `refresh_token` and `client_credentials`, checked against the grant's stored
  details (or, for `client_credentials`, a client policy this task defines) using §12's RFC 8259
  comparison rules with no normalization, and refused with `invalid_authorization_details` otherwise.
  `unsupportedRar` is deleted. Update task 7's deviation table in
  `docs/superpowers/specs/2026-07-31-rar-conformance-design.md` as each row is closed. Note the
  strict token body schema: adding a parameter there is a deliberate exception to the "standard
  parameters only" rule, so record why. Tests: details requested through the device flow and through
  CIBA reach the issued token; a token request asking for details outside the grant is refused with
  the correct code; `client_credentials` with a permitting and a non-permitting client policy.
  **Consider splitting** — the two channels and the token parameter are independent enough for
  separate Spec Kit cycles if the first one runs long.

### 32. Compiled antd CSS for the hydrated pages, and a fully derived script/style policy — ✅ Implemented

- **Delivered by** commit `1a4628d` (2026-08-05; design note
  `docs/superpowers/specs/2026-08-05-compiled-antd-css-and-derived-script-src-design.md`,
  gitignored). Both parts landed together:
  - **Part A:** `lib/html/csp.ts` now derives `script-src` from the document (`'self'` only when a
    same-origin `<script src>` exists; `'none'` when no script and no handler — the error page, both
    logout pages, the four verification pages, the registration refusals, the password-reset pages,
    device confirmation), and splits `style-src` into the CSP3 pair: `style-src-elem` hashes inline
    `<style>` bodies on script-free documents and keeps `'unsafe-inline'` on bundle-shipping pages
    **because `@ant-design/icons` calls `useInsertStyles` on every icon render** — pinned by a test
    with the reason named, so a later tidy-up does not strip icon styling. Flat `style-src` retained
    as the pre-CSP3 fallback. Verified live over HTTP on a real 400 and a 404.
  - **Part B:** the two hydrated families (interaction pages, admin console) link precompiled
    `antd/dist/antd.css` copied to `public/` by `build.ts` and run under `zeroRuntime` via one shared
    `lib/html/zeroRuntime.tsx`; terminal pages deliberately keep inline styles. Runtime CSS
    generation ~246 KB → ~17.5 KB (cssinjs CSS-variable registers ignore `zeroRuntime` — the
    original "zero `data-css-hash` tags" criterion was wrong, corrected 2026-08-05). Fix in
    passing: shared `lib/html/versionedAsset.ts` cache-busts both bundles.
  - Tests: `test/csp/csp.spec.ts` rewritten (+256 lines), `test/html/compiledStylesheets.spec.ts`,
    `test/html/versionedAsset.spec.ts`. Wiki updated: `html-response-security-policy.md`,
    `interaction-page-families.md`.
- **Known trade, recorded when found:** the stylesheet ships **uncompressed** (1,005,591 B —
  `staticPlugin` does not compress and the repo has no compression middleware), so part B is a trade
  until compression exists; that, the possibly-broken 304 revalidation, and the never-captured
  login-page total transfer size are task 36. Bundle size itself is task 34. The non-HTML security
  headers finding spun out as task 33.

### 33. Security headers on non-HTML responses — Implement

- (P1; spun out of scoping task 32.)
- **Context:** `lib/html/csp.ts`'s `htmlResponse` covers every rendered page, but nothing covers the
  JSON surfaces. `/token`, `/userinfo`, discovery and the whole admin API carry no
  `X-Content-Type-Options`, no `Referrer-Policy`, and no CSP. Deliberately kept out of task 32 —
  this is plugin-shaped work on a different surface, and bundling it would have dragged the rejected
  CSP-as-a-plugin rework back in with it.
- **Expected result:** A callback-shaped plugin in the `lib/plugins/noCache.ts` form (not a named
  Elysia instance — see the `cors.ts:33` rationale) setting `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer` and a locked-down `default-src 'none'; frame-ancestors 'none'` on
  non-HTML responses. It must not touch a response `htmlResponse` built, so the HTML policy keeps one
  writer. Note that this flips `test/csp/csp.spec.ts`'s `leaves protocol responses alone`, which
  currently asserts discovery carries **no** CSP header — that assertion becomes "carries the
  non-HTML policy, not a page policy".

---

## P2 — Incomplete product surfaces

### 16. End-user password reset — ✅ Implemented

- **Delivered by** `specs/020-enduser-password-reset` (commit `ba720ff`). A `lib/password_reset/`
  module mirroring `lib/verification/`; request form inside the interaction
  (`GET|POST /ui/:uid/forgot-password`, bucket resolved from the client, never a form field);
  standalone consumption pages (`GET|POST /reset-password`, cookie-less); two declared storage areas
  (`PasswordResetChallenge` `byAccount`, `PasswordResetThrottle` unowned/computed-id) under the
  task 4/10 inventory and drift guards; the login page's dead link is live. Session invalidation
  reuses task 10's cascade engine (`endSessionsForAccount`). Suite: 2594 pass.
- **Deliberate divergences from the verification flow it copies** (a reset secret changes a
  credential; a verification secret only proves an address): record id is `sha256hex(token)`, never
  the token; expiry compared in `load()`, not left to lazy TTL eviction; a GET never consumes the
  secret (mail scanners prefetch) — only the POST spends it, destroying the record before the
  update; the reserved admin bucket is refused (FR-004a, added by the Constitution Check — an
  unaudited path to console credentials was not acceptable); link only, no 6-digit variant; a
  completed reset marks the address verified.
- **Findings:** filed in `wiki/concepts/self-service-password-reset.md` (and the computed-id note in
  `deletion-and-revocation.md`) — including: the verification flow trusts store eviction for expiry,
  so an expired verification link keeps working until Mongo's TTL monitor runs — left alone there,
  but not to be copied into a third flow; `resolveBucketForClient` maps the console client to the
  admin bucket, so every `/ui` surface is operator-reachable unless it says otherwise.
- **Not run:** the manual quickstart walkthrough (needs live SMTP); covered by the suite except
  message rendering and the two 429 pages in a browser.

### 17. Interaction UI fixes batch — ✅ Implemented

- **Delivered by** `specs/021-interaction-ui-fixes` (commit `6618e91`). The `?notice=verify`
  producer/consumer mismatch fixed via a closed notice vocabulary (`lib/interactions/notices.ts`);
  the three registration refusals are rendered pages at the same status codes (mismatch comes back
  as the user's own form with the address preserved); `registrationServer` now substitutes props
  (items 2+3 were one piece of work — an unsubstituted hydrated page erases its own server-rendered
  content, browser-only, nothing logged); the decorative Google button deleted, the
  "Forgot password" link **kept** (task 16 landed first and made it real — FR-023, the one place
  this cycle contradicts the original task text); consent groups all got headings and friendly-label
  handling. Shared plain-page shell extracted to `lib/interactions/plainPage.tsx`. Suite: 2619 pass.
- **Findings:** filed in `wiki/concepts/interaction-page-families.md`.

### 18. Social login / federation — ✅ Implemented

- **Decision (Investigate half, 2026-08-05):** federation entered the roadmap as **generic OIDC
  only, configured per bucket** with upstream credentials on the bucket document, linking only on a
  trusted verified email, upstream tokens discarded once the ID token verifies. Design note
  `docs/superpowers/specs/2026-08-05-social-federation-login-design.md` (gitignored).
- **Delivered by** `specs/022-oidc-federation-login` (commit `246b400`). A `lib/federation/`
  subsystem (discovery + bounded `RemoteJWKSet` cache, ID-token verification, two-stage round-trip
  record, decision ladder, terminal pages, callback route), `lib/admin/federation/` management
  plane with audit + masked `clientSecret` + write-time issuer validation,
  `UserBucket.passwordLogin`/`federation` replacing the dead `authMethods`, `User.federated` links
  with per-bucket index, `FederationState` model area, `federation.enabled` flag through the task 1
  gate, 92 new tests. Suite: 2722 pass.
- **The load-bearing shape:** three hops and no new cookie — the interaction cookie is
  `path: /ui/${uid}` + `sameSite: 'strict'`, so a fixed `/federation/callback` provably cannot read
  it; everything is resolved from a DB record found by `sha256(state)`, and hop 2 → 3 is a
  **relative** redirect, which is what restores the cookie. Documented in
  `wiki/concepts/upstream-federation.md`.
- **Divergences from the design as written, argued where the decision lives:** the round-trip area
  is `byAccount`, not `unowned` (the reverse ownership drift guard forced it, and a deleted
  account's outstanding handoff is swept); the handoff `ref` is stored as a digest like `state`;
  the management routes are **not** feature-gated (FR-035a — a deployment that switches federation
  off must still be able to delete a provider); a declined sign-in redirects to the login page
  rather than rendering at the callback URL (hydration derives the page from
  `window.location.pathname`); a masked `clientSecret` means "keep", following the SMTP precedent.
- **Framework findings:** a guarded route's `params` schema is merged, not overridden (an
  undeclared second parameter 422s before the handler); a gated route may sit under an
  always-available prefix because `gatedRoutes` is consulted first.
- **Not done:** the browser-only quickstart steps (hydrated provider controls, password-form
  removal after hydration, a real upstream IdP's extra callback parameters).

### 19. Admin UI completion — Implement

- **Context:** Backend routes exist with no UI reaching them, creating dead ends:
  `PATCH/DELETE /admin/api/projects/:id` and `PUT /admin/api/projects/:id/bucket` are unreachable
  (`lib/admin/ui/pages/Projects.tsx` lists/creates only, plus task 3's origins editor) — and since
  the "Users" button is `disabled={!row.bucketId}`, **a newly created project can never be given a
  bucket through the UI**; admins page is list+create only (no roles/deactivate UI, and no password
  change for admins at all — `UpdateAdminBody` lacks `password` while end-users have a reset
  route); `DELETE /admin/api/buckets/:id` has no UI; bucket `managedBy` accepted by API but not
  editable; `restartRequired` is displayed but no restart action exists anywhere. Known related
  defect from task 3: `POST /admin/api/projects` silently drops `clientIds` (nothing sends it yet).
- **Expected result:** Project edit/delete/bucket-assign flows in the SPA (unblocking the Users
  dead end); admin management UI (roles, deactivate, guarded by the existing last-super-admin
  rule) plus an admin password-change path (self-service at minimum — schema + route + UI);
  bucket delete and `managedBy` editing in the UI. Delete dialogs consume task 10's `blockers`
  contract (409 bodies list client ids / end-user counts). For restart: this task only adds an
  explicit "restart required" affordance explaining the manual step — an actual restart trigger is
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

- **Context:** Catalog covers a subset of `ApplicationConfig` keys. Functional omissions:
  `registration.initialAccessToken` (the only lever that closes open registration now task 1
  gates the endpoint — and a prerequisite for `registration.policies` per
  `lib/configs/configuration.ts:202-210`) and `claims` (drives `claims_supported` and
  claim-backed scopes; omitted without the documented-intentional note `discovery` has).
  `dpop.nonceSecret` is **settled by task 5**: server-provisioned state, deliberately absent, reason
  recorded in the catalog module (a test pins the note). Remaining function-valued key:
  `registration.policies` — legitimately non-serializable, so document why it is absent.
- **Expected result:** `registration.initialAccessToken` (write-only/masked like the SMTP
  password if a string secret) and `claims` are editable via the settings API/UI with proper
  validation; intentionally-omitted keys carry an explanatory note in the catalog module; a test
  pins the catalog-vs-ApplicationConfig key diff so future keys must be classified explicitly.
- **Amended by task 2's decision note:** task 3 added `cors.enabled` (catalogued there), so the
  key-diff test must account for it. `cors.maxAge` was dropped because the catalog has no `number`
  `SettingType`; if this task adds one, that key becomes a viable follow-up.
- **Amended by task 7:** `richAuthorizationRequests.types` is no longer function-valued and is **now
  a catalog key** — a serializable descriptor map behind the new `json` `SettingType`. Two
  consequences: the diff must account for it, and a structured key is no longer automatically
  un-catalogable — `claims` should be reconsidered against the `json` precedent rather than assumed
  exposed as some flatter shape.
- **Amended by task 18:** `federation.enabled` is now catalogued too; per-provider federation
  settings live on the bucket document, not in `ApplicationConfig`.

### 22. Admin session/grant/token visibility and revocation — Implement

- **Context:** `lib/admin/` has zero references to `Grant`, `Session`, `AccessToken`,
  `RefreshToken`, or `helpers/revoke` (outside incidental substrings). No admin can see or revoke an
  end-user's sessions, grants, or tokens; `AdminSessionStoreInstance` has no list-by-user, so
  admins can't manage their own other sessions either.
- **Expected result:** Per end-user: list active sessions and grants (with client, scopes,
  timestamps) and revoke them (grant revocation cascades to its tokens via the task-9/10-aligned
  semantics). Per admin: list own sessions, revoke others ("sign out everywhere"). Store
  interfaces gain the needed list methods in **both** adapters with storage-contract tests. All
  mutations audited (task 8 pattern — and each new mutating route must be added to
  `lib/consts/admin_audit_routes.ts`, or task 8's drift guard fails the suite by design).
- **Amended by task 9's decision note:** "the task-9/10-aligned semantics" resolves to D3 —
  revocation is per-collection and `revoke()` always sweeps all five grantable areas, with no
  grant-type filter. The list-by-user surface this task needs is the **read half** of task 10's
  `destroyByOwner`: both walk the same ownership declarations in `storage_inventory.ts`, so build
  on that table rather than a second enumeration path. Deleting an admin still deactivates rather
  than deletes, which is why task 10 leaves `adminSession` alone and this task owns it.

### 23. JWKS management: non-RSA keys — Implement

- **Context:** Admin key generation is RSA-only (`lib/admin/jwks/service.ts:16`), while the
  configured algorithm surface and test keystore include ES256/EdDSA. No encryption-use keys can
  be provisioned via the admin API.
- **Expected result:** Admin JWKS API can generate EC (ES256) and OKP (EdDSA) signing keys, and
  the key list/status/delete/audit behavior covers them identically to RSA. Planning decides
  whether encryption-use keys are in scope now or documented as follow-up. Tests mirror the
  existing RSA route specs for each new type. Note task 11's finding: `idTokenSigningAlgValues` is
  computed at module load from the boot-time snapshot and goes stale on hot-applied new key types —
  this task must not widen that hole.

### 36. Static assets are served uncompressed, and may not revalidate — Investigate

- (P2; found 2026-08-05 by task 32's final review and confirmed by request.)
- **Context:** `staticPlugin({ assets: 'public' })` (`lib/index.ts:84`) does **not** compress: with
  `Accept-Encoding: gzip, deflate, br`, the response carries no `Content-Encoding` and transfers the
  full 1,005,591 B of `antd.css`. There is no compression middleware in the repo. This is what
  turned task 32's part B from the win it was scoped as into a trade — the design priced that file
  at its 109,545 B gzip size. It also applies to `loginClient.js` (~1 MB), `admin.js` (~1.6 MB) and
  every JSON response the protocol serves. Separately and unconfirmed: a conditional request
  carrying the correct `If-None-Match` was answered **200 with the full body** rather than 304, and
  the etag is emitted unquoted (`K9WnLSEFPtxrTmRQOAiPqQ==` rather than `"…"`), which may itself
  explain the miss — if real, the full megabyte re-downloads whenever the 86,400 s `max-age`
  expires even when nothing changed.
- **Deliverable:** A decision on where compression belongs. The operator's stated intent
  (2026-08-05) is an external plugin rather than application middleware, so this may be deployment
  configuration (`fly.toml`) rather than code — in which case record that and close it. If it lands
  in the app, measure the before/after on the four hydrated pages and finally satisfy task 32's
  unmet acceptance criterion (login page total transfer size, which was never captured — only
  per-asset sizes). Confirm or dismiss the 304 behaviour separately; it is cheap to test and
  independent of compression.

---

## P3 — Debt, coverage, docs

### 24. Migrate ignored and skipped test suites — Implement

- **Context (re-verified 2026-08-23):** `bunfig.toml`'s ignore list is down to one entry —
  `test/helpers/attention.spec.ts` (uses Mocha's `context()`); the `test/cors/*` entries were
  absorbed by task 3 as its amendment predicted. Additionally never running:
  `test/provider/provider_instance.spec.ts` (whole file `describe.skip`, targets a removed
  constructor API — likely delete or rewrite), `test/configuration/secure.spec.ts`
  (`describe.skip`, obsolete `x-forwarded-proto` trust — decide delete vs revive), one intentional
  skip in `test/signatures/signatures.spec.ts` (HS256, keep). Dead orphan configs:
  `test/routing/routing.config.ts` (no spec at all), `test/provider/set_session.config.ts`.
- **Expected result:** `bunfig.toml` ignore list is empty (or every entry carries a written
  justification); each skipped file is migrated, rewritten against current APIs, or deleted with
  rationale in the commit message; orphan configs deleted or given specs. Suite count reflects
  reality (no silently-dead specs).

### 25. MongoDB adapter test strategy — Investigate

- **Context:** The production storage backend (`lib/adapters/mongodb/`) has zero automated test
  coverage — tests always run the in-memory adapter (`lib/adapters/index.ts`; `MONGODB_URI` never
  set under test). Known behavioral divergences already found: email lowercasing on insert (mongo)
  vs as-supplied (memory), `upsert` never `$unset`s a stale `expiresAt`. **The predicted failure
  class has now materialized once:** the Mongo `DPoPNonceSecret` store returned a BSON `Binary` the
  resolver rejects, so the server could not boot against MongoDB at all — shipped unnoticed
  precisely because the store contract spec covers the memory implementation alone (task 35, fixed
  in `71d9b53`).
- **Deliverable:** A decision note: how mongo-backed tests run (real local mongod in CI /
  testcontainers / a dedicated `bun test` project with `MONGODB_URI` + cleanup strategy), which
  suites run against it (minimum: the existing `test/storage_contract/` round-trips + the store
  specs, parameterized over both adapters — the DPoP nonce secret binary round trip explicitly
  included), and how divergences get pinned. Produces the spec input for the implementation task it
  defines.
- **Measurements blocked on this task** (from task 4 / `specs/012-db-setup-provisioning`, recorded
  here because `specs/` is gitignored — whichever option this task picks should carry all four):
  1. **Automatic reaping observed** — expired verification challenges/resend counters actually
     leave storage (TTL monitor runs on its own ~60s schedule, so a timed test). (SC-002)
  2. **Concurrent registrations** — two simultaneous registrations of one address produce exactly
     one account (today only a sequential duplicate insert is verified). (SC-003)
  3. **Sign-in cost independent of bucket size** — benchmark 10 vs 100,000 accounts; only the
     `email` index's existence is verified today. (SC-004)
  4. **No implicitly-created storage area after exercising every capability** — provision, drive
     every capability against the mongo adapter, diff the collection list; the one that would catch
     an area missing from the inventory altogether. (SC-001)
     Also outstanding from later tasks: the Mongo `adminAuditStore` list/filter/index behavior
     (task 8) and the HTTP-level deletion walkthrough (task 10, quickstart §§ 4.2–4.5).
- **The stake grew with task 15** (2026-08-23): the class that materialized this task's predicted
  failure — the Mongo singleton secret store — now holds **two** instances, the DPoP nonce secret
  and the pairwise identifier salt, and the salt's failure mode is worse than the nonce secret's (a
  server that refuses pairwise clients, rather than one client retry). Still verified by reading plus
  a database-free BSON round-trip probe; the boot → restart → same-`sub` check against a real
  deployment remains unrun. Whichever option this task picks, the salt's round trip belongs in the
  same parameterized set as the nonce secret's.

### 26. Typecheck remediation strategy — Investigate

- **Context:** `bun run typecheck` (`tsc --noEmit`) fails repo-wide by design — ~2587 errors as of
  2026-08-05 (was 2633 at the original analysis; `lib/` ~808, overwhelmingly implicit-`any` — known
  accepted debt from the non-aggressive typing approach; the rest in `test/`). Worst offenders:
  `lib/models/client/schema.ts` (89), `test/configuration/client_metadata.spec.ts` (243). Because
  the command fails wholesale, it gates nothing and new type errors land unnoticed — each completed
  task has been measuring before/after by hand to prove it added none.
- **Deliverable:** A decision note choosing the path to a _useful_ typecheck signal: e.g. a
  ratchet (error-count budget file enforced in CI), a scoped `tsconfig.typecheck.json` that is
  green today and grows, or a phased burn-down plan with per-directory milestones. Includes the
  measured baseline per directory and defines the follow-up implementation task(s).

### 27. Dead code removal — Implement

- **Context (verified zero importers / unreachable):** entire `lib/views/` directory (3 legacy
  template files — `interaction.ts:42-46` was the repo's only RAR rendering, and task 7 has
  superseded it with the `'rar-detail'` consent group, so deleting it loses no function),
  `lib/admin/ui/pages/Stub.tsx`, `lib/helpers/params.ts`, `lib/helpers/set_www_authenticate.ts`
  (superseded by inline code in `authorization_error_handler.ts`), `lib/helpers/_/pick_by.ts`,
  `provider.urlFor/pathFor` (`lib/provider.ts:33-45` — reads never-assigned fields, would throw if
  called), empty-body addon asserts (`lib/addon/claims.ts:9-13` `assertClaimsParameter`,
  `lib/addon/default.ts:13-22` — verify whether empty-by-design as override seams; if so, document
  instead of delete).
- **Already handled elsewhere:** `lib/shared/cors.ts` and `lib/addon/cors.ts` were removed by
  task 3; `lib/helpers/script_src_sha.ts` was superseded by task 14's CSP constructor (verify it is
  gone or delete it here); `grant.addRar` is **kept** — task 7 made it the live consent-persistence
  path.
- **Expected result:** Each listed item deleted, or kept with a written reason (override-seam
  documentation counts). Zero importers re-verified at deletion time. Full suite and lint green
  afterward.

### 28. Documentation sync — Implement

- **Context (re-verified 2026-08-23 — still wrong):** `README.md` endpoint table has 6 of 11 rows
  wrong (real paths: `/auth`, `/par`, `/reg`, `/token/introspect`, `/token/revocation`, `/logout`;
  userinfo is GET+POST); Features claims "Static and dynamic client registration" (static clients
  were removed — clients are DB-backed via admin API/DCR/seed); Features/Standards omit implemented
  capabilities (Device Flow RFC 8628, CIBA, JARM, RAR RFC 9396, mTLS RFC 8705, Resource Indicators
  RFC 8707, RFC 8414, RFC 9207 `iss`, RFC 7592, DPoP nonces, upstream OIDC federation, email
  verification, password reset) and the admin control plane. `AGENTS.md` says interaction routes are
  `/interaction/*`; they are `/ui/:uid/*`. Housekeeping: check off the 24 stale checkboxes in
  `specs/004-findaccount-direct-db/tasks.md` (work landed in `ab8eb01`, `88e3ae5`) — note `specs/`
  is untracked, so this is local hygiene only.
- **Expected result:** README endpoint table matches mounted routes exactly (source of truth:
  `lib/consts/param_list.ts`); Features/Standards list what is actually implemented, with
  flag-gated features marked as opt-in; AGENTS.md route reference corrected. No code changes.

### 29. Knowledge-base location decision — Investigate (re-scoped 2026-08-23)

- **Original task** ("initialize `docs/wiki/`") is **overtaken by events**: the knowledge base
  materialized instead as the git-tracked llm-wiki at `wiki/` (`wiki/SCHEMA.md` + 15+ concept pages
  — feature-flag-gating, client-identity-from-database, admin-audit-trail, deletion-and-revocation,
  html-response-security-policy, interaction-page-families, upstream-federation,
  rich-authorization-requests, self-service-password-reset, admin-console-signin, and more), which
  the completed tasks above actively file into. Much of the originally planned seed content already
  exists there.
- **What remains to decide:** the org standard (and this repo's SessionStart hook) asserts a
  `docs/wiki/` knowledge base with different conventions (docs-wiki skill: Business Rules /
  Troubleshooting / Integrations / Overview categories, `Index.md` wikilinks). Either adopt `wiki/`
  as this repo's canonical KB and align the hook/org expectation, or scaffold `docs/wiki/` per the
  standard and define the relationship between the two. Also still unfiled anywhere tracked except
  this file's git history: tasks 3 and 4's retrospective findings (CORS mechanism gotchas, storage
  provisioning gotchas) — wherever the decision lands, file those two.

### 30. Missing OIDC surfaces roadmap — Investigate

- **Context:** Entirely absent, with traces suggesting past intent: OIDC Session Management /
  `check_session_iframe` (stale docstring at `lib/actions/authorization/respond.ts:13` references an
  OP iframe cookie that is never written) and Front-Channel Logout (no discovery keys, no client
  metadata). `request_uri`-by-reference is deliberately unsupported and correctly advertised —
  leave it.
- **Deliverable:** A decision note: implement, or explicitly declare unsupported. If declared
  unsupported: remove the stale docstring and record the decision in the knowledge base (task 29).
  If implementing: a spec input defining scope (front-channel logout is the likelier candidate;
  session management is legacy — modern guidance leans on back-channel logout, which already
  works).

### 34. Why the sign-in bundle costs 1 MB — Investigate

- (P3; surfaced while scoping task 32, which established that `zeroRuntime` does **not** reduce
  bundle size — so this is the remaining lever, and the only one that touches end-user bytes rather
  than operator bytes.)
- **Context:** `public/loginClient.js` is ~1 MB minified for three pages built from
  `Form`/`Input`/`Button`/`Card`/`Checkbox`/`Flex`/`Typography`/`Alert`, and `public/admin.js` is
  ~1.6 MB. `lib/interactions/{loginPage,registration}.tsx` import named icons from
  `@ant-design/icons` — a barrel of thousands of modules — reached through the custom resolve
  plugin at `build.ts`, which redirects `@ant-design/icons-svg/lib/*` to `es/*` for a CJS interop
  reason. Whether Bun tree-shakes that barrel is unknown and was never measured.
- **Deliverable:** A measurement, then a decision. Report each entry's size broken down by source
  (`bun build --analyze` or equivalent), the delta from importing icons by direct path instead of
  from the barrel, and the delta from `splitting: true` (deferred from task 32 for being
  operator-only). If a change wins, it becomes the expected result of a follow-up implementation
  task; if nothing wins, record the numbers here so the question is not reopened by guesswork.

---

## Suggested order

Everything through the original P0 band is done, plus 8–11, 14, 16–18, 32 and 35. What remains,
in rough order of value:

- **33** (non-HTML security headers) — the cheapest open item; spun out of 32 with the mechanism
  already decided.
- **12** (guard the throwing toggles) → **13** (protocol conformance batch) → **15** (pairwise
  salt, with tasks 5/35 as the direct precedent).
- P2 product work: **19** (admin UI completion — consumes task 10's blockers contract) → **20**
  (client schema breadth) → **21** (settings catalog) → **22** (session/grant visibility) → **23**
  (non-RSA JWKS); **36** (compression/304) is a small investigation that mostly needs a deployment
  decision.
- **31** (RAR's remaining channels) is P1 by band but lowest-urgency — nothing reaches those
  channels today.
- Debt: **25** (MongoDB adapter test strategy — now carrying a materialized failure as evidence) is
  the highest-leverage investigation; **24**, **26**, **27**, **34** as capacity allows. **28**
  (docs sync) and **29** (KB location decision) are safe anytime.
