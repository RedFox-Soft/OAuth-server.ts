# Implementation Gap Backlog

The live backlog for this repo, derived from the code-level gap analysis of 2026-07-28 and kept
current since. **Completed work is not recorded here** — it moves to `CHANGELOG.md` `[Unreleased]`
as one-liners; full retrospectives live in this file's git history and in the tracked knowledge
base at `wiki/` (read `wiki/SCHEMA.md` first). `specs/` and `docs/superpowers/` are **gitignored**,
so where a design note is cited by path, the decisions restated here are the committed record.

**How to work this list.** Each open task is sized for one Spec Kit cycle: feed the task body to
`/speckit-specify`, then clarify → plan → tasks → implement. Tasks marked **Investigate** exist
because the expected result is a product/design decision that must be made first — their
deliverable is a written decision that becomes the "Expected result" of the follow-up
implementation task; once that follow-up task exists (with the binding decisions inlined), the
resolved entry is dropped too. When a task is finished (full suite green), delete its entry and
add a one-liner to `CHANGELOG.md`. Decisions live on in the knowledge base or this file's git
history.

Evidence pointers are given as `path:line` at the time of analysis; re-verify before relying on
exact line numbers. Numbering is append-only — a new task takes the next free number regardless of
its priority band, so references stay valid even for removed (completed) numbers.

Health baseline 2026-08-26: `bun test` 3061 pass / 3 skip / 0 fail (200 files); `bun run typecheck`
red by design (2622 errors — task 26 owns the strategy).

---

## P1 — Security & conformance

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
- **Scope notes from resolved decisions:** `clientBasedCORS` needs no guard (task 2 — spec 011
  deleted the addon). `richAuthorizationRequests.enabled` needs no hook-presence guard (task 6 D7 —
  spec 015 gave the hooks working defaults and delivered its own empty-types guard). Remaining
  flags: `ciba.enabled`, `resourceIndicators.enabled`, `mTLS.*` — the `resourceIndicators` guard
  also closes task 6 D8's operational hole.

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
  4. **`registrationManagement.enabled`:** currently affects nothing beyond spec 010's endpoint
     gating (this item makes sure discovery/`registration_client_uri` behavior matches the flag).
- **Expected result:** All four items fixed with spec tests; discovery baseline fixtures updated.

### 31. RAR on the device, CIBA and token-endpoint channels — Implement

- (P1; added by task 6's decision note; spec 015 landed, so unblocked.)
- **Context:** Spec 015 deliberately scopes RAR to the authorization-code and refresh-token flows
  (task 6, decision D2), leaving two documented gaps against final RFC 9396. §3 says
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
  CIBA channels, reusing spec 015's descriptor validation, consent view model and grant persistence
  across those channels' own consent surfaces (device code verification, CIBA's backchannel
  authorization). `authorization_details` is accepted on the `/token` request for
  `authorization_code`, `refresh_token` and `client_credentials`, checked against the grant's stored
  details (or, for `client_credentials`, a client policy this task defines) using §12's RFC 8259
  comparison rules with no normalization, and refused with `invalid_authorization_details` otherwise.
  `unsupportedRar` is deleted. Update the deviation table in
  `docs/superpowers/specs/2026-07-31-rar-conformance-design.md` as each row is closed. Note the
  strict token body schema: adding a parameter there is a deliberate exception to the "standard
  parameters only" rule, so record why. Tests: details requested through the device flow and through
  CIBA reach the issued token; a token request asking for details outside the grant is refused with
  the correct code; `client_credentials` with a permitting and a non-permitting client policy.
  **Consider splitting** — the two channels and the token parameter are independent enough for
  separate Spec Kit cycles if the first one runs long.

### 33. Security headers on non-HTML responses — Implement

- (P1; spun out of the CSP work — spec 018 / `1a4628d`.)
- **Context:** `lib/html/csp.ts`'s `htmlResponse` covers every rendered page, but nothing covers the
  JSON surfaces. `/token`, `/userinfo`, discovery and the whole admin API carry no
  `X-Content-Type-Options`, no `Referrer-Policy`, and no CSP. Deliberately kept out of the CSP work —
  this is plugin-shaped work on a different surface, and bundling it would have dragged the rejected
  CSP-as-a-plugin rework back in with it (that rework was built, measured and rejected:
  `mapResponse({ as: 'global' })` never fires for an `onError`-built response nor the named
  `adminApp`, failing silently — see `wiki/concepts/html-response-security-policy.md`).
- **Expected result:** A callback-shaped plugin in the `lib/plugins/noCache.ts` form (not a named
  Elysia instance — see the `cors.ts:33` rationale) setting `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer` and a locked-down `default-src 'none'; frame-ancestors 'none'` on
  non-HTML responses. It must not touch a response `htmlResponse` built, so the HTML policy keeps one
  writer. Note that this flips `test/csp/csp.spec.ts`'s `leaves protocol responses alone`, which
  currently asserts discovery carries **no** CSP header — that assertion becomes "carries the
  non-HTML policy, not a page policy".

---

## P2 — Incomplete product surfaces

### 19. Admin UI completion — Implement

- **Context:** Backend routes exist with no UI reaching them, creating dead ends:
  `PATCH/DELETE /admin/api/projects/:id` and `PUT /admin/api/projects/:id/bucket` are unreachable
  (`lib/admin/ui/pages/Projects.tsx` lists/creates only, plus spec 011's origins editor) — and since
  the "Users" button is `disabled={!row.bucketId}`, **a newly created project can never be given a
  bucket through the UI**; admins page is list+create only (no roles/deactivate UI, and no password
  change for admins at all — `UpdateAdminBody` lacks `password` while end-users have a reset
  route); `DELETE /admin/api/buckets/:id` has no UI; bucket `managedBy` accepted by API but not
  editable; `restartRequired` is displayed but no restart action exists anywhere. Known related
  defect from spec 011: `POST /admin/api/projects` silently drops `clientIds` (nothing sends it
  yet).
- **Amended by spec 024 (admin MCP control plane):** operators can now reach project
  update/bucket-assign and admin update/deactivate through an AI agent at `POST /mcp`, so the
  *operator* dead end is relieved — but this task's subject is the SPA, and every UI gap above
  still stands (the MCP surface also has no admin password change, which remains missing
  everywhere).
- **Expected result:** Project edit/delete/bucket-assign flows in the SPA (unblocking the Users
  dead end); admin management UI (roles, deactivate, guarded by the existing last-super-admin
  rule) plus an admin password-change path (self-service at minimum — schema + route + UI);
  bucket delete and `managedBy` editing in the UI. Delete dialogs consume spec 019's blockers
  contract (task 9 D6: 409 bodies list client ids / end-user counts). For restart: this task only
  adds an explicit "restart required" affordance explaining the manual step — an actual restart
  trigger is deployment-specific and stays out of scope unless a later investigation adds it. UI
  changes covered by route-level tests; SPA pages at least smoke-rendered.

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
  `registration.initialAccessToken` (the only lever that closes open registration now spec 010
  gates the endpoint — and a prerequisite for `registration.policies` per
  `lib/configs/configuration.ts:202-210`) and `claims` (drives `claims_supported` and
  claim-backed scopes; omitted without the documented-intentional note `discovery` has).
  `dpop.nonceSecret` is settled by spec 014: server-provisioned state, deliberately absent, reason
  recorded in the catalog module (a test pins the note). Remaining function-valued key:
  `registration.policies` — legitimately non-serializable, so document why it is absent.
- **Expected result:** `registration.initialAccessToken` (write-only/masked like the SMTP
  password if a string secret) and `claims` are editable via the settings API/UI with proper
  validation; intentionally-omitted keys carry an explanatory note in the catalog module; a test
  pins the catalog-vs-ApplicationConfig key diff so future keys must be classified explicitly.
- **Notes from landed work:** spec 011 added `cors.enabled` (catalogued) and dropped `cors.maxAge`
  for want of a `number` `SettingType` — if this task adds one, that key becomes a viable
  follow-up. Spec 015 made `richAuthorizationRequests.types` a catalog key behind the new `json`
  `SettingType`, so a structured key is no longer automatically un-catalogable — reconsider
  `claims` against that precedent. Spec 022 catalogued `federation.enabled`; per-provider
  federation settings live on the bucket document, not in `ApplicationConfig`.

### 22. Admin session/grant/token visibility and revocation — Implement

- **Context:** `lib/admin/` has zero references to `Grant`, `Session`, `AccessToken`,
  `RefreshToken`, or `helpers/revoke` (outside incidental substrings). No admin can see or revoke an
  end-user's sessions, grants, or tokens; `AdminSessionStoreInstance` has no list-by-user, so
  admins can't manage their own other sessions either.
- **Expected result:** Per end-user: list active sessions and grants (with client, scopes,
  timestamps) and revoke them (grant revocation per task 9 D3 — per-collection, all five grantable
  areas, no grant-type filter). Per admin: list own sessions, revoke others ("sign out
  everywhere"). Store interfaces gain the needed list methods in **both** adapters with
  storage-contract tests. All mutations audited (spec 016 pattern — and each new mutating route
  must be added to `lib/consts/admin_audit_routes.ts`, or its drift guard fails the suite by
  design).
- **Build on the ownership table:** the list-by-user surface this task needs is the **read half**
  of spec 019's `destroyByOwner` — both walk the same ownership declarations in
  `storage_inventory.ts`, so build on that table rather than a second enumeration path. Deleting an
  admin still deactivates rather than deletes, which is why spec 019 left `adminSession` alone and
  this task owns it.

### 23. JWKS management: non-RSA keys — Implement

- **Context:** Admin key generation is RSA-only (`lib/admin/jwks/service.ts:16`), while the
  configured algorithm surface and test keystore include ES256/EdDSA. No encryption-use keys can
  be provisioned via the admin API.
- **Expected result:** Admin JWKS API can generate EC (ES256) and OKP (EdDSA) signing keys, and
  the key list/status/delete/audit behavior covers them identically to RSA. Planning decides
  whether encryption-use keys are in scope now or documented as follow-up. Tests mirror the
  existing RSA route specs for each new type. Note spec 017's finding: `idTokenSigningAlgValues` is
  computed at module load from the boot-time snapshot and goes stale on hot-applied new key types —
  this task must not widen that hole.

### 36. Static assets are served uncompressed, and may not revalidate — Investigate

- (P2; found 2026-08-05 by the antd-CSS work's final review — `1a4628d` — and confirmed by
  request.)
- **Context:** `staticPlugin({ assets: 'public' })` (`lib/index.ts:84`) does **not** compress: with
  `Accept-Encoding: gzip, deflate, br`, the response carries no `Content-Encoding` and transfers the
  full 1,005,591 B of `antd.css`. There is no compression middleware in the repo. This is what
  turned the compiled-antd-CSS change from the win it was scoped as into a trade — the design
  priced that file at its 109,545 B gzip size. It also applies to `loginClient.js` (~1 MB),
  `admin.js` (~1.6 MB) and every JSON response the protocol serves. Separately and unconfirmed: a
  conditional request carrying the correct `If-None-Match` was answered **200 with the full body**
  rather than 304, and the etag is emitted unquoted (`K9WnLSEFPtxrTmRQOAiPqQ==` rather than `"…"`),
  which may itself explain the miss — if real, the full megabyte re-downloads whenever the
  86,400 s `max-age` expires even when nothing changed.
- **Deliverable:** A decision on where compression belongs. The operator's stated intent
  (2026-08-05) is an external plugin rather than application middleware, so this may be deployment
  configuration (`fly.toml`) rather than code — in which case record that and close it. If it lands
  in the app, measure the before/after on the four hydrated pages and capture the login page's
  total transfer size (never measured — only per-asset sizes). Confirm or dismiss the 304
  behaviour separately; it is cheap to test and independent of compression.

---

## P3 — Debt, coverage, docs

### 24. Migrate ignored and skipped test suites — Implement

- **Context (re-verified 2026-08-23):** `bunfig.toml`'s ignore list is down to one entry —
  `test/helpers/attention.spec.ts` (uses Mocha's `context()`); the `test/cors/*` entries were
  absorbed by spec 011. Additionally never running: `test/provider/provider_instance.spec.ts`
  (whole file `describe.skip`, targets a removed constructor API — likely delete or rewrite),
  `test/configuration/secure.spec.ts` (`describe.skip`, obsolete `x-forwarded-proto` trust —
  decide delete vs revive), one intentional skip in `test/signatures/signatures.spec.ts` (HS256,
  keep). Dead orphan configs: `test/routing/routing.config.ts` (no spec at all),
  `test/provider/set_session.config.ts`.
- **Expected result:** `bunfig.toml` ignore list is empty (or every entry carries a written
  justification); each skipped file is migrated, rewritten against current APIs, or deleted with
  rationale in the commit message; orphan configs deleted or given specs. Suite count reflects
  reality (no silently-dead specs).

### 26. Typecheck remediation strategy — Investigate

- **Context:** `bun run typecheck` (`tsc --noEmit`) fails repo-wide by design — 2622 errors as of
  2026-08-26 (was 2633 at the original analysis; `lib/` ~800, overwhelmingly implicit-`any` — known
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
  template files — `interaction.ts:42-46` was the repo's only RAR rendering, and spec 015 has
  superseded it with the `'rar-detail'` consent group, so deleting it loses no function),
  `lib/admin/ui/pages/Stub.tsx`, `lib/helpers/params.ts`, `lib/helpers/set_www_authenticate.ts`
  (superseded by inline code in `authorization_error_handler.ts`), `lib/helpers/_/pick_by.ts`,
  `provider.urlFor/pathFor` (`lib/provider.ts:33-45` — reads never-assigned fields, would throw if
  called), empty-body addon asserts (`lib/addon/claims.ts:9-13` `assertClaimsParameter`,
  `lib/addon/default.ts:13-22` — verify whether empty-by-design as override seams; if so, document
  instead of delete).
- **Already handled elsewhere:** `lib/shared/cors.ts` and `lib/addon/cors.ts` were removed by
  spec 011; `lib/helpers/script_src_sha.ts` was superseded by spec 018's CSP constructor (verify it
  is gone or delete it here); `grant.addRar` is **kept** — spec 015 made it the live
  consent-persistence path.
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
  verification, password reset, the admin MCP control plane) and the admin control plane.
  `AGENTS.md` says interaction routes are `/interaction/*`; they are `/ui/:uid/*`. Housekeeping:
  check off the 24 stale checkboxes in `specs/004-findaccount-direct-db/tasks.md` (work landed in
  `ab8eb01`, `88e3ae5`) — note `specs/` is untracked, so this is local hygiene only.
- **Expected result:** README endpoint table matches mounted routes exactly (source of truth:
  `lib/consts/param_list.ts`); Features/Standards list what is actually implemented, with
  flag-gated features marked as opt-in; AGENTS.md route reference corrected. No code changes.

### 29. Knowledge-base location decision — Investigate (re-scoped 2026-08-23)

- **Original task** ("initialize `docs/wiki/`") is **overtaken by events**: the knowledge base
  materialized instead as the git-tracked llm-wiki at `wiki/` (`wiki/SCHEMA.md` + concept pages —
  feature-flag-gating, client-identity-from-database, admin-audit-trail, deletion-and-revocation,
  html-response-security-policy, interaction-page-families, upstream-federation,
  rich-authorization-requests, self-service-password-reset, admin-console-signin,
  mongodb-test-fidelity, and more), which completed work actively files into.
- **What remains to decide:** the org standard (and this repo's SessionStart hook) asserts a
  `docs/wiki/` knowledge base with different conventions (docs-wiki skill: Business Rules /
  Troubleshooting / Integrations / Overview categories, `Index.md` wikilinks). Either adopt `wiki/`
  as this repo's canonical KB and align the hook/org expectation, or scaffold `docs/wiki/` per the
  standard and define the relationship between the two. Also still unfiled anywhere tracked except
  this file's git history: the CORS-implementation and storage-provisioning retrospective findings
  (from the entries for specs 011 and 012, removed 2026-08-26 when completed work moved to
  `CHANGELOG.md`) — wherever the decision lands, file those two.

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

- (P3; surfaced while scoping the antd-CSS work, which established that `zeroRuntime` does **not**
  reduce bundle size — so this is the remaining lever, and the only one that touches end-user bytes
  rather than operator bytes.)
- **Context:** `public/loginClient.js` is ~1 MB minified for three pages built from
  `Form`/`Input`/`Button`/`Card`/`Checkbox`/`Flex`/`Typography`/`Alert`, and `public/admin.js` is
  ~1.6 MB. `lib/interactions/{loginPage,registration}.tsx` import named icons from
  `@ant-design/icons` — a barrel of thousands of modules — reached through the custom resolve
  plugin at `build.ts`, which redirects `@ant-design/icons-svg/lib/*` to `es/*` for a CJS interop
  reason. Whether Bun tree-shakes that barrel is unknown and was never measured.
- **Deliverable:** A measurement, then a decision. Report each entry's size broken down by source
  (`bun build --analyze` or equivalent), the delta from importing icons by direct path instead of
  from the barrel, and the delta from `splitting: true` (deferred from the antd-CSS work for being
  operator-only). If a change wins, it becomes the expected result of a follow-up implementation
  task; if nothing wins, record the numbers here so the question is not reopened by guesswork.

### 37. Storage encoding contract (task 25, Tier 1) — Implement

- (P3; defined by task 25's decision note, `wiki/concepts/mongodb-test-fidelity.md`. Independent of
  task 38 — it needs no database, no constitution carve-out, and none of the three barriers.)
- **Context:** The defect that made task 25 urgent was an _encoding_ defect: a `Buffer` goes into
  BSON and a `Binary` comes back, which the callers' `instanceof Uint8Array` guards reject, so the
  server could not boot against MongoDB (fixed in `71d9b53`). Proving that needs the codec, not a
  server. `bson@7.2.0` is already installed and re-exported as `BSON` from `mongodb`, so
  `BSON.serialize`/`BSON.deserialize` is reachable without touching `lib/adapters/mongodb/db.ts`.
- **Expected result:** A spec in `test/storage_contract/` that imports no `db.js` and runs in the
  default suite, asserting: the `Buffer → Binary → Buffer` round trip for **both** singleton secrets
  (`dpopNonceSecret` and `pairwiseSalt` — one class, two instances, and the salt's failure mode is
  the worse one); the `Date` round trip for `expiresAt` as `mongoAdapter.ts:25-29` writes it; and the
  round trip of every other field a store reads back and type-checks. The spec MUST fail if the
  unwrap at `lib/adapters/mongodb/singletonSecretStore.ts:53` is deleted — verify that by deleting it
  and watching it go red, not by reading the assertion. Full suite green afterward.

### 38. Storage fidelity suite against a real mongod (task 25, Tier 2) — Implement

- (P3; defined by task 25's decision note. **Do not start before task 37** — Tier 1 establishes what
  is already covered, and this tier must not absorb coverage a database-free test can provide, which
  Principle III now forbids.)
- **Context:** Six measurements have no other home, because each asserts a behaviour of the server
  itself. Principle III was amended to 2.2.0 precisely to allow this suite and nothing wider.
- **Expected result — the three barriers first**, each a work item in its own right:
  1. `lib/adapters/mongodb/db.ts` connects lazily or takes an injected `Db`, so importing a store no
     longer requires a live connection at module load. `lib/adapters/mongodb/provision.ts:13-16` is
     the pattern to follow — it is already `Db`-injectable and import-safe, and the fidelity suite
     should provision through its `ensureCollection`/`applyIndexes`/`provisionUserArea` helpers
     rather than growing its own.
  2. `lib/adapters/index.ts:74-76`'s `NODE_ENV === 'test'` override becomes conditional on an
     explicit fidelity-mode signal, so the model adapter switches together with the stores instead
     of leaving the run half-memory.
  3. `test/storage_contract/round_trip.ts:26`'s `syncFind` coupling is replaced by an async accessor
     both adapters satisfy, so the existing contract can be parameterized over each.
- **Expected result — the suite:** a separate CI job in `.github/workflows/ci.yml` with a `mongo`
  service container (an image that honours Stable API `v1` `strict: true`, which both `db.ts:9-15`
  and `database/mongodb.ts:37-43` set), running `bun test` over the fidelity paths only, with
  `MONGODB_URI` + `DATABASE_NAME` set. It MUST NOT be reachable from the default `bun test` run.
  Cleanup is a per-file database drop, because Bun runs every spec file in one process. Every
  adapter divergence the suite surfaces is either converged or declared with a written reason
  (known: email lower-cased on insert at `lib/adapters/mongodb/userStore.ts:31,67` vs as-supplied
  in memory; `mongoAdapter.ts:25-29` never `$unset`ing a stale `expiresAt`).
- **Expected result — the six measurements** (four from spec 012, restated here because `specs/` is
  gitignored):
  1. **No implicitly-created storage area after exercising every capability** — provision, drive
     every capability against the mongo adapter, diff the collection list; the one that would catch
     an area missing from the inventory altogether. (SC-001)
  2. **Automatic reaping observed** — expired verification challenges/resend counters actually leave
     storage. The TTL monitor runs on its own ~60s schedule, so this is a timed test; the same
     laziness is why `self-service-password-reset` re-checks expiry in code. (SC-002)
  3. **Concurrent registrations** — two simultaneous registrations of one address produce exactly
     one account (today only a sequential duplicate insert is verified). (SC-003)
  4. **Sign-in cost independent of bucket size** — benchmark 10 vs 100,000 accounts; only the
     `email` index's existence is verified today. (SC-004)
  5. The Mongo `adminAuditStore` list/filter/index behavior (outstanding from spec 016).
  6. The HTTP-level deletion walkthrough (outstanding from spec 019, quickstart §§ 4.2–4.5).
- **Also unrun and belonging here:** the pairwise salt's boot → restart → same-`sub` check against a
  real deployment (spec 023). It is the only one of the six that is an end-to-end behaviour rather
  than a storage property, and it is the one that proves the salt is server state.

---

## Suggested order

- **33** (non-HTML security headers) — the cheapest open item; the mechanism is already decided.
- **12** (guard the throwing toggles) → **13** (protocol conformance batch).
- Debt with production evidence: **37** (storage encoding contract) — no database, no barriers, and
  it closes the class that actually broke production; **38** (fidelity suite) is the large one and
  depends on it.
- P2 product work: **19** (admin UI completion — the MCP surface already unblocks the operator, not
  the UI) → **20** (client schema breadth) → **21** (settings catalog) → **22** (session/grant
  visibility) → **23** (non-RSA JWKS); **36** (compression/304) is a small investigation that
  mostly needs a deployment decision.
- **31** (RAR's remaining channels) is P1 by band but lowest-urgency — nothing reaches those
  channels today.
- Then **26** (typecheck strategy) is the remaining strategy investigation; **24**, **27**, **34**
  as capacity allows. **28** (docs sync) and **29** (KB location decision) are safe anytime.
