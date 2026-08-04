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
  2. `set.headers` **does** merge into a raw `Response` returned by a handler _and_ into one returned
     from an `onRequest` short-circuit. That is what lets `corsOpen` work on `jwks` (which builds its
     own `Response`) and lets the preflight 204 inherit `no-store` from `nocache` with no duplicated
     constant.
  3. `OPTIONS` on a mounted path already 404s identically to an unrouted path, `no-store` included —
     so the fall-through half of the no-leak contract held before any code was written.
  4. `POST /admin/api/projects` forwarded only four fields to `store.create()`, silently dropping
     `clientIds`. A schema-only addition would have accepted `corsOrigins` and discarded it. Fixed for
     `corsOrigins`; the `clientIds` drop is still there (nothing sends it).
  5. The in-memory project store is a process-wide singleton and `findByClientId` returns the _first_
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
     auditing project mutations stays task 8 — **now delivered**: `project.update` records the submitted
     field names, so a `corsOrigins` change is already audited.
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

### 4. Complete `db:setup` provisioning — ✅ Implemented

- **Delivered by** `specs/012-db-setup-provisioning` (branch `012-db-setup-provisioning`). Mechanism:
  a declared inventory (`lib/consts/storage_inventory.ts`) that every consumer reads — the operator
  routine provisions from it, the seven MongoDB store classes take their collection names from it,
  `KnownModelName` derives from its model tuple, and a two-way drift guard
  (`test/storage_contract/inventory_drift.spec.ts`) fails the suite when it and the code disagree.
  Same shape as `route_classification.ts` from task 1. Provisioned areas went 19 → 24 on a fresh
  database (22 fixed + one per bucket); decisions live in pure helpers (`database/reconcile.ts`) so
  they are testable without a datastore. Suite: 2251 pass / 0 fail (was 2210); typecheck unchanged at 2474.
- **Findings worth carrying forward** (belong in the wiki alongside tasks 1 and 3):
  1. **MongoDB's `create` is idempotent when the options match**, so `createCollection` returns ok for
     a collection that already exists. Inferring "I created it" from the absence of a throw made every
     re-run report all 24 collections as freshly created — contradicting the routine's own promise to
     print only real work. Existence has to be asked (`listCollections`), not deduced. Found by
     running the routine twice against a real database; pinned by a `Db`-stub regression test. This is
     also the mechanism behind this task's original note that the duplicate list entries were
     "harmless".
  2. **The wrong TTL indexes were inert, not live bugs.** `Client`/`projects`/`userBuckets` never
     write `expiresAt`, and MongoDB never expires a document lacking the indexed field. They are
     dropped anyway because the failure mode if that ever changes is silent deletion of registered
     OAuth clients — including via the known `upsert` bug that never `$unset`s a stale `expiresAt`.
     Inert now, unrecoverable later.
  3. **Dropping indexes must be scoped by capability, not by absence from the inventory.** An
     unrecognised ordinary index may be an operator's deliberate addition; only expiry rules are safe
     to remove (removing one cannot lose a record, and nothing here queries by an expiry field).
     Verified in practice: a hand-added `payload.clientName_1` on `Client` survived reconciliation
     while three stale TTL indexes were dropped.
  4. **`ModelPayloadByName` is a type, so a runtime drift guard cannot read it.** The guard instead
     scans `adapter('X')` literals across `lib/` and dynamically imports `lib/models/*.ts`, keeping
     classes that inherit `BaseModel`'s static `adapter` accessor (which resolves the collection as
     `adapter(this.name)`, so the class name _is_ the area name). Base classes are excluded
     structurally — a base appears in another discovered class's prototype chain — so there is no
     allow-list to maintain and `IdToken` is excluded correctly.
  5. **`lib/adapters/mongodb/db.ts` connects at module scope** and throws without `MONGODB_URI`, which
     the suite deliberately lacks. That single fact dictates where the inventory can live: anything
     importing it transitively is unloadable under test, so the table sits in `lib/consts/` and
     imports nothing.
  6. **Seed before per-bucket provisioning.** The `admin` and `redfox` buckets are created by the
     seed, so provisioning per-bucket areas first leaves a fresh deployment with zero user
     collections — while still exiting 0.
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
  endpoints once client-based CORS lands. **Already provisioned by task 3**; it moved into the
  inventory unchanged and is now covered by the drift guard rather than being new work.
- **Verification:** the drift guard and the reconciliation/exit-code helpers are covered
  automatically; the MongoDB path itself has no automated test, because Principle III keeps the suite
  off real datastores and how mongo-backed tests should run is task 25's decision. It was instead
  verified by hand against a throwaway database per
  `specs/012-db-setup-provisioning/quickstart.md` — fresh inventory, idempotency, runtime bucket
  provisioning, per-bucket uniqueness, reconciliation without record loss, and the duplicate-email
  exit-1 path. That procedure is the seed for the automated equivalent once task 25 lands.

### 5. DPoP nonce configuration safety — ✅ Implemented (one manual verification outstanding)

- **Delivered by** `specs/014-dpop-nonce-safety` (commit `670c7f2`, on `main`). The approach chosen at
  planning was the second of the three candidates the Expected result listed: the server
  **provisions its own 32-byte secret** at startup, unconditionally and before serving traffic, so no
  operator ever handles secret material and the broken combination is unrepresentable rather than merely
  detected. Mechanism: one resolver (`lib/configs/nonceSecret.ts`, a sibling of `keys.ts`), a store class
  per adapter over the **existing** `serviceConfig` area (no new collection, no inventory entry), two
  invariants in the shared validator, and the removal of four bare-`Error` sites plus a test-only static
  seam. A stored secret that reads back unusable is replaced and the write is read back to confirm the
  round trip; startup fails in exactly one case — a replacement that also reads back unusable, which is a
  broken persistence layer and is reported as one.
- **Findings worth carrying forward:**
  1. **Provisioning is unconditional, and that is what closes the defect.** Gating it on
     `dpop.enabled` or `dpop.requireNonce` would leave the arming path exactly as reachable; the state has
     to be impossible to hold, not merely refused when noticed. The cost is one unused secret on
     deployments that never enable DPoP.
  2. **An unusable stored secret is replaced, not refused — deliberately asymmetric with signing keys.**
     An invalid key set refuses to boot because silently replacing a signing key invalidates every issued
     token; a nonce secret derives short-lived values, so replacing it costs each client one retry through
     a path the RFC already requires to work. The second reason is decisive: the admin plane is served by
     the same process, so a server that will not boot cannot be repaired through any supported surface.
  3. **Both store writes return the value as read back.** That makes the round-trip check structural
     rather than a follow-up read, and it hands a losing writer the winner's value — so instances starting
     together converge instead of each serving nonces the others reject. Conditional write, first writer
     wins.
  4. **The same concurrent-provisioning race exists for signing keys**, where divergence is materially
     worse than a retry loop. Not addressed there; recorded so the omission is a scoping decision.
  5. **The two validator rules can never fire on a healthy boot** — provisioning runs first — and are
     retained anyway, tested by handing the pure validator a configuration a running server cannot reach.
     If provisioning is ever reordered or made conditional, boot fails with a message naming the setting
     instead of every DPoP request failing internally.
- **Outstanding — `T037`, the manual datastore procedure, was not executed.** This environment has no
  throwaway MongoDB (no local `mongod`, no Docker, no `mongosh`; the only `MONGODB_URI` present is not
  disposable, and steps 4–5 are destructive by design). So the **MongoDB store class has no coverage at
  all** — it cannot be imported under test — and its binary round trip through the driver, its
  duplicate-key conflict signal, and its value-matching `replace` filter are verified **by reading only**.
  The stub-store tests prove the resolver reacts correctly _when_ storage misbehaves; they cannot prove
  whether this driver does. Quickstart step 3 is the one that matters most, because it is the only place
  the driver's binary round trip can be observed — and that is exactly the failure FR-002a exists to
  survive. Procedure: `specs/014-dpop-nonce-safety/quickstart.md`. This is the same gap task 25 exists to
  close for every mongo-backed path.
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

### 6. Rich Authorization Requests product scope — Investigate — **RESOLVED 2026-07-31**

- **Context:** RAR is enable-able from the admin UI but cannot work end-to-end: the consent page
  drops `authorization_details` (`lib/interactions/consentView.ts:26-30` omits the `rar` key the
  consent prompt emits), `grant.addRar` has zero callers (`lib/models/grant.ts:289-292`), all four
  addon hooks throw 'not implemented' (`lib/addon/rar.ts`), and `richAuthorizationRequests.types`
  is function-valued so it cannot be configured via the admin API (empty `{}` → every
  `authorization_details` value rejected at `lib/shared/check_rar.ts:62`). The only RAR-rendering
  code in the repo is in the dead legacy template `lib/views/interaction.ts:42-46`.
- **Also found — the implementation tracks a draft, not the published RFC.** The admin catalog still
  says so (`experimental: true`, "Implemented from a draft of the specification",
  `lib/admin/settings/catalog.ts:285-293`); RFC 9396 has been final since May 2023. Divergences from
  the published text: `authorization_details` is refused on the device-authorization and CIBA
  channels that §3 names explicitly; it is absent from the `/token` body schema
  (`lib/actions/token.ts:45-59`) although §6 defines it as a token-request parameter, which makes the
  four grant-level rejections unreachable dead code and their `invalid_request` the wrong code for
  §6's `invalid_authorization_details`; §5's unknown-field rejection cannot be expressed because no
  type descriptor declares a field set; and `lib/configs/configuration.ts:212-218` invents a
  dependency on `resourceIndicators` that the RFC does not have. Two bugs: RAR over PAR or a signed
  request object **always** fails, because PAR stores the parameter parsed
  (`pushed_authorization_request_response.ts:36-38`), nothing re-stringifies it, and `checkRar`
  `JSON.parse`s an array into `"[object Object]"`; and the `rar` model schemas disagree (array on the
  code and Grant, object on the access token, bare unknown on the refresh token).
- **Deliverable — done:** `docs/superpowers/specs/2026-07-31-rar-conformance-design.md`. It records
  the §-by-§ audit against final RFC 9396 and nine decisions: RAR is a **supported** feature (D1)
  scoped to the **authorization-code and refresh-token flows** (D2); `richAuthorizationRequests.types`
  becomes a **serializable per-type descriptor** — label, per-common-field `required`/`allowed`,
  `allowUnknownFields` — with the code-registered `validate` demoted to an optional escape hatch (D3);
  enabling the flag with zero types fails validation at boot and on admin `PUT` (D4); `checkRar`
  accepts both the string and array shapes (D5); consent **displays all** requested details and
  grants them wholesale, with no per-detail selection (D6); the four addon hooks get **working
  generic defaults** (D7); the `resourceIndicators` coupling is kept and documented (D8); and the
  deviations are written down rather than left implicit (D9). It also amends tasks 12, 27 and 29 and
  adds task 31 — see "Backlog impact" in the note.

### 7. Rich Authorization Requests end-to-end — ✅ Implemented

- **Delivered by** `specs/015-rar-end-to-end` (commit `c9a70dd`, on `main`). All six acceptance areas
  below are in place: descriptor-as-data configuration with the empty-map guard, §5-conformant
  validation with normalization, consent rendering plus idempotent grant persistence, working defaults
  for all four hooks, the corrections, and a `test/rar/` suite that is the first anywhere to send
  `authorization_details`. Suite: 2366 pass / 0 fail (was 2302); `lib/` typecheck improved 820 → 812.
- **Findings worth carrying forward** (added to `wiki/concepts/rich-authorization-requests.md`):
  1. **A declared TypeBox shape on a request parameter is a runtime coercion contract, not
     documentation.** `authorization_details` was typed `t.Array(t.Object({}))`, and Elysia coerces a
     JSON query value against that schema _and strips undeclared properties_ — so every detail arrived
     as `{}` with its `type` gone, before any validation ran. RAR could not have worked whatever
     `checkRar` did, and no amount of reading the parser would have shown it. Measured, not reasoned.
     `t.Array(t.Unknown())` — the obvious loosening, and the shape the Grant model used — is worse: it
     splits the raw JSON string on its commas.
  2. **Form-encoded bodies do not coerce JSON at all.** A JSON string in a form body arrives as one
     object per _character_, with status 200 and no error. PAR is form-encoded, so every pushed rich
     request was silently corrupt. Fixed by `parseJsonParams` in `lib/plugins/coerce_array_params.ts`,
     the sibling of the existing `coerceArrayParams` — which exists for exactly this class of quirk, and
     is the precedent to reach for next time a parameter's wire form fights its schema.
  3. **Fixing the parser alone would have made things worse.** `pushed_authorization_request_response.ts`
     ran `JSON.parse` on the value; that line was unreachable only because `checkRar` threw first, so
     accepting arrays turned a clean 4xx into an unhandled 500. The two changes had to land together.
  4. **`Value.Check` runs in the `BaseModel` constructor only, and never cleans.** So a wrong payload
     schema on a field assigned _after_ construction is inert — until something constructs the model with
     the field present, at which point it is a hard `TypeError`. Same shape as task 4's inert TTL
     indexes: harmless now, unrecoverable later.
  5. **Two live bugs found by the first test to exercise their paths**, both outside RAR:
     `introspectionAllowedPolicy` read the removed top-level `token.clientId`, so **any public client
     introspecting its own token received `active: false`**; and `loadExistingGrant` froze `trusted` at
     grant-creation time, so a returning End-User of a consent-not-required client silently under-granted
     scopes, claims _and_ details. Both are the `.payload.*` / stale-derivation classes already recorded
     in the knowledge base — worth re-reading before trusting any addon default.
  6. **The feature's remaining hole is operational, not protocol.** Details reach a token only when a
     resource server resolves, which needs a `getResourceServerInfo` override whose default throws. A
     deployment without one grants details at consent that no token carries, with no error anywhere. It
     is D8's coupling seen from the operator's side, pinned by a test, and the guard belongs to task 12.
- **Source of truth:** `docs/superpowers/specs/2026-07-31-rar-conformance-design.md`, whose deviation
  table now carries the two consequences discovered during implementation. The summary below is the
  acceptance surface.
- **Expected result** (per task 6's decision note, which is the spec input — read it first):
  `authorization_details` works end to end on the authorization-code and refresh-token flows,
  conformant to **final RFC 9396** within the boundary D2 sets. Definition of done:
  - **Types are configurable as data.** `richAuthorizationRequests.types` holds a JSON descriptor per
    type (`label`, optional `fields` constraints over the five §2 common fields,
    `allowUnknownFields` defaulting to `false`). `checkRichAuthorizationRequests`
    (`lib/configs/configuration.ts:137-162`) validates descriptor shape instead of requiring a
    `validate` function, and rejects an empty map when the flag is on. A new `json` catalog entry
    exposes the map to the admin API through the existing `validateEffectiveConfig` path.
  - **Request validation is §5-conformant.** `checkRar` accepts the parameter as a JSON string _or_
    an already-parsed array (fixes the PAR / request-object bug), enforces the descriptor's
    required/allowed values, rejects unknown fields unless `allowUnknownFields`, and raises
    `invalid_authorization_details` for every type-and-field violation, and **normalizes** — the
    parsed array is written back to `oidc.params.authorization_details` so every downstream consumer
    sees one shape and the consent prompt's second `JSON.parse`
    (`lib/helpers/interaction_policy/prompts/consent.ts:133`) goes away. The dead `response_type`
    branch goes; the `none` rejection stays.
  - **Consent shows and stores the details.** `PromptDetails` carries `rar`; `buildConsentView` emits
    a `'rar-detail'` permission group per detail (descriptor label + one item per present common
    field, raw type as the fallback label), labels passed in by the caller so the module stays
    config-free; `createGrant` calls `grant.addRar` for each entry; `addRar` is idempotent by
    sorted-key structural comparison with **no string normalization** (§12); and `rar_prompt` fires
    only when a requested detail is not already granted, so repeat authorizations stop re-prompting.
  - **The hooks have real defaults.** `rarForAuthorizationCode` = requested ∩ granted;
    `rarForCodeResponse` / `rarForRefreshTokenResponse` = the stored details filtered to the resource
    server by `locations` (a detail without `locations` is kept);
    `rarForIntrospectionResponse` = the token's details unchanged. No `mustChange`, no throw; the
    override registry still wins.
  - **Corrections.** `rar` is an array schema on the access token and refresh token; the catalog
    entry drops `experimental` and the draft sentence and cites RFC 9396 as published (update
    `test/admin/settings_catalog.spec.ts:85-88` with it); the `types` docstring describes the
    descriptor.
  - **Tests** (today zero send `authorization_details`): full code flow through consent to token
    response, JWT claim and introspection; the same over **PAR** and a **signed request object**;
    refresh-token flow with per-resource-server filtering; the §5 error cases;
    no-duplicate-on-re-consent and no-re-prompt-when-granted; boot and admin-`PUT` rejection of the
    flag with no types and of malformed descriptors; a registered code validator still running; and
    device/CIBA/`client_credentials` still refusing the parameter, pinning D2's boundary.
  - **Out of scope, by D2:** the §3 device and CIBA channels and the §6 token-request parameter —
    task 31.

---

## P1 — Security & conformance

### 8. Admin audit completeness and readability — ✅ Implemented

- **Delivered by** `specs/016-admin-audit-completeness`. Mechanism: a declarative table
  (`lib/consts/admin_audit_routes.ts`) enumerating all 23 state-changing admin routes with their action
  name and target type, made **load-bearing** rather than documentary — `recordAdminAudit` takes an
  `AuditAction` (the union of the table's action values) and resolves `targetType` from the table, so an
  unlisted action cannot compile and a target type cannot be mistyped — plus a two-way drift guard
  (`test/admin/audit_route_classification.spec.ts`) that fails when a mounted mutating admin route has no
  entry or an entry names an unmounted route. Same shape as `route_classification.ts` (task 1) and
  `storage_inventory.ts` (task 4). Coverage went 4 fully-audited routes (+1 branch-conditional) → 23 of
  23; the read surface is `GET /admin/api/audit` (super-admin, newest-first, offset-paged, filterable by
  actor/action/target/scope/time window) with an `Audit` page in the admin SPA. Suite: 2446 pass / 0 fail
  (was 2366); `lib/` typecheck unchanged at 812.
- **Findings worth carrying forward** (filed as `wiki/concepts/admin-audit-trail.md`):
  1. **Audit-first and authorization-first are both required, and the order is not interchangeable.** The
     obvious cleanup — move 23 call sites into one route-level plugin so nobody can forget — is unsafe
     here: the admin handlers authorize in their own bodies, so an `onBeforeHandle` plugin records
     entries for callers who are not yet known to be authorized. Into an append-only, never-expiring
     collection, that is an unauthenticated write path into permanent storage, i.e. trail poisoning and
     unbounded growth reachable by anyone who can reach `/admin/api/*`. Completeness is bought with a
     table and a guard instead; the write stays inside the handler, after authorization.
  2. **An entry therefore means "an authorized actor reached the point of applying this change", not
     "the change took effect".** A not-found, a uniqueness conflict or the last-super-admin guard can
     follow a written entry. Recording effects instead would need either a second write per operation or
     giving up the guarantee that nothing changes unrecorded; the trail states the caveat where it is
     read rather than pretending otherwise.
  3. **Elysia strips undeclared query parameters before validation**, so `additionalProperties: false` on
     a query schema cannot refuse one — the check has to read the raw URL. Measured, not reasoned. It
     matters disproportionately here: a mistyped filter that is silently dropped answers with the
     _unfiltered_ trail, a wrong answer wearing a 200 on the one surface whose purpose is to be trusted.
     Same family as task 7's finding that a declared parameter schema is a coercion contract.
  4. **Creations had to allocate their own identifier** for audit-first to hold without a per-operation
     exception. Two of the four stores already accepted an optional `_id`; `UserStoreInstance.create` and
     `createClient` gained one. The alternative — record after the insert — creates exactly one class of
     mutation that can be applied unrecorded.
  5. **A per-bucket target does not resolve on its own.** An `EndUser` entry naming only a user id
     cannot be turned into an account, or even an email, without searching every bucket, because those
     users live in `user_<bucket>` collections. The bucket is recorded in its own `targetScope` field
     rather than fused into `targetId`, so exact-match retrieval on a bare user id keeps working.
  6. **Two action names were wrong as originally specified.** `DELETE /admin/api/admins/:id` deactivates
     (`active: false`) and keeps the row, so it records `admin.deactivate` — a trail that says "delete"
     is a false statement an investigator acts on. And `bucket.settings.update` fired only when a
     registration/verification field was present, so a rename or a manager reassignment left no trace;
     it is now `bucket.update`, recorded unconditionally, with the changed field names in `attributes`.
     Historical entries keep the old name and stay filterable, because the action filter matches
     recorded values rather than a fixed enum.
  7. **Field names, never values** makes secret-freedom structural instead of a redaction rule a future
     call site can forget. A mail-settings change records `password` as a _name_; `enduser.password.reset`
     records no names at all, because the action already says everything.
  8. **The route census in the spec was wrong** (18 of 18 → 23 of 23). 18 is the number of routes with
     _no_ record; the surface is 24 mutating admin routes, 23 audited and `POST /admin/api/logout`
     deliberately excluded as session lifecycle. Caught during planning by enumerating handlers, and
     confirmed by the drift guard, which pins both counts.
- **Verification gap, unclosed:** the MongoDB `adminAuditStore` rewrite — `$or` actor filter, timestamp
  range, `sort`/`skip`/`limit`, `countDocuments`, six declared indexes — has **no automated coverage**,
  because `MONGODB_URI` is deliberately absent under test (Principle III). The store contract is pinned
  against the in-memory adapter (`test/storage_contract/admin_audit.round_trip.spec.ts`, 19 clauses) and
  the MongoDB class is verified by reading only. `specs/016-admin-audit-completeness/quickstart.md` § 4 is
  the manual procedure; it was **not executed** — same constraint task 5 recorded, and what task 25 exists
  to fix.
- **Original context (for history):** `recordAdminAudit` had exactly 5 call sites (bucket policy branch,
  JWKS ×2, settings, SMTP), and the trail was write-only — `adminAuditStore.list()` existed in both
  adapters but no route or UI read it.

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
- **Amended by task 6's decision note:** `richAuthorizationRequests.enabled` is not among the flags
  needing a hook-presence guard either — task 7 gives all four `lib/addon/rar.ts` hooks working
  defaults (decision D7), so no override is required to enable the feature. It needs a _different_
  guard, which task 7 has now delivered: enabling the flag with an empty
  `richAuthorizationRequests.types` map fails validation (D4). Remaining flags for this task:
  `ciba.enabled`, `resourceIndicators.enabled`, `mTLS.*`.

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

### 31. RAR on the device, CIBA and token-endpoint channels — Implement (added by task 6; task 7 landed, so unblocked)

- **Numbering is append-only:** this task belongs to P1 but takes the next free number so the
  existing references (including "Suggested order") stay valid.
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
     and `missingResourceScopes` actually render; RAR display shipped with task 7.

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
  `dpop.nonceSecret` is **settled by task 5**: it is server-provisioned state rather than an operator
  setting, so its absence is deliberate and the reason is now recorded in the catalog module (a test pins
  that the note exists). Remaining function-valued key: `registration.policies` — legitimately
  non-serializable, so document why it is absent instead of leaving it implicit.
- **Expected result:** `registration.initialAccessToken` (write-only/masked like the SMTP
  password if a string secret) and `claims` are editable via the settings API/UI with proper
  validation; intentionally-omitted keys carry an explanatory note in the catalog module; a test
  pins the catalog-vs-ApplicationConfig key diff so future keys must be classified explicitly.
- **Amended by task 2's decision note:** task 3 adds `cors.enabled` (catalogued there), so the
  key-diff test must account for it. `cors.maxAge` was dropped because the catalog has no `number`
  `SettingType`; if this task adds one, that key becomes a viable follow-up.
- **Amended by task 7:** `richAuthorizationRequests.types` is no longer function-valued and is **now a
  catalog key** — it became a serializable descriptor map behind the new `json` `SettingType`, and the
  key-diff test reclassifies it from "excluded structured key" to an exposed one. Two consequences for
  this task: the diff must account for it, and the `json` precedent means a structured key is no longer
  automatically un-catalogable — `claims` should be reconsidered against it rather than assumed exposed
  as some flatter shape. Adding a `number` type for `cors.maxAge` remains untouched by this.

### 22. Admin session/grant/token visibility and revocation — Implement

- **Context:** `lib/admin/` has zero references to `Grant`, `Session`, `AccessToken`,
  `RefreshToken`, or `helpers/revoke`. No admin can see or revoke an end-user's sessions, grants,
  or tokens; `AdminSessionStoreInstance` has no list-by-user, so admins can't manage their own
  other sessions either.
- **Expected result:** Per end-user: list active sessions and grants (with client, scopes,
  timestamps) and revoke them (grant revocation cascades to its tokens via the task-9/10-aligned
  semantics). Per admin: list own sessions, revoke others ("sign out everywhere"). Store
  interfaces gain the needed list methods in **both** adapters with storage-contract tests. All
  mutations audited (task 8 pattern — and each new mutating route must be added to
  `lib/consts/admin_audit_routes.ts`, or task 8's drift guard fails the suite by design).

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
- **Measurements blocked on this task.** Task 4 (`specs/012-db-setup-provisioning`) established four
  guarantees structurally — the constraint was verified present, the outcome never observed — because
  each needs a datastore-backed test this investigation has to enable first. They are recorded here
  because a note in `specs/` would not be found: that directory is gitignored. Whichever option this
  task picks should be able to carry all four.
  1. **Automatic reaping observed.** That expired verification challenges and resend counters actually
     leave storage. The TTL indexes are provisioned and verified; the datastore's expiry task runs on
     its own ~60s schedule, so this needs a timed test. (Task 4 SC-002.)
  2. **Concurrent registrations.** That two simultaneous registrations of one address into one bucket
     produce exactly one account. Verified today only as a sequential duplicate insert rejected by the
     unique index. (Task 4 SC-003.)
  3. **Sign-in cost independent of bucket size.** A benchmark over, say, 10 versus 100,000 accounts.
     Only the existence of the `email` index is verified today. (Task 4 SC-004.)
  4. **No implicitly-created storage area after exercising every capability.** Provision a database,
     drive every server capability against the mongo adapter, then diff the collection list. Today only
     the weaker half is verified: all 24 _declared_ areas exist after provisioning. This is the one that
     would catch an area missing from the inventory altogether. (Task 4 SC-001.)

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
  template files — `interaction.ts:42-46` was the repo's only RAR rendering, and task 7 has superseded
  it with the `'rar-detail'` consent group, so deleting it now loses no function), `lib/admin/ui/pages/Stub.tsx`, `lib/helpers/params.ts`,
  `lib/helpers/set_www_authenticate.ts` (superseded by inline code in
  `authorization_error_handler.ts`), `lib/helpers/_/pick_by.ts`, `lib/helpers/script_src_sha.ts`
  (only call commented out — task 14 item 3 decides its fate first), `provider.urlFor/pathFor`
  (`lib/provider.ts:33-45` — reads never-assigned fields, would throw if called),
  ~~`lib/models/grant.ts` `addRar`~~ (**kept** — task 7 made it the live consent-persistence path),
  empty-body addon asserts
  (`lib/addon/claims.ts:9-13` `assertClaimsParameter`, `lib/addon/default.ts:13-22` — verify
  whether empty-by-design as override seams; if so, document instead of delete).
- **Expected result:** Each listed item deleted, or kept with a written reason (override-seam
  documentation counts). Zero importers re-verified at deletion time (tasks 7/14 may have changed
  things). Full suite and lint green afterward.
- **Amended by task 2's decision note:** `lib/shared/cors.ts` and `lib/addon/cors.ts` (plus its
  `AddonImplementations` entry and `lib/addon/index.ts` re-export) are removed by task 3, not here.
- **Amended by task 6's decision note:** the RAR block in the legacy template
  (`lib/views/interaction.ts:42-46`) is the repository's only extant RAR-rendering code, but task 7
  supersedes it with a `'rar-detail'` group in the consent view. Deleting the template here loses no
  function — this is recorded so the block is not mistaken for live behaviour worth preserving.

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

Quick wins first: **14** (bug batch) → ~~**1** (flag gating)~~ → ~~**4** (db provisioning)~~ →
~~**5** (DPoP safety)~~ → **11** (id_token verification). Then the investigation pair-ups: ~~**3** (CORS)~~,
**9→10** (deletion), ~~**6→7**~~ (RAR). Then P1 remainder (~~**8**~~, **12**, **13**, **15**), P2
product work (**16**–**23**), and P3 (**24**–**30**) as capacity allows. Tasks 28 and 29 are safe to
do anytime. **31** (RAR's remaining channels) is P1 and **now unblocked** — task 7 landed the descriptor
validation, consent view model and grant persistence it reuses — but it remains the lowest-urgency P1
item, since nothing reaches those channels today.
