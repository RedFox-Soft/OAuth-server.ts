# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). No release has
been cut yet — everything below is unreleased. Spec numbers refer to the (untracked) `specs/`
directories; open work is tracked as GitHub issues; full retrospectives live in the git history
of the retired `TASKS.md` and in the knowledge base at `wiki/`.

## [Unreleased]

### Added

- Brute-force protection on the password sign-in door (issue #9, spec 032). `POST /ui/:uid/login`
  accepted unlimited guesses against any address, each one buying a full password hash on a
  shared-CPU machine — so the door was both a credential-stuffing opportunity and a cheap
  CPU-exhaustion vector, and the only unbounded secret surface left in the server. Failed attempts
  are now counted per `${bucketId}:${email}` in a new `LoginThrottle` area; at the cap the door shuts
  for that address and refuses everything — **including the correct password** — until the window
  ends, and each further exhaustion shuts it for longer, doubling 15 → 30 → 60 minutes. That holds a
  sustained attack to roughly 120 guesses a day against unlimited before, and a refused attempt does
  no lookup and no hashing, so the CPU half of the issue closes with the guessing half.
  The refusal is the door's existing invalid-credentials page, produced by the _same expression_ the
  two ordinary failure paths use rather than a copy of the wording, and failures are counted for
  addresses that resolve to no account — so neither the response nor the existence of a counter is
  evidence that an address is registered. Two things clear a counter, and both are proofs an attacker
  guessing passwords does not hold: a password that verifies, and a **completed** password reset.
  The second is why no "enter the code from your email" step was built — consuming the emailed secret
  already proves control of the address, through a flow that has its own cooldown and cap, while a
  dedicated step would have been an account-existence oracle, an email-bombing vector, a hard mail
  dependency for sign-in, and unavailable to the one bucket with no reset at all. Requesting a reset
  clears nothing.
  Three decisions are worth reading the code for. The record's retention (24h from the last failure)
  must **outlive** its own lockout window or the escalation silently never happens — a counter reaped
  when the door reopens restores the opening allowance, so an attacker who waits is never escalated;
  the boot validator enforces the ordering. The escalation ceiling is the first window wherever the
  bucket sets `totpRequired`, read from the bucket's policy and never from its identity, because a
  guessed password is not a sign-in there while the lockout it risks — the admin console, which has no
  self-service reset — is the one nobody can undo. And the counter's key is built by one new
  `emailScopedId` helper stating its rule as parity with `findByEmail`'s normalization: a key built
  from the raw submission would have given a 16-letter address 65,536 independent counters, and every
  test written in lower case would still have passed. That helper replaced three copies of the
  expression and one inlined fourth in the end-user delete route which had dropped its `toLowerCase()`
  — under the in-memory adapter, whose user store does not normalise what it stores, that line was
  already missing the email-scoped records of mixed-case accounts and reporting success.
  Bounds are `loginThrottle.failureCap`, `.windowSeconds` and `.windowCeilingSeconds`, super-admin
  editable and boot-only. There is deliberately no `loginThrottle.enabled`: unlike the per-origin
  limiter this is persisted, holds across restarts and machines, and is therefore a security boundary
  rather than a resource protection — a kill switch for it is a switch that reopens the vulnerability,
  so the validator bounds the numbers to a range in which the protection still means something instead.

- The last three security headers issue #2 asked for (issues #10 and #2, spec 029).
  `Strict-Transport-Security: max-age=63072000; includeSubDomains` and a `Permissions-Policy` denying
  seventeen high-privilege browser features now ride on every response, from the same pre-routing hook
  that already carried `nosniff`, `Referrer-Policy` and the non-page content policy — so they reach the
  error pipeline, the named admin instance and static assets, which after-the-fact response hooks miss
  silently. `preload` is deliberately omitted and the reason recorded: the deployment host is already
  preloaded through the whole `dev` TLD, submission needs an apex domain this deployment does not own,
  and the effect is global and slow to undo — a self-hoster's choice to add at their own edge. HSTS is
  emitted unconditionally, including over plaintext, because TLS terminates at the proxy so the hop RFC
  6797 governs is HTTPS, and the alternatives are either spoofable (`X-Forwarded-Proto`) or invisible
  to the merge gate. `clipboard-write` is **not** denied, and a named test enforces that: antd's
  `copyable` reaches for `navigator.clipboard.writeText` first, so denying it would have stranded five
  secret-copy surfaces — the TOTP enrolment secret among them — on the deprecated `execCommand` path.
  The legacy `X-Frame-Options: DENY` is emitted by `htmlResponse` on rendered pages only, derived from
  the same single evaluation as `frame-ancestors` and therefore absent on the one deliberately framable
  page, the `form_post` hand-off; a blanket emission was not merely inelegant but unimplementable,
  since a returned `Response` can override a merged header but never remove one and the header has no
  permissive value, so it would have broken silent authentication with no downstream fix
- Per-origin request rate limiting (issue #1). An origin that spends its allowance inside a window is
  refused with `429` and a `Retry-After`, before the endpoint does any work. Allowances are tiered by
  route class rather than blanket — strict on the unauthenticated and expensive surface, loose on
  static assets and discovery, the liveness probe exempt — declared as a third dimension on the route
  table under the same two-way drift guard as the feature gate and CORS. Counting is per instance and
  never persisted, so no storage area is added; the price is that the effective allowance multiplies
  by concurrent machine count and clears on restart, which is why this is a resource protection and
  not a security boundary. The per-identity throttles are unchanged, and the login door's brute-force
  protection remains issue #9. Nine `rateLimit.*` settings, editable from the console; invalid values
  refuse the boot rather than serving with limiting silently absent. `elysia-rate-limit` was evaluated
  and not adopted: its single static `errorResponse` cannot produce this server's three channel
  shapes, and its default refunds requests whose handler threw — which is every failed credential
  guess
- The administration console can be put behind the second factor. A new settings resource under
  `/admin/api/admins` carries the reserved admin bucket's `totpRequired` — audited as
  `admin.settings.update`, exposed to MCP as `admin_settings_read` and `admin_settings_update`, with
  a switch on the Admins page. The generic bucket routes still refuse that bucket; this is the
  surface their 403 already pointed at. Nobody is locked out by turning it on: an administrator
  without an authenticator enrols at their next sign-in
- TOTP second factor per user bucket: `totpRequired` makes a password sign-in also require a
  six-digit authenticator code, with enrolment at registration and at the first sign-in of an
  existing account, RFC 4226/6238 implemented in-repo against the published test vectors, replay and
  two-tier throttling, `amr: ['pwd','otp']` on the ID token, and operator recovery via
  `DELETE /admin/api/buckets/:id/users/:uid/totp` (audited, ends sessions, exposed to MCP as
  `bucket_user_totp_clear`). Federated sign-in is not gated (spec 027)
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

- Groups read as themselves in the admin console, and a personal group is nobody else's to work in.
  Four things were wrong at once, all of them about the same list. Every personal group displayed as
  the bare word "Personal" — including in a super administrator's list, where N administrators
  produced N identical rows and the owner's email that is *stored* as the group's name was thrown
  away by both display sites. Personal groups appeared in the Groups table at all, which is a page
  about the teams work is shared with. `GET /admin/api/scope` offered a super administrator every
  group on the instance, other people's personal groups among them, and `PUT` accepted them — so the
  console could be pointed at one person's own workspace by somebody who was never in it. And the
  reserved holding group was called "Unassigned", which reads like a data-quality problem rather than
  the name of the one group that is not a tenant.
  It is now: **System** (`SYSTEM_GROUP_NAME`, `$set` by the deployment seed so an existing database is
  renamed too, and preferred over the stored name by the console so it does not wait on `db:setup`);
  no personal rows in the Groups table; and one `groupLabel` helper shared by the table and the scope
  switcher, rendering "Personal" for your own and "Personal — owner@email" for a personal group you
  were added to. Both scope routes now apply the same carve-out — the list never offers what the
  switch would refuse — and all three of the switch's refusals still say one thing, so it cannot be
  used to learn which ids are real or which of them are personal. Whether a personal group is your
  own is answered by the server from `members[0]`, the only place that can answer it: a shared
  personal group may promote a second owner, and `findPersonalFor` matches any personal group you are
  a member of
- Switching the console's active scope no longer writes to the audit trail. `PUT /admin/api/scope`
  changes `AdminSession.activeGroupId` and nothing else, and grants no access a member did not already
  have — while which scope a change was made from is already carried by `ownerGroupId` on that change's
  own entry. It joins `POST /admin/api/logout` in `excludedAdminRoutes`, whose reason already described
  it: session lifecycle, not a change to a managed entity. `scope_switch` is withdrawn from the agent
  surface with it, as `inapplicable` — an agent has no console session, so the tool could only ever
  answer 400
- `README.md` and `AGENTS.md` now describe the server that exists (issue #20, spec 031). The endpoint
  table was wrong on six of eleven rows — `/authorize`, `/introspect`, `/revoke`, `/register`,
  `/session/end` and `/request` are really `/auth`, `/token/introspect`, `/token/revocation`, `/reg`,
  `/logout` and `/par` — and was missing twelve routes and every method on `/userinfo` but `GET`. It is
  now derived from `lib/consts/route_classification.ts`, which pairs each route with its governing flag
  and is already guarded both ways against `elysia.routes`, and it is split by availability because 23
  of the 28 feature flags default off and a disabled endpoint is deliberately indistinguishable from
  one that does not exist. Five Features bullets had presented opt-in capabilities as shipping
  defaults, Client Credentials and Refresh Token among them; the Features list now separates what a
  default install serves from what a deployment switches on, and drops the claim of static client
  registration, which was removed when clients became DB-backed. The Standards table gained eleven
  implemented specifications plus a flag column, and admits CIBA, JARM and OAuth 2.1, which its
  RFC-only shape had excluded. `AGENTS.md` had pointed contributors and agents at `/interaction/*`
  routes; login and consent are served under `/ui/:uid/*`. Two claims the issue asked for were dropped
  after checking the code: RFC 8414 is not implemented, and no `/.well-known/oauth-authorization-server`
  is served
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

### Removed

- Seven unreferenced modules deleted (issue #19, spec 030): the whole `lib/views/` directory of legacy
  interaction templates — safe because spec 015's `'rar-detail'` consent group had taken over the RAR
  rendering that was its one unique job — plus the `Stub.tsx` admin placeholder, `helpers/params.ts`,
  `helpers/set_www_authenticate.ts` and `helpers/_/pick_by.ts`. The two addon functions the issue
  suspected of being dead are **kept**: `assertClaimsParameter` and
  `assertJwtClientAuthClaimsAndHeader` are live override seams reached through the call-time registry
  in `lib/addon/index.ts`, so an empty body is their default rather than an abandoned stub, and each
  now carries a comment saying so. `AGENTS.md`'s source-tree map lost three stale entries it had kept
  describing — `views/`, the long-deleted `provider.ts`, and CORS under `shared/`. Test counts, type-error
  count and lint findings all held at their pre-change values.

### Fixed

- A super administrator's scope switch is no longer accepted and then silently discarded.
  `resolveActiveGroup` (`lib/admin/auth/rbac.ts`) re-validated the session's choice against membership
  alone, with no exception for the role that is allowed to switch without one — so a super
  administrator switching into a group answered 200, and on the very next request their active scope
  resolved to empty and `assertActiveGroup` sent everything they created to the `unassigned` holding
  group while the console went on showing the group they picked. Their choice is now honoured after
  one re-read of the group, which also refuses it if the group has since been deleted or is an
  administrator's personal group

- An agent naming an operation the MCP surface withholds now hears why, instead of `Tool <name> not
  found`. The refusal text existed and never ran: the call that delivered it sat in the tool
  registration loop, where it can only fire for a name that *is* registered, and an excluded operation
  never is. It now also runs in the transport, before the SDK and after the credential, answering a
  failed tool call rather than a JSON-RPC error. A genuine typo still gets the SDK's not-found, so a
  mistake is not dressed up as a policy decision
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
- The interaction cookie is cleared at its own path and expires with the interaction: the clear went
  out with `Path=/` while the cookie lives at `/ui/<uid>` (a different cookie, so a browser kept it),
  and its `Max-Age` was set in milliseconds -- a ~41-day lifetime for a one-hour interaction
- Small-batch fixes: duplicate first-run admin setup surface removed, error pages carry the real
  status and illustration, stale `interaction.returnTo` corrected, unimplemented CIBA `push` mode
  removed from the admin schema (spec 018)

### Security

- The reserved admin bucket can no longer be gated on email verification. Both paths that create an
  administrator write `verified: false` and no verification mail is ever sent for that bucket, so the
  flag would have refused every administrator at the door with no way back short of editing the
  database. It was unreachable through the API rather than prevented; it is now refused at the point
  of enforcement
- The end-user cookies (`_session`, `_interaction`) carry `Secure` -- and the `/ui/*` responses,
  which is where the authenticated `_session` is first written, now carry the full
  `HttpOnly; SameSite=Strict; Secure` set instead of no attributes at all: that route family
  declared a second, option-less cookie schema, so a `Set-Cookie` from it inherited nothing.
  Both schemas now build from one `endUserCookieAttributes` owner
- The admin console verifies its id_token's signature (plus `nonce`, expiry, audience) against the
  live keystore before trusting it — previously a documented decode-only shortcut (spec 017)
- The DPoP nonce secret is self-provisioned at startup, making the requireNonce-without-secret 500
  state unrepresentable (spec 014)
