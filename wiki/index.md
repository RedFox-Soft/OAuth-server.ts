# Wiki Index

The catalog of all pages in this wiki. Each entry: a wikilink to the page and a one-line summary. The LLM reads this first when answering queries to identify candidate pages.

Keep summaries tight — one line each. The index is engineered to be cheap to read; a fat index defeats its purpose.

When this file exceeds ~300 lines or the wiki passes ~150 pages, shard into `wiki/indexes/<type>.md` and replace this file with a directory of shards. See the `scaling-playbook.md` reference in the `llm-wiki` skill for the migration procedure.

---

## Sources

- [[oauth-server-codebase]] — the tracked `lib/` source tree, read at commit `2125ad0`; the source of record for every page below.

## Entities

- [[addon-registry]] — the single call-time seam for replaceable behaviour; type-only imports keep it free of the model graph, and source modules import the accessor, not the implementation.
- [[admin-console]] — the admin API plus the HTML shell that drives it, split so the MCP plane can mount the same route set; two error handlers, one bootstrap surface, and a shell too expensive for an agent to import.
- [[elysia-lifecycle]] — the callback-shaped cross-cutting hooks and the mount order that makes them correct; registration order is a correctness constraint, and each plugin argues its own lifecycle stage.
- [[event-bus]] — the lifecycle `EventEmitter` that used to be the provider; a leaf module that must import no model, and imports the key store for its side effect.
- [[html-rendering]] — the one constructor every HTML response passes through, deliberately not a lifecycle plugin; the framing verdict rides along with the derived policy.

## Concepts

- [[account-resolution]] — `findAccount` is a direct-import DB resolver, not a config option; enforces active status at every resolution and merges claims from the user record.
- [[admin-audit-trail]] — audit-first *and* authorization-first, in that order and inside the handler; a load-bearing route table; field names never values, and only the names that actually changed; Elysia strips undeclared query params before validation.
- [[group-ownership]] — a group owns every project and bucket and is the only thing that grants access; owner-vs-member is a property of a membership, not a role; the active scope lives on the session and is re-validated per request; a refusal must not reveal existence; the migration groups by identical manager set so two tenants sharing one manager are never merged.
- [[admin-console-signin]] — the console is a relying party on its own issuer and must verify the ID token; the advertised alg list contains `HS256` and is a boot snapshot, `assertPayload` skips future-`iat` whenever `exp` is present, and no `azp` is ever emitted.
- [[admin-mcp-control-plane]] — an agent administers the instance by re-dispatching into the real admin routes, so there is no second implementation; a load-bearing tool catalogue, the audience boundary in both directions, two withheld deletions, and four traps (flat `id` collision, closed schema vs open-map body, Elysia eating the body, the model-graph lazy import).
- [[admin-plane-error-shape]] — the admin plane answers `{ error: 'admin_error', message }`; the root OAuth handler is registered first and silently replaced it with `server_error` in the composed app, which every standalone-mounted admin spec missed.
- [[client-identity-from-database]] — `adapter('Client')` is the single source of client identity; the adapter is read every call and the LRU memo caches only validated objects, keyed by property hash.
- [[cookie-path-scoping]] — `(name, domain, path)` identifies a cookie, so `remove()` — which takes its `Path` from the route's schema (`/` in practice), never from the cookie — clears a different cookie than the one the browser keeps sending.
- [[end-user-cookie-attributes]] — a cookie's attributes come from whichever route's schema is running, so the weakest schema naming a cookie decides what the browser stores; two schemas named `_session` and the `/ui` one carried no attributes at all.
- [[deletion-and-revocation]] — revoke, cascade and guard are three different operations; ownership is declared per storage area and read by one engine; two areas no grant walk reaches.
- [[error-store-capture-sites]] — recorded faults are captured in two places, because the global handler stands aside on the `adminPlane` *marker* and only a deliberate `AdminError` carries one; `set.status` may be a status name, so an un-narrowed `>= 500` test silently records nothing.
- [[error-store-is-not-flag-gated]] — the admin operation set is invariant under capability switches, guarded twice; gating an admin route also splits the console from the agent surface, which re-dispatches without the gate plugin — so the flag is reported in the payload and the agent purge is withheld outright rather than opt-in.
- [[feature-flag-gating]] — flat dotted keys on `ApplicationConfig`, an overrides document holding only edited keys, boot-only derived `configuration`, and the `onRequest` gate that makes a disabled endpoint answer as unserved.
- [[first-run-setup-had-two-surfaces]] — `GET /admin` is the only bootstrap surface; the deleted `/admin/setup` twin pointed at an unserved bundle and rendered a blank page nothing linked to.
- [[html-response-security-policy]] — one constructor builds every HTML response and hashes its own inline scripts; a global lifecycle plugin was measured and misses the error page and the named admin instance.
- [[non-html-response-hardening]] — the companion policy for everything that is not a page, written from one `onRequest` hook; there is deliberately no page-detection branch because a page's own `Response` header wins over the merge, the CORS mount-order caveat does not bind a pre-routing hook, and the single-writer guard is a substring scan a comment can fail.
- [[interaction-page-families]] — every end-user screen is either the hydrated antd shell or a plain self-contained page; a hydrated page without props erases its own server-rendered message, silently and only in a browser; antd's `zeroRuntime` never reaches zero because a second, ungated hook always injects a small cssVar block.
- [[model-graph-import-order]] — `lib/models/` has a cycle, so a cold entry throws a TDZ `ReferenceError`; enter through `test_helper` first, and the existing drift guard only passes by accident.
- [[mongodb-test-fidelity]] — the production backend carried zero coverage by constitutional rule, until the rule shipped a server that could not boot; two tiers now, split on whether a property can be proven without a server, and three import-time barriers in the way.
- [[per-origin-rate-limiting]] — mounting before the feature gate is a correctness call, not an optimisation; the refusal renders at the root because the throw precedes routing; counters are bounded, in-process and never persisted, which makes it a resource protection rather than a security boundary.
- [[override-seams-vs-dead-code]] — an empty addon body is an extension point's default, not an abandoned stub; source modules import the accessor rather than the implementation, so an importer census reports live seams as dead, and resolving a removal candidate by symbol name instead of path nearly deleted a live `urlFor`.
- [[pairwise-identifier-salt]] — the pseudonym is a relying party's account key, so its salt is stored server state, never the hostname; an unusable salt fails closed at the token endpoint and is never replaced, and the logout notification derives its `sub` a layer away in the claim pipeline.
- [[form-action-redirect-chain]] — a browser checks form-action against every hop of a submission's redirect chain, so `'self'` blocked the hand-off to a foreign callback after the code had already been issued; only a real browser can see it.
- [[first-consent-grant-id]] — an interaction's grantId is a hint, not proof of storage; a first consent resolved it with find() and answered 401 invalid_token for a missing record, and the harness's pre-seeded grant hid the branch.
- [[login-door-throttle]] — the second factor's failure window moved to the password door; two horizons whose confusion silently removes the escalation, a ceiling that reads the bucket's second factor rather than its id, the reset flow as the escape hatch, and a casing bypass that passes every lower-case test.
- [[loopback-redirect-port-matching]] — a native client's loopback redirect may differ from its registration in the port alone; registration-time validation knew this shape and request-time matching did not.
- [[pkce-verifier-length]] — the challenge is 43 characters because it is a digest; the verifier is 43..128 because the client chose, and pinning it at 43 refused conformant clients at schema validation with a 422, three steps upstream of the 401 they saw.
- [[self-service-password-reset]] — a reset secret is hashed at rest, expiry-checked in code because Mongo's TTL monitor is lazy, never consumed by a GET, and refused for the reserved admin bucket; one accepted page for every outcome.
- [[upstream-federation]] — a bucket may accept sign-in through external OIDC providers; the flow is three hops because the interaction cookie provably cannot survive the trip to an upstream, both round-trip records are keyed by a digest of the value they never store, and linking to an existing account needs operator trust *and* a verified assertion.
- [[rich-authorization-requests]] — `authorization_details` end to end on the code and refresh flows; the declared parameter schema is a runtime coercion contract, and details reach a token only when a resource server resolves.
- [[token-payload-access-contract]] — model state lives under `.payload.*`; reading a bare field yields `undefined` silently, and payload schemas are composed per token type.
- [[two-meanings-of-origin]] — `origin` names the caller's network address on the record and the code location on the occurrence, so the outbound event carries both under different names and must never merge them; the location is sendable only because no stack is kept, the permitted list is enforced one level deep, and grouping cannot be disturbed because a client fingerprint suppresses the destination's algorithm entirely.
- [[totp-second-factor]] — one bucket boolean turns a password door into a two-key one; the algorithm is in-repo because the RFCs publish test vectors, and four placements of state buy deletion integrity, expiry, un-guessable enrolment and a throttle that survives a new interaction for free.

## Synthesis

(populated as query answers are filed back)
