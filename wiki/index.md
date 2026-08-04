# Wiki Index

The catalog of all pages in this wiki. Each entry: a wikilink to the page and a one-line summary. The LLM reads this first when answering queries to identify candidate pages.

Keep summaries tight — one line each. The index is engineered to be cheap to read; a fat index defeats its purpose.

When this file exceeds ~300 lines or the wiki passes ~150 pages, shard into `wiki/indexes/<type>.md` and replace this file with a directory of shards. See the `scaling-playbook.md` reference in the `llm-wiki` skill for the migration procedure.

---

## Sources

- [[oauth-server-codebase]] — the tracked `lib/` source tree, read at commit `2125ad0`; the source of record for every page below.

## Entities

- [[event-bus]] — the lifecycle `EventEmitter` that used to be the provider; a leaf module that must import no model, and imports the key store for its side effect.

## Concepts

- [[account-resolution]] — `findAccount` is a direct-import DB resolver, not a config option; enforces active status at every resolution and merges claims from the user record.
- [[admin-audit-trail]] — audit-first *and* authorization-first, in that order and inside the handler; a load-bearing route table; field names never values; Elysia strips undeclared query params before validation.
- [[admin-console-signin]] — the console is a relying party on its own issuer and must verify the ID token; the advertised alg list contains `HS256` and is a boot snapshot, `assertPayload` skips future-`iat` whenever `exp` is present, and no `azp` is ever emitted.
- [[admin-plane-error-shape]] — the admin plane answers `{ error: 'admin_error', message }`; the root OAuth handler is registered first and silently replaced it with `server_error` in the composed app, which every standalone-mounted admin spec missed.
- [[client-identity-from-database]] — `adapter('Client')` is the single source of client identity; the adapter is read every call and the LRU memo caches only validated objects, keyed by property hash.
- [[deletion-and-revocation]] — revoke, cascade and guard are three different operations; ownership is declared per storage area and read by one engine; two areas no grant walk reaches.
- [[feature-flag-gating]] — flat dotted keys on `ApplicationConfig`, boot-only derived `configuration`, and the `onRequest` gate that makes a disabled endpoint answer as unserved.
- [[first-run-setup-had-two-surfaces]] — `GET /admin` is the only bootstrap surface; the deleted `/admin/setup` twin pointed at an unserved bundle and rendered a blank page nothing linked to.
- [[html-response-security-policy]] — one constructor builds every HTML response and hashes its own inline scripts; a global lifecycle plugin was measured and misses the error page and the named admin instance.
- [[interaction-page-families]] — every end-user screen is either the hydrated antd shell or a plain self-contained page; a hydrated page without props erases its own server-rendered message, silently and only in a browser.
- [[model-graph-import-order]] — `lib/models/` has a cycle, so a cold entry throws a TDZ `ReferenceError`; enter through `test_helper` first, and the existing drift guard only passes by accident.
- [[self-service-password-reset]] — a reset secret is hashed at rest, expiry-checked in code because Mongo's TTL monitor is lazy, never consumed by a GET, and refused for the reserved admin bucket; one accepted page for every outcome.
- [[rich-authorization-requests]] — `authorization_details` end to end on the code and refresh flows; the declared parameter schema is a runtime coercion contract, and details reach a token only when a resource server resolves.
- [[token-payload-access-contract]] — model state lives under `.payload.*`; reading a bare field yields `undefined` silently, and payload schemas are composed per token type.

## Synthesis

(populated as query answers are filed back)
