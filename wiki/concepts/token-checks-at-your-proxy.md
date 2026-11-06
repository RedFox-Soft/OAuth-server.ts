---
type: concept
title: 'Token checks at your proxy: an API or MCP server with no authorization code'
tags: [architecture, contract, gotcha, oauth, mcp]
sources: [oauth-server-codebase]
created: 2026-11-05
updated: 2026-11-06
---

# Token checks at your proxy

Spec 123. An API that a project declares (a protected resource, see [[mcp-server-authorization]]) can say its
tokens are checked by the operator's reverse proxy instead of by its own server. The proxy (Caddy
`forward_auth`, Traefik `forwardAuth`, nginx `auth_request`) asks the project about every request before passing
it on. The project reads the bearer token as the API would have, and for an MCP server it can also require
scopes per tool. The server behind the proxy writes no authorization code at all.

It reuses the endpoint family, the limiter, the answers and the recipes of [[behind-your-proxy]] (spec 122).

## Who checks is a field on the API

`checkedBy` is `'server'` or `'proxy'`, absent meaning the server (`lib/adapters/types.ts:1505`). The tools table
is the optional `tools` beside it (`:1507`). Both live in the record's document on every backend, so there was no
migration, and both ride the existing `PATCH …/resources/:resourceId`. The MCP tool `resource_update` is high,
which means it needs a two-call confirmation, whenever it sets either (`lib/mcp/catalogue.ts:1010`).

Switching changes no token. Switching back to the server makes the proxy's checks answer `not_found`, so a proxy
left configured fails closed. `tools` is kept across the switch.

The proxy mode needs an `https` identifier, because there must be a host to compare. It also needs a project with
an address of its own, or the default project (`lib/admin/resources/routes.ts:263`). A check at the root answers for
the project served at the root, so an API of a legacy project with no address could never be found.

## The check names the API by a digest

`/verify/api/:checkId` sits one level below spec 122's `/verify/:appId`, so no app id can name an API
(`lib/consts/behind_proxy.ts:27-28`). An API's stored key joins its namespace and identifier with a space, which
no path segment can carry. So `checkId` is the first 22 characters of the base64url SHA-256 of the identifier
(`lib/behind_proxy/check_id.ts:9`). It is derived, never stored, and does not change when the API is switched.

The project comes from the request address, as everywhere. The API is the one in that project's
`listByBucket` whose digest matches and whose `checkedBy` is `proxy` (`lib/behind_proxy/api_find.ts:43-60`). The
administrators' project never answers (`:51`).

Every way of naming something the project does not check gives one byte-identical `403 not_found`: an unknown
project, a scheduled one, an unknown id, another project's API, a server-checked API, or a host that is not the
API's.

## Reading the token as the API would

`readBearer` (`lib/behind_proxy/bearer.ts`) repeats the order of the two readers that already existed: token
exchange's `fromJwt` (`lib/connected_services/subject.ts`) and introspection.

- **Where the token may be.** Only one `Authorization` header is read (`:58`). A token in the query or the body,
  two headers (Bun joins them with a comma), or another scheme count as no token. The `DPoP` scheme is answered
  as a bound token, so the client learns why (`:68`).
- **A self-contained token (JWT)** (`:89`) is verified with the keys and issuer the API's tokens carry: the
  project's own, or the root's for the root namespace. Then `aud` must be the identifier, `exp`/`nbf` must hold, and
  `typ` must be `at+jwt`. Any `cnf` refuses it (`:108`).
- **An opaque token** (`:122`) is `AccessToken` then `ClientCredentials`. It must be unexpired, issued where the API's
  tokens are issued (`servingBucketIdOf`), and for this audience. If it names a grant, the grant must still stand
  (`:145`), exactly as introspection checks. `jkt` or `x5t#S256` refuses it (`:157`).
- **The subject the API is told** is the `sub` it would have read: a JWT's `sub`; for an opaque token, the account
  id, its pairwise form for a pairwise client, or the client id for a machine token. That is why the header is
  `X-Auth-Subject` and not spec 122's `X-Auth-User`: it is not always an account id.

**Revocation is the price of a JWT.** No grant is read for a self-contained token. A revoked one stays usable at
the proxy until it expires, as it would at an API checking it itself. Reading the grant on every request would put
a database read on every MCP call. The opaque format gives immediate revocation to whoever chooses it, and the
console says so where the format and lifetime are chosen.

**Bound tokens are refused, not accepted unproven.** A DPoP or certificate proof is bound to the request the client
made to the API. The proxy forwards headers only, and checking a proof against forwarded values would trust the
proxy for exactly what the proof exists to prove.

## The project serves the API's metadata

Every token refusal carries `WWW-Authenticate: Bearer …resource_metadata="<M>"`. `<M>` is
`{project}/verify/api/{checkId}/metadata`, an RFC 9728 document the project serves with
`Access-Control-Allow-Origin: *` (`lib/behind_proxy/api_metadata.ts:11-45`). Under spec 107 the API itself had to
serve that document. Here the challenge may point anywhere, because a client's check is that `resource` equals
the URL it called (RFC 9728 §7.3), and it is the identifier. Without this, the promise of "no auth code in the
server" would fail at the first `401`.

In proxy mode the vouching diagnostic fetches nothing and answers `servedByProject`
(`lib/admin/resources/routes.ts:430`).

## Tools by MCP header

`decideTool` (`lib/behind_proxy/tools.ts:102`) is pure and import-free. The check and the console's Tools drawer
use it, and the test drives one table through both. With an empty table, only the token is checked.

- **The headers.** MCP 2026-07-28 puts `Mcp-Method` on every client message and `Mcp-Name` on `tools/call`,
  `resources/read` and `prompts/get`. That revision also makes the server refuse a request whose headers and body
  disagree. The proxy never sees the body, so a header is only as true as that server-side check.
- **Old clients.** A request with no `Mcp-Method`, or whose `MCP-Protocol-Version` is absent, malformed or earlier
  than `2026-07-28` (`:35`, `:82`), follows the administrator's old-clients choice, `refuse` by default. The
  specification asks this of intermediaries that act on these headers. Trusting `Mcp-Method` alone would let a
  2025 client steer the decision with a header its server never compares.
- **Encoded names.** A name a header cannot carry plainly arrives as `=?base64?…?=`. It is decoded before matching
  (`:53`). An undecodable value, or a control character on either side of decoding, is `bad_mcp_header`, never
  "any other tool".
- **Matching is exact.** `Delete_File` is not `delete_file`. A missing scope is a `403` with
  `error="insufficient_scope", scope="<every scope of the row>"`, so a client asks for all of them at once.
  `resources/read` and `prompts/get` are "other methods": token only, as the drawer says.

## Answers and the nginx exception

Token problems are `401`; every other refusal is `403`, including `bad_mcp_header`. MCP asks only for an
"appropriate" status, and nginx `auth_request` turns anything other than 2xx, 401 and 403 into 500.

nginx copies `WWW-Authenticate` to the client by itself on a 401 but not on a 403. So the API recipe adds a `map`
in the http context that re-adds the captured challenge on a 403 only (`lib/behind_proxy/recipes.ts:253-264`).
Caddy and Traefik return the check's whole answer on any non-2xx.

A CORS preflight (`OPTIONS` with `Access-Control-Request-Method`) passes before any token is read, with every
identity header empty (`lib/behind_proxy/api_check.ts:115`). A browser never attaches a credential to one.

The limiter is spec 122's, keyed `api:<checkId>` (`api_check.ts:92`).

## Known limitations

- **Refusals carry no CORS headers.** A browser-based MCP client cannot read the `401` challenge across origins
  unless the proxy adds CORS headers to errors. The check does not guess the API's CORS policy.
- **`resources/read` and `prompts/get` are not covered** by the table, and agreement between header and body is the
  MCP server's to enforce.
- **Group, attribute, network and time conditions** came with spec 124 (`tools.access`, decided before the table;
  see [[conditions-at-your-proxy]]). Without one, anyone who can sign in to the project can get a token for the API.
  A JWT counts as a person only when it carries `auth_time`, which tokens issued before spec 124 do not.
- **Existence of a check id leaks to a probe without `X-Forwarded-Host`.** Such a check answers `missing_forwarded`
  for an existing id and `not_found` for an unknown one, the same order as for apps. The id is a digest of a public
  identifier, so nothing secret is revealed.

## Related

- [[behind-your-proxy]] — the app check this one sits beside, with its forwarded-host rule and limiter.
- [[mcp-server-authorization]] — declared APIs, their audiences and what an API checks itself.
- [[admin-mcp-control-plane]] — the `highWhenSets` gate on `resource_update`.
- [[caller-address]] — why the proxy's forwarded address is never the caller.
- [[conditions-at-your-proxy]] — who may call the API at all (spec 124).
