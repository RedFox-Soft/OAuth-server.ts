---
type: concept
title: 'The administrative MCP control plane'
tags: [architecture, contract, gotcha, config]
sources: [oauth-server-codebase]
created: 2026-08-24
updated: 2026-08-24
graph:
  node_type: concept
---

# The administrative MCP control plane

An AI agent administers this instance over MCP at `POST /mcp`, as an OAuth 2.1 protected resource of
the very server it administers. The constitution requires it (Principle II) and requires it to have no
back door: every agent action must run the same management API, authorization and audit trail as a
human's.

That last requirement is the whole design. A tool does not call a service — it rebuilds the HTTP
request the console would have sent and hands it to the real admin routes in-process
(`lib/mcp/dispatch.ts`). There is no second implementation to keep in step, so a tool cannot skip
`assertRole` or `recordAdminAudit` by forgetting to call them: it never calls them at all.

## Mount the route plugins, never `adminApp`

`lib/mcp/dispatch.ts` composes `adminApiRoutes` (`lib/admin/routes.ts`), not `adminApp`. Measured:
importing `lib/admin/index.ts` takes **~86s** because it pulls `renderAdminShell` and with it React and
antd's CSS-in-JS; the ten route plugins take **~350ms**. Same route set either way — `adminApp` is
`adminApiRoutes` plus the HTML shell.

`lib/admin/routes.ts` exists for that split, and it is also what the parity guard compares against. Two
consequences worth knowing:

- Every route group owns its own `onError` with the `AdminError` → `{ error: 'admin_error', message }`
  mapping, so a composition inherits it. The `VALIDATION` → 422 arm belongs to no group, so
  `adminApiRoutes` carries it — a bare composition of the plugins answers a validation failure in
  Elysia's own shape instead.
- `GET /admin/api/me` used to be an inline route on `adminApp`, invisible to any composition. It moved
  to `lib/admin/me.ts` because the `whoami` tool needs it, and because the drift guard needs a complete
  route set.

## The catalogue is load-bearing

`lib/mcp/catalogue.ts` enumerates all 39 published tools over the 43 routes under `/admin/api/`, plus
the four deliberate exclusions. Same technique as [[admin-audit-trail]]'s route table, for the same
reason: the tool-name union derives from the table, `action` is typed as `AuditAction` so a tool cannot
claim an audit action the audit table does not declare, and
`test/mcp/catalogue_drift.spec.ts` compares the table against the mounted routes in **both**
directions. A new admin route is published, named as an exclusion, or a test failure.

It imports schema modules and never route modules — a route module reaches the adapters and from there
`lib/adapters/mongodb/db.ts`, which connects at import time.

Tool input schemas *are* the TypeBox objects the routes validate against, so the schema an agent reads
cannot drift from the schema the route enforces. That decided against Zod, the SDK's documented default.

## Five traps this cost us

**One flat argument object cannot hold two things called `id`.** A tool takes a single flat object, so
`federation_provider_create` — `POST /admin/api/buckets/:id/federation`, whose body carries the
*provider's* own `id` — silently dropped the provider id and failed every call. Path parameters can now
be aliased (`pathArgs`, the bucket is `bucketId` there), and the drift guard refuses any tool whose
final argument names collide.

**A closed input schema breaks an open-map body.** `UpdateSettingsBody` is
`t.Record(t.String(), t.Unknown())`, validated per key by the handler against the catalog. With
`additionalProperties: false` applied uniformly, every settings key was refused as an additional
property and `settings_update` never reached its own confirmation gate. Openness is now inherited from
the route's body, and a tool with path parameters is never opened — an arbitrary body key could
otherwise shadow a path segment.

**Elysia consumes the request body before the handler runs.** The SDK cannot read the stream a second
time, so every exchange — `initialize` included — answered an opaque JSON-RPC `-32603`. The SDK provides
`parsedBody` for exactly this; `lib/mcp/index.ts` passes Elysia's parsed value. Isolating the SDK
handler from the Elysia route is what located it.

**Elysia's `t` is not TypeBox, and publishing the difference is visible.** `t.Integer()` is a *decoder*,
not an integer: `elysia/dist/type-system/index.js:96` renders it as
`anyOf: [{ type: 'string', format: 'integer', default: 0 }, { type: 'integer' }]` so a form field arriving
as `"587"` still validates. Harmless inside Elysia, whose registry declares that format — but the same
object is the tool's published input schema (`lib/mcp/server.ts:230`), where Ajv compiles it and logs
`unknown format "integer" ignored in schema at path "#/properties/port/anyOf/0"` twice at every boot, and
where an agent reads a `default: 0` the field does not have. `smtp_settings_update` was the only offender.
Fixed at the source rather than translated at the boundary: `lib/admin/settings/smtp/schema.ts:26` declares
`t.Number({ multipleOf: 1 })`, plain JSON Schema meaning the same thing (TypeBox's real `Type.Integer` is
not reachable through Elysia's `t`). The console then has to send a number — antd's `<Input type="number">`
submits a *string*, and leaning on the coercion was what hid that; it is an `InputNumber` now
(`lib/admin/ui/pages/Settings.tsx:192`). `test/mcp/schema_bridge.spec.ts:108` walks every published schema
for a coercion format, so the next `t.Integer()` in an admin body fails a test instead of logging at boot.

**`resolveAdmin` must import the model graph lazily.** Teaching it a second credential type meant
reaching `AccessToken`, and `lib/models/` has an import cycle that dies cold — see
[[model-graph-import-order]]. A static import put that cycle in the chain of all ten admin route
groups and took the whole admin suite down. The import inside the derive is deliberate.

The refusal it wraps is narrow on purpose. The bearer arm answers one `admin: null` for every
*authorization* cause, so a caller cannot probe which check failed — but a bare `catch` also turned a
storage outage into "not authenticated", sending an operator to debug a credential while the database was
down, and the cookie arm beside it would have answered 500 for the same fault. Only `McpUnauthorized` is
a refusal; anything else is rethrown, so both credential types report an outage identically. A DPoP nonce
challenge is among the rethrown: it is a protocol step telling the caller to retry with a nonce, and
flattening it leaves a compliant client nowhere to go.

## Authorization is the audience boundary

A token reaches `/mcp` only if this server minted it for `MCP_RESOURCE` (`${ISSUER}/mcp`). The converse
already held before the feature existed: `lib/actions/userinfo.ts` refuses any token carrying an
audience at all. So the separation holds both ways, and only one half needed writing.

Two things make it work at all, and neither is obvious:

- `lib/addon/resources.ts` ships `getResourceServerInfo` as a `mustChange` stub that **throws**, while
  `resourceIndicators.enabled` defaults true. Without a built-in answer for `MCP_RESOURCE`, no
  audience-bound token could ever be minted. It now answers for this server's own resource and delegates
  everything else.
- `lib/admin/auth/resolveBucket.ts` routes a client to the administrator bucket only if it is the
  reserved console client or belongs to a project whose bucket is the admin bucket. A dynamically
  registered client falls through to `redfox` and **cannot authenticate an administrator at all** — so
  the agent client is seeded (`admin-mcp`, public, PKCE) rather than obtained by DCR. A documented
  deviation from the MCP authorization spec's preference, and the reason a DCR-only MCP client cannot
  use this surface.

RFC 9728 metadata is **path-aware**: a resource at `/mcp` publishes at
`/.well-known/oauth-protected-resource/mcp`, not the bare well-known root.

## What agents may not do

Deleting a project, a user bucket, or a **group** is withheld — not confirmation-gated, absent. These
are the operations that destroy a container with nothing left afterwards to inspect; a group joined
them when ownership moved to groups ([[group-ownership]]), and for a sharper version of the same
reason — destroying one takes with it the only thing that granted anyone access to what it held.
Widening the project-administrator role deliberately did not widen this list. They are not
registered as refusing tools either, because a registered tool appears in `tools/list` however it
behaves; the server's `instructions` carry the explanation, read from the exclusion table so the two
cannot disagree.

The table distinguishes two kinds of absence, and the distinction is what makes that claim true.
`withheld` entries are operations an agent could perform and an operator has decided it may not;
`inapplicable` ones have no meaning for an agent at all — there is no browser session to end, nobody to
authorize first-run setup, and no agent principal to accept a group invitation as, since acceptance is
a person following a link in their own mail. Only the `withheld` ones reach the instructions, and they reach them by
being filtered out of the table rather than named a second time. Naming them literally is the bug this
replaced: the list read `['project_delete', 'bucket_delete']` directly beneath a comment claiming it
could not disagree with the table, so a third withholding would have been refused correctly when
guessed and silently missing from the announcement that exists so an agent need not guess. That third
withholding has since arrived — `group_delete` — and cost only a table row, which is the arrangement
working as intended.

The other eleven destructive operations take two calls: describe, then confirm. The confirmation binds
five ways — tool, target, arguments hash, administrator, agent — and each is a real case. Arguments,
because a target-only binding would miss a password reset confirmed for one value and submitted with
another. Administrator separately from agent, because one operator's confirmation must not be spendable
by another working through the same agent. The record is deleted *before* the bindings are compared, so
a token presented for the wrong operation is consumed rather than left to probe with.

Neither identity may fall back to a placeholder, and both once did. `principalId` defaulted to `''` when
`whoami` failed and `viaClientId` to `''` when `authInfo` carried no client — either turns that binding
into a wildcard, so two callers whose id could not be read would match each other's confirmations. A
binding that degrades to "matches anything" is worse than no binding, because it still looks enforced.
Both now refuse the call. Both facts also come from a **single** `whoami` dispatch: as two, a role
revoked between them would pass the role check and then bind a confirmation the perform step must
refuse.

The describe step writes no audit entry, which follows from what an entry means here (see
[[admin-audit-trail]]): it attests that an authorized actor reached the point of applying a change.

## The capability set does not vary

`FR-006` originally said to hide operations whose capability is switched off. That described behaviour
the console does not have. `/admin` is an `alwaysAvailablePrefixes` entry in
`lib/consts/route_classification.ts`, and that table's own comment names the deciding case: a federation
provider must stay deletable by a deployment that has just switched federation off. The console applies
the same policy in its forms rather than mirroring flags client-side, because that would restate a
server rule in a second place.

So the published set is one per release, identical on every instance, and
`test/mcp/capability_invariance.spec.ts` asserts no tool module reads `ApplicationConfig`. The surface's
own `mcp.enabled` switch is different in kind: with it off, `featureGate` answers exactly as for a path
the server does not serve, and there is no set to vary.

## Related

- [[admin-audit-trail]] — what an entry means, why audit-first, and the route table this catalogue copies.
- [[admin-plane-error-shape]] — the `{ error, message }` shape the dispatcher inherits.
- [[model-graph-import-order]] — the cycle that forces the lazy import in `resolveAdmin`.
- [[feature-flag-gating]] — how `mcp.enabled` makes a disabled endpoint indistinguishable from an absent one.
- [[upstream-federation]] — the provider secrets the bucket routes were leaking until this feature's secrecy sweep found it.
- [[pkce-verifier-length]] — the token-endpoint bound that stopped a real MCP client signing in, and surfaced here as this page's own opaque 401.
- [[loopback-redirect-port-matching]] — why this client's ephemeral callback port was refused before consent.
- [[first-consent-grant-id]] — why approving consent for this client answered 401 until the grantId was resolved with tryFind.
- [[group-ownership]] — the ownership model the group tools administer, and why `group_delete` joined the withheld list rather than the confirmation-gated one.
