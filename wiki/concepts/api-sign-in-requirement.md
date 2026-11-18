---
type: concept
title: "An API's sign-in requirement: a code, or a recent sign-in"
tags: [architecture, contract, gotcha, security]
sources: [oauth-server-codebase]
created: 2026-11-12
updated: 2026-11-18
---

# An API's sign-in requirement: a code, or a recent sign-in

Spec 130. Any declared API (whoever checks its tokens: its own server or the operator's proxy) can carry two fields
an administrator sets: `requireCode` (a token is issued only after a sign-in with a code from an authenticator app)
and `signInEveryMinutes` (60 to 20160, whole hours: the sign-in behind a token may be no older). They live at the top
level of `ProtectedResource` (`lib/adapters/types.ts`), written only by the admin routes.

## Why the authorization server enforces it, not the client

RFC 9470's `401 insufficient_user_authentication` with `acr_values` / `max_age` is the standard way for an API to ask
for a stronger or fresher sign-in. On 2026-11-12 no MCP client read it (TypeScript, Python and Rust SDKs, Claude Code,
claude.ai, ChatGPT, Codex, VS Code, Cursor, Goose, Zed, Gemini CLI), and the MCP specification does not mention it.
But every client fetches a new token on any `401`: by a refresh, or by sending the person to `/authorize`. FoxAuth
answers both, so it makes the requirement hold itself:

- the sign-in for a token for the API asks for the code, or a new sign-in, whatever the client sent;
- every grant for a person refuses a token whose sign-in does not meet it;
- a refresh that would not meet it is refused before rotation, so the client starts a new authorization;
- the proxy check still sends the RFC 9470 challenge, for clients that learn it.

The behaviour a person sees still depends on the client (Claude Code: reconnect in `/mcp`; ChatGPT, Codex: an error),
so the console says that in plain words and links to the site's client table. Getting this wrong in the console
("FoxAuth makes it work") was the UX critique's first finding.

Tried live on 2026-11-17 with Claude Code 2.1.220 against 2.0.1, an API at a Caddy proxy behind a tunnel. Its sign-in
through its client metadata document failed on 2.0.0 ([[loopback-redirect-port-matching]]). With a code required, and
later past a one-hour interval mid-session, the check answered `401 insufficient_user_authentication`; Claude Code
retried once without the token, failed the call and marked the server as needing authentication, and the person
authenticated again in `/mcp`. It renewed its 15-minute token by itself in between. Setting a code up through the mailed
link during that sign-in can outlast its wait for the redirect. It speaks MCP 2025-11-25 and sends no `Mcp-Method` or
`Mcp-Name`, so an API whose tools have conditions refuses it. claude.ai was not tried.

## One answer everywhere

`signInRequirementUnmet(signIn, { acr, authTime }, now)` (`lib/resources/sign_in_requirement.ts`) answers
`{ code, recent }` or null. Since spec 131 its arithmetic is `requirementUnmet` in the import-free
`lib/resources/sign_in_rule.ts`, given whether the sign-in had a code, so the console's "Check access" bundles the same
rule; the wrapper maps `acr` to that flag (`hadCode`). A missing or non-finite `authTime` is never recent: `undefined` arithmetic is `NaN`, and
every comparison with `NaN` is false, which would read as a pass. The requirement reaches every token path through the
descriptor the path already builds: `signInOf` (`lib/resources/registry.ts:28`) fills `ResourceServer.signIn`, so no
check reads the store again.

## The sign-in

Two login-prompt reasons (`lib/helpers/interaction_policy/prompts/login.ts:120`, `:287`):

- `resource_code`: a requested API requires a code and the session's acr is not multi-factor. It joins spec 127's
  `second_factor` in `CODE_REASONS` (`lib/consts/code_reasons.ts`), so the refusal page, the set-up from it (with the
  fresh password and the mailed link, never `totpRequired`'s bare QR) and "Return" are spec 127's own. The page names
  the API by its declared name (`apiAsking`, `lib/interactions/index.ts:1151`), never the client.
- `resource_max_age`: the session is older than the strictest requested API allows. A reason of its own rather than a
  written `params.max_age`, which would reach the ID token and the proxy's notice. `freshSignInParams`
  (`lib/interactions/index.ts:1304`) sends a provider `prompt=login` and the smaller of the request's and the API's
  `max_age`.

## Every grant

`assertSignInMeets` (`lib/resources/sign_in_requirement.ts:67`) after the resource server is built in the
authorization code, device and CIBA grants. jwt-bearer (ID-JAG, plain assertions) and client credentials are refused
for such an API outright (`jwt_bearer.ts:188`, `client_credentials.ts:132`): an assertion carries no sign-in this
server saw, and a machine token stands for no one. Token exchange issues no access token of this server.

## Refresh: refused before rotation

`refresh_token.ts:116`. The resource is resolved, and the requirement judged, before `rotateRefreshToken` /
`consume()`. Refused after rotation, the presented token would be spent, and the client's retry with it would read as
reuse and revoke the person's whole grant (`revokeReused`). Refused before, the token is untouched and still renews
for any other resource.

## At the proxy

`decideApiCall` (`lib/behind_proxy/api_decision.ts`, spec 131), which the check calls: after the access conditions (a refusal no new sign-in could change comes first)
and before the tools table, so it holds for every request whatever MCP method it names. `Presented` carries the token's
own `signedInAt` and `acr` (`lib/behind_proxy/bearer.ts:49`), from the JWT or the opaque record, never from the
person: a pairwise JWT has no `accountId` and is still judged. No sign-in time → `403 no_person`, never a `401`
(a machine asked to sign in again would loop). Otherwise `401` with `error="insufficient_user_authentication"`,
`acr_values` (the configured multi-factor value) and/or `max_age`, and `X-Auth-Reason` `code_required` or
`sign_in_not_fresh`, the app check's own reasons.

`challenge()` (`api_check.ts:90`) keeps only parameters whose value is RFC 6750 §3 text (`quotable`, `:81`). Bun
throws building a header with a value outside Latin-1 (that was a `500`), and a quote let a value add a parameter.

## Around it

- Introspection returns `acr` and `auth_time` (RFC 9470 §6.2), so an API that checks its own tokens can apply the
  same rule.
- Turning a requirement on, or shortening it, is previewed and confirmed with its counts
  (`lib/admin/resources/sign_in_preview.ts:167`), the application requirement's protocol; usage per API is not
  recorded, so the counts are an upper bound over the project or the API's group condition.
- A code typed again after another window used it says "This code was just used" (`reason: 'reused'`,
  `lib/totp/verify.ts:132`) and is not reported as an attack: VS Code opens several sign-in windows at once.
- A no-op fence migration `2026-11-14-api-sign-in-requirement-fence` (`lib/consts/migrations.ts:1863`): the top level
  of `ProtectedResource` is an open schema, so an older release would read past the fields and issue tokens without a
  code.

## Not here (later specs)

A fresh sign-in before one tool; verifying a provider's own `auth_time`.

**A fresh sign-in before one tool is postponed** (owner, 2026-11-18) until some MCP client sends `Mcp-Name`, which
MCP 2026-07-28 asks for. The check learns the tool only from that header, and no client known on 2026-11-18 sends it:
Claude Code 2.1.220 speaks 2025-11-25, and the site's client table says No for Codex, VS Code, Cursor, Zed and Gemini
CLI (claude.ai and ChatGPT unchecked). Such a requirement would therefore refuse every known client the whole API, as
a tool's conditions already do. When it comes back, the live run changes the design: Claude Code answers this 401 by
asking the person to authenticate again in `/mcp`, not by a refresh, so for it applying the strictest tool freshness
at `/auth` is enough. A server-side mark that makes a refresh fail is needed only for clients that refresh on a 401.
If one is built, it is bound to the sign-in that caused it (`auth_time`, and the grant for an opaque token), set only
by a request carrying the project's proxy key, never read by the check, and cleared only by a sign-in that meets the
requirement. A requirement the person cannot meet (a provider sign-in, or no authenticator when the project does not
let people set one up) answers 403 and sets no mark, so the other tools keep working. The API's own console page came with spec 132: the requirement is
set on its Access tab, beside the conditions it is judged with.
