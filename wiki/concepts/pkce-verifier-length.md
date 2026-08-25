---
type: concept
title: "PKCE verifier length"
tags: [oauth, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-08-25
updated: 2026-08-25
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:admin-mcp-control-plane
      source: oauth-server-codebase
      evidence: "An MCP client that generates a verifier longer than 43 characters cannot exchange its code, so `/mcp` refuses it as `malformed_credential`."
      confidence: high
      status: current
---

# PKCE verifier length

The `code_challenge` and the `code_verifier` do **not** share a length, and treating them as if they
do is how this server locked out conformant clients.

- The **challenge** is a SHA-256 digest, base64url-encoded, so under the only method this server
  supports (`S256`) it is *always exactly* 43 characters. `lib/consts/param_list.ts:14` pins it at
  `^[A-Za-z0-9_-]{43}$`, and that is correct.
- The **verifier** is whatever the client generated. RFC 7636 §4.1 sizes it at 43 to 128 characters,
  and every length in that range is conformant. `lib/actions/grants/index.ts:22` therefore accepts
  `^[A-Za-z0-9_-]{43,128}$`.

## The failure this caused

`code_verifier` was pinned at exactly 43 characters, copying the challenge's pattern. A client that
generated 64, 86 or 128 characters was refused at **schema validation** with a 422 — before the grant
ran, so `lib/helpers/pkce.ts` never got to compare anything. No correct verifier could redeem such a
client's code, and nothing in the response said why the length was the problem.

Seen from the client the symptom is displaced from the cause, which is what made it expensive:
authorization and consent both succeed, the browser returns to the redirect URI, and only the token
exchange fails. An MCP client that stores what it got then holds an *empty* access token, and the next
call to `/mcp` is refused by `resolveMcpPrincipal` as `malformed_credential`
(`lib/mcp/principal.ts:129`) — a 401 on a protected resource, three steps downstream of the schema
that actually rejected the request. See [[admin-mcp-control-plane]] for why that 401 says nothing
about its cause.

## Why the suite did not catch it

Every verifier this project produces is 43 characters, so the bound was never crossed from inside:

- `lib/admin/auth/login.ts:23` derives the console's verifier from `crypto.randomBytes(32)`, which is
  exactly 43 base64url characters — see [[admin-console-signin]].
- `test/pkce/pkce.spec.ts` used RFC 7636's own 43-character example value.

The negative tests were no help either: they asserted 42 and 129 characters are rejected — both true
under either pattern — so they passed while the range between them was closed. The regression test is
`test/pkce/pkce.spec.ts:337`, which exchanges a code with an 86-character verifier and a real matching
`S256` challenge.

The general shape: a bound only tested at its two failing edges is not tested at all. What proves a
range is a value from its interior.

## Related

- [[admin-mcp-control-plane]] — the surface whose sign-in this blocked, and its single opaque 401.
- [[admin-console-signin]] — the in-repo client whose 43-character verifier hid the bug.
- [[feature-flag-gating]] — the other reason `/mcp` can answer a request that looks unauthorized.
