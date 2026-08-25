---
type: concept
title: "Loopback redirect port matching"
tags: [oauth, contract, gotcha]
sources: [oauth-server-codebase]
created: 2026-08-25
updated: 2026-08-25
graph:
  node_type: concept
  relationships:
    - predicate: depends_on
      object: concept:client-identity-from-database
      source: oauth-server-codebase
      evidence: "redirectUriAllowed reads client.redirectUris and client.applicationType off the validated client object the database supplied."
      confidence: high
      status: current
---

# Loopback redirect port matching

`redirectUriAllowed` (`lib/models/client/checks.ts`) is exact membership **plus one liberty**: for a
native client redirecting to an `http:` loopback host, the **port** may differ from what was
registered. Scheme, host, path and query still have to match a registered URI exactly.

RFC 8252 §7.3 requires this. A native client receives its code on a port it binds when the request is
made, not when it registered — so the port is unknowable in advance, and an authorization server that
compares it refuses every such client.

## Why it is scoped the way it is

Widening redirect matching is how authorization codes get stolen, so each condition is load-bearing:

- **native clients only.** A web client's redirect is a host it controls; nothing about it is
  ephemeral, so there is no port to excuse.
- **`http:` on a loopback host only.** A claimed-HTTPS or private-scheme redirect names a host or
  scheme the client owns, and stays exact. `LOOPBACKS` (`lib/consts/client_attributes.ts`) is the same
  set registration-time validation uses.
- **hostnames compared as written.** `localhost` and `127.0.0.1` are *not* made interchangeable; the
  seed registers both forms rather than relying on the server to equate them.

What stays open by design is a local port race — another process could bind the port and receive the
code. PKCE closes it, and it is mandatory for public clients here; that is the trade RFC 8252 §8.10
makes too.

## The failure it fixes

Registration-time validation already knew this shape: `lib/helpers/validateRedirectUri.ts` admits
`http:` for a native client **only** on a LOOPBACKS host. The request-time half was missing, so a
loopback URI could be registered and then never matched unless the client happened to bind the exact
port it registered.

`lib/admin/seed.ts` registers the reserved MCP agent on three loopback URIs and says why — "the port
is unpredictable ... OAuth 2.1 allows a loopback port to vary" — which is an assumption the matcher
did not honour. A real MCP client bound 3118, then 46937, then 39548: a different port every attempt.
Each one was refused with `400 invalid_redirect_uri` *before* the consent screen, so the client's
flow timed out with nothing to show.

Claude Code's VSCode extension is worth naming: it ignores a configured callback port (`--callback-port`
is a CLI-only flag) and always binds an ephemeral one, so pinning a port in client configuration is not
a workaround.

## Related

- [[admin-mcp-control-plane]] — the surface that could not be signed in to while this was missing.
- [[first-consent-grant-id]] — the next failure in the same chain, once the redirect matched.
- [[pkce-verifier-length]] — the failure before it, at the token endpoint.
