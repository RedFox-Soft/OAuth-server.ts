---
type: concept
title: 'A path parameter that is a URI is decoded from its raw segment'
tags: [contract, gotcha, security]
sources: [oauth-server-codebase]
created: 2026-11-09
updated: 2026-11-09
---

# A path parameter that is a URI is decoded from its raw segment

Some admin and protocol routes take a URI as a path parameter: a declared resource's identifier
(`/admin/api/projects/:id/resources/:resourceId`) and a `client_id` that is a URL
(`/reg/:clientId`, the console's client and administrators'-application routes, a session sign-out).
The caller percent-encodes it, so `https://api.example/mcp` arrives as one segment,
`https%3A%2F%2Fapi.example%2Fmcp`.

## What Elysia 1.4.31 changed

Up to 1.4.30 Elysia decoded a parameter fully. 1.4.31 (advisory GHSA-pxh4-839p-c8c8, "harden encoded
path routing") rewrites `%2F` to `%252F` before decoding (`node_modules/elysia/dist/index.mjs`,
`decodePathParameter`). A handler therefore receives `https:%2F%2Fapi.example%2Fmcp`. Because `%25` is
still decoded to `%`, an identifier with a real `/` and one with a literal `%2F` reach the handler as
the same string. Decoding the parameter again cannot tell them apart.

## The rule

A route whose parameter is a URI mounts `uriPathParams(name)` (`lib/plugins/uri_path_params.ts`). At the
transform stage it reads the parameter's segment from the raw request path and decodes it once. It counts
the segment from the end of the route, so a `/:bucket` prefix or a mounting path never shifts it. The
handlers keep reading `params.<name>`.

It is mounted, scoped, in `lib/actions/registration.ts`, `lib/admin/clients/routes.ts`,
`lib/admin/resources/routes.ts`, `lib/admin/administrator-applications/routes.ts` and
`lib/admin/users-end/routes.ts`. A new route that takes a URI in its path mounts it too. Nothing fails if
you forget, unless a test addresses the route with a URL.

It is deliberately not global. The hardening protects routing and handlers that build file paths from a
parameter (the static plugin's wildcard). Restoring the old decoding for every parameter would undo it.

`test/resources/encoded_slash.spec.ts` proves that two identifiers differing only in `/` versus `%2F` are
read and updated separately.

## Also in that upgrade

`@elysiajs/static` 1.4.12 mounts `GET /public` beside `GET /public/*`. The bare route is classified
`public` in `lib/consts/route_classification.ts` like the wildcard.
