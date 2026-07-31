---
type: source
title: "OAuth server codebase (lib/)"
tags: [architecture, oauth, oidc]
authors: [Anton Shchekota]
url: null
raw: lib/
ingested: 2026-07-31
created: 2026-07-31
updated: 2026-07-31
revision: 2125ad02c4c178eea0df357287b5ac1bfb8dbb23
---

# OAuth server codebase (lib/)

The tracked source tree of this repository, read at commit `2125ad0` (2026-07-31,
`feat(cors): serve browser-based clients cross-origin`). It is the source of record for every
non-source page in this wiki: an OAuth 2.1 / OpenID Connect authorization server written in
TypeScript on Bun and Elysia, descended from `oidc-provider` but no longer structured like it.

Unlike a paper or an article, this source is mutable — it changes with every commit. Pages drawn
from it therefore cite exact `file:line` locations and record the revision they were verified
against, so a later reader can tell whether a claim still holds rather than trusting the wiki's
word for it.

## Why the codebase is the source rather than the planning documents

`TASKS.md` and `specs/` describe intended work, not the server that exists: they are scratch
artifacts that get deleted or rewritten, and `specs/` is not committed. Ingesting them would fill
the wiki with claims whose sources vanish — the silent-corruption failure mode. Only committed
code and committed documentation are treated as ingestable here.

## Shape of the tree

- `lib/actions/` — endpoint behaviour: `authorization/`, `grants/`, `userinfo.ts`, `registration.ts`.
- `lib/models/` — persisted protocol objects (tokens, codes, sessions, grants) plus
  `models/mixins/` and `models/formats/`. See [[token-payload-access-contract]].
- `lib/models/client/` — client validation, secrets, checks, sector identifiers. See
  [[client-identity-from-database]].
- `lib/configs/` — `application.ts` (settings), `configuration.ts` (derived + validated),
  `keys.ts`/`keystore.ts` (signing keys). See [[feature-flag-gating]].
- `lib/plugins/` — Elysia lifecycle plugins, including `featureGate.ts` and `cors.ts`.
- `lib/consts/route_classification.ts` — the route/flag table the gate and CORS both read.
- `lib/adapters/` — persistence (`mongodb/`, `memory/`).
- `lib/admin/` — the admin plane: buckets, clients, projects, users, JWKS, settings, audit, UI.
- `lib/addon/` — deployment-facing resolvers such as `account.ts`. See [[account-resolution]].
- `lib/event_bus.ts` — the lifecycle event emitter. See [[event-bus]].

## Documentary quality of the source

The code carries unusually long explanatory comments that record *why* a structure is the way it
is, often naming the failure that forced it (an initialisation cycle, a stale-metadata window, a
lifecycle ordering trap). Those comments, and the commit messages, are the highest-value material
in this source: they capture reasoning that cannot be re-derived by reading the code's control
flow. Where a page below states a rationale, it is drawn from one of them rather than inferred.

## Where this fits

- [[token-payload-access-contract]]
- [[client-identity-from-database]]
- [[account-resolution]]
- [[feature-flag-gating]]
- [[event-bus]]
