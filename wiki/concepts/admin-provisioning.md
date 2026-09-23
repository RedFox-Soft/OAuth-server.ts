---
type: concept
title: "Admin provisioning: seeded by a script, never at boot"
tags: [architecture, config, gotcha]
sources: [oauth-server-codebase]
created: 2026-09-23
updated: 2026-09-23
---

# Admin provisioning

The records the console needs to exist — the reserved admin project, the "Administrators" bucket, the
first-party `admin-panel` OAuth client, the default bucket and the `unassigned` system group — are
written by the provisioning scripts, **not at boot**. There is no boot-time seeding, so console login
requires a database-backed, provisioned deployment.

- **MongoDB**: `bun run db:setup` (`database/mongodb.ts`) writes raw documents with `$setOnInsert`,
  because a one-shot script deliberately avoids the application's module graph.
- **PostgreSQL**: `bun run db:setup:pg` (`database/postgres.ts`) calls `ensureAdminSeed` through a
  deferred import at the very end, since `lib/admin/seed.ts` reaches the model graph, which reads the
  persisted configuration as it loads.
- **Tests** call `ensureAdminSeed` (`lib/admin/seed.ts:34`) directly, against the in-memory adapter.

Both scripts are idempotent and must be **re-run after upgrading** an existing install; that is how a
new seeded record reaches a deployment that already exists.

## The values are declared once

`lib/consts/admin_seed.ts` holds the values every seeder writes. The mechanisms legitimately differ; the
values must not, and they used to be written out twice with a comment on each asking the next author to
remember the other. That arrangement failed silently: a change made to one seeder and not the other
no-ops in production while the suite stays green, because the suite runs the copy production never
does. Change a seeded value in `admin_seed.ts`, never in a seeder.

One seeded value worth knowing: the reserved admin bucket is `registrationOpen: false`
(`lib/consts/admin_seed.ts:60`), while the default bucket is open. See [[end-user-onboarding]].

The first administrator account is **not** seeded; it is created by first-run setup — see
[[first-run-setup-had-two-surfaces]].

## Related

- [[group-ownership]] — the `unassigned` group the seed creates, and what it holds
- [[signing-keys]] — the initial key the same scripts provision
- [[postgresql-backend]] — why the PostgreSQL script can reuse the store path and MongoDB's cannot
