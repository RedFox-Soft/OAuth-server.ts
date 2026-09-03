---
type: concept
title: 'The error store is not flag-gated (and the agent purge cannot be)'
tags: [architecture, gotcha, config]
sources: [oauth-server-codebase]
created: 2026-08-26
updated: 2026-08-26
graph:
  node_type: concept
  relationships:
    - predicate: constrained_by
      object: concept:admin-mcp-control-plane
      source: oauth-server-codebase
      evidence: "lib/consts/route_classification.ts:139 states the omission as a decision, not an oversight: 'The error store read surface is deliberately NOT here, though errorStore.enabled exists and it would be mechanically possible'. lib/mcp/catalogue.ts:1017 withholds the purge instead."
      confidence: high
      status: current
---

# The error store is not flag-gated (and the agent purge cannot be)

`errorStore.enabled` governs **writes only**. Its read surface at `/admin/api/errors` is deliberately
absent from `gatedRoutes`, and an agent's ability to purge is not configurable at all. Both fall out of
one invariant of the admin/MCP control plane, and both were discovered by building the opposite first.

## The invariant

The admin operation set does not vary with capability switches. `/admin` is an
`alwaysAvailablePrefixes` entry in `lib/consts/route_classification.ts`, and the table's own comment
names the deciding case: a federation provider must stay deletable by a deployment that has just
switched federation off.

Two guards hold it, and they are worth knowing before touching the MCP surface:

- `test/mcp/capability_invariance.spec.ts` compares the published tool list across flag configurations;
- the same file asserts `lib/mcp/server.ts` contains **no capability-flag read at all**.

## Gating an admin route also splits the two surfaces

`gatedFlagForRequest` consults only `gatedRoutes`, matching exactly on (method, path) — so an exact
`/admin/...` entry *does* win over the prefix, and gating an admin path looks like it works. It does
not: `lib/mcp/dispatch.ts` re-dispatches agent calls into `adminApiRoutes` **without** the `featureGate`
plugin, so the console answered 404 while an agent answered 403 for the identical call. Five MCP specs
caught it.

The capability is reported in the payload instead: `recording: false` on the listing and summary. That
keeps "nothing is being recorded" distinguishable from "nothing has failed" — an empty page alone
asserts the second while meaning the first, which on a diagnostic surface is the one lie that matters.

## The agent purge is withheld, not opt-in

Specification 025 asked for agent purging to be an operator opt-in. It cannot be. A conditionally
registered tool fails the first guard; a tool that reads the flag in its body fails the second by
construction. So `DELETE /admin/api/errors` is an unconditional entry in `excludedConsoleOperations`,
alongside project and bucket deletion, and `error_purge_preview` is published so an agent can still
report what a purge would remove without performing one.

There is no `errorStore.mcpPurgeEnabled`. It was removed rather than left inert: a setting that does
nothing is worse than its absence.

## Related

- [[error-store-capture-sites]] — where faults are recorded, and why in two places
- [[feature-flag-gating]] — the gate this capability deliberately does not use
- [[admin-mcp-control-plane]] — the invariance requirement and the withheld-operations mechanism
- [[admin-plane-error-shape]] — the shape the read surface refuses in
