# Wiki Log

Append-only chronological record of operations on the wiki. Each entry begins with `## [YYYY-MM-DD] <op> | <description>` so it's parseable with `grep "^## \[" log.md | tail -N`.

Operations:
- `ingest` — a source was processed into the wiki.
- `query` — a question was answered against the wiki (typically only logged when the answer was filed back as synthesis).
- `lint` — a health check was run.
- `schema` — the schema was modified.
- `shard` — an index was sharded.

---

## [2026-07-31] schema | Fixed script invocation (wiki/bin/wiki.py launcher), recorded codebase-as-source and transient-artifact rules, added `subsystem` node type and `implements` predicate to the ontology.

## [2026-07-31] ingest | OAuth server codebase (lib/) at commit 2125ad0 — first real ingest. Pilot pass: 1 source page + 5 pages on durable subsystem contracts (token payload access, client identity, account resolution, feature-flag gating, eventBus).

## [2026-08-27] ingest | Admin console sign-out fix: new page on cookie Path identity (`remove()` omits Path); `admin-console-signin` gains the sign-out half — two sessions, and why not RP-initiated logout.
