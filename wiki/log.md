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

## [2026-08-27] ingest | TOTP second factor (spec 027): new concept page on the bucket-level second factor — why the algorithm is in-repo (published RFC vectors beat a dependency), why the bucket field is a boolean beside `passwordLogin` rather than an enum replacing it, and the four state placements that buy deletion integrity, expiry, un-guessable enrolment and a cross-interaction throttle. Records two incidental findings: `Interaction.persist()` has never been able to succeed, and the Mongo user store's `$set`-only patch could not clear a field.

## [2026-08-27] update | Admin bucket second factor: `totp-second-factor` gains the administrator-bucket section — why the reserved bucket needed its own endpoint (`assertNotReserved` refuses it on the generic routes and its 403 names `/admin/api/admins`), and why that endpoint carries one field. Records the `emailVerificationRequired` console brick: both admin-creation paths write `verified: false` and no verification mail is ever sent for this bucket, so the flag would refuse every administrator with no way back.

## [2026-08-29] ingest | Group ownership (spec 033): new concept page on the ownership model that replaced `managedBy: string[]` — a group owns every project and bucket and belonging to it is the only thing that grants access, with a personal group per account so ownership has a single mechanism and sharing personal work is adding a member rather than a transfer. Records why owner-vs-member is a property of the membership and not a role on the account, why the active scope is server-held and re-validated per request, and the migration rule that groups by *identical* manager set — `{A,B}` and `{A,C}` must not merge, which would be a cross-tenant leak created by the migration itself. Three incidental findings: a foreign container answered 403 while a nonexistent one answered 404, handing out an existence oracle over every id; the permanent-owner rule for a personal group was never enforced, because the last-owner check does not fire once a second owner exists; and bucket listing disagreed with bucket access, so a bucket you could administer never appeared. Updates `admin-audit-trail` (the read is group-scoped, not super-admin only), `admin-mcp-control-plane` (`group_delete` is the third withholding, invitation acceptance the third inapplicable) and `admin-console-signin` (the session carries the active scope).

## [2026-09-01] graph | Four subsystem entity pages written to resolve dangling typed edges: [[html-rendering]], [[elysia-lifecycle]], [[addon-registry]] and [[admin-console]] were referenced by `depends_on` edges on five concept pages but had never been created, so the graph carried five edges pointing at nodes that did not resolve. Each page is grounded in the code it documents — the single-`htmlResponse` guarantee and why it is deliberately not a lifecycle plugin; the callback-shaped hooks whose mount order in `lib/index.ts` is a correctness constraint rather than an optimisation; the call-time `resolve()` seam whose type-only imports keep the model graph out of the test preload; and the `routes.ts`/`index.ts` split that gives the MCP plane one definition of the admin API. Ontology gains two predicates, `complements` and `constrained_by`, which two existing evidence-backed edges already used without declaring.
