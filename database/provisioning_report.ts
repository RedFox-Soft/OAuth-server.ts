/*
 * What provisioning reports, for any backend.
 *
 * Split out of `database/reconcile.ts` when the PostgreSQL applier arrived, and the split line is
 * worth stating because the obvious guess is wrong. The *comparison* in reconcile.ts cannot be
 * shared: it describes an index as MongoDB reports one — a key document plus `expireAfterSeconds` —
 * while PostgreSQL reports a definition string, an access method and a predicate, and has no expiry
 * index at all, so `staleExpiryIndexes` has no counterpart there by construction rather than by
 * omission.
 *
 * What genuinely is shared is everything below: how a run is counted, what its exit code means, and
 * the operator-facing account of a constraint that could not be applied. Those are policy, not
 * driver detail, and two backends disagreeing about any of them would be a defect.
 *
 * Pure by the same rule reconcile.ts is: no driver import, no connection, so both appliers' decisions
 * stay checkable in the default test run.
 */

export interface ProvisioningSummary {
	collectionsCreated: number;
	indexesCreated: number;
	indexesDropped: number;
	bucketsProcessed: number;
	/* Declared constraints the routine could not apply, because existing data or an existing index
	 * conflicts with them. The only thing that makes a completed run a failed one. */
	constraintsSkipped: number;
}

/*
 * The routine's exit status, decided in one place.
 *
 * Non-zero means "provisioning ran to completion but at least one declared constraint is not in
 * force" — the operator has data to fix and a re-run to do. It deliberately does not mean "nothing
 * happened": creating collections, creating indexes and dropping stale expiry rules are all ordinary
 * work and exit 0. A deployment pipeline reads this and nothing else, so conflating the two would
 * either cry wolf on every first run or hide an unenforced uniqueness constraint.
 */
export function exitCodeFor(summary: ProvisioningSummary): 0 | 1 {
	return summary.constraintsSkipped > 0 ? 1 : 0;
}

/*
 * One duplicated address in a bucket.
 *
 * `value` rather than `_id`: MongoDB's `$group` names the grouped key `_id` and PostgreSQL's
 * `GROUP BY` names it after the column, so neither name belongs in a shared type. Each backend
 * projects into this shape at the point it runs the query, which is where it knows what it produced.
 */
export interface DuplicateEmailRow {
	readonly value: string;
	readonly count: number;
}

/*
 * The operator-facing account of why a bucket's uniqueness constraint could not be applied.
 *
 * Pre-checking rather than letting index creation fail is what makes this actionable: a driver's
 * duplicate-key error names one offending value, aborting the run and saying nothing about the rest.
 * Resolving the conflict is deliberately left to the operator — deleting a record is forbidden here,
 * and choosing which of two accounts survives is a product decision, not a script's.
 *
 * Shared verbatim between backends on purpose. An operator who moves a deployment should read the
 * same sentence about the same data, and a message reimplemented per backend is a message that
 * drifts.
 */
export function duplicateEmailReport(
	bucketId: string,
	rows: readonly DuplicateEmailRow[]
): string | null {
	if (rows.length === 0) {
		return null;
	}

	const conflicts = rows
		.map((row) => `  ${row.value} (${row.count} accounts)`)
		.join('\n');

	return (
		`bucket ${bucketId}: skipped the unique email constraint — ` +
		`${rows.length} address(es) are already duplicated:\n${conflicts}\n` +
		'  resolve these and re-run; no records were changed.'
	);
}
