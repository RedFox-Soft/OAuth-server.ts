import {
	indexesFor,
	type IndexSpec,
	type StorageArea
} from '../lib/consts/storage_inventory.js';

/*
 * The provisioning routine's decisions, as pure functions over index descriptors.
 *
 * Kept out of the driver calls on purpose. Automated tests may not reach MongoDB (constitution
 * Principle III), so logic embedded in `db.collection(...).createIndexes(...)` would be verifiable
 * only by hand. Everything here takes plain descriptors and returns plain data, which is what lets
 * test/storage_contract/provisioning_reconcile.spec.ts cover the risky parts —
 * above all which indexes may be dropped.
 */

/* One index as MongoDB reports it, once it is known to be actionable. */
export interface ExistingIndex {
	readonly name: string;
	readonly key: Readonly<Record<string, unknown>>;
	readonly unique?: boolean;
	readonly expireAfterSeconds?: number;
}

/*
 * An index descriptor as it arrives from the datastore, before anything is known about it. Described
 * structurally rather than by importing the driver's `IndexDescriptionInfo`: that type is assignable to
 * this one, so the call site needs no conversion, and this module stays free of any driver import — it
 * is pure decision logic, and coupling it to the driver would make it untestable the moment the driver
 * needed a connection to load.
 *
 * `name` is optional here because the driver declares it optional, which is the whole reason a mapper
 * exists rather than an assertion.
 */
export interface RawIndexDescriptor {
	readonly name?: string;
	readonly key: Readonly<Record<string, unknown>>;
	readonly unique?: boolean;
	readonly expireAfterSeconds?: number;
}

/*
 * Narrow raw descriptors to the ones this routine can act on, keeping only the four fields the
 * decisions below read.
 *
 * A descriptor with no name (or a non-string one) is dropped. Every action available here — dropping a
 * stale expiry index — addresses an index *by name*, so a nameless one cannot be acted on; passing it
 * through would make `dropIndex(undefined)` reachable. Dropping it also correctly leaves it unable to
 * satisfy a declaration, so a nameless expiry index causes the declared one to be created rather than
 * being mistaken for it.
 *
 * This replaced `as unknown as ExistingIndex[]` at the call site. The assertion claimed the driver's
 * shape matched this one; it does not, and that difference is exactly what needed handling.
 */
export function toExistingIndexes(
	raw: readonly RawIndexDescriptor[]
): ExistingIndex[] {
	const actionable: ExistingIndex[] = [];
	for (const descriptor of raw) {
		if (typeof descriptor.name !== 'string') {
			continue;
		}
		actionable.push({
			name: descriptor.name,
			key: descriptor.key,
			...(descriptor.unique !== undefined ? { unique: descriptor.unique } : {}),
			...(descriptor.expireAfterSeconds !== undefined
				? { expireAfterSeconds: descriptor.expireAfterSeconds }
				: {})
		});
	}
	return actionable;
}

/* MongoDB's mandatory primary-key index. Never ours to touch. */
const ID_INDEX = '_id_';

function sameKey(
	declared: Readonly<Record<string, unknown>>,
	existing: Readonly<Record<string, unknown>>
): boolean {
	const declaredEntries = Object.entries(declared);
	const existingEntries = Object.entries(existing);
	if (declaredEntries.length !== existingEntries.length) {
		return false;
	}
	// Order-sensitive, because a compound index on (a, b) is not the index on (b, a).
	return declaredEntries.every(([field, direction], i) => {
		const actual = existingEntries[i];
		return (
			actual !== undefined && actual[0] === field && actual[1] === direction
		);
	});
}

function satisfies(declared: IndexSpec, existing: ExistingIndex): boolean {
	return (
		sameKey(declared.key, existing.key) &&
		(declared.unique ?? false) === (existing.unique ?? false) &&
		(declared.expireAfterSeconds ?? null) ===
			(existing.expireAfterSeconds ?? null)
	);
}

/*
 * Declared indexes the area does not already carry. An index present with different options does not
 * satisfy the declaration and is reported as missing — a non-unique `email` index where a unique one
 * is declared enforces nothing.
 */
export function missingIndexes(
	area: StorageArea,
	existing: readonly ExistingIndex[]
): IndexSpec[] {
	return indexesFor(area).filter(
		(declared) => !existing.some((index) => satisfies(declared, index))
	);
}

/*
 * Expiry indexes present on the area that the inventory does not declare — the only indexes this
 * routine will ever drop.
 *
 * Selected by capability (an index that expires documents), never by "not in the inventory". An
 * unrecognised ordinary index may be an operator's deliberate addition, and dropping it would
 * override their intent for no gain. An unrecognised *expiry* index is different in kind: it deletes
 * records on a schedule nobody declared, so leaving it is the greater risk — and removing one cannot
 * lose a record, nor change a query plan, because nothing in this codebase queries by an expiry
 * field.
 *
 * A declared key with a different lifetime counts as stale too: MongoDB refuses to re-create an index
 * whose options conflict with an existing one of the same key, so the wrong one has to go first.
 */
export function staleExpiryIndexes(
	area: StorageArea,
	existing: readonly ExistingIndex[]
): string[] {
	const declared = indexesFor(area);

	return existing
		.filter(
			(index) =>
				index.name !== ID_INDEX &&
				index.expireAfterSeconds !== undefined &&
				!declared.some((spec) => satisfies(spec, index))
		)
		.map((index) => index.name);
}

/* One duplicated address in a bucket, as a $group/$match aggregation reports it. */
export interface DuplicateEmailRow {
	readonly _id: string;
	readonly count: number;
}

/*
 * The operator-facing account of why a bucket's uniqueness constraint could not be applied.
 *
 * Pre-checking rather than letting createIndex fail is what makes this actionable: the driver's
 * duplicate-key error names one offending value, aborting the run and saying nothing about the rest.
 * Resolving the conflict is deliberately left to the operator — deleting a record is forbidden here,
 * and choosing which of two accounts survives is a product decision, not a script's.
 */
export function duplicateEmailReport(
	bucketId: string,
	rows: readonly DuplicateEmailRow[]
): string | null {
	if (rows.length === 0) {
		return null;
	}

	const conflicts = rows
		.map((row) => `  ${row._id} (${row.count} accounts)`)
		.join('\n');

	return (
		`bucket ${bucketId}: skipped the unique email constraint — ` +
		`${rows.length} address(es) are already duplicated:\n${conflicts}\n` +
		'  resolve these and re-run; no records were changed.'
	);
}

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
