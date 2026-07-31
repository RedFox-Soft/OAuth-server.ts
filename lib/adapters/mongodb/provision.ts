import type { Db } from 'mongodb';
import {
	areaForBucket,
	indexesFor,
	type IndexSpec
} from '../../consts/storage_inventory.js';

/*
 * Applying the inventory to a database. Shared by the operator routine (database/mongodb.ts, which
 * opens its own one-shot connection) and by UserBucketStore.create, which provisions a bucket's
 * end-user collection the moment the bucket is created through the admin control plane.
 *
 * Both callers pass their own `Db` rather than this module importing ./db.js: the script deliberately
 * avoids opening a second connection, and a type-only import of the driver keeps this file loadable
 * without MONGODB_URI.
 *
 * A bucket created at runtime needs this as much as one that existed at setup time — a
 * setup-script-only fix would leave every later bucket with an unconstrained user collection, which
 * is precisely the hole that made the duplicate-registration race reachable.
 */

/* MongoDB error codes. Re-creating a collection or an identical index is the normal case on any run
 * after the first, so neither is fatal. */
const NAMESPACE_EXISTS = 48;
const INDEX_OPTIONS_CONFLICT = 85;
const INDEX_KEY_SPECS_CONFLICT = 86;

function codeOf(error: unknown): number | undefined {
	return typeof error === 'object' && error !== null
		? (error as { code?: number }).code
		: undefined;
}

export function isNamespaceExists(error: unknown): boolean {
	return codeOf(error) === NAMESPACE_EXISTS;
}

/*
 * An index with this key already exists with different options. Reported rather than resolved: the
 * fix would be dropping an index the inventory does not describe, and only expiry indexes are ours to
 * drop.
 */
export function isIndexConflict(error: unknown): boolean {
	const code = codeOf(error);
	return code === INDEX_OPTIONS_CONFLICT || code === INDEX_KEY_SPECS_CONFLICT;
}

export async function collectionExists(
	target: Db,
	name: string
): Promise<boolean> {
	return target.listCollections({ name }, { nameOnly: true }).hasNext();
}

/*
 * Returns whether the collection had to be created, so callers can report only real work.
 *
 * Existence is checked explicitly rather than inferred from createCollection throwing: MongoDB's
 * `create` is idempotent when the options match, so it returns ok for a collection that already
 * exists. Trusting it made a re-run report every collection as freshly created — measured, not
 * assumed. The NamespaceExists catch stays as the race guard it always was, for two runs at once.
 */
export async function ensureCollection(
	target: Db,
	name: string
): Promise<boolean> {
	if (await collectionExists(target, name)) {
		return false;
	}
	try {
		await target.createCollection(name);
		return true;
	} catch (error) {
		if (!isNamespaceExists(error)) {
			throw error;
		}
		return false;
	}
}

export interface AppliedIndexes {
	readonly created: IndexSpec[];
	/* Declared but not applied, because an incompatible index of the same key is already there. */
	readonly conflicted: IndexSpec[];
}

/*
 * Applied one at a time rather than as a batch so a single conflict cannot block the other
 * constraints on the same collection, and so the report names exactly which one was refused.
 */
export async function applyIndexes(
	target: Db,
	name: string,
	specs: readonly IndexSpec[]
): Promise<AppliedIndexes> {
	const created: IndexSpec[] = [];
	const conflicted: IndexSpec[] = [];

	for (const spec of specs) {
		try {
			await target.collection(name).createIndex(spec.key, {
				...(spec.unique === true ? { unique: true } : {}),
				...(spec.expireAfterSeconds !== undefined
					? { expireAfterSeconds: spec.expireAfterSeconds }
					: {})
			});
			created.push(spec);
		} catch (error) {
			if (!isIndexConflict(error)) {
				throw error;
			}
			conflicted.push(spec);
		}
	}

	return { created, conflicted };
}

/*
 * Provision one bucket's end-user collection with the constraints the inventory declares for it —
 * today a unique index on the stored (already lower-cased) email, which is what makes two concurrent
 * registrations of one address unwinnable rather than merely unlikely.
 */
export async function provisionUserArea(
	target: Db,
	bucketId: string
): Promise<AppliedIndexes> {
	const area = areaForBucket(bucketId);
	await ensureCollection(target, area.name);
	return applyIndexes(target, area.name, indexesFor(area));
}
