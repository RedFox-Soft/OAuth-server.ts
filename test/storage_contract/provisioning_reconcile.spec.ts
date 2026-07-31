import { describe, it, expect } from 'bun:test';

import { areaForBucket, areaNamed } from 'lib/consts/storage_inventory.js';
import type { Db } from 'mongodb';
import { ensureCollection } from 'lib/adapters/mongodb/provision.js';
import {
	duplicateEmailReport,
	exitCodeFor,
	missingIndexes,
	staleExpiryIndexes,
	toExistingIndexes,
	type DuplicateEmailRow,
	type ExistingIndex,
	type ProvisioningSummary,
	type RawIndexDescriptor
} from '../../database/reconcile.js';

// The provisioning routine's decisions, tested as pure functions over index descriptors.
//
// Principle III keeps automated tests off MongoDB, so the only way to cover this logic is to keep it
// out of the driver calls: `database/mongodb.ts` asks these functions what to do and then does it.
// Everything genuinely risky about reconciliation lives here — above all that dropping an index must
// be scoped to expiry rules and must never touch an index an operator added deliberately.

const idIndex: ExistingIndex = { name: '_id_', key: { _id: 1 } };

const expiresAtIndex: ExistingIndex = {
	name: 'expiresAt_1',
	key: { expiresAt: 1 },
	expireAfterSeconds: 0
};

// The shared lookup every caller here uses. It throws rather than returning undefined because an
// unknown area name is a programming error, not a runtime condition — and because the `StorageArea |
// undefined` it replaced is what three `as never` casts in the sibling expiry spec existed to silence.
describe('areaNamed', () => {
	it('resolves a declared area by name', () => {
		expect(areaNamed('Session').name).toBe('Session');
		expect(areaNamed('serviceConfig').kind).toBe('store');
	});

	it('throws for a name the inventory does not declare', () => {
		expect(() => areaNamed('NotAnArea')).toThrow('NotAnArea');
	});

	// The per-bucket entry is templated: its inventory name is the prefix, and concrete collections come
	// from areaForBucket. Looking it up by a bucket's collection name must not silently succeed.
	it('throws for a concrete per-bucket collection name', () => {
		expect(() => areaNamed('user_redfox')).toThrow();
	});
});

// The boundary where the datastore's own index descriptors enter this logic. It replaced an
// `as unknown as ExistingIndex[]` — a double assertion, which suppresses every check at exactly the
// point where an external shape arrives.
//
// The nameless case is the substantive one, not a formality: this routine reads indexes in order to
// drop one *by name*, and the driver types `name` as optional. A descriptor without one is not
// actionable and must never reach dropIndex.
describe('toExistingIndexes', () => {
	it('carries through the fields the reconciliation logic reads', () => {
		const raw: RawIndexDescriptor[] = [
			{ name: 'expiresAt_1', key: { expiresAt: 1 }, expireAfterSeconds: 0 },
			{ name: 'email_1', key: { email: 1 }, unique: true },
			{ name: 'payload.grantId_1', key: { 'payload.grantId': 1 } }
		];

		expect(toExistingIndexes(raw)).toEqual([
			{ name: 'expiresAt_1', key: { expiresAt: 1 }, expireAfterSeconds: 0 },
			{ name: 'email_1', key: { email: 1 }, unique: true },
			{ name: 'payload.grantId_1', key: { 'payload.grantId': 1 } }
		]);
	});

	it('drops a descriptor with no name, because it cannot be acted on', () => {
		const raw: RawIndexDescriptor[] = [
			{ key: { expiresAt: 1 }, expireAfterSeconds: 0 },
			{ name: 'email_1', key: { email: 1 }, unique: true }
		];

		expect(toExistingIndexes(raw)).toEqual([
			{ name: 'email_1', key: { email: 1 }, unique: true }
		]);
	});

	it('drops a descriptor whose name is not a string', () => {
		// The assertion is the subject of the test, not a workaround: the type system cannot express
		// "data that violates this very type", and a boundary mapper exists precisely because what the
		// datastore returns is not constrained by our declarations.
		const raw = [
			{ name: 7, key: { expiresAt: 1 } },
			{ name: 'keep_1', key: { keep: 1 } }
		] as unknown as RawIndexDescriptor[];

		expect(toExistingIndexes(raw)).toEqual([
			{ name: 'keep_1', key: { keep: 1 } }
		]);
	});

	it('returns nothing for an empty descriptor list', () => {
		expect(toExistingIndexes([])).toEqual([]);
	});

	// A nameless expiry index must not become a phantom drop target, and must not be mistaken for a
	// satisfied declaration either — dropping it silently from the input is the only safe reading.
	it('makes a nameless expiry index invisible to both decisions', () => {
		const raw: RawIndexDescriptor[] = [
			{ key: { expiresAt: 1 }, expireAfterSeconds: 0 }
		];
		const mapped = toExistingIndexes(raw);

		expect(staleExpiryIndexes(areaNamed('Client'), mapped)).toEqual([]);
		expect(missingIndexes(areaNamed('AccessToken'), mapped)).toContainEqual({
			key: { expiresAt: 1 },
			expireAfterSeconds: 0
		});
	});
});

describe('missingIndexes', () => {
	it('reports every declared index on an unprovisioned area', () => {
		const missing = missingIndexes(areaNamed('Session'), [idIndex]);

		expect(missing).toEqual([
			{ key: { 'payload.uid': 1 }, unique: true },
			{ key: { expiresAt: 1 }, expireAfterSeconds: 0 }
		]);
	});

	it('reports nothing when every declared index is present', () => {
		const existing: ExistingIndex[] = [
			idIndex,
			{ name: 'payload.uid_1', key: { 'payload.uid': 1 }, unique: true },
			expiresAtIndex
		];

		expect(missingIndexes(areaNamed('Session'), existing)).toEqual([]);
	});

	it('reports nothing for an area that declares no index', () => {
		expect(missingIndexes(areaNamed('userBuckets'), [idIndex])).toEqual([]);
		expect(missingIndexes(areaNamed('Client'), [idIndex])).toEqual([]);
	});

	// A non-unique index where a unique one is declared does not satisfy the declaration — this is the
	// case an existing deployment hits if it ever gained a plain email index by hand.
	it('treats an index with the wrong options as missing', () => {
		const existing: ExistingIndex[] = [
			idIndex,
			{ name: 'email_1', key: { email: 1 } }
		];

		expect(missingIndexes(areaForBucket('abc'), existing)).toEqual([
			{ key: { email: 1 }, unique: true }
		]);
	});

	it('ignores unrelated indexes when deciding what is missing', () => {
		const existing: ExistingIndex[] = [
			idIndex,
			{ name: 'operator_hand_rolled', key: { 'payload.accountId': 1 } },
			expiresAtIndex,
			{ name: 'payload.uid_1', key: { 'payload.uid': 1 }, unique: true }
		];

		expect(missingIndexes(areaNamed('Session'), existing)).toEqual([]);
	});
});

describe('staleExpiryIndexes', () => {
	// The reason the subtractive half of reconciliation exists: earlier versions applied an expiry
	// index to every area they did not otherwise recognise, including three that hold permanent
	// records. Inert while those areas never write `expiresAt`, and silent data loss the moment one
	// does.
	it('drops an expiry index from an area that holds permanent records', () => {
		const stale = staleExpiryIndexes(areaNamed('Client'), [
			idIndex,
			expiresAtIndex
		]);

		expect(stale).toEqual(['expiresAt_1']);
	});

	it('keeps a declared expiry index', () => {
		expect(
			staleExpiryIndexes(areaNamed('AccessToken'), [idIndex, expiresAtIndex])
		).toEqual([]);
	});

	// The narrowing that makes this safe. An index the inventory does not declare may be an
	// operator's deliberate performance addition; only expiry rules are ours to remove, because
	// removing one cannot lose a record and nothing here queries by the expiry field.
	it('never drops a non-expiry index it does not recognise', () => {
		const stale = staleExpiryIndexes(areaNamed('Client'), [
			idIndex,
			{ name: 'payload.clientName_1', key: { 'payload.clientName': 1 } },
			{ name: 'payload.sector_1', key: { 'payload.sectorIdentifier': 1 } }
		]);

		expect(stale).toEqual([]);
	});

	// Same key, different lifetime: MongoDB refuses to re-create an index with conflicting options,
	// so the wrong one has to go before the right one can be created.
	it('drops an expiry index whose lifetime disagrees with the declaration', () => {
		const stale = staleExpiryIndexes(areaNamed('AccessToken'), [
			idIndex,
			{
				name: 'expiresAt_1',
				key: { expiresAt: 1 },
				expireAfterSeconds: 3600
			}
		]);

		expect(stale).toEqual(['expiresAt_1']);
	});

	it('drops an expiry index keyed on a field the area does not expire on', () => {
		const stale = staleExpiryIndexes(areaNamed('AccessToken'), [
			idIndex,
			expiresAtIndex,
			{ name: 'createdAt_1', key: { createdAt: 1 }, expireAfterSeconds: 90 }
		]);

		expect(stale).toEqual(['createdAt_1']);
	});

	it('never drops the _id index', () => {
		const stale = staleExpiryIndexes(areaNamed('Client'), [
			{ name: '_id_', key: { _id: 1 }, expireAfterSeconds: 0 }
		]);

		expect(stale).toEqual([]);
	});

	it('reports nothing on an area with no indexes yet', () => {
		expect(staleExpiryIndexes(areaNamed('VerificationChallenge'), [])).toEqual(
			[]
		);
	});

	it('leaves a per-bucket user area alone when it is correctly constrained', () => {
		const existing: ExistingIndex[] = [
			idIndex,
			{ name: 'email_1', key: { email: 1 }, unique: true }
		];

		expect(staleExpiryIndexes(areaForBucket('abc'), existing)).toEqual([]);
		expect(missingIndexes(areaForBucket('abc'), existing)).toEqual([]);
	});
});

// A unique index cannot be created over data that already violates it. Only the race this feature
// closes can have produced such data, so the deployments most likely to hit this are the ones that
// have been running unprotected the longest — which is exactly when a clear report matters.
describe('duplicateEmailReport', () => {
	it('reports nothing when a bucket has no duplicates', () => {
		expect(duplicateEmailReport('redfox', [])).toBeNull();
	});

	it('names the bucket and every conflicting address', () => {
		const rows: DuplicateEmailRow[] = [
			{ _id: 'clash@example.com', count: 2 },
			{ _id: 'other@example.com', count: 3 }
		];

		const report = duplicateEmailReport('dupcheck', rows);

		expect(report).toContain('dupcheck');
		expect(report).toContain('clash@example.com');
		expect(report).toContain('other@example.com');
	});

	// The operator has to know the index was not applied, not merely that duplicates exist — an
	// unenforced constraint reported as a warning reads as cosmetic.
	it('says the uniqueness constraint was skipped', () => {
		const report = duplicateEmailReport('redfox', [
			{ _id: 'clash@example.com', count: 2 }
		]);

		expect(report?.toLowerCase()).toContain('skipped');
		expect(report?.toLowerCase()).toContain('email');
	});

	it('reports the multiplicity so the operator knows how much to clean up', () => {
		const report = duplicateEmailReport('redfox', [
			{ _id: 'clash@example.com', count: 4 }
		]);

		expect(report).toContain('4');
	});
});

// The exit code is the whole of this routine's machine-readable contract: a deployment pipeline reads
// it and nothing else. The distinction it has to carry is "complete" versus "complete but
// incomplete-by-data" — never "nothing happened".
describe('exitCodeFor', () => {
	const clean: ProvisioningSummary = {
		collectionsCreated: 0,
		indexesCreated: 0,
		indexesDropped: 0,
		bucketsProcessed: 2,
		constraintsSkipped: 0
	};

	it('succeeds when nothing needed doing', () => {
		expect(exitCodeFor(clean)).toBe(0);
	});

	// Doing work is the normal first run, not a failure.
	it('succeeds when it provisioned and reconciled', () => {
		expect(
			exitCodeFor({
				...clean,
				collectionsCreated: 22,
				indexesCreated: 31,
				indexesDropped: 3
			})
		).toBe(0);
	});

	it('fails when a constraint could not be applied', () => {
		expect(exitCodeFor({ ...clean, constraintsSkipped: 1 })).toBe(1);
	});

	it('fails on a skipped constraint even when everything else succeeded', () => {
		expect(
			exitCodeFor({
				...clean,
				collectionsCreated: 22,
				indexesCreated: 30,
				constraintsSkipped: 2
			})
		).toBe(1);
	});
});

// Regression: MongoDB's `create` command is idempotent when the options match, so createCollection
// returns ok for a collection that already exists. Inferring "I created it" from the absence of a
// throw made every re-run report all 24 collections as freshly created — found by running the routine
// twice against a real database, not by reading the driver docs. Existence has to be asked, not
// deduced.
describe('ensureCollection', () => {
	// A Db stub, so the behaviour is pinned without a database. Only the three members
	// ensureCollection touches are implemented, hence the narrow cast.
	function fakeDb(present: string[]) {
		const created: string[] = [];
		const db = {
			listCollections: (filter: { name: string }) => ({
				hasNext: async () => present.includes(filter.name)
			}),
			createCollection: async (name: string) => {
				// Deliberately succeeds even when the collection exists — what the real server does.
				created.push(name);
				if (!present.includes(name)) {
					present.push(name);
				}
			}
		} as unknown as Db;
		return { db, created };
	}

	it('creates a collection that does not exist and reports it', async () => {
		const { db, created } = fakeDb([]);

		expect(await ensureCollection(db, 'VerificationChallenge')).toBeTrue();
		expect(created).toEqual(['VerificationChallenge']);
	});

	it('reports no work for a collection that already exists', async () => {
		const { db, created } = fakeDb(['AccessToken']);

		expect(await ensureCollection(db, 'AccessToken')).toBeFalse();
		// Not merely "returned false": it must not issue the create at all, or a re-run against a
		// server whose `create` is idempotent looks identical to a first run.
		expect(created).toEqual([]);
	});

	it('is idempotent across repeated runs', async () => {
		const { db } = fakeDb([]);

		expect(await ensureCollection(db, 'serviceConfig')).toBeTrue();
		expect(await ensureCollection(db, 'serviceConfig')).toBeFalse();
		expect(await ensureCollection(db, 'serviceConfig')).toBeFalse();
	});
});
