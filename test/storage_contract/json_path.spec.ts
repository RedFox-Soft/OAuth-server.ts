import { describe, it, expect } from 'bun:test';

import {
	FIXED_AREAS,
	PER_BUCKET_AREA,
	indexesFor,
	type StorageArea
} from 'lib/consts/storage_inventory.js';
import {
	columnFor,
	jsonPath,
	translateIndex
} from 'lib/adapters/postgres/jsonPath.js';

/*
 * The translation from a declared MongoDB index key to a PostgreSQL index.
 *
 * Pure arithmetic on values the inventory already declares, so it belongs in the default run rather
 * than in the local-instance verification — Principle III's second condition forbids moving coverage
 * a database-free test can provide into the tier that needs a database.
 *
 * What makes this worth pinning row by row: getting a key wrong does not fail, it degrades. A scalar
 * expression where a containment index belongs turns a lookup into a sequential scan, and nothing but
 * a slow query ever says so.
 */

/**
 * @proves Every declared field and index translates to a PostgreSQL expression that actually
 * addresses the stored document, quoted so a field name cannot close the literal.
 */
describe('jsonPath', () => {
	describe('reserved keys that are real columns, not JSON', () => {
		it('maps expiresAt to the expires_at column', () => {
			expect(jsonPath('payload', 'expiresAt')).toBe('expires_at');
			// Reserved regardless of which document column the area uses.
			expect(jsonPath('doc', 'expiresAt')).toBe('expires_at');
		});

		it('maps _id to the id column', () => {
			expect(jsonPath('doc', '_id')).toBe('id');
			expect(jsonPath('payload', '_id')).toBe('id');
		});
	});

	describe('model areas, whose declared keys carry the column as a prefix', () => {
		it('drops the payload prefix rather than nesting under it', () => {
			expect(jsonPath('payload', 'payload.grantId')).toBe(
				"(payload->>'grantId')"
			);
			expect(jsonPath('payload', 'payload.userCode')).toBe(
				"(payload->>'userCode')"
			);
		});

		it('handles the owner fields indexesFor derives', () => {
			expect(jsonPath('payload', 'payload.accountId')).toBe(
				"(payload->>'accountId')"
			);
			expect(jsonPath('payload', 'payload.clientId')).toBe(
				"(payload->>'clientId')"
			);
		});
	});

	describe('store and per-bucket areas, whose keys are bare', () => {
		it('addresses a top-level field of the document column', () => {
			expect(jsonPath('doc', 'email')).toBe("(doc->>'email')");
			expect(jsonPath('doc', 'fingerprint')).toBe("(doc->>'fingerprint')");
		});

		it('walks a dotted path with -> and extracts the leaf with ->>', () => {
			expect(jsonPath('doc', 'federated.providerId')).toBe(
				"(doc->'federated'->>'providerId')"
			);
			expect(jsonPath('doc', 'samples.clientId')).toBe(
				"(doc->'samples'->>'clientId')"
			);
		});
	});

	it('quotes defensively, so a field name can never close the literal', () => {
		// Field names come from the inventory and the drift guard proves they are plain identifiers,
		// so this cannot arise today. Asserted anyway: the guarantee lives in another file, and a
		// translation that relied on it silently would be one refactor away from an injection.
		expect(() => jsonPath('doc', "ev'il")).toThrow(/identifier/i);
		expect(() => jsonPath('doc', 'has space')).toThrow(/identifier/i);
		expect(() => jsonPath('doc', '')).toThrow(/identifier/i);
	});
});

describe('columnFor', () => {
	it('gives model areas the payload column their declared keys already name', () => {
		expect(columnFor({ kind: 'model' } as StorageArea)).toBe('payload');
	});

	it('gives store and per-bucket areas the doc column', () => {
		expect(columnFor({ kind: 'store' } as StorageArea)).toBe('doc');
		expect(columnFor({ kind: 'perBucket' } as StorageArea)).toBe('doc');
	});
});

describe('translateIndex', () => {
	it('builds a plain b-tree expression index', () => {
		expect(
			translateIndex('payload', { key: { 'payload.grantId': 1 } })
		).toEqual({
			method: 'btree',
			columns: ["(payload->>'grantId')"],
			unique: false
		});
	});

	it('carries uniqueness through', () => {
		expect(
			translateIndex('payload', {
				key: { 'payload.userCode': 1 },
				unique: true
			})
		).toEqual({
			method: 'btree',
			columns: ["(payload->>'userCode')"],
			unique: true
		});
	});

	it('keeps a composite key in its declared order', () => {
		// Order is the whole value of a composite index; reversing it serves a different query.
		expect(translateIndex('doc', { key: { lastSeenAt: 1, _id: 1 } })).toEqual({
			method: 'btree',
			columns: ["(doc->>'lastSeenAt')", 'id'],
			unique: false
		});
	});

	it('makes an expiry index partial, so it covers only rows that can expire', () => {
		// Two areas hold expiring and permanent records side by side by design
		// (InitialAccessToken, RegistrationAccessToken), and the sweeper only ever scans non-null rows.
		expect(
			translateIndex('payload', {
				key: { expiresAt: 1 },
				expireAfterSeconds: 0
			})
		).toEqual({
			method: 'btree',
			columns: ['expires_at'],
			unique: false,
			where: 'expires_at IS NOT NULL'
		});
	});

	describe('multikey keys, where MongoDB indexes array members for free', () => {
		it('emits a GIN index over the array container, not a scalar expression', () => {
			// `projects.clientIds` is queried as findOne({ clientIds: someId }) — containment, not
			// equality. A b-tree on (doc->>'clientIds') would index the whole array as one text value
			// and match nothing, turning every project-by-client lookup into a sequential scan.
			expect(
				translateIndex('doc', { key: { clientIds: 1 }, multikey: 'clientIds' })
			).toEqual({
				method: 'gin',
				columns: ["(doc->'clientIds')"],
				unique: false
			});
		});

		it('indexes the container named by multikey, not the leaf the key walks to', () => {
			// `groups.members.userId` is an array OF OBJECTS. The container is `members`; the leaf is
			// what a containment predicate names inside it.
			expect(
				translateIndex('doc', {
					key: { 'members.userId': 1 },
					multikey: 'members'
				})
			).toEqual({
				method: 'gin',
				columns: ["(doc->'members')"],
				unique: false
			});
		});
	});
});

describe('every index the inventory declares translates', () => {
	// The drift half of this file. A key added to the inventory that this translation cannot express
	// fails here rather than at provisioning time against a real database — which is the only other
	// place it would surface, and only for whoever happens to run the script.
	const areas: StorageArea[] = [...FIXED_AREAS, PER_BUCKET_AREA];

	for (const area of areas) {
		it(`translates every declared index of '${area.name}'`, () => {
			const column = columnFor(area);
			for (const spec of indexesFor(area)) {
				const translated = translateIndex(column, spec);
				expect(translated.columns.length).toBeGreaterThan(0);
				for (const expression of translated.columns) {
					expect(typeof expression).toBe('string');
					expect(expression.length).toBeGreaterThan(0);
				}
			}
		});
	}

	it('emits a GIN index for exactly the two array-valued declarations', () => {
		// Pinned as a count rather than left implicit: a third multikey key is a design decision
		// somebody must make deliberately, because it changes both the index and the query that uses it.
		const gin = areas.flatMap((area) =>
			indexesFor(area)
				.map((spec) => translateIndex(columnFor(area), spec))
				.filter((translated) => translated.method === 'gin')
				.map((translated) => `${area.name}:${translated.columns.join(',')}`)
		);

		expect(gin.sort()).toEqual([
			"groups:(doc->'members')",
			"projects:(doc->'clientIds')"
		]);
	});
});
