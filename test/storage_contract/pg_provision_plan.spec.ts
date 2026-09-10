import { describe, it, expect } from 'bun:test';

import {
	FIXED_AREAS,
	PER_BUCKET_AREA,
	areaForBucket,
	areaNamed
} from 'lib/consts/storage_inventory.js';
import {
	indexStatements,
	planFor,
	tableStatement
} from 'lib/adapters/postgres/provision.js';

/*
 * The DDL the PostgreSQL applier will run, as data.
 *
 * Generating the plan separately from applying it is what puts this in the default test run at all:
 * the statements are a pure function of the inventory, so every table shape, every index expression
 * and every generated name is checkable with no database anywhere — which is the same reason
 * `database/reconcile.ts` holds decisions rather than driver calls.
 *
 * Two failure modes make it worth pinning the exact text. An unquoted camelCase identifier is folded
 * to lower case by PostgreSQL, so `adminAudit` silently becomes a different table than the one the
 * store reads. And a generated index name over 63 bytes is truncated by the server, which turns two
 * distinct indexes into one collision on a long bucket id.
 */

const MODEL = areaNamed('AccessToken');
const STORE = areaNamed('projects');

/**
 * @proves The PostgreSQL provisioning plan covers every declared area with quoted identifiers,
 * correct index kinds, and names that are unique, bounded and deterministic.
 */
describe('tableStatement', () => {
	it('gives a model area the payload column its declared keys already name', () => {
		expect(tableStatement(MODEL)).toBe(
			'CREATE TABLE IF NOT EXISTS "AccessToken" ' +
				'(id text PRIMARY KEY, payload jsonb NOT NULL, expires_at timestamptz)'
		);
	});

	it('gives a store area the doc column', () => {
		expect(tableStatement(STORE)).toBe(
			'CREATE TABLE IF NOT EXISTS "projects" ' +
				'(id text PRIMARY KEY, doc jsonb NOT NULL, expires_at timestamptz)'
		);
	});

	it('names a per-bucket area for its bucket', () => {
		expect(tableStatement(areaForBucket('redfox'))).toContain('"user_redfox"');
	});

	it('quotes every identifier, so camelCase survives', () => {
		// Unquoted, PostgreSQL folds `adminAudit` to `adminaudit` and the store's reads miss entirely.
		expect(tableStatement(areaNamed('adminAudit'))).toContain('"adminAudit"');
		expect(tableStatement(areaNamed('adminAudit'))).not.toContain(
			' adminaudit'
		);
	});

	it('gives serviceConfig a bytea column, the one declared exception', () => {
		// The three singleton secrets must come back as bytes a caller's `instanceof Uint8Array` guard
		// accepts. Base64 inside the jsonb document would be the extra encoding hop that made the
		// MongoDB store hand back a `Binary` and stopped the server booting.
		expect(tableStatement(areaNamed('serviceConfig'))).toBe(
			'CREATE TABLE IF NOT EXISTS "serviceConfig" ' +
				'(id text PRIMARY KEY, doc jsonb NOT NULL, expires_at timestamptz, secret bytea)'
		);
	});

	it('gives no other area a bytea column', () => {
		// Pinned as an exhaustive check rather than left implicit: a second bespoke table shape is a
		// decision, and the value of one uniform shape is that the adapter writes the same three
		// columns everywhere.
		const bespoke = [...FIXED_AREAS, PER_BUCKET_AREA]
			.filter((area) => tableStatement(area).includes('bytea'))
			.map((area) => area.name);

		expect(bespoke).toEqual(['serviceConfig']);
	});

	it('gives an area with no expiry the column anyway', () => {
		// One table shape per kind, not one per area: the adapter writes the same three columns
		// everywhere, and only the partial index below is conditional on `reaped`.
		expect(tableStatement(areaNamed('Client'))).toContain(
			'expires_at timestamptz'
		);
	});
});

describe('indexStatements', () => {
	function statementsFor(area: Parameters<typeof indexStatements>[0]) {
		return indexStatements(area).map((planned) => planned.statement);
	}

	it('builds a b-tree expression index over a payload field', () => {
		expect(statementsFor(MODEL)).toContain(
			'CREATE INDEX IF NOT EXISTS "AccessToken_payload_grantId_idx" ' +
				'ON "AccessToken" ((payload->>\'grantId\'))'
		);
	});

	it('makes the expiry index partial', () => {
		// The sweeper only ever scans rows that can expire, and two areas hold expiring and permanent
		// records side by side by design.
		expect(statementsFor(MODEL)).toContain(
			'CREATE INDEX IF NOT EXISTS "AccessToken_expires_at_idx" ' +
				'ON "AccessToken" (expires_at) WHERE expires_at IS NOT NULL'
		);
	});

	it('creates no expiry index for a permanent area', () => {
		const statements = statementsFor(areaNamed('Client'));
		expect(statements.some((s) => s.includes('expires_at'))).toBe(false);
	});

	it('builds a unique index where uniqueness is declared', () => {
		expect(statementsFor(areaNamed('DeviceCode'))).toContain(
			'CREATE UNIQUE INDEX IF NOT EXISTS "DeviceCode_payload_userCode_key" ' +
				'ON "DeviceCode" ((payload->>\'userCode\'))'
		);
	});

	it('builds a GIN index over an array container', () => {
		expect(statementsFor(STORE)).toContain(
			'CREATE INDEX IF NOT EXISTS "projects_clientIds_gin" ' +
				'ON "projects" USING gin ((doc->\'clientIds\'))'
		);
	});

	it('builds the per-bucket unique email index', () => {
		expect(statementsFor(areaForBucket('redfox'))).toContain(
			'CREATE UNIQUE INDEX IF NOT EXISTS "user_redfox_email_key" ' +
				'ON "user_redfox" ((doc->>\'email\'))'
		);
	});
});

describe('generated index names', () => {
	const areas = [...FIXED_AREAS, PER_BUCKET_AREA, areaForBucket('redfox')];
	const planned = areas.flatMap((area) => indexStatements(area));

	it('plans indexes at all, so the sweep below cannot pass vacuously', () => {
		expect(planned.length).toBeGreaterThan(30);
	});

	it('never exceeds PostgreSQL identifier length', () => {
		// Over 63 bytes the server truncates silently, and two long names collapse into one index.
		const tooLong = planned
			.map((index) => index.name)
			.filter((name) => Buffer.byteLength(name, 'utf8') > 63);

		expect(tooLong).toEqual([]);
	});

	it('stays unique across the whole inventory', () => {
		// Index names are per-schema in PostgreSQL, not per-table, so a collision between two areas is
		// a real one.
		const names = planned.map((index) => index.name);
		expect(new Set(names).size).toBe(names.length);
	});

	it('survives a bucket id long enough to overflow the limit', () => {
		const long = areaForBucket('b'.repeat(80));
		const names = indexStatements(long).map((index) => index.name);

		expect(names.length).toBeGreaterThan(0);
		for (const name of names) {
			expect(Buffer.byteLength(name, 'utf8')).toBeLessThanOrEqual(63);
		}
		// Truncation alone would collide; the names must still differ from each other.
		expect(new Set(names).size).toBe(names.length);
	});

	it('is deterministic, so a re-run plans the same names', () => {
		const again = areas.flatMap((area) => indexStatements(area));
		expect(again.map((i) => i.name)).toEqual(planned.map((i) => i.name));
	});
});

describe('planFor', () => {
	it('carries the table and its indexes together', () => {
		const plan = planFor(MODEL);

		expect(plan.table).toBe(tableStatement(MODEL));
		expect(plan.indexes).toEqual(indexStatements(MODEL));
	});

	it('covers every declared area without throwing', () => {
		for (const area of [...FIXED_AREAS, areaForBucket('redfox')]) {
			const plan = planFor(area);
			expect(plan.table).toContain('CREATE TABLE');
			expect(Array.isArray(plan.indexes)).toBe(true);
		}
	});
});
