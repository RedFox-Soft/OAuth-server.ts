import { describe, it, expect } from 'bun:test';
import { readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { STORE_AREAS } from 'lib/consts/storage_inventory.js';

/*
 * The two production backends must cover the same storage areas.
 *
 * The forward direction — every area the inventory declares is provisioned — is satisfied by
 * construction on both, because each applier derives its work from `STORAGE_INVENTORY` rather than
 * from a list of its own. What that leaves unchecked is the reverse and more likely failure: a store
 * class that exists on one backend and not the other.
 *
 * It is likely because of how a backend gets written. Sixteen store classes are ported one at a time,
 * and the sixteenth is the easiest thing in the world to forget — nothing fails, because the selection
 * site simply keeps the in-memory default for whatever was not overridden, and the deployment quietly
 * holds that area's records in a process that restarts.
 *
 * Compared by the area each store names rather than by file name, so a differently-named class that
 * covers the same area still counts, and a file that covers nothing does not.
 */

const ADAPTERS = resolve(import.meta.dir, '../../lib/adapters');

function areasNamedBy(backend: string): Set<string> {
	const dir = join(ADAPTERS, backend);
	const found = new Set<string>();

	for (const entry of readdirSync(dir)) {
		if (!entry.endsWith('.ts')) continue;
		const source = readFileSync(join(dir, entry), 'utf8');
		for (const match of source.matchAll(/STORE_AREAS\.([A-Za-z]\w*)/g)) {
			const key = match[1];
			if (key !== undefined) found.add(key);
		}
	}

	return found;
}

describe('storage backend parity', () => {
	const postgres = areasNamedBy('postgres');
	const mongodb = areasNamedBy('mongodb');

	it('finds the areas it claims to, so the comparison cannot pass vacuously', () => {
		// Two empty sets are equal, and a renamed constant or a moved directory would produce exactly
		// that.
		expect(postgres.size).toBeGreaterThan(10);
		expect(mongodb.size).toBeGreaterThan(10);
	});

	it('covers the same store areas on both backends', () => {
		const onlyPostgres = [...postgres].filter((area) => !mongodb.has(area));
		const onlyMongo = [...mongodb].filter((area) => !postgres.has(area));

		expect({ onlyPostgres, onlyMongo }).toEqual({
			onlyPostgres: [],
			onlyMongo: []
		});
	});

	it('names only areas the inventory declares', () => {
		// The other half of the drift guard one layer up: a store reaching an area the inventory does not
		// declare is an area `db:setup` never provisions, which auto-creates on first write with no
		// indexes and nothing reaping it.
		const declared = new Set(Object.keys(STORE_AREAS));
		const undeclared = [...postgres, ...mongodb].filter(
			(area) => !declared.has(area)
		);

		expect(undeclared).toEqual([]);
	});

	it('leaves no dedicated-store area uncovered by either backend', () => {
		// `serviceConfig` is named by several stores and every other key by exactly one, so the union
		// across a backend should be the whole table. An area declared and reached by no store class is
		// one the in-memory default silently keeps.
		const declared = Object.keys(STORE_AREAS);
		const uncovered = declared.filter(
			(area) => !postgres.has(area) || !mongodb.has(area)
		);

		expect(uncovered).toEqual([]);
	});
});
