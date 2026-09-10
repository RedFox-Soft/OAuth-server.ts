import { describe, it, expect } from 'bun:test';

import type { Migration } from 'lib/consts/migrations.js';
import {
	baseline,
	plan,
	run,
	type MigrationBackend
} from 'lib/migrations/runner.js';
import type { SchemaMigrationRecord } from 'lib/adapters/types.js';

/*
 * The runner, over a fixture set — contract M3.
 *
 * The real declared set ships empty, so without injecting one there would be nothing to run and the
 * machinery would first be exercised by whoever writes the first migration, against production data.
 * That is the whole reason the runner takes both the set and the backend as arguments.
 *
 * The fixture backend below is not a mock of a datastore. It is the smallest thing that satisfies the
 * contract — a list of records and a lock — which is precisely the surface the runner is allowed to
 * know about.
 */

function migration(id: string, extra: Partial<Migration> = {}): Migration {
	return {
		id,
		description: `the ${id} migration`,
		reversible: true,
		rerunnable: 'idempotent by construction in this fixture',
		mongodb: { noop: true, reason: 'fixture' },
		postgres: { noop: true, reason: 'fixture' },
		...extra
	};
}

interface Fixture extends MigrationBackend {
	readonly records: SchemaMigrationRecord[];
	readonly locks: number[];
}

function fixture(name: MigrationBackend['name'] = 'postgres'): Fixture {
	const records: SchemaMigrationRecord[] = [];
	const locks: number[] = [];
	let held = 0;

	return {
		name,
		handle: { fixture: true },
		records,
		locks,
		async readAll() {
			return [...records];
		},
		async write(entry) {
			records.push(entry);
		},
		async withLock(inner) {
			held += 1;
			locks.push(held);
			try {
				return await inner();
			} finally {
				held -= 1;
			}
		}
	};
}

describe('run', () => {
	it('applies outstanding migrations in declared order', async () => {
		const order: string[] = [];
		const step = (id: string) => ({
			apply: async () => {
				order.push(id);
			}
		});
		const declared = [
			migration('0001', { postgres: step('0001') }),
			migration('0002', { postgres: step('0002') }),
			migration('0003', { postgres: step('0003') })
		];

		const result = await run(declared, fixture());

		expect(order).toEqual(['0001', '0002', '0003']);
		expect(result.applied).toEqual(['0001', '0002', '0003']);
		expect(result.status).toBe('current');
	});

	it('is a no-op on a database that is already current', async () => {
		const declared = [migration('0001'), migration('0002')];
		const backend = fixture();

		await run(declared, backend);
		const second = await run(declared, backend);

		expect(second.applied).toEqual([]);
		expect(second.skipped).toEqual([]);
		expect(backend.records).toHaveLength(2);
	});

	it('records a no-op half as applied without performing anything', async () => {
		// Skipping the record instead would leave this backend reporting itself behind forever, on a
		// migration it will never have work for.
		const declared = [
			migration('0001', {
				postgres: { noop: true, reason: 'MongoDB-only rewrite' }
			})
		];
		const backend = fixture('postgres');

		const result = await run(declared, backend);

		expect(result.skipped).toEqual(['0001']);
		expect(result.applied).toEqual([]);
		expect(backend.records.map((r) => r.id)).toEqual(['0001']);
	});

	it('runs the half belonging to the backend it was given', async () => {
		const ran: string[] = [];
		const declared = [
			migration('0001', {
				mongodb: {
					apply: async () => {
						ran.push('mongo');
					}
				},
				postgres: {
					apply: async () => {
						ran.push('postgres');
					}
				}
			})
		];

		await run(declared, fixture('mongodb'));
		expect(ran).toEqual(['mongo']);
	});

	it('resumes after a failure without repeating what succeeded', async () => {
		// The property that makes a failed run recoverable. Re-running one step is safe by contract;
		// re-running the whole set would multiply that risk by every step that had already worked.
		const ran: string[] = [];
		let failing = true;
		const declared = [
			migration('0001', {
				postgres: {
					apply: async () => {
						ran.push('0001');
					}
				}
			}),
			migration('0002', {
				postgres: {
					apply: async () => {
						if (failing) throw new Error('deliberate');
						ran.push('0002');
					}
				}
			}),
			migration('0003', {
				postgres: {
					apply: async () => {
						ran.push('0003');
					}
				}
			})
		];
		const backend = fixture();

		await expect(run(declared, backend)).rejects.toThrow('deliberate');
		expect(ran).toEqual(['0001']);
		expect(backend.records.map((r) => r.id)).toEqual(['0001']);

		failing = false;
		const resumed = await run(declared, backend);

		expect(ran).toEqual(['0001', '0002', '0003']);
		expect(resumed.applied).toEqual(['0002', '0003']);
	});

	it('holds the lock for the whole run, not per migration', async () => {
		const declared = [migration('0001'), migration('0002')];
		const backend = fixture();

		await run(declared, backend);

		expect(backend.locks).toHaveLength(1);
	});

	it('refuses to apply anything against a database that is ahead', async () => {
		// An older binary against a newer database. Applying here would write on top of a disagreement
		// rather than resolve it.
		const backend = fixture();
		await backend.write({
			id: '0099-from-the-future',
			appliedAt: new Date(),
			checksum: 'whatever'
		});

		const result = await run([migration('0001')], backend);

		expect(result.status).toBe('ahead');
		expect(result.applied).toEqual([]);
		expect(backend.records).toHaveLength(1);
	});

	it('refuses to apply anything against a diverged database', async () => {
		const backend = fixture();
		await run([migration('0001')], backend);

		const edited = [migration('0001', { description: 'quietly changed' })];
		const result = await run(edited, backend);

		expect(result.status).toBe('diverged');
		expect(result.applied).toEqual([]);
	});
});

describe('plan', () => {
	it('reports what would run and changes nothing', async () => {
		const declared = [migration('0001'), migration('0002')];
		const backend = fixture();

		const reported = await plan(declared, backend);

		expect(reported.status).toBe('behind');
		expect(reported.outstanding).toEqual(['0001', '0002']);
		expect(backend.records).toEqual([]);
	});
});

describe('baseline', () => {
	it('marks every declared migration applied without performing any', async () => {
		const ran: string[] = [];
		const declared = [
			migration('0001', {
				postgres: {
					apply: async () => {
						ran.push('0001');
					}
				}
			})
		];
		const backend = fixture();

		const marked = await baseline(declared, backend);

		expect(marked).toEqual(['0001']);
		expect(ran).toEqual([]);
		expect((await plan(declared, backend)).status).toBe('current');
	});

	it('leaves an already-recorded migration alone', async () => {
		const declared = [migration('0001'), migration('0002')];
		const backend = fixture();

		await baseline(declared, backend);
		const again = await baseline(declared, backend);

		expect(again).toEqual([]);
		expect(backend.records).toHaveLength(2);
	});
});
