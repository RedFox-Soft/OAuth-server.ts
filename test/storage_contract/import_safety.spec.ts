import { describe, it, expect, beforeAll, afterAll } from 'bun:test';
import { readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

/*
 * Every module under lib/adapters/postgres/ must import with no POSTGRES_URL set, and must open no
 * connection while doing so — contract C1 in the storage-backend contract.
 *
 * This is the property `lib/adapters/mongodb/db.ts` does not have. It awaits `connect()` at module
 * scope and throws without MONGODB_URI, and the consequences reach far past that one file:
 * `lib/consts/storage_inventory.ts` has to import nothing so the drift guard can run, the
 * reconciliation logic had to be extracted into pure functions to be testable at all, and the first
 * of the three barriers on GitHub issue #25 exists solely to undo it.
 *
 * A second backend that repeated the mistake would double that cost, so the property is pinned before
 * there is much to pin — and the check is cheap enough to keep as the directory grows to sixteen
 * stores.
 */

const POSTGRES = resolve(import.meta.dir, '../../lib/adapters/postgres');

function modules(): string[] {
	return readdirSync(POSTGRES, { recursive: true, encoding: 'utf8' })
		.filter((entry) => entry.endsWith('.ts'))
		.map((entry) => join(POSTGRES, entry));
}

describe('postgres adapter import safety', () => {
	const saved = process.env.POSTGRES_URL;

	beforeAll(() => {
		// Bun runs spec files in one process, so this is restored rather than merely deleted.
		delete process.env.POSTGRES_URL;
	});

	afterAll(() => {
		if (saved === undefined) delete process.env.POSTGRES_URL;
		else process.env.POSTGRES_URL = saved;
	});

	it('finds the modules it claims to, so it cannot pass vacuously', () => {
		expect(modules().length).toBeGreaterThan(0);
	});

	it('imports every module with no POSTGRES_URL set', async () => {
		const failed: string[] = [];

		for (const file of modules()) {
			try {
				await import(pathToFileURL(file).href);
			} catch (err) {
				failed.push(`${file}: ${(err as Error).message}`);
			}
		}

		expect(failed).toEqual([]);
	});

	it('defers the missing-URL failure to first use, not to import', async () => {
		// The positive half. Importing succeeding proves nothing on its own — a module that silently
		// built a handle against `undefined` would also import fine. What proves the handle was never
		// built is that asking for one now still complains about the variable.
		const { sql } = await import(pathToFileURL(join(POSTGRES, 'db.ts')).href);

		expect(() => sql()).toThrow(/POSTGRES_URL/);
	});
});
