import { describe, it, expect } from 'bun:test';
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';

/*
 * Constitution Principle III, as a guard: "Business logic MUST NOT reference MongoDB, SQL, or any
 * specific database technology."
 *
 * It holds today, so this passes on first run. It is here because the property is the one that makes
 * a second storage backend possible at all, and because the way it breaks is undramatic — one import
 * added to one helper, for one query that was easier to write directly. Nothing fails; the codebase
 * just quietly acquires a place that only works on one datastore, and the next backend discovers it.
 *
 * Scoped to `lib/` deliberately. `database/` holds operator scripts that connect on purpose, and
 * `lib/adapters/` is where knowing about a driver is the entire job.
 */

const LIB = resolve(import.meta.dir, '../../lib');
const ADAPTERS = 'adapters/';

/* Import specifiers that mean "this module talks to a specific datastore". `bun` is listed by
 * symbol rather than by module, because the runtime's SQL client shares a package with everything
 * else Bun exports — importing `file` or `serve` from it says nothing about storage. */
const DRIVER_MODULES = ['mongodb', 'pg', 'postgres'];
const DRIVER_SYMBOLS_FROM_BUN = ['SQL', 'sql'];

function sources(): { file: string; shown: string; source: string }[] {
	return readdirSync(LIB, { recursive: true, encoding: 'utf8' })
		.filter((entry) => entry.endsWith('.ts'))
		.map((entry) => {
			const file = join(LIB, entry);
			return {
				file,
				shown: relative(LIB, file).replaceAll('\\', '/'),
				source: readFileSync(file, 'utf8')
			};
		});
}

function importsDriver(source: string): string | null {
	for (const module of DRIVER_MODULES) {
		const from = new RegExp(`from\\s+'${module}'`);
		const required = new RegExp(`require\\(\\s*'${module}'\\s*\\)`);
		if (from.test(source) || required.test(source)) return module;
	}

	/* `import { SQL } from 'bun'` — the runtime's PostgreSQL client. */
	const bunImport = /import\s*\{([^}]*)\}\s*from\s*'bun'/.exec(source);
	if (bunImport?.[1]) {
		const named = bunImport[1].split(',').map((part) => part.trim());
		const driver = named.find((name) => DRIVER_SYMBOLS_FROM_BUN.includes(name));
		if (driver) return `bun:${driver}`;
	}

	return null;
}

/**
 * @proves Every database driver import stays inside lib/adapters/, so business logic never
 * references a specific datastore.
 */
describe('adapter isolation', () => {
	const files = sources();

	it('reads the library it claims to, so it cannot pass vacuously', () => {
		expect(files.length).toBeGreaterThan(100);
	});

	it('keeps every database driver import inside lib/adapters/', () => {
		const leaked = files
			.filter(({ shown }) => !shown.startsWith(ADAPTERS))
			.map(({ shown, source }) => ({ shown, driver: importsDriver(source) }))
			.filter((entry) => entry.driver !== null)
			.map((entry) => `${entry.shown} imports ${entry.driver}`);

		expect(leaked).toEqual([]);
	});

	it('finds the drivers where they belong, so the detection itself is proved', () => {
		// Without this half the check above would also pass if `importsDriver` matched nothing at all —
		// which is exactly what a renamed package or a changed import style would cause.
		const found = new Set(
			files
				.filter(({ shown }) => shown.startsWith(ADAPTERS))
				.map(({ source }) => importsDriver(source))
				.filter((driver): driver is string => driver !== null)
		);

		expect(found.has('mongodb')).toBe(true);
		expect(found.has('bun:SQL')).toBe(true);
	});
});
