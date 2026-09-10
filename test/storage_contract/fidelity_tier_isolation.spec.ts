import { describe, it, expect } from 'bun:test';
import { readdirSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

/*
 * The fidelity tier must be unreachable from `bun test`, and unreachable by *construction* rather
 * than by exclusion.
 *
 * Constitution Principle III's second binding condition is that a suite touching a real database is
 * invoked separately and cannot be reached from the default run. There are two ways to satisfy it:
 * name the files so the runner never discovers them, or list them in `bunfig.toml`'s
 * `pathIgnorePatterns`. Only the first survives a rename, a copy, or a new file added beside them by
 * somebody who did not read this comment — an exclusion list is a promise kept somewhere else.
 *
 * So: nothing under `database/` may match the runner's discovery patterns, and no entry in the
 * ignore list may be doing that work for it. A file that needed one would be a file one edit away
 * from connecting to somebody's database during a routine `bun test`.
 */

const DATABASE = resolve(import.meta.dir, '../../database');
const BUNFIG = resolve(import.meta.dir, '../../bunfig.toml');

/* Bun's default test discovery: `*.test.*`, `*_test.*`, `*.spec.*`, `*_spec.*`. */
const DISCOVERED = /\.(test|spec)\.[cm]?[jt]sx?$|_(test|spec)\.[cm]?[jt]sx?$/;

describe('the storage fidelity tier', () => {
	const files = readdirSync(DATABASE, { recursive: true, encoding: 'utf8' });

	it('finds the scripts it is guarding, so it cannot pass vacuously', () => {
		expect(files).toContain('verify_postgres.ts');
		expect(files).toContain('verify_migrations.ts');
	});

	it('names nothing under database/ the way the test runner discovers a spec', () => {
		expect(files.filter((file) => DISCOVERED.test(file))).toEqual([]);
	});

	it('needs no bunfig exclusion to stay out of the default run', () => {
		const bunfig = readFileSync(BUNFIG, 'utf8');

		expect(bunfig).not.toContain('database/');
	});
});
