import { describe, it, expect, beforeAll, afterAll } from 'bun:test';
import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';

/*
 * The release workflow runs the CLI on a bare checkout with no database and no ISSUER. A child
 * process is the only honest test of that: the script must choose a loadable environment itself,
 * and the same technique test/boot/boot_state.spec.ts uses proves it did.
 */
describe('docs:export CLI', () => {
	let dir = '';
	let out = '';

	beforeAll(async () => {
		dir = await fs.mkdtemp(path.join(os.tmpdir(), 'docs-export-'));
		out = path.join(dir, 'docs-export.json');
	});

	afterAll(async () => {
		await fs.rm(dir, { recursive: true, force: true });
	});

	it('writes a parseable export from a bare environment', async () => {
		const env = { ...process.env };
		delete env.ISSUER;
		delete env.MONGODB_URI;
		delete env.DATABASE_NAME;
		delete env.NODE_ENV;

		const proc = Bun.spawn(['bun', 'scripts/docs_export.ts', out], {
			cwd: process.cwd(),
			env,
			stdout: 'pipe',
			stderr: 'pipe'
		});
		const [exitCode, stderr] = await Promise.all([
			proc.exited,
			new Response(proc.stderr).text()
		]);

		expect(stderr).toBe('');
		expect(exitCode).toBe(0);

		const parsed = JSON.parse(await fs.readFile(out, 'utf8')) as {
			schemaVersion: number;
			version: string;
			settings: { entries: unknown[] };
		};
		expect(parsed.schemaVersion).toBe(1);
		expect(parsed.version).toMatch(/^\d+\.\d+\.\d+/);
		expect(parsed.settings.entries.length).toBeGreaterThan(50);
	}, 20_000);

	it('ignores a live database and exports shipped defaults, even with MONGODB_URI set', async () => {
		const env = {
			...process.env,
			MONGODB_URI: 'mongodb://127.0.0.1:1/unreachable',
			DATABASE_NAME: 'bogus'
		};

		const proc = Bun.spawn(['bun', 'scripts/docs_export.ts', out], {
			cwd: process.cwd(),
			env,
			stdout: 'pipe',
			stderr: 'pipe'
		});
		const [exitCode, stderr] = await Promise.all([
			proc.exited,
			new Response(proc.stderr).text()
		]);

		expect(stderr).toBe('');
		expect(exitCode).toBe(0);

		const parsed = JSON.parse(await fs.readFile(out, 'utf8')) as {
			settings: { entries: { key: string; value: unknown }[] };
		};
		const clientCredentials = parsed.settings.entries.find(
			(entry) => entry.key === 'clientCredentials.enabled'
		);
		expect(clientCredentials?.value).toBe(false);
	}, 20_000);
});
