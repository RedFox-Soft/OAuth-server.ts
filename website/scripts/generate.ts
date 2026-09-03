import { resolve } from 'node:path';

/*
 * Everything the build needs that is not committed, in dependency order. Each generator is its own
 * script so it can be run alone while developing; this file only sequences them and fails fast.
 */
const here = import.meta.dir;
const root = resolve(here, '../..');

async function run(label: string, cmd: string[], cwd: string): Promise<void> {
	const proc = Bun.spawn(cmd, { cwd, stdout: 'inherit', stderr: 'inherit' });
	const code = await proc.exited;
	if (code !== 0) {
		throw new Error(`${label} failed with exit code ${code}`);
	}
}

await run(
	'docs export',
	['bun', 'scripts/docs_export.ts', 'website/generated/docs-export.json'],
	root
);
await run('version stamp', ['bun', resolve(here, 'version.ts')], here);
if (process.env.SITE_SKIP_CAPTURE !== '1') {
	// Task 7 adds capture.ts; until then the file is absent and this branch is skipped by the guard.
	const capture = Bun.file(resolve(here, 'capture.ts'));
	if (await capture.exists()) {
		await run(
			'screenshots and OG images',
			['bun', resolve(here, 'capture.ts')],
			here
		);
	}
}
