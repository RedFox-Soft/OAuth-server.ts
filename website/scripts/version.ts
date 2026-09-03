import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';

/*
 * What the site says it documents. The site builds from `main`, which is usually ahead of the last
 * tag, so Reference and Changelog pages need to know whether they describe a release or unreleased
 * work — a reader running the published image must not be told about a setting it does not have.
 */
const root = resolve(import.meta.dir, '../..');
const pkg = (await Bun.file(resolve(root, 'package.json')).json()) as {
	version: string;
};

async function git(...args: string[]): Promise<string | null> {
	const proc = Bun.spawn(['git', ...args], {
		cwd: root,
		stdout: 'pipe',
		stderr: 'pipe'
	});
	const out = await new Response(proc.stdout).text();
	return (await proc.exited) === 0 ? out.trim() : null;
}

// Before the first tag `git describe` fails; that is "unreleased", not an error.
const lastTag = await git('describe', '--tags', '--abbrev=0');
const commit = (await git('rev-parse', '--short', 'HEAD')) ?? 'unknown';
const tagCommit = lastTag ? await git('rev-list', '-n', '1', lastTag) : null;
const headCommit = await git('rev-parse', 'HEAD');

const stamp = {
	version: pkg.version,
	lastTag,
	commit,
	unreleased: tagCommit === null || tagCommit !== headCommit,
	generatedAt: new Date().toISOString()
};

const out = resolve(import.meta.dir, '../generated/version.json');
mkdirSync(resolve(import.meta.dir, '../generated'), { recursive: true });
await Bun.write(out, `${JSON.stringify(stamp, null, 2)}\n`);
console.log(
	`version.json: ${stamp.version} (${stamp.unreleased ? 'unreleased, ' : ''}${commit})`
);
