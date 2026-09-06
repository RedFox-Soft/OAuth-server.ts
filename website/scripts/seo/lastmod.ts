import { execFileSync } from 'node:child_process';
import { statSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/*
 * Per-page last-modified dates, from git.
 *
 * The sitemap integration offers a global `lastmod` option, which would stamp one date on every
 * entry and tell crawlers the whole site changed on every deploy — a signal a crawler learns to
 * ignore. Filesystem mtime is no better: a fresh CI checkout gives every file the checkout time.
 * Commit dates are the only source that says what actually changed.
 *
 * Synchronous and on node:child_process rather than Bun.spawn, because the sitemap integration's
 * `serialize` hook runs inside `astro build`, where the runtime is whatever launched the Astro CLI.
 * Results are cached, so the ~35 files cost one `git log` each per build.
 */

// Not import.meta.dir/dirname: this module is also loaded from astro.config.mjs through Vite's
// module runner, which inlines it without either.
const HERE = fileURLToPath(new URL('.', import.meta.url));
const ROOT = resolve(HERE, '../../..');

export class MissingGitHistory extends Error {
	constructor(file: string) {
		super(
			`Cannot derive a last-modified date for ${file}: no git history found.\n` +
				'The build needs full history — CI checks out with fetch-depth: 0.\n' +
				'Refusing to emit a fabricated date; fix the checkout rather than the sitemap.'
		);
		this.name = 'MissingGitHistory';
	}
}

const cache = new Map<string, string | undefined>();

/*
 * A file git has never seen has no commit date, and a page cannot be built until it is committed —
 * which would mean a contributor writing a new page could not get a green build until they had
 * committed it. For an *untracked* file the filesystem mtime is not a guess: it is genuinely when
 * the file was last written.
 *
 * The check is `ls-files --error-unmatch` rather than "git returned nothing", deliberately. A
 * shallow clone also returns nothing, and there the mtime is the checkout time — the exact wrong
 * answer this module exists to refuse. Tracked file with no history still fails loudly.
 */
function isUntracked(relativePath: string): boolean {
	try {
		execFileSync('git', ['ls-files', '--error-unmatch', '--', relativePath], {
			cwd: ROOT,
			stdio: 'ignore'
		});
		return false;
	} catch {
		return true;
	}
}

function commitDate(relativePath: string): string | undefined {
	if (cache.has(relativePath)) return cache.get(relativePath);

	let value: string | undefined;
	try {
		const out = execFileSync(
			'git',
			['log', '-1', '--format=%cI', '--', relativePath],
			{
				cwd: ROOT,
				encoding: 'utf8',
				stdio: ['ignore', 'pipe', 'ignore']
			}
		).trim();
		value = out === '' ? undefined : out;
	} catch {
		value = undefined;
	}

	if (value === undefined && isUntracked(relativePath)) {
		const stats = statSync(resolve(ROOT, relativePath), {
			throwIfNoEntry: false
		});
		value = stats?.mtime.toISOString();
	}

	cache.set(relativePath, value);
	return value;
}

/** Newest commit date across a page's own source and the repository files it renders. */
export function lastModified(
	sourceFile: string | undefined,
	dataSources: string[]
): string | undefined {
	const files = [sourceFile, ...dataSources].filter((f): f is string =>
		Boolean(f)
	);
	if (files.length === 0) return undefined;

	const dates = files
		.map(commitDate)
		.filter((d): d is string => d !== undefined);
	if (dates.length === 0) return undefined;

	return dates.reduce((newest, d) =>
		Date.parse(d) > Date.parse(newest) ? d : newest
	);
}
