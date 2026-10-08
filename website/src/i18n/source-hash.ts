import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/*
 * Which revision of its English source a translation was made from.
 *
 * A content hash rather than a git date: it works on a shallow checkout and on uncommitted edits, and
 * a rename or a whitespace-only commit does not mark every translation stale. Line endings are
 * normalised first because this repository is edited on Windows, and a hash over raw bytes would
 * call every translation out of date after a CRLF round-trip that changed nothing a reader sees.
 */

/*
 * The Astro project root. Every caller — the build, `astro check` and the scripts — runs from the
 * project directory; refusing anything else is better than hashing a file that is not there.
 */
export function siteRoot(): string {
	const root = process.cwd();
	if (!existsSync(join(root, 'astro.config.mjs'))) {
		throw new Error(
			`Translation freshness has to run from the website/ directory; ${root} is not it.`
		);
	}
	return root;
}

export function hashText(text: string): string {
	return createHash('sha256')
		.update(text.replace(/\r\n/g, '\n'))
		.digest('hex')
		.slice(0, 12);
}

/** Hash of a file, by path relative to the project root. */
export function sourceHash(relativePath: string): string {
	return hashText(readFileSync(join(siteRoot(), relativePath), 'utf8'));
}
