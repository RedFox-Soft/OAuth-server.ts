import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { siteRoot, sourceHash } from '../../src/i18n/source-hash.ts';
import {
	FRONTMATTER_SOURCE,
	MODULE_SOURCE,
	englishExists,
	translationOf,
	type Translation
} from './translations.ts';

/*
 * `bun run i18n:stamp <translation>...` — record that a translation now matches its English file.
 *
 * Run after re-translating, never instead of it: the hash is the whole of what the site knows
 * about a translation's age, so stamping an untouched file removes the page's "English version is
 * newer" notice while leaving the old text in place.
 *
 * The file is rewritten with the line endings it already had. This repository is edited on
 * Windows, and a stamp that normalised a CRLF file to LF would turn a one-line change into a
 * whole-file diff that buries the line that matters.
 */

/*
 * YAML reads an all-digit value, or digits-e-digits, as a number, and the content schema wants a
 * string, so such a hash is quoted in frontmatter. Any other hash is left as the author wrote it.
 */
function numberLike(hash: string): boolean {
	return /^[0-9]+(?:e[0-9]+)?$/.test(hash);
}

/* Lines and the separator they were joined with, so the file can be put back exactly. */
function splitLines(text: string): { lines: string[]; eol: string } {
	const eol = text.includes('\r\n') ? '\r\n' : '\n';
	return { lines: text.split(eol), eol };
}

function stampFrontmatter(lines: string[], hash: string): string[] | string {
	const bom = lines[0]?.startsWith('﻿') ? '﻿' : '';
	if (lines[0]?.slice(bom.length) !== '---') return 'it has no frontmatter';
	const end = lines.indexOf('---', 1);
	if (end === -1) return 'its frontmatter is not closed';

	const out = [...lines];
	for (let i = 1; i < end; i += 1) {
		const match = out[i].match(FRONTMATTER_SOURCE);
		if (!match) continue;
		const quote = match[1] || (numberLike(hash) ? "'" : '');
		out[i] = `source: ${quote}${hash}${quote}`;
		return out;
	}

	const quote = numberLike(hash) ? "'" : '';
	/*
	 * After the description, which every translation has, so the two translated fields and the hash
	 * sit together at the top. A folded description runs on over indented lines, which belong to it.
	 */
	let at = end;
	const description = out.findIndex(
		(line, i) => i > 0 && i < end && line.startsWith('description:')
	);
	if (description !== -1) {
		at = description + 1;
		while (at < end && /^\s/.test(out[at])) at += 1;
	}
	out.splice(at, 0, `source: ${quote}${hash}${quote}`);
	return out;
}

function stampModule(lines: string[], hash: string): string[] {
	const out = [...lines];
	for (let i = 0; i < out.length; i += 1) {
		const match = out[i].match(MODULE_SOURCE);
		if (!match) continue;
		const quote = match[1];
		out[i] = out[i].replace(
			/(=\s*)(['"])[^'"]*\2/,
			`$1${quote}${hash}${quote}`
		);
		return out;
	}

	// After the imports, where the contract puts it: above the messages, below what they depend on.
	let lastImport = -1;
	for (let i = 0; i < out.length; i += 1) {
		if (!/^import\b/.test(out[i])) continue;
		let j = i;
		while (
			j < out.length - 1 &&
			!/(?:from\s+['"][^'"]+['"]|^import\s+['"][^'"]+['"])\s*;?\s*$/.test(
				out[j]
			)
		) {
			j += 1;
		}
		lastImport = j;
		i = j;
	}
	const line = `export const source = '${hash}';`;
	if (lastImport === -1) out.splice(0, 0, line, '');
	else out.splice(lastImport + 1, 0, '', line);
	return out;
}

interface Plan {
	path: string;
	text: string;
	next: string;
	message: string;
}

function plan(translation: Translation): Plan | string {
	const path = join(siteRoot(), translation.file);
	const text = readFileSync(path, 'utf8');
	const hash = sourceHash(translation.english);
	const { lines, eol } = splitLines(text);

	const stamped =
		translation.kind === 'messages'
			? stampModule(lines, hash)
			: stampFrontmatter(lines, hash);
	if (typeof stamped === 'string') {
		return `${translation.file}: not stamped — ${stamped}`;
	}

	const next = stamped.join(eol);
	return {
		path,
		text,
		next,
		message:
			next === text
				? `${translation.file}: already ${hash}`
				: `${translation.file}: stamped ${hash} from ${translation.english}`
	};
}

function main(): void {
	const files = process.argv.slice(2);
	if (files.length === 0) {
		console.error('usage: bun run i18n:stamp <translation-file>...');
		process.exit(1);
	}

	// Every argument is checked before any file is written, so a mistake in the third leaves the
	// first two as they were rather than half the batch stamped.
	const refused: string[] = [];
	const plans: Plan[] = [];
	for (const file of files) {
		const translation = translationOf(file);
		if (!translation) {
			refused.push(
				`${file}: not a translation — expected src/i18n/messages/<group>/<locale>.ts, ` +
					'src/content/blog/<locale>/<slug>.mdx or src/content/docs/<locale>/…'
			);
			continue;
		}
		if (!englishExists(translation)) {
			refused.push(
				`${file}: its English source ${translation.english} does not exist`
			);
			continue;
		}
		const planned = plan(translation);
		if (typeof planned === 'string') refused.push(planned);
		else plans.push(planned);
	}
	if (refused.length > 0) {
		for (const line of refused) console.error(line);
		process.exit(1);
	}

	for (const { path, text, next, message } of plans) {
		// The string goes down byte for byte, carrying the line endings it was read with.
		if (next !== text) writeFileSync(path, next, 'utf8');
		console.log(message);
	}
}

main();
