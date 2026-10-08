import { existsSync, readFileSync } from 'node:fs';
import { join, relative, resolve, sep } from 'node:path';
import { LOCALE_DEFINITIONS, type LocaleKey } from '../../src/data/seo.ts';
import { siteRoot } from '../../src/i18n/source-hash.ts';

/*
 * What a translation is, and which English file it was made from. One definition, read by both the
 * freshness report and the stamp command, so the file a translator stamps is always the file the
 * report compares it with.
 */

export type TranslationKind = 'messages' | 'blog' | 'docs';

export interface Translation {
	/* Relative to website/, with forward slashes. */
	file: string;
	english: string;
	locale: LocaleKey;
	kind: TranslationKind;
}

/*
 * Every language a translation can be written in, published or not: a translation is checked from
 * the day it is written, not from the day its language goes live.
 */
export const TRANSLATED_LOCALES: readonly LocaleKey[] = Object.values(
	LOCALE_DEFINITIONS
)
	.map((locale) => locale.key)
	.filter((key) => key !== 'en');

/*
 * compareCards has no en.ts: its English is the compare collection's own frontmatter, so there is
 * no one file a card translation was made from and nothing to hash it against.
 */
const UNHASHED_GROUPS: readonly string[] = ['compareCards'];

function isTranslatedLocale(value: string | undefined): value is LocaleKey {
	return TRANSLATED_LOCALES.some((key) => key === value);
}

/** A path as this module spells it: relative to website/, forward slashes. */
export function siteRelative(path: string): string {
	const root = siteRoot();
	return relative(root, resolve(root, path)).split(sep).join('/');
}

/*
 * The translation a path names, or undefined when it is not one. Decided by location alone, the
 * same locations the site loads translations from, so nothing the site renders as a translation
 * can escape the report, and nothing else can be stamped as one.
 */
export function translationOf(path: string): Translation | undefined {
	const file = siteRelative(path);
	const parts = file.split('/');

	if (
		parts.length === 5 &&
		parts[0] === 'src' &&
		parts[1] === 'i18n' &&
		parts[2] === 'messages' &&
		!UNHASHED_GROUPS.includes(parts[3]) &&
		parts[4].endsWith('.ts')
	) {
		const locale = parts[4].slice(0, -'.ts'.length);
		if (!isTranslatedLocale(locale)) return undefined;
		return {
			file,
			english: `src/i18n/messages/${parts[3]}/en.ts`,
			locale,
			kind: 'messages'
		};
	}

	if (
		parts.length === 5 &&
		parts[0] === 'src' &&
		parts[1] === 'content' &&
		parts[2] === 'blog' &&
		isTranslatedLocale(parts[3]) &&
		parts[4].endsWith('.mdx')
	) {
		return {
			file,
			english: `src/content/blog/${parts[4]}`,
			locale: parts[3],
			kind: 'blog'
		};
	}

	if (
		parts.length >= 5 &&
		parts[0] === 'src' &&
		parts[1] === 'content' &&
		parts[2] === 'docs' &&
		isTranslatedLocale(parts[3]) &&
		/\.mdx?$/.test(file)
	) {
		return {
			file,
			english: `src/content/docs/${parts.slice(4).join('/')}`,
			locale: parts[3],
			kind: 'docs'
		};
	}

	return undefined;
}

function scan(pattern: string): string[] {
	return [...new Bun.Glob(pattern).scanSync({ cwd: siteRoot() })].map((path) =>
		path.split(sep).join('/')
	);
}

/** Every translation in the tree, in a stable order. */
export function listTranslations(): Translation[] {
	const found: Translation[] = [];
	for (const locale of TRANSLATED_LOCALES) {
		for (const pattern of [
			`src/i18n/messages/*/${locale}.ts`,
			`src/content/blog/${locale}/*.mdx`,
			`src/content/docs/${locale}/**/*.{md,mdx}`
		]) {
			for (const path of scan(pattern)) {
				const translation = translationOf(path);
				if (translation) found.push(translation);
			}
		}
	}
	return found.sort((a, b) => a.file.localeCompare(b.file));
}

export function englishExists(translation: Translation): boolean {
	return existsSync(join(siteRoot(), translation.english));
}

export function readSite(path: string): string {
	return readFileSync(join(siteRoot(), path), 'utf8');
}

/*
 * The frontmatter block's lines, without the fences, or undefined when the file has none. A BOM
 * is tolerated because an editor on Windows may add one, and the hash ignores nothing else.
 */
export function frontmatterLines(text: string): string[] | undefined {
	const lines = text.replace(/^\uFEFF/, '').split(/\r?\n/);
	if (lines[0] !== '---') return undefined;
	const end = lines.indexOf('---', 1);
	return end === -1 ? undefined : lines.slice(1, end);
}

export const FRONTMATTER_SOURCE = /^source:\s*(['"]?)([^'"\s#]*)\1\s*(?:#.*)?$/;
export const MODULE_SOURCE =
	/^export const source(?:\s*:\s*string)?\s*=\s*(['"])([^'"]*)\1\s*;?\s*(?:\/\/.*)?$/;

/*
 * The hash a translation records. Read as text, not through a YAML parser: an all-digit hash, or
 * one shaped like `12e3456789ab`'s digits-e-digits, is a number to YAML, and a parsed value would
 * compare unequal to the very hash it was written from.
 */
export function recordedSource(
	translation: Translation,
	text: string
): string | undefined {
	if (translation.kind === 'messages') {
		for (const line of text.split(/\r?\n/)) {
			const match = line.match(MODULE_SOURCE);
			if (match) return match[2];
		}
		return undefined;
	}
	for (const line of frontmatterLines(text) ?? []) {
		const match = line.match(FRONTMATTER_SOURCE);
		if (match) return match[2];
	}
	return undefined;
}
