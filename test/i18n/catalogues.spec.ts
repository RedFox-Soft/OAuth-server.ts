/*
 * Every text an end user can be shown exists in every language, as the same sentence with the same slots.
 *
 * A missing key would show the English fallback in the middle of a Russian page; a translation that dropped
 * `{app}` would hide which application is asking for access. Both are proved over the catalogues as they are
 * on disk, so a surface added later is held to this without anyone remembering to list it.
 */

import { readdirSync } from 'node:fs';
import { join } from 'node:path';

import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.js';
import {
	FORMAT_LOCALE,
	SUPPORTED_LANGUAGES,
	type Language
} from 'lib/i18n/languages.ts';
import { placeholders } from 'lib/i18n/message.tsx';

const TEXTS_DIR = join(import.meta.dir, '..', '..', 'lib', 'i18n', 'texts');
const surfaces = readdirSync(TEXTS_DIR, { withFileTypes: true })
	.filter((entry) => entry.isDirectory())
	.map((entry) => entry.name);

type Node = string | { readonly [key: string]: Node };

function isPlural(node: Node): node is Record<string, string> {
	return typeof node === 'object' && typeof node.other === 'string';
}

function leaves(
	node: Node,
	path: string[] = []
): Array<[string, string | Record<string, string>]> {
	if (typeof node === 'string' || isPlural(node))
		return [[path.join('.'), node]];
	return Object.entries(node).flatMap(([key, child]) =>
		leaves(child, [...path, key])
	);
}

function slotsOf(entry: string | Record<string, string>): string[] {
	const templates = typeof entry === 'string' ? [entry] : Object.values(entry);
	return [...new Set(templates.flatMap((t) => [...placeholders(t)]))].sort();
}

const cases = await Promise.all(
	surfaces.map(async (surface) => {
		const module = (await import(join(TEXTS_DIR, surface, 'index.ts'))) as {
			TEXTS: Record<Language, Node>;
		};
		return [surface, module.TEXTS] as const;
	})
);

describe('end-user text catalogues', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('exist for at least the surfaces end users see', () => {
		for (const surface of [
			'consent',
			'signIn',
			'pages',
			'plain',
			'account',
			'email'
		]) {
			expect(surfaces).toContain(surface);
		}
	});

	for (const [surface, texts] of cases) {
		const english = new Map(leaves(texts.en));

		for (const language of SUPPORTED_LANGUAGES) {
			const translated = new Map(leaves(texts[language]));
			const categories = new Intl.PluralRules(
				FORMAT_LOCALE[language]
			).resolvedOptions().pluralCategories;

			it(`${surface} in ${language} has exactly the English entries`, () => {
				expect([...translated.keys()].sort()).toEqual(
					[...english.keys()].sort()
				);
			});

			it(`${surface} in ${language} keeps every slot of every English entry`, () => {
				const mismatched = [...english].filter(([key, entry]) => {
					const other = translated.get(key);
					return (
						other === undefined ||
						slotsOf(other).join() !== slotsOf(entry).join()
					);
				});
				expect(mismatched.map(([key]) => key)).toEqual([]);
			});

			it(`${surface} in ${language} has every plural form the language uses, and no other`, () => {
				const wrong = [...english].filter(([key, entry]) => {
					const other = translated.get(key);
					if (typeof entry === 'string') return typeof other !== 'string';
					return (
						typeof other !== 'object' ||
						Object.keys(other).sort().join() !== [...categories].sort().join()
					);
				});
				expect(wrong.map(([key]) => key)).toEqual([]);
			});

			it(`${surface} in ${language} has no empty text`, () => {
				const empty = [...translated].filter(([, entry]) =>
					(typeof entry === 'string' ? [entry] : Object.values(entry)).some(
						(t) => t.trim() === ''
					)
				);
				expect(empty.map(([key]) => key)).toEqual([]);
			});
		}
	}
});
