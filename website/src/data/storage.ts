import { loadExport } from './export.ts';
import { LOCALE_DEFINITIONS, type LocaleKey } from './seo.ts';

/*
 * How the site talks about the datastore, in one place, derived from the server.
 *
 * This exists because of a specific failure. When PostgreSQL shipped, the documentation pages were
 * updated by name from a task list and everything else was not: five comparison tables, the feature
 * grid and the home page went on saying the server stores its data in MongoDB, and the Zitadel
 * comparison offered "most teams already run PostgreSQL; fewer already run MongoDB" as a reason to
 * choose the competitor. Nothing failed, because prose is not checked against anything.
 *
 * So the sentence is computed from `docs-export.json`, whose `storage.backends` comes from
 * `lib/adapters/selectBackend.ts` — the module that actually makes the choice. A third backend
 * changes this text by existing. `scripts/seo/verify.ts` covers the copy that cannot be computed,
 * by failing any marketing or comparison page that names one production datastore and omits another.
 */

export interface StorageBackend {
	name: string;
	selectedBy: string;
	label: string;
}

export function storageBackends(): StorageBackend[] {
	return loadExport().storage.backends;
}

/** Just the words: `['PostgreSQL', 'MongoDB']`. */
export function backendLabels(): string[] {
	return storageBackends().map((backend) => backend.label);
}

/*
 * English keeps its hand-written joiner (no serial comma, which is the house style); a translation
 * joins with the language's own `Intl.ListFormat` — «или», «和» — rather than an English "or"
 * dropped into a Russian or Chinese sentence.
 */
function join(
	labels: string[],
	type: 'disjunction' | 'conjunction',
	locale: LocaleKey
): string {
	if (labels.length <= 1) return labels[0] ?? '';
	if (locale !== 'en') {
		return listParts(labels, type, locale)
			.map((part) => part.value)
			.join('');
	}
	const word = type === 'disjunction' ? 'or' : 'and';
	return `${labels.slice(0, -1).join(', ')} ${word} ${labels[labels.length - 1]}`;
}

/*
 * The language's own list, as parts, so a caller can wrap each name in a link. Chinese sets a Latin
 * word apart from the surrounding Han text with a space, which Intl.ListFormat does not do around
 * 和 / 或 (`PostgreSQL或MongoDB`), so the conjunction gets its spaces here. The enumeration comma 、
 * needs none.
 */
export function listParts(
	items: string[],
	type: 'disjunction' | 'conjunction',
	locale: LocaleKey
): { type: 'element' | 'literal'; value: string }[] {
	const parts = new Intl.ListFormat(LOCALE_DEFINITIONS[locale].lang, {
		type
	}).formatToParts(items);
	if (locale !== 'zh-cn') return parts;
	return parts.map((part) =>
		part.type === 'literal' && part.value.trim() !== '、'
			? { ...part, value: ` ${part.value.trim()} ` }
			: part
	);
}

/** `PostgreSQL or MongoDB` — for a sentence that offers a choice. */
export function backendChoice(locale: LocaleKey = 'en'): string {
	return join(backendLabels(), 'disjunction', locale);
}

/** `PostgreSQL, MongoDB and in-memory` — for a sentence that lists what ships. */
export function backendList(
	trailing?: string,
	locale: LocaleKey = 'en'
): string {
	return join(
		[...backendLabels(), ...(trailing ? [trailing] : [])],
		'conjunction',
		locale
	);
}
