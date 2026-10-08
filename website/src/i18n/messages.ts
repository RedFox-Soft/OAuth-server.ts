import { LOCALES, type LocaleKey } from '../data/seo.ts';
import { sourceHash } from './source-hash.ts';
import { isRich } from './types.ts';

/*
 * Message modules: one directory per page or component group under ./messages/, one file per
 * language. The English file is the source; a translation exports `source`, the hash of the English
 * file it was made from, and a default export typed `satisfies typeof en` so `astro check` rejects
 * a missing or an extra key.
 *
 * `satisfies` cannot see array lengths or the order of entries, so the loader checks the shape too:
 * a translation of a feature list that dropped one card would otherwise type-check and render a page
 * that silently says less than the English one.
 */

interface MessageModule {
	default: unknown;
	source?: string;
}

const modules = import.meta.glob<MessageModule>('./messages/*/*.ts', {
	eager: true
});

function modulePath(group: string, locale: LocaleKey): string {
	return `./messages/${group}/${locale}.ts`;
}

function sameShape(
	english: unknown,
	translated: unknown,
	path: string
): string | undefined {
	// A sentence may become rich text in another language, or stop being rich; both are sentences.
	const englishSentence = typeof english === 'string' || isRich(english);
	const translatedSentence =
		typeof translated === 'string' || isRich(translated);
	if (englishSentence || translatedSentence) {
		return englishSentence && translatedSentence
			? undefined
			: `${path}: a sentence on one side and a structure on the other`;
	}
	if (typeof english !== typeof translated)
		return `${path}: ${typeof translated} where English has ${typeof english}`;
	if (Array.isArray(english)) {
		if (!Array.isArray(translated)) return `${path}: not a list`;
		if (english.length !== translated.length)
			return `${path}: ${translated.length} entries where English has ${english.length}`;
		for (let i = 0; i < english.length; i++) {
			const problem = sameShape(english[i], translated[i], `${path}[${i}]`);
			if (problem) return problem;
		}
		return undefined;
	}
	if (typeof english === 'object' && english !== null) {
		const a = Object.keys(english).sort();
		const b = Object.keys(translated as object).sort();
		if (a.join() !== b.join())
			return `${path}: keys ${b.join(', ')} where English has ${a.join(', ')}`;
		for (const key of a) {
			const problem = sameShape(
				(english as Record<string, unknown>)[key],
				(translated as Record<string, unknown>)[key],
				`${path}.${key}`
			);
			if (problem) return problem;
		}
	}
	return undefined;
}

/*
 * The messages for one group in one language. English is returned as passed; a translation is read
 * from its module, which must exist for every language this build publishes.
 */
export function messagesFor<T>(
	group: string,
	english: T,
	locale: LocaleKey
): T {
	if (locale === 'en') return english;
	if (!LOCALES.some((candidate) => candidate.key === locale)) {
		throw new Error(
			`messages "${group}" requested in ${locale}, which this build does not publish`
		);
	}
	const module = modules[modulePath(group, locale)];
	if (!module) {
		throw new Error(
			`src/i18n/messages/${group}/${locale}.ts is missing; every published language needs it`
		);
	}
	const problem = sameShape(english, module.default, `${group}/${locale}`);
	if (problem)
		throw new Error(
			`Translation does not match the English messages — ${problem}`
		);
	// The module's default export is typed `satisfies typeof en` at its definition and its shape was
	// checked against the English value above; the glob import cannot carry that type through.
	return module.default as T;
}

/* Whether a translation was made from the English file as it is now (FR-017). */
export function isStale(group: string, locale: LocaleKey): boolean {
	if (locale === 'en') return false;
	const module = modules[modulePath(group, locale)];
	if (!module) return false;
	return module.source !== sourceHash(`src/i18n/messages/${group}/en.ts`);
}
