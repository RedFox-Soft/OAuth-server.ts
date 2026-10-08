import { sourceHash } from '../../src/i18n/source-hash.ts';
import {
	englishExists,
	frontmatterLines,
	listTranslations,
	readSite,
	recordedSource,
	type Translation
} from './translations.ts';

/*
 * Which translations were made from an older revision of their English file.
 *
 * Staleness only warns, for the reason comparison freshness only warns (scripts/seo/freshness.ts):
 * an English edit would otherwise block every build until somebody re-translated it, and the fix a
 * hurried contributor reaches for is to stamp the hash without translating anything — which
 * silences the page's own "English version is newer" notice too, the signal readers actually see.
 *
 * Two conditions fail, because neither is the passage of time; both are mistakes. A translation
 * whose English file is gone describes a page that no longer exists in English — renamed or
 * deleted — and goes on being published with nothing to be stale against. And a translated docs
 * page whose `sidebar.order` differs from the English page's puts the same pages in a different
 * order in each language, which a reader moving between them takes for a different set.
 */

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function sidebarOrder(text: string): unknown {
	const lines = frontmatterLines(text);
	if (!lines) return undefined;
	const data: unknown = Bun.YAML.parse(lines.join('\n'));
	if (!isRecord(data) || !isRecord(data.sidebar)) return undefined;
	return data.sidebar.order;
}

interface Finding {
	translation: Translation;
	detail: string;
}

function main(): void {
	const translations = listTranslations();
	const stale: Finding[] = [];
	const failures: Finding[] = [];

	for (const translation of translations) {
		if (!englishExists(translation)) {
			failures.push({
				translation,
				detail: `its English source ${translation.english} does not exist`
			});
			continue;
		}

		const text = readSite(translation.file);
		const recorded = recordedSource(translation, text);
		const current = sourceHash(translation.english);
		if (recorded === undefined) {
			stale.push({ translation, detail: 'records no source hash' });
		} else if (recorded !== current) {
			stale.push({
				translation,
				detail: `made from ${recorded}, ${translation.english} is now ${current}`
			});
		}

		if (translation.kind === 'docs') {
			const own = sidebarOrder(text);
			const english = sidebarOrder(readSite(translation.english));
			if (own !== english) {
				failures.push({
					translation,
					detail: `sidebar.order is ${String(own)}, the English page's is ${String(english)}`
				});
			}
		}
	}

	if (stale.length > 0) {
		console.warn(
			[
				`seo: ${stale.length} stale translation${stale.length === 1 ? '' : 's'} — bring each up to date, then \`bun run i18n:stamp <file>\``,
				...stale.map(
					({ translation, detail }) => `  ${translation.file}  ${detail}`
				)
			].join('\n')
		);
	}

	if (failures.length > 0) {
		console.error(
			`\nTranslation check failed: ${failures.length} problem${failures.length === 1 ? '' : 's'}\n`
		);
		for (const { translation, detail } of failures) {
			console.error(`  ${translation.file}  ${detail}`);
		}
		console.error('');
		process.exit(1);
	}

	console.log(
		`seo: ${translations.length} translations, ${stale.length} stale`
	);
}

main();
