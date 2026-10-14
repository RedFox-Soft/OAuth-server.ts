/*
 * Every page an end user can be shown, in every language: it says which language it is in, in the document
 * and in the response, and no message slot is left unfilled.
 */

import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.js';
import { END_USER_PAGES } from '../end_user_pages.ts';
import { visible } from '../page_text.js';
import { SUPPORTED_LANGUAGES } from 'lib/i18n/languages.ts';

/**
 * @proves No end-user page, in any language, is shown without saying which language it is in — to a screen
 * reader through the document, to a cache through the response — or with a sentence missing the name or count
 * it was written around (WCAG 2.2 SC 3.1.1, RFC 9110 §8.5).
 */
describe('every end-user page in every language', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	for (const [name, , render] of END_USER_PAGES) {
		for (const language of SUPPORTED_LANGUAGES) {
			it(`declares ${language} and fills every slot on the ${name} page`, async () => {
				const response = await render(language);
				const html = await response.text();

				expect(/<html lang="([^"]+)"/.exec(html)?.[1]).toBe(language);
				expect(response.headers.get('content-language')).toBe(language);
				expect(response.headers.get('vary')).toContain('Accept-Language');
				expect(visible(html)).not.toMatch(/\{[a-zA-Z][a-zA-Z0-9]*\}/);
			});
		}
	}
});
