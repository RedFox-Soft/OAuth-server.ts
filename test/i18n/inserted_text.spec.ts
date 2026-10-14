/*
 * Text an application supplies is a value inside a translated sentence, never part of the sentence.
 */

import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.js';
import { visible } from '../page_text.js';
import { consentServer } from 'lib/interactions/serverRender.tsx';
import { emptyConsentView } from 'lib/interactions/consentView.ts';
import { SUPPORTED_LANGUAGES } from 'lib/i18n/languages.ts';
import { text as fill } from 'lib/i18n/message.tsx';
import { CONSENT_TEXTS } from 'lib/i18n/texts/consent/index.ts';

// A slot name, markup and a right-to-left override: each would change the sentence if it were read as one.
const HOSTILE = '{app} <b>bold</b> \u202Eevil';

async function consentFor(language: (typeof SUPPORTED_LANGUAGES)[number]) {
	const response = await consentServer(
		{
			...emptyConsentView('uid-1'),
			client: { name: HOSTILE, tier: 'self-registered' }
		},
		{ language }
	);
	return response.text();
}

/**
 * @proves An application cannot rewrite the consent sentence that names it, in any language: its name is
 * shown exactly as registered, isolated from the text around it, and never parsed as markup or as a slot.
 */
describe('an application’s name inside a translated consent sentence', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	for (const language of SUPPORTED_LANGUAGES) {
		it(`is shown literally and isolated in ${language}`, async () => {
			const html = await consentFor(language);
			const headline = CONSENT_TEXTS[language].headline.app;
			const [before, after] = headline.split('{app}');

			expect(html).toContain(
				'<bdi>{app} &lt;b&gt;bold&lt;/b&gt; \u202Eevil</bdi>'
			);
			expect(html).not.toContain('<b>bold</b>');
			expect(visible(html)).toContain(`${before}${HOSTILE}${after}`);
			expect(visible(html)).toContain(fill(headline, { app: HOSTILE }));
		});
	}
});
