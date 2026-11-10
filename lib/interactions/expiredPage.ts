import { page } from './plainPage.js';
import { foxVar } from '../html/theme/palette.js';
import type { Language } from '../i18n/languages.js';
import { html, text } from '../i18n/message.js';
import { PLAIN_TEXTS } from '../i18n/texts/plain/index.js';

/*
 * A sign-in page asked for after its sign-in is gone (specs/127 FR-022): the hour ran out, the browser lost its cookie,
 * or the address was never one of its sign-ins. The same page for all three, as the guard gives the same refusal for
 * all three, so the answer does not say whether the sign-in existed. The application cannot be named: it went with the
 * sign-in. Plain, with no action, because the only way forward starts at the application.
 */
export function signInExpiredPage(language: Language): Response {
	const t = PLAIN_TEXTS[language].signInExpired;
	return page(
		text(t.title),
		`<h2 style="color:${foxVar('text')};">${html(t.title)}</h2><p style="color:${foxVar('text-secondary')};">${html(t.body)}</p>`,
		400,
		{ language }
	);
}
