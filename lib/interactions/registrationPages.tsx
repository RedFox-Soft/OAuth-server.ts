/*
 * The two terminal registration refusals. They belong to the plain family rather than the antd shell
 * because neither has a form: there is nothing for the user to work in and nothing to hydrate, so a
 * client bundle and an inline props script would be payload for a page that only carries a sentence.
 *
 * The re-render after a password mismatch is deliberately *not* here — that one is the user's own form
 * coming back with their address still in it, which only the hydrated family can do.
 */

import { page } from './plainPage.js';
import { foxVar } from '../html/theme/palette.js';
import type { Language } from '../i18n/languages.js';
import { html } from '../i18n/message.js';
import { PLAIN_TEXTS } from '../i18n/texts/plain/index.js';

// Constants with nothing interpolated: the same refusal reaches the GET and the POST, and "identical
// whichever way you got here" is then a property of the function rather than a promise at two call sites.
export function registrationClosedPage(language: Language = 'en'): Response {
	const t = PLAIN_TEXTS[language].registration.closed;
	return page(
		t.title,
		`<h2 style="color:${foxVar('text')};">${html(t.heading)}</h2><p style="color:${foxVar('text-secondary')};">${html(t.body)}</p><p style="color:${foxVar('text-muted')}; font-size:13px;">${html(t.hint)}</p>`,
		403,
		{ language }
	);
}

/*
 * The account exists and is unverified by the time this renders, so the wording must neither claim the
 * sign-up failed nor invite the same address to register again — it is taken, by them.
 */
export function registrationSendFailedPage(
	language: Language = 'en'
): Response {
	const t = PLAIN_TEXTS[language].registration.sendFailed;
	return page(
		t.title,
		`<h2 style="color:${foxVar('text')};">${html(t.heading)}</h2><p style="color:${foxVar('text-secondary')};">${html(t.body)}</p>`,
		502,
		{ language }
	);
}
