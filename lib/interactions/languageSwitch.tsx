/*
 * The one language control end users get (specs/097): a single button under the card that switches between
 * English and the visitor's own language, shown only when the visitor has a language other than English.
 * There is no menu of every language: the page already guessed the language from the browser and the
 * application, and this is the way out when the guess is wrong — the owner's decision.
 *
 * A form of its own, not a link and not part of the page's form: it posts nothing the person typed, and works
 * the same with scripts off, because it is the same markup either way. The server answers with a redirect
 * back to the page it names from a closed list (lib/interactions/index.ts), never to an address from the
 * request.
 */

import { useLanguage } from '../i18n/context.js';
import { esc } from '../html/escape.js';
import { foxVar } from '../html/theme/palette.js';
import { NATIVE_NAMES, type Language } from '../i18n/languages.js';
import { SWITCHER_TEXTS } from '../i18n/texts/switcher/index.js';

export const SWITCH_PAGES = [
	'login',
	'registration',
	'totp',
	'totp/enroll',
	'consent',
	'forgot-password'
] as const;

export type SwitchPage = (typeof SWITCH_PAGES)[number];

export interface SwitcherProps {
	uid: string;
	page: SwitchPage;
	/* The language the button switches to — English, or back to the visitor's own. */
	target: Language;
}

/* What the switch offers on a page in `language`, for a visitor whose own language is `alternative`. */
export function switcherFor(
	uid: string,
	page: SwitchPage,
	language: Language,
	alternative: Language | undefined
): SwitcherProps | undefined {
	if (alternative === undefined) return undefined;
	return { uid, page, target: language === 'en' ? alternative : 'en' };
}

const FORM_STYLE = 'display:flex; justify-content:center; margin:16px 0 0;';

// At least 24 × 24 CSS px (WCAG 2.2 SC 2.5.8), a link's colour, and the browser's own focus ring.
const BUTTON_STYLE = {
	minHeight: 24,
	minWidth: 24,
	padding: '2px 8px',
	background: 'transparent',
	border: 0,
	color: foxVar('link'),
	textDecoration: 'underline',
	cursor: 'pointer',
	fontSize: 14,
	fontFamily: 'inherit'
} as const;

export function LanguageSwitch({ uid, page, target }: SwitcherProps) {
	const T = SWITCHER_TEXTS[useLanguage()];
	return (
		<form
			method="post"
			action={`/ui/${uid}/language`}
			aria-label={T.label}
			style={{ display: 'flex', justifyContent: 'center', margin: '16px 0 0' }}
		>
			<input
				type="hidden"
				name="lang"
				value={target}
			/>
			<input
				type="hidden"
				name="page"
				value={page}
			/>
			<button
				type="submit"
				lang={target}
				style={BUTTON_STYLE}
			>
				{NATIVE_NAMES[target]}
			</button>
		</form>
	);
}

/* The same control for the plain pages, which are written as markup rather than rendered by React. */
export function languageSwitchHtml(
	{ uid, page, target }: SwitcherProps,
	language: Language
): string {
	const button = Object.entries(BUTTON_STYLE)
		.map(
			([key, value]) =>
				`${key.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`)}:${typeof value === 'number' ? `${value}px` : value}`
		)
		.join('; ');
	return `<form method="post" action="/ui/${esc(uid)}/language" aria-label="${esc(SWITCHER_TEXTS[language].label)}" style="${FORM_STYLE}"><input type="hidden" name="lang" value="${target}"/><input type="hidden" name="page" value="${page}"/><button type="submit" lang="${target}" style="${button}">${esc(NATIVE_NAMES[target])}</button></form>`;
}
