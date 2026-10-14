import type { Language } from '../../languages.js';
import { plural, text, type Shape } from '../../message.js';
import { en } from './en.js';
import { ru } from './ru.js';
import { zhHans } from './zh-Hans.js';

export type SignInTexts = Shape<typeof en>;

export const SIGN_IN_TEXTS: Record<Language, SignInTexts> = {
	en,
	ru,
	'zh-Hans': zhHans
};

export const TEXTS = SIGN_IN_TEXTS;

/* "Use at least N characters." in the reader's language, with the plural form N needs. */
export function passwordTooShort(language: Language, minimum: number): string {
	return text(
		plural(SIGN_IN_TEXTS[language].errors.passwordTooShort, minimum, language),
		{ count: minimum }
	);
}
