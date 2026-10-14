import type { Language } from '../../languages.js';
import type { Shape } from '../../message.js';
import { en } from './en.js';
import { ru } from './ru.js';
import { zhHans } from './zh-Hans.js';

export type EmailTexts = Shape<typeof en>;

export const EMAIL_TEXTS: Record<Language, EmailTexts> = {
	en,
	ru,
	'zh-Hans': zhHans
};

export const TEXTS = EMAIL_TEXTS;
