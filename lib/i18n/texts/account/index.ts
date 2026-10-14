import type { Language } from '../../languages.js';
import type { Shape } from '../../message.js';
import { en } from './en.js';
import { ru } from './ru.js';
import { zhHans } from './zh-Hans.js';

export type AccountTexts = Shape<typeof en>;

export const ACCOUNT_TEXTS: Record<Language, AccountTexts> = {
	en,
	ru,
	'zh-Hans': zhHans
};

export const TEXTS = ACCOUNT_TEXTS;
