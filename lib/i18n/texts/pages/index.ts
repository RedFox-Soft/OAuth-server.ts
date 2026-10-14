import type { Language } from '../../languages.js';
import type { Shape } from '../../message.js';
import { en } from './en.js';
import { ru } from './ru.js';
import { zhHans } from './zh-Hans.js';

export type PagesTexts = Shape<typeof en>;

export const PAGES_TEXTS: Record<Language, PagesTexts> = {
	en,
	ru,
	'zh-Hans': zhHans
};

export const TEXTS = PAGES_TEXTS;
