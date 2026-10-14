import type { Language } from '../../languages.js';
import type { Shape } from '../../message.js';
import { en } from './en.js';
import { ru } from './ru.js';
import { zhHans } from './zh-Hans.js';

export type PlainTexts = Shape<typeof en>;

export const PLAIN_TEXTS: Record<Language, PlainTexts> = {
	en,
	ru,
	'zh-Hans': zhHans
};

export const TEXTS = PLAIN_TEXTS;
