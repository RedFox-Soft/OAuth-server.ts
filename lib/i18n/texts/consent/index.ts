import type { Language } from '../../languages.js';
import type { Shape } from '../../message.js';
import { en } from './en.js';
import { ru } from './ru.js';
import { zhHans } from './zh-Hans.js';

export type ConsentTexts = Shape<typeof en>;

export const CONSENT_TEXTS: Record<Language, ConsentTexts> = {
	en,
	ru,
	'zh-Hans': zhHans
};

export const TEXTS = CONSENT_TEXTS;
