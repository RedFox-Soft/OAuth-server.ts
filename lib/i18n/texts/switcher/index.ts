import type { Language } from '../../languages.js';
import type { Shape } from '../../message.js';
import { en } from './en.js';
import { ru } from './ru.js';
import { zhHans } from './zh-Hans.js';

export type SwitcherTexts = Shape<typeof en>;

export const SWITCHER_TEXTS: Record<Language, SwitcherTexts> = {
	en,
	ru,
	'zh-Hans': zhHans
};

export const TEXTS = SWITCHER_TEXTS;
