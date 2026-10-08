import type { LocaleKey } from '../data/seo.ts';
import { messagesFor } from './messages.ts';
import english from './messages/chrome/en.ts';

export type ChromeMessages = typeof english;

export function chrome(locale: LocaleKey): ChromeMessages {
	return messagesFor('chrome', english, locale);
}
