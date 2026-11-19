import type { Passkey } from '../adapters/types.js';
import { formatDate } from '../i18n/format.js';
import type { Language } from '../i18n/languages.js';
import { text } from '../i18n/message.js';
import { ACCOUNT_TEXTS } from '../i18n/texts/account/index.js';
import { deviceWords } from '../mail/templates/passkeys.js';

/*
 * What a passkey is called on its owner's page (specs/139 research R18): the name they gave it, else "{browser} on
 * {system}" from the closed sets it was made on, in the reader's language, else — both unknown — the day it was
 * added. Never "Passkey 1": a number tells two passkeys apart by nothing the person can see on their devices.
 */
export function passkeyName(
	passkey: Pick<Passkey, 'name' | 'createdOn' | 'createdAt'>,
	language: Language
): string {
	if (passkey.name !== undefined) return passkey.name;
	return (
		deviceWords(passkey.createdOn, language) ??
		text(ACCOUNT_TEXTS[language].passkeyAddedOn, {
			date: formatDate(language, new Date(passkey.createdAt).getTime())
		})
	);
}
