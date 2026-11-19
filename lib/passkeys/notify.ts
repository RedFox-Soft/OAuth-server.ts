import type { User, UserBucket } from '../adapters/types.js';
import { emailLanguage } from '../i18n/resolve.js';
import { deliver } from '../mail/mailer.js';
import {
	passkeyNoticeEmail,
	type PasskeyNotice
} from '../mail/templates/passkeys.js';

/*
 * Tells the person about a passkey added to or removed from their account (specs/139 contracts/mails.md), at a
 * confirmed address only: the message names the account's security state, and an address nobody proved may be
 * someone else's. A notice that cannot be sent never fails what it reports — the passkey is added or removed either
 * way — and is logged without the address, which a mail server's error often repeats. Answers whether it was sent,
 * which an administrator's revocation reports (specs/140).
 */
export async function notifyPasskey(
	bucket: UserBucket,
	user: User,
	notice: PasskeyNotice
): Promise<boolean> {
	if (!user.verified || !user.email) return false;
	try {
		await deliver({
			to: user.email,
			...passkeyNoticeEmail(
				notice,
				{ service: bucket.displayName ?? bucket.name, email: user.email },
				emailLanguage(user)
			)
		});
		return true;
	} catch (error) {
		console.error('passkeys: a notice could not be sent', {
			accountId: user._id,
			kind: notice.kind,
			...failureOf(error)
		});
		return false;
	}
}

/* What a failed delivery may say in a log: its kind and the server's status, never its text, which can quote the address. */
function failureOf(error: unknown): {
	reason: string;
	code?: string;
	responseCode?: number;
} {
	if (!(error instanceof Error)) return { reason: typeof error };
	const code =
		'code' in error && typeof error.code === 'string' ? error.code : undefined;
	const responseCode =
		'responseCode' in error && typeof error.responseCode === 'number'
			? error.responseCode
			: undefined;
	return {
		reason: error.name,
		...(code === undefined ? {} : { code }),
		...(responseCode === undefined ? {} : { responseCode })
	};
}
