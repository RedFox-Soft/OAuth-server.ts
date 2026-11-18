import { getPersonActivityStore, getUserStore } from '../adapters/index.js';
import type { User, UserBucket } from '../adapters/types.js';
import { ADMIN_BUCKET_ID } from '../admin/consts.js';
import { superAdminIds } from '../admin/super_admins.js';
import { ISSUER } from '../configs/env.js';
import { deliver } from '../mail/mailer.js';
import { signInReportedEmail } from '../mail/templates/sign_in_reported.js';
import { signInWords } from './alerts.js';

/*
 * An administrator said a sign-in was not theirs (specs/138 FR-010): every other active super administrator with an
 * address is told who, when and from where. Never awaited by anything that could fail because of it; a failed
 * delivery is logged by count only.
 */
export async function reportToSuperAdministrators(
	administrator: User,
	bucket: UserBucket,
	signInId: string | undefined
): Promise<void> {
	try {
		const ids = (await superAdminIds()).filter(
			(id) => id !== administrator._id
		);
		if (ids.length === 0) return;
		const recipients = (
			await getUserStore(ADMIN_BUCKET_ID).findMany(ids)
		).filter((user) => user.active && !!user.email);
		const { rows } = await getPersonActivityStore().listForPerson(
			bucket._id,
			administrator._id,
			{ kind: 'signIn', outcome: 'let_in', limit: 50, now: new Date() }
		);
		const row = rows.find((candidate) => candidate._id === signInId);
		const words = row
			? await signInWords(row, bucket, 'en')
			: { app: 'Console', browser: null, place: null, network: null };
		const message = signInReportedEmail({
			administrator: administrator.email,
			at: row?.firstAt ?? new Date(),
			app: words.app,
			browser: words.browser,
			place: words.place,
			network: words.network,
			consoleUrl: `${ISSUER}/admin/administrators/sign-ins/${encodeURIComponent(administrator._id)}`
		});
		for (const recipient of recipients) {
			await deliver({ to: recipient.email, ...message }).catch(
				(error: unknown) => {
					console.error(
						'a reported sign-in was not mailed to a super administrator',
						{
							error
						}
					);
				}
			);
		}
	} catch (error) {
		console.error('a reported sign-in was not mailed', { error });
	}
}
