import { useMemo } from 'react';
import { request } from '../../frame/request.js';
import { useFeedback } from '../../frame/feedback.js';
import { useConfirm } from '../../frame/confirm.js';
import { usersApi, type EndUser } from './endUser.js';

/*
 * The acts on one person that ask a question and send one request, shared by the users table's row menu
 * and the person's page so both ask the same question in the same words. Each answers whether it was done.
 * The ones that need a form of their own — set password, lock, change email, hand over — are dialogs.
 */
export function useUserActions(bucketId: string) {
	const feedback = useFeedback();
	const confirm = useConfirm();
	return useMemo(() => {
		async function send(
			method: string,
			user: EndUser,
			path: string,
			body?: unknown
		): Promise<boolean> {
			const result = await request(
				method,
				`${usersApi(bucketId, user._id)}${path}`,
				body
			);
			if (!result.ok) {
				// The server's own reason: a partial sweep names the areas whose records survived.
				feedback.failed(result);
				return false;
			}
			return true;
		}

		return {
			async signOut(user: EndUser) {
				const agreed = await confirm('user.signOut', {
					target: user.email,
					consequences: [
						'Every session and token ends at once and relying parties are told.',
						'The account stays active: they can sign in again, and will be asked to consent again.'
					]
				});
				if (!agreed || !(await send('POST', user, '/sign-out'))) return false;
				feedback.done(`${user.email} signed out everywhere.`);
				return true;
			},

			async unlock(user: EndUser) {
				const lock = user.lockedLocally;
				const agreed = await confirm('user.unlock', {
					target: user.email,
					consequences: [
						...(lock
							? [
									`Locked ${new Date(lock.at).toLocaleString()}${lock.byEmail ? ` by ${lock.byEmail}` : ''}: ${lock.reason}`
								]
							: []),
						'They can sign in again at once. Unlock only once whatever the lock was for has been dealt with.'
					]
				});
				if (!agreed || !(await send('POST', user, '/unlock'))) return false;
				feedback.done(`User ${user.email} unlocked.`);
				return true;
			},

			async resetTotp(user: EndUser) {
				const agreed = await confirm('user.totp.reset', {
					target: user.email,
					consequences: [
						'Their current authenticator stops working immediately.',
						'They are signed out everywhere.',
						'They set up a new one at their next sign-in.'
					]
				});
				if (!agreed || !(await send('DELETE', user, '/totp'))) return false;
				feedback.done(`Authenticator of ${user.email} reset.`);
				return true;
			},

			async deactivate(user: EndUser) {
				const agreed = await confirm('user.deactivate', {
					target: user.email,
					consequences: [
						'They cannot sign in, and every session and token they hold ends.',
						'Their account, groups and claims are kept; Activate lets them in again.'
					]
				});
				if (!agreed || !(await send('PATCH', user, '', { active: false }))) {
					return false;
				}
				feedback.done(`User ${user.email} deactivated.`);
				return true;
			},

			async activate(user: EndUser) {
				if (!(await send('PATCH', user, '', { active: true }))) return false;
				feedback.done(`User ${user.email} activated.`);
				return true;
			},

			async remove(user: EndUser) {
				const agreed = await confirm('user.delete', {
					target: user.email,
					consequences: [
						'Their sign-in sessions, consents and every issued token are destroyed immediately — they are signed out everywhere.',
						'The account cannot be restored.'
					]
				});
				if (!agreed || !(await send('DELETE', user, ''))) return false;
				feedback.done(`User ${user.email} deleted.`);
				return true;
			},

			async resendVerification(user: EndUser) {
				if (!(await send('POST', user, '/verification'))) return false;
				feedback.done(`Verification message sent to ${user.email}.`);
				return true;
			},

			// specs/089: the person chooses their own password from a link that also proves the address.
			async invite(user: EndUser) {
				const agreed = await confirm('user.invite', {
					target: user.email,
					consequences: [
						'They get a message with a link to choose their own password. The link works for 7 days, and opening it confirms their address.',
						'Any earlier invitation or password-reset link for them stops working.',
						...(user.passwordSet
							? [
									'They already have a password: it stops working once they choose a new one.'
								]
							: [])
					]
				});
				if (!agreed || !(await send('POST', user, '/invitation'))) return false;
				feedback.done('Invitation sent. The link works for 7 days.');
				return true;
			},

			async markVerified(user: EndUser) {
				const agreed = await confirm('user.verified.mark', {
					target: user.email,
					consequences: [
						'Only do this once you have confirmed they control this address some other way.',
						'A verification message already sent to them stops working.'
					]
				});
				if (!agreed || !(await send('POST', user, '/verified'))) return false;
				feedback.done(`${user.email} marked as verified.`);
				return true;
			}
		};
	}, [bucketId, feedback, confirm]);
}

export type UserActions = ReturnType<typeof useUserActions>;
