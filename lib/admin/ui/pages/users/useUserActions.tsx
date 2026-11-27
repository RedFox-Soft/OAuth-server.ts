import { useMemo } from 'react';
import { request } from '../../frame/request.js';
import { useFeedback } from '../../frame/feedback.js';
import { useConfirm } from '../../frame/confirm.js';
import {
	usersApi,
	type EndUser,
	type PasskeysOfPerson,
	type PasskeyView
} from './endUser.js';

/*
 * What a revocation leaves the person (specs/140 contracts/console-and-mail.md), from the server's own rule
 * (lib/passkeys/ways_in.ts): their password and providers, and the passkeys that still sign in and are not being
 * revoked; or, when nothing is left, how they get back in.
 */
function remainingLines(
	of: PasskeysOfPerson,
	revoked: readonly PasskeyView[]
): string[] {
	const others = of.passkeys.filter(
		(passkey) =>
			passkey.state === 'works' &&
			!revoked.some((gone) => gone.id === passkey.id)
	).length;
	const ways = [
		...(of.ways.password ? ['a password'] : []),
		...of.ways.providers,
		...(others === 0
			? []
			: [others === 1 ? 'another passkey' : `${String(others)} other passkeys`])
	];
	if (ways.length > 0)
		return [`They can still sign in with: ${ways.join(', ')}.`];
	return [
		'They will have no way to sign in.',
		of.restore === 'self'
			? 'They can choose a password with “Forgot your password?” on the sign-in page.'
			: of.restore === 'admin'
				? 'You can set a password for them on this page.'
				: 'Nobody can restore their access until a way to sign in is added for them.'
	];
}

function mailLine(of: PasskeysOfPerson, all: boolean): string {
	return of.mailable
		? `We email them that ${all ? 'they were' : 'it was'} removed.`
		: "They have no confirmed address, so we can't email them.";
}

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

		/* A revocation's answer says whether the person was mailed; a mail that should have gone and did not is said. */
		async function revoked(
			user: EndUser,
			path: string,
			of: PasskeysOfPerson
		): Promise<boolean> {
			const result = await request<{ removed: number; mailed: boolean }>(
				'DELETE',
				`${usersApi(bucketId, user._id)}${path}`
			);
			if (!result.ok) {
				feedback.failed(result);
				return false;
			}
			feedback.done(
				of.mailable && !result.data.mailed
					? 'Revoked. The email to them could not be sent.'
					: 'Revoked.'
			);
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
						'Their authenticator app stops working immediately, and they are signed out everywhere.',
						'Until they set up a new one, their password alone signs them in. Anyone who knows it can sign in too.',
						'A new one needs a link we email them. We also email them that this one was removed.'
					]
				});
				if (!agreed || !(await send('DELETE', user, '/totp'))) return false;
				feedback.done(`Authenticator app of ${user.email} removed.`);
				return true;
			},

			/* One passkey, for a stolen or lost device; answers whether it was revoked. */
			async revokePasskey(
				user: EndUser,
				passkey: PasskeyView,
				of: PasskeysOfPerson
			) {
				const agreed = await confirm('user.passkey.revoke', {
					target: user.email,
					consequences: [
						'This passkey stops working immediately, and they are signed out everywhere.',
						...remainingLines(of, [passkey]),
						mailLine(of, false)
					]
				});
				if (!agreed) return false;
				return revoked(user, `/passkeys/${encodeURIComponent(passkey.id)}`, of);
			},

			/* Every passkey of the person, for a password manager account that was taken over. */
			async revokeAllPasskeys(user: EndUser, of: PasskeysOfPerson) {
				const count = of.passkeys.length;
				const agreed = await confirm('user.passkey.revokeAll', {
					target: `Revoke all ${String(count)} passkeys of ${user.email}?`,
					consequences: [
						'They all stop working immediately, and they are signed out everywhere.',
						...remainingLines(of, of.passkeys),
						mailLine(of, true)
					]
				});
				if (!agreed) return false;
				return revoked(user, '/passkeys', of);
			},

			async deactivate(user: EndUser) {
				const agreed = await confirm('user.deactivate', {
					target: user.email,
					consequences: [
						'They cannot sign in, and every session and token they hold ends.',
						'Their account, groups, claims and activity are kept; Activate lets them in again.'
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
						'Their activity — sign-ins and what apps answered them — is deleted too.',
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
			},

			async sendPasskeyLink(user: EndUser) {
				const agreed = await confirm('enduser.passkey.linkSend', {
					target: user.email,
					consequences: [
						`A 24-hour single-use passkey setup link is emailed to ${user.email}.`,
						'The link is delivered by email only and is never shown here.'
					]
				});
				if (!agreed || !(await send('POST', user, '/passkey-link')))
					return false;
				feedback.done(`Passkey setup link sent to ${user.email}.`);
				return true;
			}
		};
	}, [bucketId, feedback, confirm]);
}

export type UserActions = ReturnType<typeof useUserActions>;
