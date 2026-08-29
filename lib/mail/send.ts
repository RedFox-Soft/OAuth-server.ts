import type { VerificationMethod } from '../adapters/types.js';
import { deliver } from './mailer.js';
import { groupInvitationEmail } from './templates/group_invitation.js';
import { passwordResetEmail } from './templates/password_reset.js';
import {
	verificationLinkEmail,
	verificationCodeEmail
} from './templates/verification.js';

interface SendParams {
	email: string;
	appName: string;
	method: VerificationMethod;
	// Present for the link method: the fully-qualified https verification URL.
	verifyUrl?: string;
	// Present for the code method: the plaintext 6-digit code (never persisted).
	code?: string;
}

// Renders and delivers the standard verification email for the bucket's method. Throws
// on delivery failure so the caller can leave the account unverified and offer a retry
// (FR-013).
export async function sendVerificationEmail(params: SendParams): Promise<void> {
	const { email, appName, method, verifyUrl, code } = params;
	const message =
		method === 'code'
			? verificationCodeEmail({ appName, code: code ?? '' })
			: verificationLinkEmail({ appName, verifyUrl: verifyUrl ?? '' });
	await deliver({ to: email, ...message });
}

interface ResetSendParams {
	email: string;
	appName: string;
	// Fully-qualified https URL carrying the single-use reset token.
	resetUrl: string;
}

/*
 * Renders and delivers the password-reset email. Throws on delivery failure like its verification
 * counterpart — but the reset caller deliberately swallows that throw, because a visible send failure
 * would only ever be visible for an address that *does* have an account (FR-006).
 */
export async function sendPasswordResetEmail(
	params: ResetSendParams
): Promise<void> {
	const { email, appName, resetUrl } = params;
	await deliver({ to: email, ...passwordResetEmail({ appName, resetUrl }) });
}

/*
 * Delivers an invitation into an administrative group.
 *
 * Throws on delivery failure, and the caller does NOT swallow it — the opposite of the password-reset
 * caller above. There the throw is hidden because a visible failure would only ever be visible for an
 * address that has an account, which is an enumeration oracle. Here the sender is an authenticated
 * owner inviting somebody deliberately: they need to know the mail did not go, and there is nothing
 * to leak, because they already chose the address.
 */
export async function sendGroupInvitationEmail(params: {
	email: string;
	appName: string;
	groupName: string;
	invitedByEmail: string;
	acceptUrl: string;
	createsAccount: boolean;
}): Promise<void> {
	const { email, ...rest } = params;
	await deliver({ to: email, ...groupInvitationEmail(rest) });
}
