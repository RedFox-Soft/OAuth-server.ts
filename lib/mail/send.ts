import type { VerificationMethod } from '../adapters/types.js';
import { deliver } from './mailer.js';
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
