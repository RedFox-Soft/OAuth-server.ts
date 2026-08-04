import {
	sentEmails,
	resetSentEmails,
	type OutgoingEmail
} from '../lib/mail/mailer.js';

export { sentEmails, resetSentEmails };

export function lastEmail(): OutgoingEmail | undefined {
	return sentEmails[sentEmails.length - 1];
}

export function emailsTo(address: string): OutgoingEmail[] {
	return sentEmails.filter((e) => e.to.toLowerCase() === address.toLowerCase());
}

// Pull the first https verification link out of a captured email body.
export function extractVerifyUrl(email: OutgoingEmail): string | undefined {
	const match = email.text.match(/https?:\/\/\S*\/verify-email\S*/);
	return match?.[0];
}

// Pull the first https password-reset link out of a captured email body. Read from the text part for the
// same reason extractVerifyUrl is: it carries the bare URL with no markup to unpick.
export function extractResetUrl(email: OutgoingEmail): string | undefined {
	const match = email.text.match(/https?:\/\/\S*\/reset-password\S*/);
	return match?.[0];
}

// Pull the 6-digit code out of a captured code email body.
export function extractCode(email: OutgoingEmail): string | undefined {
	const match = email.text.match(/\b(\d{6})\b/);
	return match?.[1];
}
