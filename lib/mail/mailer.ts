import nodemailer from 'nodemailer';
import { getSmtpSettingsStore } from '../adapters/index.js';
import type { SmtpSettings } from '../adapters/types.js';

export interface OutgoingEmail {
	to: string;
	subject: string;
	html: string;
	text: string;
}

export class MailNotConfiguredError extends Error {
	constructor() {
		super('SMTP is not configured');
	}
}

// Under NODE_ENV=test the mailer never touches the network: every message is pushed
// here so integration specs can assert on what "was sent" (subject, recipient, and the
// verification link/code embedded in the body).
export const sentEmails: OutgoingEmail[] = [];

export function resetSentEmails(): void {
	sentEmails.length = 0;
}

const isTest = process.env.NODE_ENV === 'test';

async function configuredSmtp(): Promise<SmtpSettings | null> {
	const smtp = await getSmtpSettingsStore().get();
	return smtp && smtp.host && smtp.fromEmail ? smtp : null;
}

/*
 * Whether a message could be sent at all, by the same test `deliver` applies, so a setting that refuses to
 * turn on without mail and the send that would fail without it cannot disagree. Reads the store even under
 * NODE_ENV=test — the test capture below says nothing about whether an operator configured anything.
 */
export async function mailDeliveryConfigured(): Promise<boolean> {
	return (await configuredSmtp()) !== null;
}

export async function deliver(email: OutgoingEmail): Promise<void> {
	if (isTest) {
		sentEmails.push(email);
		return;
	}

	const smtp = await configuredSmtp();
	if (!smtp) {
		throw new MailNotConfiguredError();
	}

	// Built per send so a settings change takes effect without a restart.
	const transport = nodemailer.createTransport({
		host: smtp.host,
		port: smtp.port,
		secure: smtp.secure,
		auth: smtp.username
			? { user: smtp.username, pass: smtp.password }
			: undefined
	});

	await transport.sendMail({
		from: smtp.fromName
			? `${smtp.fromName} <${smtp.fromEmail}>`
			: smtp.fromEmail,
		to: email.to,
		subject: email.subject,
		text: email.text,
		html: email.html
	});
}
