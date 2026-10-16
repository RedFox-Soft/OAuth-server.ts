import nodemailer from 'nodemailer';
import { getSmtpSettingsStore } from '../adapters/index.js';
import type { SmtpSettings } from '../adapters/types.js';
import type { Language } from '../i18n/languages.js';

export interface OutgoingEmail {
	to: string;
	subject: string;
	html: string;
	text: string;
	// Set by the end-user templates only; an administrator's email declares no language, as before.
	language?: Language;
}

/* What an end-user template renders: everything but the recipient, always in a declared language. */
export type RenderedEmail = Required<Omit<OutgoingEmail, 'to'>>;

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
			: undefined,
		/*
		 * Several sends are awaited inside a request, the console's test among them. Left at nodemailer's
		 * defaults (two minutes to connect, ten of socket silence) an unreachable server held that request
		 * for minutes before saying anything.
		 */
		connectionTimeout: 15_000,
		greetingTimeout: 15_000,
		socketTimeout: 30_000
	});

	try {
		await transport.sendMail({
			from: smtp.fromName
				? `${smtp.fromName} <${smtp.fromEmail}>`
				: smtp.fromEmail,
			to: email.to,
			subject: email.subject,
			text: email.text,
			html: email.html,
			...(email.language
				? { headers: { 'Content-Language': email.language } }
				: {})
		});
	} catch (err) {
		/*
		 * Logged here, the one place every message passes, because most callers cannot say why: the
		 * password reset hides a failure from the requester, verification turns it into a bare outcome, and
		 * an operator who saw "no mail arrived" had nothing to read. No recipient, which is personal data.
		 */
		console.error(
			`mail could not be delivered: ${describeDeliveryFailure(err)}`
		);
		throw err;
	}
}

/*
 * Why a send failed, in the mail server's own words where it gave any: its reply line ("535 5.7.8
 * Authentication failed"), else the transport's message, with nodemailer's code (EAUTH, EENVELOPE,
 * ECONNECTION, ETIMEDOUT) after it. Shown to a super administrator and written to the log, and safe for
 * both: a server's reply never echoes the password, and nodemailer's own messages name only host and port.
 */
export function describeDeliveryFailure(err: unknown): string {
	if (!(err instanceof Error)) return String(err).slice(0, 500);
	const { code, response } = err as Error & {
		code?: unknown;
		response?: unknown;
	};
	const said =
		typeof response === 'string' && response.trim()
			? response.trim()
			: err.message;
	const described =
		typeof code === 'string' && !said.includes(code)
			? `${said} (${code})`
			: said;
	return described.slice(0, 500);
}
