import { expect } from 'bun:test';

import { getBucketStore, getSmtpSettingsStore } from 'lib/adapters/index.ts';
import type { SmtpSettings, UserBucket } from 'lib/adapters/types.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { hotp, stepFor } from 'lib/totp/code.ts';
import { decodeBase32 } from 'lib/totp/base32.ts';
import epochTime from 'lib/helpers/epoch_time.ts';
import { sentEmails, type OutgoingEmail } from 'lib/mail/mailer.ts';
import { present } from '../shape.ts';
import {
	Browser,
	defaultBucket,
	PASSWORD,
	person,
	signInThroughPage,
	textOf,
	xsrfFrom
} from '../connected_apps/helpers.ts';

export { Browser, PASSWORD, person, textOf, xsrfFrom };

export const PAGE = '/account/security';

const MAIL: SmtpSettings = {
	host: 'smtp.example.test',
	port: 587,
	secure: false,
	username: '',
	password: '',
	fromName: 'Acme',
	fromEmail: 'no-reply@example.test'
};

/* Mail delivery as an operator configured it; under NODE_ENV=test the mailer captures instead of sending. */
export async function mailOn(on = true): Promise<void> {
	await getSmtpSettingsStore().set(
		on ? MAIL : { ...MAIL, host: '', fromEmail: '' }
	);
}

/* The default bucket the config's client signs people in to, with the sign-in settings a case needs. */
export async function project(
	settings: Partial<
		Pick<UserBucket, 'totpRequired' | 'totpSelfService' | 'passwordLogin'>
	> = {}
): Promise<UserBucket> {
	await defaultBucket();
	forgetBucketAddresses();
	const updated = await getBucketStore().update(DEFAULT_BUCKET_ID, {
		totpRequired: false,
		totpSelfService: undefined,
		passwordLogin: true,
		...settings
	});
	return present(updated, 'the default bucket');
}

/* A person signed in with their password through the security page, as they would. */
export async function signedIn(): Promise<{
	browser: Browser;
	email: string;
	accountId: string;
}> {
	const { email, accountId } = await person();
	const browser = new Browser();
	const landed = await signInThroughPage(browser, email);
	expect(landed.status).toBe(200);
	return { browser, email, accountId };
}

export function mailsTo(address: string): OutgoingEmail[] {
	return sentEmails.filter((m) => m.to.toLowerCase() === address.toLowerCase());
}

/* The link in the newest mail to this address that leads to `path`. */
export function linkIn(address: string, path: string): string {
	const mail = present(mailsTo(address).at(-1), `a mail to ${address}`);
	const found = mail.text
		.split(/\s+/)
		.find((word) => /^https?:\/\//.test(word) && word.includes(path));
	return present(found, `a ${path} link in "${mail.subject}"`);
}

/* The key the page shows, read back as a secret: the authenticator app's view of it. */
export function keyFrom(html: string): string {
	const shown = present(
		/data-key="([A-Z2-7 ]+)"/.exec(html)?.[1],
		'the key on the page'
	);
	return shown.replace(/ /g, '');
}

export function codeFor(secret: string, at = epochTime()): string {
	return hotp(decodeBase32(secret), stepFor(at));
}

/* The page as the person sees it, and the anti-forgery value its forms carry. */
export async function openPage(
	browser: Browser,
	query = ''
): Promise<{ response: Response; html: string; xsrf: string }> {
	const response = await browser.request(`${PAGE}${query}`);
	const html = await response.text();
	return { response, html, xsrf: xsrfFrom(html) };
}

/* Starts an enrolment from the page and follows the mailed link in the same browser; answers the key shown. */
export async function startAndFollow(
	browser: Browser,
	email: string
): Promise<{ key: string; xsrf: string }> {
	const { xsrf } = await openPage(browser);
	const started = await browser.post(PAGE, { action: 'start', xsrf });
	expect(started.status).toBe(303);
	expect(started.headers.get('location')).toContain('sent=enrol');
	await browser.open(linkIn(email, '/account/security/link'));
	const offered = await openPage(browser);
	return { key: keyFrom(offered.html), xsrf: offered.xsrf };
}

/* The whole enrolment, as a person does it; answers the secret their app now holds. */
export async function enrol(browser: Browser, email: string): Promise<string> {
	const { key, xsrf } = await startAndFollow(browser, email);
	const done = await browser.post(PAGE, {
		action: 'confirm',
		xsrf,
		code: codeFor(key)
	});
	expect(done.headers.get('location')).toContain('done=on');
	return key;
}
