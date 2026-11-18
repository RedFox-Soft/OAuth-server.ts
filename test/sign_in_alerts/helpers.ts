import {
	batchOf,
	foxtrust,
	seedFoxTrustKey
} from '../address_lookup/helpers.ts';
import { mailOn } from '../two_step_page/helpers.ts';
import {
	PASSWORD,
	PersonBrowser,
	from,
	typePassword
} from '../person_activity/helpers.ts';
import { forgetLookupsForTests } from 'lib/address_lookup/lookups.ts';
import { resetSentEmails, sentEmails } from 'lib/mail/mailer.ts';
import { flushPersonActivityNow } from 'lib/person_activity/flush.ts';

/*
 * Emails about a new sign-in (specs/138) as their owners meet them: a person or an administrator signs in through
 * the real screens from an address and a browser this file states; FoxTrust's batch answers a network owner per
 * address range; the server writes what it held, decides and sends; the test mailer keeps what was sent.
 */

export const HOME = '203.0.113.7';
export const HOME_OTHER_IP = '203.0.113.200';
export const HOSTING = '198.51.100.4';

export const CHROME_ON_WINDOWS =
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
export const FIREFOX_ON_LINUX =
	'Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0';

/* 203.0.113.0/24 is one network, 198.51.100.0/24 another. */
function owner(ip: string) {
	const hosting = ip.startsWith('198.51.100.');
	return {
		ip,
		network: hosting
			? { asn: 64501, org: 'Example Hosting', asCountry: 'NL' }
			: { asn: 64500, org: 'Home Net', asCountry: 'DE' },
		subdivisions: hosting
			? [{ isoCode: 'NH', names: { en: 'North Holland' } }]
			: [{ isoCode: 'BY', names: { en: 'Bavaria' } }],
		city: { names: { en: hosting ? 'Amsterdam' : 'Munich' } }
	};
}

/* Mail on, FoxTrust answering, nothing sent yet. */
export async function ready(): Promise<void> {
	resetSentEmails();
	forgetLookupsForTests();
	await mailOn();
	const fake = foxtrust();
	fake.batch = (ips) => batchOf(ips.map(owner));
	await seedFoxTrustKey();
}

/* A whole sign-in from `address` with `userAgent`, written by the server's flush. */
export async function signInFrom(
	email: string,
	client: string,
	address: string,
	userAgent: string = CHROME_ON_WINDOWS,
	password: string = PASSWORD
): Promise<string> {
	from(address);
	const landed = await typePassword(
		new PersonBrowser(userAgent),
		email,
		password,
		client
	);
	await flushPersonActivityNow();
	return landed.url;
}

/* What the test mailer kept for `to`. */
export function mailsTo(to: string) {
	return sentEmails.filter((mail) => mail.to === to);
}

export function newSignInMailsTo(to: string) {
	return mailsTo(to).filter(
		(mail) =>
			mail.subject.startsWith('New sign-in') ||
			mail.subject.startsWith('Новый вход') ||
			mail.subject.includes('有新的登录')
	);
}

/* The "This wasn't me" link in an email, as the person's mail client shows it. */
export function notMeLinkIn(mail: { text: string }): string {
	const found = /https?:\/\/\S+\/account\/not-me\?token=[A-Za-z0-9_%-]+/.exec(
		mail.text
	);
	if (!found) throw new Error(`no This wasn't me link in:\n${mail.text}`);
	return found[0];
}
