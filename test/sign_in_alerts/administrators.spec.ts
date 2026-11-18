import { beforeAll, beforeEach, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { admin } from '../provisioning/helpers.ts';
import { Browser } from '../connected_apps/helpers.ts';
import { administrator } from '../admin_sign_ins/helpers.ts';
import {
	FIREFOX_ON_LINUX,
	HOME,
	HOME_OTHER_IP,
	HOSTING,
	mailsTo,
	newSignInMailsTo,
	notMeLinkIn,
	ready,
	signInFrom
} from './helpers.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';

const CONSOLE = 'admin-panel';

let max: Awaited<ReturnType<typeof administrator>>;
let olga: Awaited<ReturnType<typeof administrator>>;

/**
 * @proves An administrator is emailed by default about a console sign-in from a network or a browser their account
 * has not used in 90 days, with where and how but never the address; a new address inside a known network, or a first
 * sign-in with nothing to compare, sends nothing; a super administrator can turn it off.
 */
describe('an administrator signing in from somewhere new', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		await ready();
		max = await administrator();
		olga = await administrator('super');
	});

	it('is emailed about a new network, with the place and network but not the address', async () => {
		await signInFrom(max.email, CONSOLE, HOME);
		await signInFrom(max.email, CONSOLE, HOSTING);

		const [mail, ...more] = newSignInMailsTo(max.email);
		expect(more).toEqual([]);
		expect(mail.subject).toBe('New sign-in to the FoxAuth console');
		for (const shown of [
			'Signed in to: Console',
			'Amsterdam, North Holland',
			'Network: Example Hosting',
			'Chrome on Windows',
			'from this network'
		]) {
			expect(mail.text).toContain(shown);
		}
		expect(mail.text.includes(HOSTING)).toBe(false);
		expect(mail.html.includes(HOSTING)).toBe(false);
	});

	it('is not emailed about a new address inside a known network with a known browser', async () => {
		await signInFrom(max.email, CONSOLE, HOME);
		await signInFrom(max.email, CONSOLE, HOME_OTHER_IP);

		expect(newSignInMailsTo(max.email)).toEqual([]);
	});

	it('is emailed about a new browser, saying so', async () => {
		await signInFrom(max.email, CONSOLE, HOME);
		await signInFrom(max.email, CONSOLE, HOME, FIREFOX_ON_LINUX);

		const [mail, ...more] = newSignInMailsTo(max.email);
		expect(more).toEqual([]);
		expect(mail.text).toContain('from this browser');
		expect(mail.text).toContain('Firefox on Linux');
	});

	it('is not emailed about a first sign-in, with nothing to compare', async () => {
		await signInFrom(max.email, CONSOLE, HOSTING);

		expect(newSignInMailsTo(max.email)).toEqual([]);
	});

	it('is not emailed once a super administrator turns it off', async () => {
		const off = await admin(
			'PATCH',
			`/admin/api/projects/${ADMIN_BUCKET_ID}`,
			olga.cookie,
			{ newSignInAlerts: false }
		);
		expect(off.status).toBe(200);
		await signInFrom(max.email, CONSOLE, HOME);
		await signInFrom(max.email, CONSOLE, HOSTING);

		expect(newSignInMailsTo(max.email)).toEqual([]);
		await admin(
			'PATCH',
			`/admin/api/projects/${ADMIN_BUCKET_ID}`,
			olga.cookie,
			{ newSignInAlerts: true }
		);
	});
});

/**
 * @proves An administrator's "This wasn't me" opens a confirmation that changes nothing; confirming signs them out
 * of the console and every token, tells every other super administrator who, when and from where without the address,
 * and says to ask one of them for a new password.
 */
describe("an administrator's This wasn't me", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		await ready();
		max = await administrator();
		olga = await administrator('super');
		await signInFrom(max.email, CONSOLE, HOME);
		await signInFrom(max.email, CONSOLE, HOSTING);
	});

	it('changes nothing when opened', async () => {
		const link = notMeLinkIn(newSignInMailsTo(max.email)[0]);
		const opened = await new Browser().request(link);

		expect(opened.status).toBe(200);
		expect(await opened.text()).toContain('Sign out everywhere');
		expect((await admin('GET', '/admin/api/me', max.cookie)).status).toBe(200);
	});

	it('signs them out everywhere and tells the other super administrators', async () => {
		const link = new URL(notMeLinkIn(newSignInMailsTo(max.email)[0]));
		const token = link.searchParams.get('token') ?? '';
		const done = await new Browser().post(link.pathname, { token });
		const page = await done.text();

		expect(done.status).toBe(200);
		expect(page).toContain('Ask one of them to set a new password for you');
		expect((await admin('GET', '/admin/api/me', max.cookie)).status).toBe(401);
		const [told] = mailsTo(olga.email).filter((mail) =>
			mail.subject.includes('reported a sign-in')
		);
		expect(told.subject).toBe(
			`${max.email} reported a sign-in that wasn't theirs`
		);
		expect(told.text).toContain('Amsterdam, North Holland');
		expect(told.text.includes(HOSTING)).toBe(false);
		expect(mailsTo(max.email).map((mail) => mail.subject)).not.toContain(
			'Reset your password'
		);
	});
});
