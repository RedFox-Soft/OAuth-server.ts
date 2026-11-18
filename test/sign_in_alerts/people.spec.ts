import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it
} from 'bun:test';

import bootstrap from '../test_helper.ts';
import { Browser } from '../connected_apps/helpers.ts';
import { mailOn } from '../two_step_page/helpers.ts';
import {
	PASSWORD,
	PersonBrowser,
	SECRET,
	from,
	person,
	project,
	typePassword
} from '../person_activity/helpers.ts';
import {
	CHROME_ON_WINDOWS,
	HOME,
	HOSTING,
	mailsTo,
	newSignInMailsTo,
	notMeLinkIn,
	ready,
	signInFrom
} from './helpers.ts';
import {
	adminAuditStore,
	getBucketStore,
	getPersonActivityStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { flushPersonActivityNow } from 'lib/person_activity/flush.ts';
import { issueNotMeLink } from 'lib/sign_in_alerts/link.ts';

const APP = 'activity-app';

let bucketId: string;
let anna: { email: string; accountId: string };

async function alertedProject(on: boolean): Promise<string> {
	const id = await project();
	/* As a project administrator turns it on: a change to the project, not part of creating it. */
	if (on) await getBucketStore().update(id, { newSignInAlerts: true });
	return id;
}

async function confirm(link: string): Promise<Response> {
	const url = new URL(link);
	return new Browser().post(url.pathname, {
		token: url.searchParams.get('token') ?? ''
	});
}

/**
 * @proves With the project's setting on, a person with a proven address is emailed in their own language about a
 * sign-in from a new network or browser, naming the project; with it off, or with an address not proven, an account
 * that cannot sign in, or mail not set up, nobody is emailed and no sign-in is marked.
 */
describe('a person signing in from somewhere new', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		await ready();
	});

	afterEach(async () => {
		await mailOn();
	});

	it('is emailed once in their language, naming the project', async () => {
		bucketId = await alertedProject(true);
		anna = await person(bucketId);
		await getUserStore(bucketId).update(anna.accountId, {
			profile: { locale: 'ru' }
		});
		await signInFrom(anna.email, APP, HOME);
		await signInFrom(anna.email, APP, HOSTING);

		const [mail, ...more] = newSignInMailsTo(anna.email);
		expect(more).toEqual([]);
		/* The name the project shows its people: no display name here, so its address. */
		expect(mail.subject).toBe('Новый вход в e.ly');
		expect(mail.text).toContain('Сеть: Example Hosting');
		expect(mail.text.includes(HOSTING)).toBe(false);
	});

	it('is not emailed while the project has it off', async () => {
		bucketId = await alertedProject(false);
		anna = await person(bucketId);
		await signInFrom(anna.email, APP, HOME);
		await signInFrom(anna.email, APP, HOSTING);

		expect(newSignInMailsTo(anna.email)).toEqual([]);
	});

	it('is not emailed at an address not proven', async () => {
		bucketId = await alertedProject(true);
		anna = await person(bucketId);
		await getUserStore(bucketId).update(anna.accountId, { verified: false });
		await signInFrom(anna.email, APP, HOME);
		await signInFrom(anna.email, APP, HOSTING);

		expect(newSignInMailsTo(anna.email)).toEqual([]);
	});

	it('is not emailed once the account cannot sign in any more', async () => {
		bucketId = await alertedProject(true);
		anna = await person(bucketId);
		await signInFrom(anna.email, APP, HOME);
		from(HOSTING);
		await typePassword(
			new PersonBrowser(CHROME_ON_WINDOWS),
			anna.email,
			PASSWORD,
			APP
		);
		await getUserStore(bucketId).update(anna.accountId, { active: false });
		await flushPersonActivityNow();

		expect(newSignInMailsTo(anna.email)).toEqual([]);
	});

	it('is not emailed, and nothing is marked, while mail is not set up', async () => {
		bucketId = await alertedProject(true);
		anna = await person(bucketId);
		await signInFrom(anna.email, APP, HOME);
		await mailOn(false);
		await signInFrom(anna.email, APP, HOSTING);

		const { rows } = await getPersonActivityStore().listForPerson(
			bucketId,
			anna.accountId,
			{ limit: 10, now: new Date() }
		);
		expect(newSignInMailsTo(anna.email)).toEqual([]);
		expect(rows.map((row) => row.alerted)).toEqual([undefined, undefined]);
	});
});

/**
 * @proves A person's "This wasn't me" signs them out everywhere, records their own sign-out, and sends the usual
 * reset email when they have a password; a person without one is told where to change it and gets no email; it never
 * locks, deactivates or removes a factor.
 */
describe("a person's This wasn't me", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		await ready();
		bucketId = await alertedProject(true);
		anna = await person(bucketId);
	});

	it('signs them out everywhere and sends the reset email', async () => {
		await getUserStore(bucketId).update(anna.accountId, {
			totp: { secret: SECRET, enrolledAt: new Date(), lastStep: 0 }
		});
		const bucket = await getBucketStore().find(bucketId);
		if (!bucket) throw new Error('no project');
		const done = await confirm(
			await issueNotMeLink(bucket, anna.accountId, 'a-sign-in')
		);

		expect(done.status).toBe(200);
		expect(mailsTo(anna.email).map((mail) => mail.subject)).toContain(
			'Reset your password for e.ly'
		);
		const { entries } = await adminAuditStore.list({
			action: 'enduser.signout',
			targetId: anna.accountId
		});
		expect(entries.map((entry) => entry.viaSurface)).toEqual(['self-service']);
		const after = await getUserStore(bucketId).find(anna.accountId);
		expect([after?.active, after?.lockedLocally, after?.totp?.secret]).toEqual([
			true,
			undefined,
			SECRET
		]);
	});

	it('tells a person without a password where to change it and sends nothing', async () => {
		await getUserStore(bucketId).update(anna.accountId, {
			passwordSet: false
		});
		const bucket = await getBucketStore().find(bucketId);
		if (!bucket) throw new Error('no project');
		const done = await confirm(
			await issueNotMeLink(bucket, anna.accountId, 'a-sign-in')
		);

		expect(done.status).toBe(200);
		expect(mailsTo(anna.email)).toEqual([]);
	});

	it('works from the link in the email', async () => {
		await signInFrom(anna.email, APP, HOME);
		await signInFrom(anna.email, APP, HOSTING);
		const done = await confirm(notMeLinkIn(newSignInMailsTo(anna.email)[0]));

		expect(done.status).toBe(200);
		expect(await done.text()).toContain('signed out everywhere');
	});
});
