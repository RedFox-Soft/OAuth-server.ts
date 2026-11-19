import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	setSystemTime
} from 'bun:test';
import crypto from 'node:crypto';

import bootstrap from '../test_helper.ts';
import { Browser } from '../connected_apps/helpers.ts';
import {
	PASSWORD,
	PersonBrowser,
	WRONG,
	from,
	person,
	project,
	typePassword
} from '../person_activity/helpers.ts';
import {
	HOME,
	HOSTING,
	newSignInMailsTo,
	notMeLinkIn,
	ready,
	signInFrom
} from './helpers.ts';
import { checkedAdapter, getBucketStore } from 'lib/adapters/index.ts';
import type { UserBucket } from 'lib/adapters/types.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import { sentEmails } from 'lib/mail/mailer.ts';
import { issueNotMeLink } from 'lib/sign_in_alerts/link.ts';
import { NotMeLinkPayload } from 'lib/totp/types.ts';

const APP = 'activity-app';

let bucket: UserBucket;
let anna: { email: string; accountId: string };

async function alertedProject(fields: Record<string, unknown> = {}) {
	const id = await project(fields);
	await getBucketStore().update(id, { newSignInAlerts: true });
	const found = await getBucketStore().find(id);
	if (!found) throw new Error('no project');
	return found;
}

function post(link: string, at?: string): Promise<Response> {
	const url = new URL(link);
	return new Browser().post(at ?? url.pathname, {
		token: url.searchParams.get('token') ?? ''
	});
}

/**
 * @proves No email follows a refused sign-in, and none is decided while the sign-in is answered; the This wasn't me
 * link changes nothing when opened, acts once, expires, and acts only at the address its own project is served at and
 * only as a link of its own purpose.
 */
describe("the This wasn't me link and what triggers it", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		await ready();
		bucket = await alertedProject();
		anna = await person(bucket._id);
	});

	afterEach(() => {
		setSystemTime();
	});

	it('sends nothing for a refused sign-in', async () => {
		await signInFrom(anna.email, APP, HOME);
		await signInFrom(anna.email, APP, HOSTING, undefined, WRONG);

		expect(newSignInMailsTo(anna.email)).toEqual([]);
	});

	it('decides nothing while the sign-in is answered', async () => {
		await signInFrom(anna.email, APP, HOME);
		from(HOSTING);
		const landed = await typePassword(
			new PersonBrowser(),
			anna.email,
			PASSWORD,
			APP
		);

		expect(landed.url).toStartWith('http://e.ly/activity/callback');
		expect(newSignInMailsTo(anna.email)).toEqual([]);
	});

	it('acts once: a second confirmation finds the link gone', async () => {
		const link = await issueNotMeLink(bucket, anna.accountId, 'a-sign-in');
		await new Browser().request(link);
		await new Browser().request(link);

		const first = await post(link);
		const second = await post(link);
		expect([first.status, second.status]).toEqual([200, 400]);
	});

	it('does nothing after 72 hours', async () => {
		const link = await issueNotMeLink(bucket, anna.accountId, 'a-sign-in');
		setSystemTime(new Date(Date.now() + 73 * 3_600_000));

		expect((await new Browser().request(link)).status).toBe(400);
		expect((await post(link)).status).toBe(400);
	});

	it("does nothing at an address that is not its own project's", async () => {
		const own = await alertedProject({
			slug: `own${Math.random().toString(36).slice(2, 8)}`
		});
		const bob = await person(own._id);
		const slugged = await issueNotMeLink(own, bob.accountId, 'a-sign-in');
		const rooted = await issueNotMeLink(bucket, anna.accountId, 'a-sign-in');
		const adminLink = new URL(rooted);
		adminLink.searchParams.set(
			'token',
			new URL(
				await issueNotMeLink(
					(await getBucketStore().find(ADMIN_BUCKET_ID)) ?? bucket,
					'an-administrator',
					'a-sign-in'
				)
			).searchParams.get('token') ?? ''
		);

		expect((await post(slugged, '/account/not-me')).status).toBe(400);
		expect(
			(await post(rooted, `/${own.slug ?? ''}/account/not-me`)).status
		).toBe(400);
		expect(
			(await post(adminLink.toString(), `/${own.slug ?? ''}/account/not-me`))
				.status
		).toBe(400);
	});

	it('accepts no link of another purpose, and is accepted by no other page', async () => {
		const token = crypto.randomBytes(32).toString('base64url');
		await checkedAdapter('NotMeLink', NotMeLinkPayload).upsert(
			crypto.createHash('sha256').update(token).digest('hex'),
			{
				accountId: anna.accountId,
				bucketId: bucket._id,
				purpose: 'disown',
				enrolledAt: Date.now(),
				exp: Math.floor(Date.now() / 1000) + 3600
			},
			3600
		);
		const notMe = await issueNotMeLink(bucket, anna.accountId, 'a-sign-in');
		const notMeToken = new URL(notMe).searchParams.get('token') ?? '';

		const disownAsNotMe = await new Browser().post('/account/not-me', {
			token
		});
		const notMeAsDisown = await new Browser().post('/account/security/disown', {
			token: notMeToken
		});
		expect([disownAsNotMe.status, notMeAsDisown.status]).toEqual([400, 400]);
	});
});

const ADDRESSES = ['198.51.100.23', '198.51.100.250', '::ffff:198.51.100.9'];
const AGENTS = [
	'Mozilla/5.0 (X11; Linux x86_64) Secret-Build/7 Firefox/132.0',
	'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) Probe/1.2 Version/17.0 Safari/605.1.15',
	'curl/8.4.0 needle-in-agent'
];

/**
 * @proves For every address and browser string a sign-in may come with, the email about it carries neither, nor any
 * link but its own This wasn't me link.
 */
describe('what an email about a new sign-in never carries', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	for (const [i, address] of ADDRESSES.entries()) {
		const agent = AGENTS[i];
		it(`carries neither ${address} nor the raw browser string`, async () => {
			await ready();
			bucket = await alertedProject();
			anna = await person(bucket._id);
			await signInFrom(anna.email, APP, HOME);
			await signInFrom(anna.email, APP, address, agent);

			const [mail] = newSignInMailsTo(anna.email);
			const both = `${mail.text}\n${mail.html}`;
			expect(both.includes(address.replace('::ffff:', ''))).toBe(false);
			expect(both.includes(agent)).toBe(false);
			expect(both.includes('Secret-Build') || both.includes('needle')).toBe(
				false
			);
			const links = mail.text.match(/https?:\/\/\S+/g) ?? [];
			expect(links).toEqual([notMeLinkIn(mail)]);
			expect(sentEmails.filter((sent) => sent.to === anna.email)).toHaveLength(
				1
			);
		});
	}
});
