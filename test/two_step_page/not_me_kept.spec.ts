import { beforeAll, beforeEach, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.js';
import {
	checkedAdapter,
	getBucketStore,
	getUserStore
} from 'lib/adapters/index.ts';
import type { UserBucket } from 'lib/adapters/types.ts';
import { DEFAULT_BUCKET_ID, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { destroyBucket } from 'lib/admin/buckets/destroy.ts';
import { removeEndUser, revokeEndUserAccess } from 'lib/end_users/service.ts';
import { ACCOUNT_TEXTS } from 'lib/i18n/texts/account/index.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import { issueNotMeLink } from 'lib/sign_in_alerts/link.ts';
import { digestOf } from 'lib/totp/self_service.ts';
import { NotMeLinkPayload, TotpLinkPayload } from 'lib/totp/types.ts';
import { present } from '../shape.ts';
import {
	Browser,
	enrol,
	linkIn,
	mailOn,
	openPage,
	PAGE,
	project,
	signedIn,
	textOf,
	xsrfFrom
} from './helpers.ts';

const DISOWN = '/account/security/disown';
const NOT_ME = '/account/not-me';
const T = ACCOUNT_TEXTS.en;

async function factorOf(accountId: string) {
	return (await getUserStore(DEFAULT_BUCKET_ID).find(accountId))?.totp;
}

function tokenOf(link: string): string {
	return present(new URL(link).searchParams.get('token'), 'a token');
}

/* What the owner does from the mail: open the link, then confirm on the page it shows. */
async function confirm(link: string, path: string): Promise<Response> {
	const owner = new Browser();
	await owner.request(link);
	return owner.post(path, { token: tokenOf(link) });
}

/* What whoever holds the session does on Recent sign-ins (specs/135). */
async function signOutEverywhere(browser: Browser): Promise<void> {
	const page = await browser.request('/account/sign-ins?confirm=1');
	const done = await browser.post('/account/sign-ins', {
		xsrf: xsrfFrom(await page.text())
	});
	expect(textOf(await done.text())).toContain(T.signOutDoneTitle);
}

async function defaultBucket(): Promise<UserBucket> {
	return present(await getBucketStore().find(DEFAULT_BUCKET_ID), 'the bucket');
}

async function kept(link: string): Promise<boolean> {
	return (
		(await checkedAdapter('NotMeLink', NotMeLinkPayload).find(
			digestOf(tokenOf(link))
		)) !== undefined
	);
}

/**
 * @proves The "This wasn't me" links mailed to the owner of an account, about a factor someone turned on (specs/126)
 * or a sign-in from somewhere new (specs/138), still work after that someone signs the account out everywhere or an
 * administrator does, and go only with the person or the project. Links that prove a mailbox from one browser still
 * end with the account's access.
 */
describe('"This wasn’t me" links outlive a sign-out everywhere', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		resetSentEmails();
		await mailOn();
		await project();
	});

	it('removes a factor turned on by someone who then signed out everywhere', async () => {
		const { browser, email, accountId } = await signedIn();
		await enrol(browser, email);
		const link = linkIn(email, DISOWN);

		await signOutEverywhere(browser);
		const answer = await confirm(link, DISOWN);

		expect(answer.status).toBe(200);
		expect(await factorOf(accountId)).toBeUndefined();
	});

	it('removes a factor after an administrator signed the account out', async () => {
		const { browser, email, accountId } = await signedIn();
		await enrol(browser, email);
		const link = linkIn(email, DISOWN);

		await revokeEndUserAccess(await defaultBucket(), accountId, async () => {});
		const answer = await confirm(link, DISOWN);

		expect(answer.status).toBe(200);
		expect(await factorOf(accountId)).toBeUndefined();
	});

	it('answers a sign-in from somewhere new after someone signed out everywhere', async () => {
		const { browser, accountId } = await signedIn();
		const link = await issueNotMeLink(
			await defaultBucket(),
			accountId,
			'a-sign-in'
		);

		await signOutEverywhere(browser);
		const answer = await confirm(link, NOT_ME);

		expect(answer.status).toBe(200);
		expect(textOf(await answer.text())).toContain(T.signOutDoneTitle);
	});

	it('still ends an enrolment link with the account’s access', async () => {
		const { browser, email } = await signedIn();
		const { xsrf } = await openPage(browser);
		await browser.post(PAGE, { action: 'start', xsrf });
		const link = linkIn(email, '/account/security/link');

		await signOutEverywhere(browser);

		expect(
			await checkedAdapter('TotpLink', TotpLinkPayload).find(
				digestOf(tokenOf(link))
			)
		).toBeUndefined();
	});

	it('goes with the person', async () => {
		const { browser, email, accountId } = await signedIn();
		await enrol(browser, email);
		const disown = linkIn(email, DISOWN);
		const notMe = await issueNotMeLink(
			await defaultBucket(),
			accountId,
			'a-sign-in'
		);

		await removeEndUser(
			await defaultBucket(),
			{ kind: 'admin' },
			accountId,
			async () => {}
		);

		expect([await kept(disown), await kept(notMe)]).toEqual([false, false]);
	});

	it('goes with the project', async () => {
		const doomed = await getBucketStore().create({
			_id: `doomed-${Math.random().toString(36).slice(2, 10)}`,
			name: 'Doomed',
			ownerGroupId: UNASSIGNED_GROUP_ID
		});
		const user = await getUserStore(doomed._id).create(
			`doomed-${Math.random().toString(36).slice(2)}@acme.test`,
			'not-a-hash',
			true
		);
		const notMe = await issueNotMeLink(doomed, user._id, 'a-sign-in');
		const scheduled = present(
			await getBucketStore().scheduleDeletion(doomed._id, {
				scheduledAt: new Date(),
				purgeAt: new Date(),
				scheduledBy: { userId: 'test' }
			}),
			'a scheduled project'
		);

		const outcome = await destroyBucket(
			scheduled,
			{ kind: 'server' },
			{ due: false }
		);

		expect(outcome.claimed).toBe(true);
		expect(await kept(notMe)).toBe(false);
	});
});
