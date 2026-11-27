import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	setSystemTime
} from 'bun:test';

import bootstrap from '../test_helper.js';
import {
	getBucketStore,
	getPasskeyStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import { SoftAuthenticator } from './authenticator.ts';
import {
	ACME,
	mailOn,
	person,
	project,
	seedPasskey,
	type Project
} from './helpers.ts';
import {
	atOffer,
	createAtOffer,
	offerIn,
	passwordSignIn
} from './offer_helpers.ts';

function uidOfOffer(url: string): string {
	return /\/ui\/([^/]+)\/passkey-offer$/.exec(url)?.[1] ?? '';
}

/**
 * @proves "Ask everyone to create a passkey" campaign (Spec 145 US4): prompts every password user without a passkey
 * (even with `passkeyOffer: false` or without `remember`), allows up to 3 skips within 14 days on passkey-capable
 * devices, enforces mandatory creation once skips or the 14-day window expire, lets unsupported devices continue
 * without burning a skip, and stops prompting once a passkey is created.
 */
describe('the passkey adoption campaign (passkeyRequired)', () => {
	let acme: Project;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		acme = await project(ACME);
		await getBucketStore().update(acme.bucketId, { displayName: 'Acme' });
	});

	beforeEach(async () => {
		setSystemTime();
		resetSentEmails();
		await mailOn();
		await getBucketStore().update(acme.bucketId, {
			passwordLogin: true,
			passkeyLogin: true,
			passkeyOffer: false,
			passkeyRequired: true,
			totpRequired: false
		});
	});

	afterEach(() => {
		setSystemTime();
	});

	it('allows 3 skips within 14 days, refuses skipping on the 4th sign-in, and lets unsupported devices bypass without burning a skip', async () => {
		const who = await person(acme.bucketId);

		// Unsupported device bypass does NOT burn a skip
		const unsupportedRun = await passwordSignIn(acme, who.email, {
			device: false,
			remember: false
		});
		expect(atOffer(unsupportedRun)).toBe(true);
		const firstProps = offerIn(await unsupportedRun.response.text());
		expect(firstProps.campaign).toMatchObject({
			canSkip: true,
			skipsLeft: 3,
			maxSkips: 3
		});
		const cont = await unsupportedRun.browser.post(
			`/ui/${uidOfOffer(unsupportedRun.url)}/passkey-offer`,
			{ action: 'unsupported' }
		);
		expect(cont.status).toBe(303);
		expect(cont.headers.get('location')).toContain(
			`https://${acme.clientId}.apps.test/cb`
		);
		expect(
			(await getUserStore(acme.bucketId).find(who.accountId))?.passkeyPrompt
				?.skips
		).toBe(0);

		// Crafted not_now / never actions are refused in campaign mode
		const crafted = await passwordSignIn(acme, who.email);
		const refusedNotNow = await crafted.browser.post(
			`/ui/${uidOfOffer(crafted.url)}/passkey-offer`,
			{ action: 'not_now' }
		);
		expect(refusedNotNow.status).toBe(200);

		// Consume all 3 skips
		for (let i = 0; i < 3; i += 1) {
			const run = await passwordSignIn(acme, who.email);
			expect(atOffer(run)).toBe(true);
			const props = offerIn(await run.response.text());
			expect(props.campaign?.skipsLeft).toBe(3 - i);
			const skipped = await run.browser.post(
				`/ui/${uidOfOffer(run.url)}/passkey-offer`,
				{ action: 'skip' }
			);
			expect(skipped.status).toBe(303);
			expect(skipped.headers.get('location')).toContain(
				`https://${acme.clientId}.apps.test/cb`
			);
		}

		// 4th sign-in: skips exhausted -> canSkip is false and POST action=skip is refused
		const fourth = await passwordSignIn(acme, who.email);
		expect(atOffer(fourth)).toBe(true);
		expect(
			offerIn(await fourth.response.clone().text()).campaign
		).toMatchObject({
			canSkip: false,
			skipsLeft: 0
		});
		const blockedSkip = await fourth.browser.post(
			`/ui/${uidOfOffer(fourth.url)}/passkey-offer`,
			{ action: 'skip' }
		);
		expect(blockedSkip.status).toBe(200);

		// Creating a passkey satisfies the campaign (use the fresh challenge rendered by blockedSkip)
		const created = await createAtOffer(
			acme,
			{ ...fourth, response: blockedSkip },
			new SoftAuthenticator()
		);
		expect(created.status).toBe(200);
		expect(
			(await getPasskeyStore().listOf(acme.bucketId, who.accountId)).length
		).toBe(1);

		// Next password sign-in is no longer prompted
		const after = await passwordSignIn(acme, who.email);
		expect(atOffer(after)).toBe(false);
	});

	it('exhausts skips automatically after 14 days from first presentation', async () => {
		const who = await person(acme.bucketId);
		const now = Date.now();

		const first = await passwordSignIn(acme, who.email);
		expect(atOffer(first)).toBe(true);
		await first.browser.post(`/ui/${uidOfOffer(first.url)}/passkey-offer`, {
			action: 'skip'
		});

		// Advance 15 days -> 14-day window elapsed even with only 1 skip used
		setSystemTime(new Date(now + 15 * 24 * 60 * 60 * 1000));
		const later = await passwordSignIn(acme, who.email);
		expect(atOffer(later)).toBe(true);
		expect(offerIn(await later.response.text()).campaign).toMatchObject({
			canSkip: false,
			skipsLeft: 0
		});
	});

	it('skips users who already hold a working passkey', async () => {
		const who = await person(acme.bucketId);
		await seedPasskey(acme.bucketId, who.accountId);
		const run = await passwordSignIn(acme, who.email);
		expect(atOffer(run)).toBe(false);
	});
});
