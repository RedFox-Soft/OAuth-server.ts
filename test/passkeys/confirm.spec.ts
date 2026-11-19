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
	adminAuditStore,
	getBucketStore,
	getPasskeyStore
} from 'lib/adapters/index.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import { present } from '../shape.ts';
import { SoftAuthenticator } from './authenticator.ts';
import {
	ACME,
	BETA,
	Browser,
	claimsOf,
	linkIn,
	mailOn,
	mailsTo,
	person,
	project,
	redeem,
	securityPage,
	sessionOf,
	signInWithPasskey,
	signedIn,
	xsrfFrom,
	type Project
} from './helpers.ts';
import {
	atOffer,
	createAtOffer,
	holdsCode,
	leaveOffer,
	passwordSignIn
} from './offer_helpers.ts';

const CONFIRM = '/account/security/passkey-confirm';
const MULTI_FACTOR = 'urn:example:acr:mfa';

let acme: Project;
let beta: Project;

/* A person who accepted the offer after a password alone, in `browser`; answers their "Yes, this was me" link. */
async function conditionalHeld(): Promise<{
	email: string;
	accountId: string;
	device: SoftAuthenticator;
	browser: Browser;
	link: string;
}> {
	const { email, accountId } = await person(acme.bucketId);
	const landed = await passwordSignIn(acme, email);
	expect(atOffer(landed)).toBe(true);
	const device = new SoftAuthenticator();
	await createAtOffer(acme, landed, device);
	await leaveOffer(landed, 'continue');
	return {
		email,
		accountId,
		device,
		browser: landed.browser,
		link: linkIn(email, CONFIRM)
	};
}

/* Opens the link in `browser` and confirms on the page it shows, with what its form carries. */
async function confirmIn(browser: Browser, link: string): Promise<Response> {
	const page = await (await browser.request(link)).text();
	const fields = Object.fromEntries(
		[
			...page.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)"/g)
		].map(([, name, value]) => [name, value])
	);
	return browser.post(new URL(link).pathname, {
		token: present(new URL(link).searchParams.get('token'), 'a token'),
		...fields
	});
}

async function confirmed(accountId: string): Promise<boolean> {
	const [held] = await getPasskeyStore().listOf(acme.bucketId, accountId);
	return present(held, 'the passkey').conditional === undefined;
}

/**
 * @proves A conditional passkey becomes full by its mailed "Yes, this was me" only in the browser session that made it,
 * within 72 hours and once, or by "Confirm" on the person's page after a strong sign-in; anywhere else, including the
 * owner's own browser for a passkey someone else made, the link changes nothing. Confirming is recorded without the
 * link, mails nothing, and leaves the running sign-in as it was.
 */
describe('confirming a passkey made after a password alone', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		acme = await project(ACME);
		beta = await project(BETA);
		await getBucketStore().update(acme.bucketId, { displayName: 'Acme' });
	});

	beforeEach(async () => {
		resetSentEmails();
		await mailOn();
	});

	afterEach(() => {
		setSystemTime();
	});

	describe('by the mailed link', () => {
		it('makes the passkey full in the browser session that made it', async () => {
			const { accountId, browser, link } = await conditionalHeld();

			const answer = await confirmIn(browser, link);

			expect(answer.status).toBe(200);
			expect(await answer.text()).toContain('Your passkey is confirmed');
			expect(await confirmed(accountId)).toBe(true);
		});

		it('then signs in as two-step sign-in', async () => {
			const { browser, link, device } = await conditionalHeld();
			await confirmIn(browser, link);

			const signIn = await signInWithPasskey(
				new Browser(acme.origin),
				device,
				acme
			);

			expect(
				claimsOf((await redeem(acme, signIn.auth, signIn.code)).id_token).acr
			).toBe(MULTI_FACTOR);
		});

		it('records one entry without the link, mails nothing, and leaves the running sign-in as it was', async () => {
			const { email, accountId, browser, link } = await conditionalHeld();
			const before = (await sessionOf(browser, acme)).payload;
			const mails = mailsTo(email).length;

			await confirmIn(browser, link);

			const { entries } = await adminAuditStore.list({ targetId: accountId });
			const recorded = entries.filter(
				(entry) => entry.action === 'enduser.passkey.confirm'
			);
			expect(recorded.length).toBe(1);
			const token = present(new URL(link).searchParams.get('token'), 'a token');
			expect(JSON.stringify(recorded)).not.toContain(token.split('.')[1]);
			expect(mailsTo(email).length).toBe(mails);
			const after = (await sessionOf(browser, acme)).payload;
			expect({ acr: after.acr, amr: after.amr }).toEqual({
				acr: before.acr,
				amr: before.amr
			});
		});

		it('changes nothing when only opened', async () => {
			const { accountId, browser, link } = await conditionalHeld();

			await browser.request(link);

			expect(await confirmed(accountId)).toBe(false);
		});

		it('changes nothing in another browser, even the owner’s own, signed in', async () => {
			const { email, accountId, link } = await conditionalHeld();
			const { browser: owner } = await signedIn(acme, 'password', {
				email,
				accountId
			});

			const answer = await confirmIn(owner, link);

			expect(await answer.text()).toContain('can’t be used here');
			expect(await confirmed(accountId)).toBe(false);
		});

		it('changes nothing after 72 hours', async () => {
			const { accountId, browser, link } = await conditionalHeld();
			setSystemTime(new Date(Date.now() + 73 * 3600 * 1000));

			await confirmIn(browser, link);

			expect(await confirmed(accountId)).toBe(false);
		});

		it('says it is already confirmed a second time', async () => {
			const { browser, link } = await conditionalHeld();
			await confirmIn(browser, link);

			const again = await confirmIn(browser, link);

			expect(await again.text()).toContain('already confirmed');
		});

		it('changes nothing once the passkey was removed', async () => {
			const { accountId, browser, link } = await conditionalHeld();
			await getPasskeyStore().removeAllOf(acme.bucketId, accountId);

			const answer = await confirmIn(browser, link);

			expect(await answer.text()).toContain('can’t be used here');
		});

		it('changes nothing at another project’s address', async () => {
			const { accountId, browser, link } = await conditionalHeld();
			const elsewhere = new URL(link);
			elsewhere.pathname = elsewhere.pathname.replace(acme.prefix, beta.prefix);

			await confirmIn(browser, elsewhere.toString());

			expect(await confirmed(accountId)).toBe(false);
		});
	});

	describe('on the person’s page', () => {
		it('offers Confirm after a sign-in with a password and a code, and it makes the passkey full', async () => {
			const { email, accountId } = await conditionalHeld();
			await holdsCode(acme, accountId);
			setSystemTime(new Date(Date.now() + 60 * 1000));
			const { browser } = await signedIn(acme, 'code', { email, accountId });
			const page = await (await browser.request(securityPage(acme))).text();
			expect(page).toContain('value="passkey_confirm"');

			const [held] = await getPasskeyStore().listOf(acme.bucketId, accountId);
			const answer = await browser.post(securityPage(acme), {
				action: 'passkey_confirm',
				xsrf: xsrfFrom(page),
				passkey: present(held, 'the passkey')._id
			});

			expect(answer.headers.get('location')).toContain(
				'done=passkey_confirmed'
			);
			expect(await confirmed(accountId)).toBe(true);
		});

		it('offers no Confirm after a sign-in with a password alone, and says what is needed', async () => {
			const { email, accountId } = await conditionalHeld();
			const { browser } = await signedIn(acme, 'password', {
				email,
				accountId
			});

			const page = await (await browser.request(securityPage(acme))).text();

			expect(page).not.toContain('value="passkey_confirm"');
			expect(page).toContain('Not confirmed: works like your password');
			expect(page).toContain('to confirm it.');
		});
	});
});
