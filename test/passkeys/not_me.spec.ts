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
import type { Passkey } from 'lib/adapters/types.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { DEFAULT_BUCKET_ID, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import { bindClientToBucket } from '../test_helper.ts';
import { present } from '../shape.ts';
import { SoftAuthenticator } from './authenticator.ts';
import {
	ACME,
	BETA,
	Browser,
	PASSWORD,
	acceptPasskeys,
	addOnPage,
	linkIn,
	mailOn,
	mailsTo,
	person,
	presentedAt,
	project,
	securityPage,
	signInPage,
	signedIn,
	textOf,
	xsrfFrom,
	type Project
} from './helpers.ts';

let acme: Project;
let beta: Project;

const DISOWN = '/account/security/passkey-disown';

/* A person signed in with a password and a code who adds a passkey on `device`; answers its "This wasn't me" link. */
async function added(
	browser: Browser,
	email: string,
	device = new SoftAuthenticator(),
	at = acme
): Promise<string> {
	const answer = await addOnPage(browser, device, at);
	expect(answer.headers.get('location')).toContain('done=passkey_added');
	return linkIn(email, DISOWN);
}

/*
 * What the owner does from the mail, in a browser of their own: open the link, then confirm on the page it shows,
 * sending what its form carries. Where the page shows no form, the token alone, as a forged confirmation would.
 */
async function disown(
	link: string,
	headers: Record<string, string> = {},
	origin = acme.origin
): Promise<{ page: Response; answer: Response }> {
	const owner = new Browser(origin);
	const page = await owner.request(link);
	const html = await page.clone().text();
	const form = [
		...html.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)"/g)
	].map(([, name, value]) => [name, value] as const);
	const fields =
		form.length > 0
			? Object.fromEntries(form)
			: {
					token: present(new URL(link).searchParams.get('token'), 'a token')
				};
	const answer = await owner.post(new URL(link).pathname, fields, headers);
	return { page, answer };
}

/* A project with no address of its own: it signs its people in, and serves their page, at the root. */
async function unaddressed(): Promise<Project> {
	forgetBucketAddresses();
	const bucket = await getBucketStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name: 'quiet people'
	});
	await bindClientToBucket('quiet-app', bucket._id);
	await acceptPasskeys(bucket._id);
	return {
		bucketId: bucket._id,
		clientId: 'quiet-app',
		prefix: '',
		origin: 'http://e.ly'
	};
}

/* A person of `at` signed in with a password at its app, as such a project's people are. */
async function signedInAtApp(
	at: Project
): Promise<{ browser: Browser; email: string; accountId: string }> {
	const { email, accountId } = await person(at.bucketId);
	const browser = new Browser(at.origin);
	const page = await signInPage(browser, at);
	const posted = await browser.post(page.url, {
		username: email,
		password: PASSWORD
	});
	await browser.open(
		new URL(
			present(posted.headers.get('location'), 'a resume'),
			page.url
		).toString()
	);
	return { browser, email, accountId };
}

/* Adds a passkey after a fresh password and the link mailed to this browser; answers its "This wasn't me" link. */
async function addedThroughMail(
	at: Project,
	browser: Browser,
	email: string
): Promise<string> {
	const opened = await browser.request(securityPage(at));
	expect(opened.status).toBe(200);
	const started = await browser.post(securityPage(at), {
		action: 'passkey_start',
		xsrf: xsrfFrom(await opened.text())
	});
	expect(started.headers.get('location')).toContain('sent=passkey');
	await browser.open(linkIn(email, '/account/security/link'));
	return added(browser, email, new SoftAuthenticator(), at);
}

async function held(accountId: string): Promise<Passkey[]> {
	return getPasskeyStore().listOf(acme.bucketId, accountId);
}

/* One second on, so passkeys added one after another have distinct creation times. */
function later(): void {
	setSystemTime(new Date(Date.now() + 1000));
}

/**
 * @proves The owner of an account takes it back from someone who added a passkey with their password and mailbox: the
 * link in the mail about it, confirmed within three days at the project's own address, removes that passkey and every
 * one added after it, ends every session, mails a password reset and is audited, also for a person of a project served at
 * the root (the default one, or one with no address of its own); late, twice, elsewhere, from another site, for a
 * passkey already removed, or merely opened, it changes nothing, and signing out everywhere cannot kill it.
 */
describe('"This wasn’t me" after a passkey was added', () => {
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

	it('removes that passkey and every one added after it, and keeps the ones added before', async () => {
		const { browser, email, accountId } = await signedIn(acme, 'code');
		await added(browser, email);
		const before = present((await held(accountId))[0], 'the first passkey');
		later();
		const link = await added(browser, email);
		later();
		await added(browser, email);

		const { answer } = await disown(link);

		expect(answer.status).toBe(200);
		expect((await held(accountId)).map((passkey) => passkey._id)).toEqual([
			before._id
		]);
	});

	it('stops the removed passkey signing in', async () => {
		const { browser, email } = await signedIn(acme, 'code');
		const device = new SoftAuthenticator();
		const link = await added(browser, email, device);

		await disown(link);

		expect((await presentedAt(acme, device)).status).toBe(400);
	});

	it('signs the account out everywhere', async () => {
		const { browser, email } = await signedIn(acme, 'code');
		const link = await added(browser, email);

		await disown(link);

		const page = await browser.request(securityPage(acme));
		expect(page.status).toBe(303);
		expect(page.headers.get('location')).toContain('/auth?');
	});

	it('mails a link to set a new password, and says so', async () => {
		const { browser, email } = await signedIn(acme, 'code');
		const link = await added(browser, email);

		const { answer } = await disown(link);

		expect(
			mailsTo(email).some((mail) =>
				mail.subject.startsWith('Reset your password')
			)
		).toBe(true);
		const shown = textOf(await answer.text());
		expect(shown).toContain(
			'The passkey was removed and your account was signed out everywhere.'
		);
		expect(shown).toContain('Now change your password: someone else knows it.');
	});

	it('records one audit entry with the person as its actor', async () => {
		const { browser, email, accountId } = await signedIn(acme, 'code');
		const link = await added(browser, email);

		await disown(link);

		const { entries } = await adminAuditStore.list({ targetId: accountId });
		const disowned = entries.filter(
			(entry) => entry.action === 'enduser.passkey.disown'
		);
		expect(disowned.length).toBe(1);
		expect(present(disowned[0], 'the entry').actorId).toBe(
			`enduser:${acme.bucketId}:${accountId}`
		);
	});

	it('still works after whoever added the passkey signed the account out everywhere', async () => {
		const { browser, email, accountId } = await signedIn(acme, 'code');
		const link = await added(browser, email);
		const confirm = await browser.request(
			`${acme.prefix}/account/sign-ins?confirm=1`
		);
		const signedOut = await browser.post(`${acme.prefix}/account/sign-ins`, {
			xsrf: xsrfFrom(await confirm.text())
		});
		expect(signedOut.status).toBe(200);

		const { answer } = await disown(link);

		expect(answer.status).toBe(200);
		expect(await held(accountId)).toEqual([]);
	});

	it('changes nothing when the link is only opened', async () => {
		const { browser, email, accountId } = await signedIn(acme, 'code');
		const link = await added(browser, email);

		const opened = await new Browser(acme.origin).request(link);

		expect(opened.status).toBe(200);
		expect(textOf(await opened.text())).toContain(
			`Remove this passkey from ${email}?`
		);
		expect((await held(accountId)).length).toBe(1);
		expect((await browser.request(securityPage(acme))).status).toBe(200);
	});

	it('changes nothing after 72 hours', async () => {
		const { browser, email, accountId } = await signedIn(acme, 'code');
		const link = await added(browser, email);
		setSystemTime(new Date(Date.now() + 72 * 3600 * 1000 + 1000));

		const { page, answer } = await disown(link);

		expect(page.status).toBe(400);
		expect(answer.status).toBe(400);
		expect(textOf(await answer.text())).toContain(
			'If someone else added a passkey to your account, ask the people who run Acme.'
		);
		expect((await held(accountId)).length).toBe(1);
	});

	it('changes nothing a second time', async () => {
		const { browser, email, accountId } = await signedIn(acme, 'code');
		const link = await added(browser, email);
		await disown(link);
		const signedInAgain = await signedIn(acme, 'code', { email, accountId });
		await added(signedInAgain.browser, email);

		const { answer } = await disown(link);

		expect(answer.status).toBe(400);
		expect((await held(accountId)).length).toBe(1);
	});

	it('changes nothing at another project’s address', async () => {
		const { browser, email, accountId } = await signedIn(acme, 'code');
		const link = await added(browser, email);
		const elsewhere = link.replace(`${acme.prefix}/`, `${beta.prefix}/`);
		expect(elsewhere).not.toBe(link);

		const { answer } = await disown(elsewhere);

		expect(answer.status).toBe(400);
		expect((await held(accountId)).length).toBe(1);
	});

	it('refuses a confirmation another site sent', async () => {
		const { browser, email, accountId } = await signedIn(acme, 'code');
		const link = await added(browser, email);

		const { answer } = await disown(link, { 'sec-fetch-site': 'cross-site' });

		expect(answer.status).toBe(403);
		expect((await held(accountId)).length).toBe(1);
	});

	it('changes nothing once the passkey was removed', async () => {
		const { browser, email, accountId } = await signedIn(acme, 'code');
		const link = await added(browser, email);
		const passkey = present((await held(accountId))[0], 'the passkey');
		await getPasskeyStore().remove(acme.bucketId, accountId, passkey._id);
		const other = new SoftAuthenticator();
		await addOnPage(browser, other, acme);

		const { answer } = await disown(link);

		expect(answer.status).toBe(400);
		expect((await held(accountId)).length).toBe(1);
		expect((await browser.request(securityPage(acme))).status).toBe(200);
	});

	it('works for a person of the default project, at the root', async () => {
		// The default project as an instance's provisioning writes it.
		await ensureAdminSeed();
		await acceptPasskeys(DEFAULT_BUCKET_ID);
		const root: Project = {
			bucketId: DEFAULT_BUCKET_ID,
			clientId: 'acme-app',
			prefix: '',
			origin: 'http://e.ly'
		};
		const { browser, email, accountId } = await signedIn(root, 'code');
		const link = await added(browser, email, new SoftAuthenticator(), root);
		expect(link.startsWith(`http://e.ly${DISOWN}?`)).toBe(true);

		const { answer } = await disown(link, {}, root.origin);

		expect(answer.status).toBe(200);
		expect(
			await getPasskeyStore().listOf(DEFAULT_BUCKET_ID, accountId)
		).toEqual([]);
	});

	it('works for a person of a project with no address of its own, whose page is the root’s', async () => {
		const quiet = await unaddressed();
		const { browser, email, accountId } = await signedInAtApp(quiet);
		const link = await addedThroughMail(quiet, browser, email);
		expect(link.startsWith(`http://e.ly${DISOWN}?`)).toBe(true);

		const { answer } = await disown(link, {}, quiet.origin);

		expect(answer.status).toBe(200);
		expect(textOf(await answer.text())).toContain(
			'The passkey was removed and your account was signed out everywhere.'
		);
		expect(await getPasskeyStore().listOf(quiet.bucketId, accountId)).toEqual(
			[]
		);
	});

	it('changes nothing when a link names, from the root, a project that has an address of its own', async () => {
		const { browser, email, accountId } = await signedIn(acme, 'code');
		const link = new URL(await added(browser, email));
		const elsewhere = `http://e.ly${DISOWN}?token=${present(link.searchParams.get('token'), 'a token')}&project=${acme.bucketId}`;

		const { answer } = await disown(elsewhere);

		expect(answer.status).toBe(400);
		expect((await held(accountId)).length).toBe(1);
	});
});
