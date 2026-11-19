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
	getPasskeyStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import { present } from '../shape.ts';
import { SoftAuthenticator } from './authenticator.ts';
import {
	ACME,
	addOnPage,
	creationOptionsIn,
	linkIn,
	mailOn,
	mailsTo,
	project,
	securityPage,
	holdingPasskey,
	signedIn,
	signedInWithPasskey,
	textOf,
	xsrfFrom,
	type Project
} from './helpers.ts';

let acme: Project;

async function pageText(
	browser: Awaited<ReturnType<typeof signedIn>>['browser']
): Promise<string> {
	return textOf(await (await browser.request(securityPage(acme))).text());
}

function addedMails(email: string) {
	return mailsTo(email).filter(
		(mail) =>
			mail.subject.startsWith('A passkey was added') ||
			mail.subject.startsWith('К аккаунту')
	);
}

/**
 * @proves A person adds a passkey on their own "Sign-in and security" page after a passkey sign-in, a password and a
 * code, or a password and a link mailed to them; it is listed with what they need to recognise it, they are mailed
 * once in their language, and the act is audited with them as its actor. Everything but the add button works
 * without scripts.
 */
describe('adding a passkey on your own page', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		acme = await project(ACME);
		await getBucketStore().update(acme.bucketId, { displayName: 'Acme' });
	});

	beforeEach(async () => {
		resetSentEmails();
		await mailOn();
	});

	afterEach(() => {
		setSystemTime();
	});

	it('adds one after a passkey sign-in, listed as made after a passkey sign-in', async () => {
		const { browser } = await signedIn(acme, 'passkey');

		const added = await addOnPage(browser, new SoftAuthenticator(), acme);

		expect(added.headers.get('location')).toContain('done=passkey_added');
		expect(await pageText(browser)).toContain(
			'Added after signing in with a passkey'
		);
	});

	it('adds one after a password and a code, listed with its name, date, use, sync state and proof', async () => {
		const { browser } = await signedIn(acme, 'code');

		await addOnPage(browser, new SoftAuthenticator(), acme);

		const shown = await pageText(browser);
		for (const words of [
			'Chrome on Windows',
			'Created ',
			'Never used',
			'Only on this device',
			'Added after signing in with your password and a code'
		]) {
			expect({ words, shown: shown.includes(words) }).toEqual({
				words,
				shown: true
			});
		}
	});

	it('adds one after a password and the link mailed to this browser', async () => {
		const { browser, email } = await signedIn(acme, 'password');
		const opened = await browser.request(securityPage(acme));
		const started = await browser.post(securityPage(acme), {
			action: 'passkey_start',
			xsrf: xsrfFrom(await opened.text())
		});
		expect(started.headers.get('location')).toContain('sent=passkey');

		const followed = await browser.open(
			linkIn(email, '/account/security/link')
		);
		expect(textOf(await followed.response.text())).toContain(
			'Your email is confirmed. Choose Add a passkey to continue.'
		);
		const added = await addOnPage(browser, new SoftAuthenticator(), acme);

		expect(added.headers.get('location')).toContain('done=passkey_added');
		expect(await pageText(browser)).toContain(
			'Added after signing in with your password and an emailed link'
		);
	});

	it('shows a synced passkey as synced to the person’s devices', async () => {
		const { browser } = await signedIn(acme, 'code');

		await addOnPage(browser, new SoftAuthenticator(), acme, {
			flags: { be: true, bs: true }
		});

		expect(await pageText(browser)).toContain('Synced to your devices');
	});

	it('shows when a passkey was last used to sign in', async () => {
		const { device } = await holdingPasskey(acme);

		const browser = await signedInWithPasskey(acme, device);

		const shown = await pageText(browser);
		expect(shown).toContain('Last used');
		expect(shown).not.toContain('Never used');
	});

	it('names the person as "email · project" to the browser', async () => {
		const { browser, email } = await signedIn(acme, 'code');

		const html = await (await browser.request(securityPage(acme))).text();

		const { user, rp } = creationOptionsIn(html);
		expect({
			name: user.name,
			displayName: user.displayName,
			rp: rp.name
		}).toEqual({
			name: `${email} · Acme`,
			displayName: `${email} · Acme`,
			rp: 'Acme'
		});
	});

	it('mails the person once that a passkey was added, with a link for "This wasn’t me"', async () => {
		const { browser, email } = await signedIn(acme, 'code');

		await addOnPage(browser, new SoftAuthenticator(), acme);

		const mails = addedMails(email);
		expect(mails.length).toBe(1);
		expect(present(mails[0], 'the mail').text).toContain(
			'/account/security/passkey-disown?token='
		);
	});

	it('mails the person in their own language', async () => {
		const { browser, email, accountId } = await signedIn(acme, 'code');
		await getUserStore(acme.bucketId).update(accountId, {
			profile: { locale: 'ru' }
		});

		await addOnPage(browser, new SoftAuthenticator(), acme);

		expect(present(addedMails(email)[0], 'the mail').subject).toBe(
			'К аккаунту Acme добавлен ключ доступа'
		);
	});

	it('records one audit entry with the person as its actor', async () => {
		const { browser, accountId } = await signedIn(acme, 'code');

		await addOnPage(browser, new SoftAuthenticator(), acme);

		const { entries } = await adminAuditStore.list({ targetId: accountId });
		const added = entries.filter(
			(entry) => entry.action === 'enduser.passkey.add'
		);
		expect(added.length).toBe(1);
		expect(present(added[0], 'the entry').actorId).toBe(
			`enduser:${acme.bucketId}:${accountId}`
		);
	});

	it('is called "Sign-in and security", and keeps two-step verification', async () => {
		const { browser } = await signedIn(acme, 'password');

		const html = await (await browser.request(securityPage(acme))).text();

		expect(html).toContain('<title>Sign-in and security</title>');
		expect(textOf(html)).toContain('Two-step verification');
		expect(textOf(html)).toContain('Turn on two-step verification');
	});

	it('works without scripts but for the add button, which says it needs JavaScript', async () => {
		const { browser, accountId } = await signedIn(acme, 'code');
		await addOnPage(browser, new SoftAuthenticator(), acme);
		expect(await getPasskeyStore().countOf(acme.bucketId, accountId)).toBe(1);

		const html = await (await browser.request(securityPage(acme))).text();

		expect(html).toMatch(/<li[^>]*>.*Chrome on Windows/);
		expect(html).toMatch(
			/<button type="button" disabled[^>]*>Add a passkey<\/button>/
		);
		expect(textOf(html)).toContain(
			'Adding a passkey needs JavaScript in your browser. Everything else on this page works without it.'
		);
		expect(html).not.toMatch(/<script>/);
		expect(html).toMatch(
			/<script src="\/public\/passkeyButton\.js(\?v=[^"]+)?"><\/script>/
		);
	});
});
