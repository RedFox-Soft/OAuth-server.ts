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
import type { Passkey } from 'lib/adapters/types.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import { present } from '../shape.ts';
import { SoftAuthenticator } from './authenticator.ts';
import {
	ACME,
	BETA,
	Browser,
	acceptPasskeys,
	addOnPage,
	holdingPasskey,
	linkIn,
	mailOn,
	mailsTo,
	presentedAt,
	project,
	securityPage,
	seedPasskey,
	signedIn,
	signedInWithPasskey,
	textOf,
	xsrfFrom,
	type Project
} from './helpers.ts';

let acme: Project;
let beta: Project;

const LAST_WAY =
	'This is your only way to sign in to Acme. Add another way first: a password or another passkey.';

async function pageOf(browser: Browser, at: Project = acme, query = '') {
	const html = await (
		await browser.request(`${securityPage(at)}${query}`)
	).text();
	return { html, text: textOf(html) };
}

async function held(accountId: string, at: Project = acme): Promise<Passkey[]> {
	return getPasskeyStore().listOf(at.bucketId, accountId);
}

async function only(accountId: string, at: Project = acme): Promise<Passkey> {
	return present((await held(accountId, at))[0], 'the passkey');
}

/* Posts one of the page's passkey actions with the page's anti-forgery value. */
async function act(
	browser: Browser,
	fields: Record<string, string>,
	at: Project = acme
): Promise<Response> {
	const { html } = await pageOf(browser, at);
	return browser.post(securityPage(at), { xsrf: xsrfFrom(html), ...fields });
}

/* Asks to remove a passkey, then confirms on the page the answer leads to: what a person does with two clicks. */
async function removeOnPage(
	browser: Browser,
	passkey: string,
	at: Project = acme
): Promise<Response> {
	const started = await act(
		browser,
		{ action: 'passkey_remove_start', passkey },
		at
	);
	const confirmation = present(
		started.headers.get('location'),
		'the confirmation'
	);
	expect(confirmation).toContain(`remove=${passkey}`);
	const { html } = await pageOf(browser, at, `?remove=${passkey}`);
	expect(html).toContain('value="passkey_remove"');
	return browser.post(securityPage(at), {
		action: 'passkey_remove',
		passkey,
		xsrf: xsrfFrom(html)
	});
}

function removedMails(email: string) {
	return mailsTo(email).filter((mail) =>
		mail.subject.startsWith('A passkey was removed')
	);
}

/**
 * @proves A person renames their passkeys after a recent sign-in and removes them with the proof adding one takes; a
 * removed passkey stops signing in at once and the person is mailed and the act audited; a passkey that no longer
 * works (an old address, a possible copy) is shown so and can be removed; a password alone, or a mailed link opened in
 * another browser, removes nothing; and the last way into the project cannot be removed.
 */
describe('renaming and removing your passkeys', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		acme = await project(ACME);
		beta = await project(BETA);
		await getBucketStore().update(acme.bucketId, { displayName: 'Acme' });
		await getBucketStore().update(beta.bucketId, { displayName: 'Globex' });
	});

	beforeEach(async () => {
		resetSentEmails();
		await mailOn();
	});

	afterEach(() => {
		setSystemTime();
	});

	describe('renaming', () => {
		it('shows the new name, trimmed, after a recent sign-in', async () => {
			const { browser, accountId } = await signedIn(acme, 'code');
			await addOnPage(browser, new SoftAuthenticator(), acme);

			const renamed = await act(browser, {
				action: 'passkey_rename',
				passkey: (await only(accountId))._id,
				name: '  Work laptop  '
			});

			expect(renamed.headers.get('location')).toContain('done=passkey_renamed');
			expect((await pageOf(browser)).text).toContain('Work laptop');
			expect((await only(accountId)).name).toBe('Work laptop');
		});

		it('offers a form for the new name without scripts', async () => {
			const { browser, accountId } = await signedIn(acme, 'code');
			await addOnPage(browser, new SoftAuthenticator(), acme);
			const { _id } = await only(accountId);

			const { html } = await pageOf(browser, acme, `?rename=${_id}`);

			expect(html).toContain('value="passkey_rename"');
			expect(html).toMatch(/<input[^>]*name="name"[^>]*maxlength="64"/);
		});

		it('refuses a name longer than 64 characters and keeps the old one', async () => {
			const { browser, accountId } = await signedIn(acme, 'code');
			await addOnPage(browser, new SoftAuthenticator(), acme);

			const refused = await act(browser, {
				action: 'passkey_rename',
				passkey: (await only(accountId))._id,
				name: 'x'.repeat(65)
			});

			expect(refused.headers.get('location')).toContain('notice=passkey_name');
			expect((await only(accountId)).name).toBeUndefined();
		});

		it('refuses a name with a line break in it', async () => {
			const { browser, accountId } = await signedIn(acme, 'code');
			await addOnPage(browser, new SoftAuthenticator(), acme);

			await act(browser, {
				action: 'passkey_rename',
				passkey: (await only(accountId))._id,
				name: 'Work\nlaptop'
			});

			expect((await only(accountId)).name).toBeUndefined();
		});

		it('asks for a sign-in again when the sign-in is older than fifteen minutes', async () => {
			const { browser, accountId } = await signedIn(acme, 'code');
			await addOnPage(browser, new SoftAuthenticator(), acme);
			const { _id } = await only(accountId);
			const { html } = await pageOf(browser);
			setSystemTime(new Date(Date.now() + 16 * 60 * 1000));

			const asked = await browser.post(securityPage(acme), {
				action: 'passkey_rename',
				passkey: _id,
				name: 'Work laptop',
				xsrf: xsrfFrom(html)
			});

			expect(asked.headers.get('location')).toContain('/auth?');
			expect((await only(accountId)).name).toBeUndefined();
		});

		it('renames nothing of another person', async () => {
			const { browser } = await signedIn(acme, 'code');
			const other = await holdingPasskey(acme);
			const theirs = await only(other.accountId);

			await act(browser, {
				action: 'passkey_rename',
				passkey: theirs._id,
				name: 'Mine now'
			});

			expect((await only(other.accountId)).name).toBeUndefined();
		});
	});

	describe('removing', () => {
		it('removes a passkey after a strong sign-in, and it stops signing in at once', async () => {
			const { device, accountId } = await holdingPasskey(acme, {
				keepCode: true
			});
			const first = await only(accountId);
			const browser = await signedInWithPasskey(acme, device);
			await addOnPage(browser, new SoftAuthenticator(), acme);

			const removed = await removeOnPage(browser, first._id);

			expect(removed.headers.get('location')).toContain('done=passkey_removed');
			const refused = await presentedAt(acme, device);
			expect(refused.status).toBe(400);
		});

		it('mails the person once and records one audit entry with the person as its actor', async () => {
			const { browser, email, accountId } = await signedIn(acme, 'code');
			await addOnPage(browser, new SoftAuthenticator(), acme);

			await removeOnPage(browser, (await only(accountId))._id);

			expect(removedMails(email).length).toBe(1);
			const { entries } = await adminAuditStore.list({ targetId: accountId });
			const removals = entries.filter(
				(entry) => entry.action === 'enduser.passkey.remove'
			);
			expect(removals.length).toBe(1);
			expect(present(removals[0], 'the entry').actorId).toBe(
				`enduser:${acme.bucketId}:${accountId}`
			);
			expect(await held(accountId)).toEqual([]);
		});

		it('removes a passkey after a fresh password and the link mailed to this browser', async () => {
			const { browser, email, accountId } = await signedIn(acme, 'password');
			await seedPasskey(acme.bucketId, accountId);
			const { _id } = await only(accountId);

			const started = await act(browser, {
				action: 'passkey_remove_start',
				passkey: _id
			});
			expect(started.headers.get('location')).toContain('sent=passkey_remove');
			const followed = await browser.open(
				linkIn(email, '/account/security/link')
			);
			expect(followed.url).toContain(`remove=${_id}`);
			const { html } = await pageOf(browser, acme, `?remove=${_id}`);
			const removed = await browser.post(securityPage(acme), {
				action: 'passkey_remove',
				passkey: _id,
				xsrf: xsrfFrom(html)
			});

			expect(removed.headers.get('location')).toContain('done=passkey_removed');
			expect(await held(accountId)).toEqual([]);
		});

		it('lists a passkey made for an old address with its mark, and removes it', async () => {
			const { browser, accountId } = await signedIn(acme, 'code');
			const old = await seedPasskey(acme.bucketId, accountId, {
				rpId: 'old.example.test'
			});

			expect((await pageOf(browser)).text).toContain(
				'Made for an old address of Acme; it no longer works'
			);
			await removeOnPage(browser, old._id);

			expect(await held(accountId)).toEqual([]);
		});

		it('lists a passkey that may have been copied with its mark, and removes it', async () => {
			const { browser, accountId } = await signedIn(acme, 'code');
			const copied = await seedPasskey(acme.bucketId, accountId, {
				copiedAt: new Date()
			});

			expect((await pageOf(browser)).text).toContain(
				'Refused: it may have been copied'
			);
			await removeOnPage(browser, copied._id);

			expect(await held(accountId)).toEqual([]);
		});

		it('removes nothing with a password alone: a removal posted anyway is refused', async () => {
			const { browser, accountId } = await signedIn(acme, 'password');
			const seeded = await seedPasskey(acme.bucketId, accountId);

			const forged = await act(browser, {
				action: 'passkey_remove',
				passkey: seeded._id
			});

			expect(forged.headers.get('location')).toContain(
				'notice=passkey_expired'
			);
			expect((await held(accountId)).length).toBe(1);
		});

		it('refuses the mailed removal link in another browser of the same person', async () => {
			const { browser, email, accountId } = await signedIn(acme, 'password');
			const seeded = await seedPasskey(acme.bucketId, accountId);
			await act(browser, {
				action: 'passkey_remove_start',
				passkey: seeded._id
			});
			const link = linkIn(email, '/account/security/link');
			const other = (await signedIn(acme, 'password', { email, accountId }))
				.browser;

			const followed = await other.open(link);
			const forged = await act(other, {
				action: 'passkey_remove',
				passkey: seeded._id
			});

			expect(followed.url).toContain('notice=link');
			expect(forged.headers.get('location')).toContain(
				'notice=passkey_expired'
			);
			expect((await held(accountId)).length).toBe(1);
		});

		it('refuses to remove the last way in, and says what to add first', async () => {
			const { device, accountId } = await holdingPasskey(acme);
			await getUserStore(acme.bucketId).update(accountId, {
				passwordSet: false
			});
			const browser = await signedInWithPasskey(acme, device);

			const refused = await act(browser, {
				action: 'passkey_remove_start',
				passkey: (await only(accountId))._id
			});

			expect(refused.headers.get('location')).toContain('notice=passkey_last');
			expect(
				(await pageOf(browser, acme, '?notice=passkey_last')).text
			).toContain(LAST_WAY);
			expect((await held(accountId)).length).toBe(1);
		});

		it('counts no password as a way in where the project has password sign-in off', async () => {
			const { device, accountId } = await holdingPasskey(beta);
			await acceptPasskeys(beta.bucketId, true, { passwordLogin: false });
			const browser = await signedInWithPasskey(beta, device);

			const refused = await act(
				browser,
				{
					action: 'passkey_remove_start',
					passkey: (await only(accountId, beta))._id
				},
				beta
			);

			expect(refused.headers.get('location')).toContain('notice=passkey_last');
			expect((await held(accountId, beta)).length).toBe(1);
		});

		it('removes one of two working passkeys of a person with no password', async () => {
			const { device, accountId } = await holdingPasskey(acme);
			await getUserStore(acme.bucketId).update(accountId, {
				passwordSet: false
			});
			const mine = await only(accountId);
			await seedPasskey(acme.bucketId, accountId);
			const browser = await signedInWithPasskey(acme, device);

			const removed = await removeOnPage(browser, mine._id);

			expect(removed.headers.get('location')).toContain('done=passkey_removed');
			expect((await held(accountId)).length).toBe(1);
		});
	});
});
