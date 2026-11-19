import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it
} from 'bun:test';

import bootstrap, {
	bindClientToBucket,
	findSessionSetCookie
} from '../test_helper.js';
import {
	getBucketStore,
	getPersonActivityStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import { flushPersonActivityNow } from 'lib/person_activity/flush.ts';
import { SoftAuthenticator } from './authenticator.ts';
import {
	ACME,
	BETA,
	Browser,
	PASSWORD,
	SUB,
	acceptPasskeys,
	codeAfter,
	creationOptionsIn,
	holdingPasskey,
	mailOn,
	mailsTo,
	passkeyOfferIn,
	postPasskey,
	presentedAt,
	project,
	propsIn,
	securityPage,
	seedPasskey,
	signInPage,
	signInWithPasskey,
	signedIn,
	signedInWithPasskey,
	textOf,
	type Project
} from './helpers.ts';

let acme: Project;
let beta: Project;
let sub: Project;
let host: Project;

const NOT_FOR_ACME =
	'This passkey isn’t for Acme. Choose another one, or sign in another way.';

/* A project at a host of its own, as a project with its own domain is addressed. */
async function hostProject(): Promise<Project> {
	forgetBucketAddresses();
	const bucket = await getBucketStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name: 'Host people',
		host: 'login.example.test'
	});
	await bindClientToBucket('acme-billing', bucket._id);
	await acceptPasskeys(bucket._id);
	return {
		bucketId: bucket._id,
		clientId: 'acme-billing',
		prefix: '',
		origin: 'http://login.example.test'
	};
}

/* The reasons of the refusals the person's activity keeps. */
async function refusalsOf(at: Project, accountId: string): Promise<string[]> {
	await flushPersonActivityNow();
	const { rows } = await getPersonActivityStore().listForPerson(
		at.bucketId,
		accountId,
		{ limit: 50, now: new Date() }
	);
	return rows
		.filter((row) => row.outcome === 'refused')
		.map((row) => row.reason);
}

/**
 * @proves A passkey signs in only to the project it was made for, at that project's own site and origin: a passkey of
 * another project, one nobody here holds and one made for the project's old site are refused in one sentence naming
 * no other project, and nothing is done to the passkey that was mistaken; a response for another origin, or one whose
 * counter went back, is refused and the latter marked; each project's ceremonies name its own site whatever a
 * forwarded header says; and an account the password door would turn away is turned away here, for the same reason.
 */
describe('a passkey presented where it does not belong', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		acme = await project(ACME);
		beta = await project(BETA);
		sub = await project(SUB, { subdomain: true });
		host = await hostProject();
		await getBucketStore().update(acme.bucketId, { displayName: 'Acme' });
		await getBucketStore().update(beta.bucketId, { displayName: 'Globex' });
	});

	beforeEach(async () => {
		resetSentEmails();
		await mailOn();
	});

	afterEach(async () => {
		await getBucketStore().update(acme.bucketId, {
			emailVerificationRequired: false
		});
		forgetBucketAddresses();
	});

	it('refuses another project’s passkey in one sentence that names no other project', async () => {
		const { device } = await holdingPasskey(beta);

		const refused = await presentedAt(acme, device);

		const shown = textOf(await refused.text());
		expect(refused.status).toBe(400);
		expect(shown).toContain(NOT_FOR_ACME);
		expect(shown).not.toContain('Globex');
	});

	it('still signs in with that passkey at its own project afterwards', async () => {
		const { device } = await holdingPasskey(beta);
		await presentedAt(acme, device);

		const { code } = await signInWithPasskey(
			new Browser(beta.origin),
			device,
			beta
		);

		expect(code).toBeString();
	});

	it('refuses a passkey nobody here holds in the same sentence', async () => {
		const device = new SoftAuthenticator();
		await device.create(
			{ challenge: 'AAAA', rp: { id: 'e.ly' }, user: { id: 'c29tZW9uZQ' } },
			{ origin: 'http://e.ly' }
		);

		const refused = await presentedAt(acme, device);

		expect(textOf(await refused.text())).toContain(NOT_FOR_ACME);
	});

	it('refuses a passkey made for the project’s old site, and keeps the refusal in the person’s activity', async () => {
		const { accountId } = await signedIn(acme, 'password');
		const device = new SoftAuthenticator();
		const made = await device.create(
			{ challenge: 'AAAA', rp: { id: 'e.ly' }, user: { id: 'b2xk' } },
			{ origin: 'http://e.ly' }
		);
		await seedPasskey(acme.bucketId, accountId, {
			credentialId: made.id,
			rpId: 'old.example.test'
		});

		const refused = await presentedAt(acme, device);

		expect(textOf(await refused.text())).toContain(NOT_FOR_ACME);
		expect(await refusalsOf(acme, accountId)).toContain('passkey_refused');
	});

	it('refuses a response signed for another origin than the project’s', async () => {
		const { device } = await holdingPasskey(acme);

		const refused = await presentedAt(acme, device, {
			context: { origin: 'http://other.e.ly' }
		});

		expect(refused.status).toBe(400);
		expect(textOf(await refused.text())).toContain(NOT_FOR_ACME);
	});

	it('refuses a passkey whose counter went back, and refuses it again with the right counter', async () => {
		const { device, accountId } = await holdingPasskey(acme);
		await signInWithPasskey(new Browser(acme.origin), device, acme);
		const back = await presentedAt(acme, device, { choices: { counter: 0 } });
		expect(textOf(await back.text())).toContain(NOT_FOR_ACME);

		const after = await presentedAt(acme, device);

		expect(textOf(await after.text())).toContain(NOT_FOR_ACME);
		expect(await refusalsOf(acme, accountId)).toContain('passkey_refused');
	});

	it('marks a passkey whose counter went back on the person’s own page', async () => {
		const { device } = await holdingPasskey(acme);
		const browser = await signedInWithPasskey(acme, device);

		await presentedAt(acme, device, { choices: { counter: 0 } });

		expect(
			textOf(await (await browser.request(securityPage(acme))).text())
		).toContain('Refused: it may have been copied');
	});

	it('gives one person’s accounts in two projects different passkey identities', async () => {
		const email = `same-${Math.random().toString(36).slice(2)}@acme.test`;
		const hash = await Bun.password.hash(PASSWORD);
		const ids: string[] = [];
		for (const at of [acme, beta]) {
			const user = await getUserStore(at.bucketId).create(email, hash, true);
			const { browser } = await signedIn(at, 'code', {
				email,
				accountId: user._id
			});
			const html = await (await browser.request(securityPage(at))).text();
			ids.push(creationOptionsIn(html).user.id);
		}

		expect(ids[0]).not.toBe(ids[1]);
	});

	it('turns a locked account away in words that never mention a password, and keeps why', async () => {
		const { device, accountId } = await holdingPasskey(acme);
		await getUserStore(acme.bucketId).update(accountId, {
			lockedLocally: { at: new Date(), by: 'an-administrator', reason: 'x' }
		});

		const refused = await presentedAt(acme, device);

		expect(propsIn(await refused.text())).toMatchObject({
			errorMessage:
				'This account can’t sign in right now. Ask the people who run Acme.'
		});
		expect(await refusalsOf(acme, accountId)).toContain('locked');
	});

	it('turns a deactivated account away, and keeps why', async () => {
		const { device, accountId } = await holdingPasskey(acme);
		await getUserStore(acme.bucketId).update(accountId, { active: false });

		const refused = await presentedAt(acme, device);

		expect(textOf(await refused.text())).toContain(
			'This account can’t sign in right now. Ask the people who run Acme.'
		);
		expect(await refusalsOf(acme, accountId)).toContain('deactivated');
	});

	it('turns an account with an unconfirmed address away as the password door does, and keeps why', async () => {
		const { device, accountId, email } = await holdingPasskey(acme);
		await getUserStore(acme.bucketId).update(accountId, { verified: false });
		await getBucketStore().update(acme.bucketId, {
			emailVerificationRequired: true
		});
		forgetBucketAddresses();

		const refused = await presentedAt(acme, device);

		expect(
			findSessionSetCookie(refused.headers.getSetCookie())
		).toBeUndefined();
		expect(mailsTo(email).length).toBeGreaterThan(0);
		expect(await refusalsOf(acme, accountId)).toContain('email_unverified');
	});

	it('names the instance’s host as the site of a project at a path', async () => {
		const { html } = await signInPage(new Browser(acme.origin), acme);

		expect(passkeyOfferIn(html)?.options.rpId).toBe('e.ly');
	});

	it('names its own subdomain as the site of a project at a subdomain', async () => {
		const { html } = await signInPage(new Browser(sub.origin), sub);

		expect(passkeyOfferIn(html)?.options.rpId).toBe('sub.e.ly');
	});

	it('names its own host as the site of a project at a host of its own', async () => {
		const { html } = await signInPage(new Browser(host.origin), host);

		expect(passkeyOfferIn(html)?.options.rpId).toBe('login.example.test');
	});

	it('refuses at a subdomain project a response made for the instance’s own site', async () => {
		const { device } = await holdingPasskey(sub);
		const browser = new Browser(sub.origin);
		const page = await signInPage(browser, sub);

		const refused = await postPasskey(browser, device, sub, page, {
			context: { origin: 'http://e.ly' },
			choices: { rpId: 'e.ly' }
		});

		expect(refused.status).toBe(400);
	});

	it('keeps the site of a sign-in whatever forwarded host the request carries', async () => {
		const { device } = await holdingPasskey(acme);
		const browser = new Browser(acme.origin);
		const forwarded = { 'x-forwarded-host': 'attacker.test' };
		const page = await browser.open((await signInPage(browser, acme)).url, {
			headers: forwarded
		});
		const html = await page.response.text();
		expect(passkeyOfferIn(html)?.options.rpId).toBe('e.ly');

		const refused = await postPasskey(
			browser,
			device,
			acme,
			{ url: page.url, html },
			{ context: { origin: 'http://attacker.test' } }
		);

		expect(refused.status).toBe(400);
	});

	it('keeps the site of an add whatever forwarded host the request carries', async () => {
		const { browser } = await signedIn(acme, 'code');

		const html = await (
			await browser.request(securityPage(acme), {
				headers: { 'x-forwarded-host': 'attacker.test' }
			})
		).text();

		expect(creationOptionsIn(html).rp.id).toBe('e.ly');
	});

	it('signs in at the project’s own origin after a refused attempt from another', async () => {
		const { device } = await holdingPasskey(acme);
		const browser = new Browser(acme.origin);
		const page = await signInPage(browser, acme);
		const refused = await postPasskey(browser, device, acme, page, {
			context: { origin: 'http://attacker.test' }
		});

		const again = await postPasskey(browser, device, acme, {
			url: page.url,
			html: await refused.text()
		});

		expect(await codeAfter(browser, again, page.url)).toBeString();
	});
});
