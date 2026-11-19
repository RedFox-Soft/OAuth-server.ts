import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	setSystemTime,
	spyOn
} from 'bun:test';

import bootstrap from '../test_helper.js';
import {
	adminAuditStore,
	getBucketStore,
	getPasskeyStore,
	getUserStore
} from 'lib/adapters/index.ts';
import type { FederationProvider } from 'lib/federation/types.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import { present } from '../shape.ts';
import { SoftAuthenticator } from './authenticator.ts';
import {
	ACME,
	BETA,
	Browser,
	addOnPage,
	creationOptionsIn,
	linkIn,
	mailOn,
	mailsTo,
	postAdd,
	project,
	securityPage,
	seedPasskey,
	sessionOf,
	signedIn,
	textOf,
	xsrfFrom,
	type Project
} from './helpers.ts';

let acme: Project;

async function opened(
	browser: Browser
): Promise<{ html: string; text: string }> {
	const html = await (await browser.request(securityPage(acme))).text();
	return { html, text: textOf(html) };
}

async function count(accountId: string): Promise<number> {
	return getPasskeyStore().countOf(acme.bucketId, accountId);
}

/* Asks for an add with a fresh password, and answers the link the mail carries. */
async function askForLink(browser: Browser, email: string): Promise<string> {
	const { html } = await opened(browser);
	const started = await browser.post(securityPage(acme), {
		action: 'passkey_start',
		xsrf: xsrfFrom(html)
	});
	expect(started.headers.get('location')).toContain('sent=passkey');
	return linkIn(email, '/account/security/link');
}

function isLinkRefusal(url: string): boolean {
	return url.includes('notice=link');
}

/**
 * @proves A passkey is added only with proof that a stolen password lacks: never with a password alone, a provider
 * sign-in, a mailed link in another browser, late, twice or superseded, without a confirmed address or mail, past
 * twenty, from a device that did not verify the person, from a stale or reissued ceremony, or twice for one device.
 * Adding one never raises the session that added it, and nothing about the ceremony reaches a log or the audit trail.
 */
describe('adding a passkey, refused', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		acme = await project(ACME);
	});

	beforeEach(async () => {
		resetSentEmails();
		await mailOn();
	});

	afterEach(() => {
		setSystemTime();
	});

	it('offers no add button after a password alone, and an add posted anyway stores nothing', async () => {
		const { browser, accountId } = await signedIn(acme, 'password');
		const { html } = await opened(browser);
		expect(html).not.toContain('data-passkey-add');

		const forged = await browser.post(securityPage(acme), {
			action: 'passkey_add',
			xsrf: xsrfFrom(html),
			credential: '{}'
		});

		expect(forged.headers.get('location')).toContain('notice=passkey_expired');
		expect(await count(accountId)).toBe(0);
	});

	it('is not offered on an account that signs in only through a provider, and says why', async () => {
		const beta = await project(BETA);
		const provider: FederationProvider = {
			id: 'acme-sso',
			displayName: 'Acme SSO',
			enabled: true,
			issuer: 'https://idp.example.test',
			clientId: 'client',
			clientSecret: 'secret',
			scopes: ['openid'],
			emailTrusted: false,
			provisioning: 'jit',
			allowedEmailDomains: [],
			emailClaim: 'email'
		};
		await getBucketStore().update(beta.bucketId, { federation: [provider] });
		const { browser, accountId } = await signedIn(beta, 'code');
		await getUserStore(beta.bucketId).update(accountId, {
			passwordSet: false,
			federated: [{ providerId: 'acme-sso', sub: 'u-1', linkedAt: new Date() }]
		});

		const html = await (await browser.request(securityPage(beta))).text();

		expect(html).not.toContain('data-passkey-add');
		expect(textOf(html)).toContain(
			'You sign in through Acme SSO. Passkeys for accounts like yours aren’t available yet.'
		);
	});

	it('is not offered while the address is unconfirmed, and says so', async () => {
		const { browser, accountId } = await signedIn(acme, 'code');
		await getUserStore(acme.bucketId).update(accountId, { verified: false });

		const { html, text } = await opened(browser);

		expect(html).not.toContain('data-passkey-add');
		expect(text).toContain(
			'Confirm your email address first; we email you about every passkey.'
		);
	});

	it('is not offered while mail cannot be sent, and says so', async () => {
		const { browser } = await signedIn(acme, 'code');
		await mailOn(false);

		const { html, text } = await opened(browser);

		expect(html).not.toContain('data-passkey-add');
		expect(text).toContain('Adding a passkey isn’t possible right now');
	});

	it('refuses the mailed link in another browser where the same person is signed in', async () => {
		const { browser, email, accountId } = await signedIn(acme, 'password');
		const link = await askForLink(browser, email);
		const other = new Browser(acme.origin);
		const { signInThroughPage } = await import('../connected_apps/helpers.ts');
		await signInThroughPage(other, email, acme.prefix);

		const followed = await other.open(link);

		expect(isLinkRefusal(followed.url)).toBe(true);
		const page = await (await other.request(securityPage(acme))).text();
		expect(page).not.toContain('data-passkey-add');
		expect(await count(accountId)).toBe(0);
	});

	it('refuses the mailed link after ten minutes', async () => {
		const { browser, email } = await signedIn(acme, 'password');
		const link = await askForLink(browser, email);
		setSystemTime(new Date(Date.now() + 11 * 60 * 1000));

		const followed = await browser.open(link);

		expect(isLinkRefusal(followed.url)).toBe(true);
	});

	it('refuses the mailed link a second time', async () => {
		const { browser, email } = await signedIn(acme, 'password');
		const link = await askForLink(browser, email);
		await browser.open(link);

		const again = await browser.open(link);

		expect(isLinkRefusal(again.url)).toBe(true);
	});

	it('refuses a mailed link once a newer one was sent', async () => {
		const { browser, email } = await signedIn(acme, 'password');
		const first = await askForLink(browser, email);
		// One link a minute per account.
		setSystemTime(new Date(Date.now() + 61 * 1000));
		await askForLink(browser, email);

		const followed = await browser.open(first);

		expect(isLinkRefusal(followed.url)).toBe(true);
	});

	it('refuses a twenty-first passkey', async () => {
		const { browser, accountId } = await signedIn(acme, 'code');
		for (let i = 0; i < 19; i++) await seedPasskey(acme.bucketId, accountId);
		const { html } = await opened(browser);
		await seedPasskey(acme.bucketId, accountId);

		await postAdd(browser, new SoftAuthenticator(), acme, html);

		expect(await count(accountId)).toBe(20);
		expect((await opened(browser)).text).toContain(
			'You have 20 passkeys, the most allowed. Remove one to add another.'
		);
	});

	it('refuses a device that did not verify the person, and says what to do', async () => {
		const { browser, accountId } = await signedIn(acme, 'code');

		const added = await addOnPage(browser, new SoftAuthenticator(), acme, {
			flags: { uv: false }
		});

		expect(added.headers.get('location')).toContain('notice=passkey_no_uv');
		expect(await count(accountId)).toBe(0);
		const shown = await browser.open(
			present(added.headers.get('location'), 'a page')
		);
		expect(textOf(await shown.response.text())).toContain(
			'This security key can’t confirm it’s you. Set up a PIN for it, or use another device.'
		);
	});

	it('refuses a ceremony older than five minutes', async () => {
		const { browser, accountId } = await signedIn(acme, 'code');
		const { html } = await opened(browser);
		setSystemTime(new Date(Date.now() + 6 * 60 * 1000));

		const added = await postAdd(browser, new SoftAuthenticator(), acme, html);

		expect(added.headers.get('location')).toContain('notice=passkey_expired');
		expect(await count(accountId)).toBe(0);
	});

	it('refuses a ceremony whose passkey identity is no longer the account’s', async () => {
		const { browser, accountId } = await signedIn(acme, 'code');
		const { html } = await opened(browser);
		await getUserStore(acme.bucketId).update(accountId, {
			webauthnUserId: 'A'.repeat(43)
		});

		const added = await postAdd(browser, new SoftAuthenticator(), acme, html);

		expect(added.headers.get('location')).toContain('notice=passkey_expired');
		expect(await count(accountId)).toBe(0);
	});

	it('refuses a response signed for another origin', async () => {
		const { browser, accountId } = await signedIn(acme, 'code');
		const { html } = await opened(browser);

		await postAdd(
			browser,
			new SoftAuthenticator(),
			acme,
			html,
			{},
			'http://evil.example'
		);

		expect(await count(accountId)).toBe(0);
	});

	it('refuses the same device’s passkey a second time', async () => {
		const { browser, accountId } = await signedIn(acme, 'code');
		const device = new SoftAuthenticator();
		const credentialId = 'c2FtZS1kZXZpY2UtcGFzc2tleQ';
		await addOnPage(browser, device, acme, { credentialId });

		const again = await addOnPage(browser, device, acme, { credentialId });

		expect(again.headers.get('location')).toContain('notice=passkey_exists');
		expect(await count(accountId)).toBe(1);
	});

	it('leaves the session that added it exactly as it was', async () => {
		const { browser, email } = await signedIn(acme, 'password');
		const link = await askForLink(browser, email);
		await browser.open(link);
		const before = await sessionOf(browser, acme);
		const { acr, amr, loginTs } = before.payload;

		await addOnPage(browser, new SoftAuthenticator(), acme);

		const after = (await sessionOf(browser, acme)).payload;
		expect({ acr: after.acr, amr: after.amr, loginTs: after.loginTs }).toEqual({
			acr,
			amr,
			loginTs
		});
	});

	it('writes no challenge, credential or link to a log line or the audit trail', async () => {
		const spies = (['log', 'info', 'warn', 'error', 'debug'] as const).map(
			(level) => spyOn(console, level)
		);
		const { browser, email, accountId } = await signedIn(acme, 'code');
		const { html } = await opened(browser);
		const options = creationOptionsIn(html);
		const credentialId = 'bm90LWluLWFueS1sb2c';

		await postAdd(browser, new SoftAuthenticator(), acme, html, {
			credentialId
		});

		const disown = present(
			mailsTo(email)
				.at(-1)
				?.text.split(/\s+/)
				.find((word) => word.includes('passkey-disown')),
			'the link'
		);
		const secret = present(
			new URL(disown).searchParams.get('token'),
			'a token'
		);
		const stored = present(
			(await getPasskeyStore().listOf(acme.bucketId, accountId))[0],
			'the passkey'
		);
		const logged = JSON.stringify(spies.flatMap((spy) => spy.mock.calls));
		const { entries } = await adminAuditStore.list({ targetId: accountId });
		const audited = JSON.stringify(entries);
		for (const secretValue of [
			options.challenge,
			credentialId,
			stored.publicKey,
			secret,
			options.user.id
		]) {
			expect({
				value: secretValue,
				logged: logged.includes(secretValue),
				audited: audited.includes(secretValue)
			}).toEqual({ value: secretValue, logged: false, audited: false });
		}
	});
});
