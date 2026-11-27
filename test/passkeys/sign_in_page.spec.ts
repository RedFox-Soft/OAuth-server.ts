import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	setSystemTime
} from 'bun:test';
import { createElement } from 'react';
import { renderToString } from 'react-dom/server';

import bootstrap, { bindClientToBucket } from '../test_helper.js';
import { getBucketStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { SignInPreview } from 'lib/admin/ui/pages/signin/SignInPreview.tsx';
import { REMEMBER_TICK } from 'lib/interactions/loginPage.tsx';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import { present } from '../shape.ts';
import {
	ACME,
	BETA,
	Browser,
	SUB,
	mailOn,
	passkeyOfferIn,
	project,
	securityPage,
	signInPage,
	signedIn,
	textOf,
	xsrfFrom,
	type Project
} from './helpers.ts';

let acme: Project;

/* The sign-in page a re-authentication from the person's own page leads to, after `action` there. */
async function reauthenticationFor(
	browser: Browser,
	at: Project,
	action: string
): Promise<string> {
	const opened = await browser.request(securityPage(at));
	const asked = await browser.post(securityPage(at), {
		action,
		xsrf: xsrfFrom(await opened.text())
	});
	const login = await browser.open(
		present(asked.headers.get('location'), 'a sign-in again')
	);
	expect(login.url).toMatch(/\/ui\/[^/]+\/login$/);
	return login.response.text();
}

function previewMarkup(passkeyLogin: boolean): string {
	return renderToString(
		createElement(SignInPreview, {
			bucketId: 'preview',
			service: 'Acme',
			draft: {
				passwordLogin: true,
				registrationOpen: true,
				totpRequired: false,
				passkeyLogin
			},
			providers: [],
			federationOn: true,
			loading: false
		})
	);
}

/**
 * @proves A project that accepts passkeys offers them on every form of its sign-in page — beside the password form
 * and where there is none — with an email field the browser can hang its passkey suggestions on, and the console's
 * preview draws the same button; a project that does not, and the administrators' project, show nothing about
 * passkeys; and a re-authentication the person's own page asks for a fresh password or a fresh code offers none.
 */
describe('the passkey offer on the sign-in page', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await ensureAdminSeed();
		acme = await project(ACME);
	});

	beforeEach(async () => {
		resetSentEmails();
		await mailOn();
	});

	afterEach(() => {
		setSystemTime();
	});

	it('offers a passkey beside the password form, asking the browser for any passkey of this site with the person verified', async () => {
		const { html } = await signInPage(new Browser(acme.origin), acme);

		expect(passkeyOfferIn(html)).toMatchObject({
			options: {
				rpId: 'e.ly',
				userVerification: 'required',
				timeout: 300000,
				allowCredentials: []
			},
			remember: true
		});
		expect(textOf(html)).toContain('Sign in with a passkey');
	});

	it('lets the browser suggest passkeys on the password form’s email field', async () => {
		const { html } = await signInPage(new Browser(acme.origin), acme);

		// HTML attribute names are case-insensitive; React writes this one as `autoComplete`.
		expect(html).toMatch(
			/<input[^>]*autocomplete="username webauthn"[^>]*name="username"/i
		);
	});

	it('lets the passkey’s post find the page’s "Remember me" box, so an unticked box is honoured', async () => {
		const { html } = await signInPage(new Browser(acme.origin), acme);
		let found = 0;

		// The selector the page's script copies the tick with, run against the page the script hydrates.
		new HTMLRewriter()
			.on(REMEMBER_TICK, {
				element(element) {
					if (element.getAttribute('type') === 'checkbox') found += 1;
				}
			})
			.transform(html);

		expect(found).toBe(1);
	});

	it('offers a passkey, with an email field of its own, where the page has no password form', async () => {
		const sub = await project(SUB, {
			subdomain: true,
			settings: { passwordLogin: false }
		});

		const { html } = await signInPage(new Browser(sub.origin), sub);

		expect(passkeyOfferIn(html)).toMatchObject({
			options: { rpId: 'sub.e.ly' },
			remember: false
		});
		expect(html).toMatch(/<input[^>]*autocomplete="username webauthn"/i);
		expect(html).not.toMatch(/name="password"/);
		expect(textOf(html)).toContain('Sign in with a passkey');
	});

	it('shows nothing about passkeys where the project does not accept them', async () => {
		const beta = await project(BETA, { passkeys: false });

		const { html } = await signInPage(new Browser(beta.origin), beta);

		expect(passkeyOfferIn(html)).toBeUndefined();
		expect(html).not.toContain('webauthn');
		expect(textOf(html)).not.toContain('passkey');
	});

	it('offers passkeys at the administrators’ project when passkeyLogin is on', async () => {
		await getBucketStore().update(ADMIN_BUCKET_ID, { passkeyLogin: true });
		await bindClientToBucket(BETA.clientId, ADMIN_BUCKET_ID);
		const admins: Project = {
			bucketId: ADMIN_BUCKET_ID,
			clientId: BETA.clientId,
			prefix: '',
			origin: 'http://e.ly'
		};

		const { html } = await signInPage(new Browser(admins.origin), admins);

		expect(passkeyOfferIn(html)).toBeDefined();
		expect(html).toContain('webauthn');
		await getBucketStore().update(ADMIN_BUCKET_ID, { passkeyLogin: false });
	});

	it('draws the passkey button in the console’s preview of a draft with passkeys on', () => {
		expect(textOf(previewMarkup(true))).toContain('Sign in with a passkey');
		expect(textOf(previewMarkup(false))).not.toContain('passkey');
	});

	it('offers no passkey on the sign-in again before turning on two-step verification', async () => {
		const { browser } = await signedIn(acme, 'password');
		setSystemTime(new Date(Date.now() + 16 * 60 * 1000));

		const html = await reauthenticationFor(browser, acme, 'start');

		expect(passkeyOfferIn(html)).toBeUndefined();
	});

	it('offers no passkey on the sign-in again before turning two-step verification off', async () => {
		const { browser } = await signedIn(acme, 'code');
		setSystemTime(new Date(Date.now() + 16 * 60 * 1000));

		const html = await reauthenticationFor(browser, acme, 'off');

		expect(passkeyOfferIn(html)).toBeUndefined();
	});

	it('offers a passkey on the sign-in again before adding a passkey', async () => {
		const { browser } = await signedIn(acme, 'password');
		setSystemTime(new Date(Date.now() + 16 * 60 * 1000));

		const html = await reauthenticationFor(browser, acme, 'passkey_start');

		expect(passkeyOfferIn(html)).toBeDefined();
	});
});
