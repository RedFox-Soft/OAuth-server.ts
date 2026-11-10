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
import { adminAuditStore, getUserStore } from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import {
	Browser,
	linkIn,
	mailOn,
	mailsTo,
	person,
	project,
	propsOf,
	setUpAndContinue,
	signInTo,
	textOf,
	uidIn
} from './helpers.ts';

/**
 * @proves Setting up a code from an application that requires one takes the proofs a person's own page takes — the
 * password typed in this browser within fifteen minutes, a link mailed to them opened in this same browser, then a
 * code — and has its effects: the factor is theirs, the mail with "This wasn't me" arrives, and the audit names them.
 * Without effective self-service, a fresh password or the link in this browser, nothing is set up.
 */
describe('setting up a code from an application that requires one', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		resetSentEmails();
		await mailOn();
		await project();
	});

	afterEach(() => {
		setSystemTime();
	});

	it('sets up the person’s own factor, mails them and records it as theirs', async () => {
		const { email, accountId } = await person();
		const browser = new Browser();
		const reached = await signInTo(browser, email);

		await setUpAndContinue(browser, reached.url, email);

		const user = await getUserStore(DEFAULT_BUCKET_ID).find(accountId);
		expect(user?.totp?.via).toBe('self');
		expect(user?.verified).toBe(true);
		expect(
			mailsTo(email).some((mail) =>
				mail.text.includes('/account/security/disown')
			)
		).toBe(true);
		const { entries } = await adminAuditStore.list({ targetId: accountId });
		expect(entries.map((entry) => entry.action)).toContain(
			'enduser.totp.enrol'
		);
	});

	it('asks for the mailed link before showing any secret', async () => {
		const { email } = await person();
		const browser = new Browser();
		const reached = await signInTo(browser, email);

		const page = await browser.request(`/ui/${uidIn(reached.url)}/totp/enroll`);
		const props = propsOf(await page.text());

		expect(props.mode).toBe('mailed');
		expect(props.secretText).toBeUndefined();
	});

	it('sets up nothing when the link is opened in another browser', async () => {
		const { email, accountId } = await person();
		const browser = new Browser();
		const reached = await signInTo(browser, email);
		const uid = uidIn(reached.url);
		await browser.open(`/ui/${uid}/totp/enroll`);

		await new Browser().open(linkIn(email, `/ui/${uid}/totp/enroll/link`));
		const page = await browser.request(`/ui/${uid}/totp/enroll`);

		expect(propsOf(await page.text()).mode).toBe('mailed');
		expect(
			(await getUserStore(DEFAULT_BUCKET_ID).find(accountId))?.totp
		).toBeUndefined();
	});

	it('offers nothing when the password was typed more than fifteen minutes ago', async () => {
		const { email } = await person();
		const browser = new Browser();
		const reached = await signInTo(browser, email);
		setSystemTime(new Date(Date.now() + 16 * 60 * 1000));

		const page = await browser.request(`/ui/${uidIn(reached.url)}/totp/enroll`);

		expect(page.status).toBe(303);
		expect(page.headers.get('location')).toEndWith('/code-required');
	});

	it('offers nothing when people cannot set one up themselves', async () => {
		const { email } = await person();
		const browser = new Browser();
		const reached = await signInTo(browser, email);
		await project({ totpSelfService: false });

		const page = await browser.request(`/ui/${uidIn(reached.url)}/totp/enroll`);

		expect(page.status).toBe(303);
		expect(page.headers.get('location')).toEndWith('/code-required');
	});

	// Found by the browser walk: after the hour the browser no longer holds the sign-in's cookie either.
	it('shows the same page when the browser no longer holds the sign-in’s cookie', async () => {
		const { email } = await person();
		const reached = await signInTo(new Browser(), email);

		const page = await new Browser().request(reached.url, {
			headers: { accept: 'text/html', 'accept-language': 'zh-CN' }
		});

		expect(page.status).toBe(400);
		expect(textOf(await page.text())).toContain('此登录已过期');
	});

	it('shows a plain page in the person’s language once the sign-in has expired', async () => {
		const { email } = await person();
		const browser = new Browser();
		const reached = await signInTo(browser, email);
		setSystemTime(new Date(Date.now() + 61 * 60 * 1000));

		const page = await browser.request(reached.url, {
			headers: { accept: 'text/html', 'accept-language': 'ru' }
		});

		expect(page.status).toBe(400);
		expect(page.headers.get('content-language')).toBe('ru');
		expect(textOf(await page.text())).toContain('Время на вход истекло');
	});
});
