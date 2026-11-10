import { beforeAll, beforeEach, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.js';
import { configuration } from 'lib/configs/application.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import {
	acrOf,
	Browser,
	CODE_APP,
	mailOn,
	openApp,
	PLAIN_APP,
	person,
	project,
	propsOf,
	setUpAndContinue,
	signInTo,
	textOf
} from './helpers.ts';

/**
 * @proves A person who signs in with a password to an application that requires a code, and has none, is not handed
 * back to the application with an error: they see a page that says why, from which they can set one up and continue
 * the same sign-in, or go back to the application without signing in.
 */
describe('signing in to an application that requires a code, without one', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		resetSentEmails();
		await mailOn();
		await project();
	});

	it('stops at a page that offers to set one up', async () => {
		const { email } = await person();

		const reached = await signInTo(new Browser(), email);

		expect(reached.url).toMatch(/\/ui\/[^/]+\/code-required$/);
		expect(reached.response.status).toBe(200);
		const html = await reached.response.text();
		expect(propsOf(html).variant).toBe('setUp');
		expect(textOf(html)).toContain(email);
	});

	it('continues the same sign-in once a code is set up, with a multi-factor sign-in', async () => {
		const { email } = await person();
		const browser = new Browser();
		const reached = await signInTo(browser, email);

		const landed = await setUpAndContinue(browser, reached.url, email);

		expect(landed.url).toStartWith('https://billing.acme.test/cb');
		expect(await acrOf(reached.auth, landed.url)).toBe(
			configuration.acrMap.multi_factor
		);
	});

	it('hands the application the standard error when the person goes back', async () => {
		const { email } = await person();
		const browser = new Browser();
		const reached = await signInTo(browser, email);

		const back = await browser.post(reached.url, { action: 'return' });
		const { url } = await browser.open(
			new URL(back.headers.get('location') ?? '', reached.url).toString()
		);

		expect(new URL(url).searchParams.get('error')).toBe(
			'unmet_authentication_requirements'
		);
	});

	it('says to ask the project when people cannot set one up themselves', async () => {
		await project({ totpSelfService: false });
		const { email } = await person();

		const reached = await signInTo(new Browser(), email);

		expect(propsOf(await reached.response.text()).variant).toBe('askOperators');
	});

	it('leaves an application without the setting as it was', async () => {
		const { email } = await person();

		const reached = await signInTo(new Browser(), email, PLAIN_APP);

		expect(reached.url).toStartWith('https://time.acme.test/cb');
	});

	it('refuses at once when the application asked for no page', async () => {
		const { url } = await openApp(new Browser(), CODE_APP, { prompt: 'none' });

		expect(new URL(url).searchParams.get('error')).toBe('login_required');
	});
});
