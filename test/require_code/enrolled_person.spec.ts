import { beforeAll, beforeEach, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.js';
import { getUserStore } from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { configuration } from 'lib/configs/application.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import { present } from '../shape.ts';
import {
	acrOf,
	Browser,
	codeFor,
	mailOn,
	openApp,
	person,
	PLAIN_APP,
	project,
	propsOf,
	signInTo,
	textOf,
	typePassword
} from './helpers.ts';

const SECRET = 'JBSWY3DPEHPK3PXP';

async function holdsFactor(accountId: string): Promise<void> {
	await getUserStore(DEFAULT_BUCKET_ID).update(accountId, {
		totp: { secret: SECRET, enrolledAt: new Date(), lastStep: 0, via: 'self' }
	});
}

/**
 * @proves A person who holds a code but whose sign-in in this browser gave none is not refused by an application that
 * requires one: they sign in again with their password and their code, as at any sign-in, and get in. A sign-in that
 * already gave a code is asked nothing more, and no step ever accepts a code alone on top of an existing sign-in.
 */
describe('a person with a code, at an application that requires one', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		resetSentEmails();
		await mailOn();
		await project();
	});

	it('is asked for the password and then the code, and gets a multi-factor sign-in', async () => {
		const { email, accountId } = await person();
		const browser = new Browser();
		await signInTo(browser, email, PLAIN_APP);
		await holdsFactor(accountId);

		const opened = await openApp(browser);
		expect(opened.url).toMatch(/\/ui\/[^/]+\/login$/);
		expect(textOf(await opened.response.text())).toContain(
			'asks for a code from an authenticator app'
		);
		const asked = await typePassword(browser, opened.url, email);
		const uid = present(
			/\/ui\/([^/]+)\/totp$/.exec(asked.url)?.[1],
			'the code step'
		);
		const answered = await browser.post(`/ui/${uid}/totp`, {
			code: codeFor(SECRET)
		});
		const landed = await browser.open(
			new URL(
				present(answered.headers.get('location'), 'a resume'),
				browser.url(`/ui/${uid}/`)
			).toString()
		);

		expect(landed.url).toStartWith('https://billing.acme.test/cb');
		expect(await acrOf(opened.auth, landed.url)).toBe(
			configuration.acrMap.multi_factor
		);
	});

	it('is asked nothing when the sign-in in this browser already gave a code', async () => {
		const { email, accountId } = await person();
		await holdsFactor(accountId);
		const browser = new Browser();
		const first = await signInTo(browser, email, PLAIN_APP);
		const uid = present(
			/\/ui\/([^/]+)\/totp$/.exec(first.url)?.[1],
			'the code step'
		);
		const answered = await browser.post(`/ui/${uid}/totp`, {
			code: codeFor(SECRET)
		});
		await browser.open(
			new URL(
				present(answered.headers.get('location'), 'a resume'),
				browser.url(`/ui/${uid}/`)
			).toString()
		);

		const opened = await openApp(browser);

		expect(opened.url).toStartWith('https://billing.acme.test/cb');
	});

	it('never takes a code alone over the sign-in it already has', async () => {
		const { email, accountId } = await person();
		const browser = new Browser();
		await signInTo(browser, email, PLAIN_APP);
		await holdsFactor(accountId);
		const opened = await openApp(browser);
		const uid = present(
			/\/ui\/([^/]+)\/login$/.exec(opened.url)?.[1],
			'the login'
		);

		const codeStep = await browser.request(`/ui/${uid}/totp`);

		expect(codeStep.status).toBe(303);
		expect(codeStep.headers.get('location')).toEndWith('/login');
		expect(propsOf(await opened.response.text())).not.toHaveProperty('mode');
	});
});
