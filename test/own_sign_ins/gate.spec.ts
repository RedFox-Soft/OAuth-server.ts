import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.js';
import { ACCOUNT_TEXTS } from 'lib/i18n/texts/account/index.ts';
import { present } from '../shape.ts';
import {
	addressedBucket,
	PASSWORD,
	person,
	signInThroughPage
} from '../connected_apps/helpers.ts';
import {
	Browser,
	openPage,
	PAGE,
	reshapeSession,
	signedIn,
	STALE
} from './helpers.ts';

const T = ACCOUNT_TEXTS.en;

/* Types the password on the login page a re-authentication leads to; answers where the browser lands. */
async function signInAgain(
	browser: Browser,
	start: string,
	email: string
): Promise<{ response: Response; url: string }> {
	const login = await browser.open(start);
	expect(login.url).toMatch(/\/ui\/[^/]+\/login$/);
	const posted = await browser.request(login.url, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			username: email,
			password: PASSWORD
		}).toString()
	});
	return browser.open(
		new URL(
			present(posted.headers.get('location'), 'a resume'),
			login.url
		).toString()
	);
}

/**
 * @proves Recent sign-ins opens only for a person who signed in in this browser within the last fifteen minutes, by
 * any method; anyone else is asked to sign in again and comes back to the page, at every address of the project.
 */
describe('opening recent sign-ins', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'own_sign_ins' });
	});

	it('shows the page to a person who just signed in', async () => {
		const { browser } = await signedIn();

		const { response, html } = await openPage(browser);

		expect(response.status).toBe(200);
		expect(html).toContain(T.signInsTitle);
	});

	it('asks a stale session to sign in again and comes back to the page', async () => {
		const { browser, email } = await signedIn();
		await reshapeSession(browser, { ageSeconds: STALE });

		const asked = await browser.request(PAGE);
		const location = present(asked.headers.get('location'), 'a redirect');
		const landed = await signInAgain(browser, location, email);

		expect(asked.status).toBe(303);
		expect(new URL(location, browser.origin).searchParams.get('prompt')).toBe(
			'login'
		);
		expect(new URL(landed.url).pathname).toBe(PAGE);
		expect(landed.response.status).toBe(200);
		expect(await landed.response.text()).toContain(T.signInsTitle);
	});

	it('opens for a provider-only person who just signed in through their provider', async () => {
		const { browser } = await signedIn();
		await reshapeSession(browser, { ageSeconds: 30, amr: ['fed'] });

		const { response } = await openPage(browser);

		expect(response.status).toBe(200);
	});

	it('sends a person without a session to sign in', async () => {
		const response = await new Browser().request(PAGE);

		expect(response.status).toBe(303);
		expect(response.headers.get('location')).toContain('/auth?');
	});

	it('answers beneath the project’s path as well', async () => {
		const bucket = await addressedBucket('acme-own', { slug: 'acme-own' });
		const { email } = await person(bucket._id);
		const browser = new Browser();
		await signInThroughPage(browser, email, '/acme-own');

		const { response, html } = await openPage(browser, '', '/acme-own');

		expect(response.status).toBe(200);
		expect(html).toContain(T.signInsTitle);
	});
});
