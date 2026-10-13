import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ACCOUNT_PAGE_COOKIE } from 'lib/consts/account_page.ts';
import { ACCOUNT_PAGE_TEXTS } from 'lib/account_page/texts.ts';
import { ISSUER } from 'lib/configs/env.js';
import { present } from '../shape.ts';
import {
	addressedBucket,
	Browser,
	defaultBucket,
	pageOf,
	person,
	signInThroughPage,
	textOf
} from './helpers.ts';

/**
 * @proves A person reaches their connected-applications page by signing in to the bucket it belongs to, at
 * whichever address that bucket has, and a sign-in that did not start here, or did not finish, changes
 * nothing.
 */
describe('signing in to the connected-applications page', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'connected_apps' });
		await ensureAdminSeed();
		await defaultBucket();
		await addressedBucket('acme-bucket', { slug: 'acme' });
		await addressedBucket('beta-bucket', { host: 'beta.example.test' });
	});

	it('sends a signed-out visitor to the bucket’s own sign-in with the page’s client and nothing to redeem', async () => {
		const browser = new Browser();

		const res = await browser.request(pageOf('/acme'));

		expect(res.status).toBe(303);
		const location = new URL(res.headers.get('location') ?? '');
		expect(`${location.origin}${location.pathname}`).toBe(
			`${ISSUER}/acme/auth`
		);
		expect(location.searchParams.get('client_id')).toBe('account.acme-bucket');
		expect(location.searchParams.get('response_type')).toBe('none');
		expect(location.searchParams.get('redirect_uri')).toBe(
			`${ISSUER}/acme/account/apps/callback`
		);
		const pending = res.headers
			.getSetCookie()
			.find((c) => c.startsWith(`${ACCOUNT_PAGE_COOKIE}=`));
		expect(pending).toContain('Path=/acme/account/apps');
	});

	it('lands the person on their list after the login form, with no consent page, at a path-addressed bucket', async () => {
		const { email } = await person('acme-bucket');
		const browser = new Browser();

		const landed = await signInThroughPage(browser, email, '/acme');

		expect(landed.status).toBe(200);
		const text = textOf(await landed.text());
		expect(text).toContain(ACCOUNT_PAGE_TEXTS.title);
		expect(text).toContain(email);
		expect(text).toContain(ACCOUNT_PAGE_TEXTS.empty);
		expect(browser.has(ACCOUNT_PAGE_COOKIE)).toBe(false);
	});

	it('lands the person on their list at the root, for the default bucket', async () => {
		const { email } = await person();
		const browser = new Browser();

		const landed = await signInThroughPage(browser, email);

		expect(landed.status).toBe(200);
		expect(textOf(await landed.text())).toContain(email);
	});

	it('lands the person on their list at a host-addressed bucket', async () => {
		const { email } = await person('beta-bucket');
		const browser = new Browser('http://beta.example.test');

		const landed = await signInThroughPage(browser, email);

		expect(landed.status).toBe(200);
		expect(textOf(await landed.text())).toContain(email);
	});

	it('shows the list straight away to a person already signed in', async () => {
		const { email } = await person('acme-bucket');
		const browser = new Browser();
		await signInThroughPage(browser, email, '/acme');

		const again = await browser.request(pageOf('/acme'));

		expect(again.status).toBe(200);
	});

	it('answers that the sign-in expired, and signs nobody in, for a return without the pending sign-in', async () => {
		const browser = new Browser();

		const res = await browser.request(
			`${pageOf('/acme')}/callback?state=anything`
		);

		expect(res.status).toBe(400);
		expect(textOf(await res.text())).toContain(ACCOUNT_PAGE_TEXTS.expiredTitle);
	});

	it('answers that the sign-in expired for a return carrying a different state', async () => {
		const browser = new Browser();
		await browser.request(pageOf('/acme'));

		const res = await browser.request(
			`${pageOf('/acme')}/callback?state=not-the-one`
		);

		expect(res.status).toBe(400);
		expect(browser.has(ACCOUNT_PAGE_COOKIE)).toBe(false);
	});

	it('says the person did not sign in after a cancelled sign-in', async () => {
		const browser = new Browser();
		const started = await browser.request(pageOf('/acme'));
		const state = present(
			new URL(started.headers.get('location') ?? '').searchParams.get('state'),
			'the state the sign-in was started with'
		);

		const res = await browser.request(
			`${pageOf('/acme')}/callback?state=${state}&error=access_denied`
		);

		expect(res.status).toBe(200);
		expect(textOf(await res.text())).toContain(
			ACCOUNT_PAGE_TEXTS.notSignedInTitle
		);
	});
});
