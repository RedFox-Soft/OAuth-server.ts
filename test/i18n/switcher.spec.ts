/*
 * The one language control: English and back, for a visitor whose own language is not English.
 */

import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.js';
import { Browser, langOf, switchOf } from './switch_flow.ts';
import { getUserStore } from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { SIGN_IN_TEXTS } from 'lib/i18n/texts/signIn/index.ts';

async function switchTo(
	browser: Browser,
	uid: string,
	lang: string,
	page = 'login'
) {
	return browser.post(`/ui/${uid}/language`, { lang, page });
}

/**
 * @proves A visitor whose browser asks for Russian can read the sign-in in English and come back to Russian,
 * with or without scripts, and the choice follows them through the rest of the sign-in; a visitor whose every
 * signal is English is shown no control at all.
 */
describe('the language switch', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('is not shown on the sign-in page to a visitor whose every signal is English', async () => {
		const browser = new Browser('en-US,en;q=0.9');
		const { location } = await browser.startSignIn();

		const { html } = await browser.page(location);

		expect(langOf(html)).toBe('en');
		expect(switchOf(html)).toBeUndefined();
	});

	it('offers English, named in English, to a visitor whose browser asks for Russian', async () => {
		const browser = new Browser('ru-RU,ru;q=0.9');
		const { uid, location } = await browser.startSignIn();

		const { html } = await browser.page(location);

		const offered = switchOf(html);
		expect(offered?.action).toBe(`/ui/${uid}/language`);
		expect(offered?.lang).toBe('en');
		expect(offered?.page).toBe('login');
		expect(offered?.button?.slice(1)).toEqual(['en', 'English']);
	});

	it('shows the same page again in English and offers Russian back after switching', async () => {
		const browser = new Browser('ru-RU,ru;q=0.9');
		const { uid } = await browser.startSignIn();

		const switched = await switchTo(browser, uid, 'en');

		expect(switched.status).toBe(303);
		expect(switched.headers.get('location')).toBe(`/ui/${uid}/login`);
		const { html } = await browser.page(`/ui/${uid}/login`);
		expect(langOf(html)).toBe('en');
		expect(html).toContain(SIGN_IN_TEXTS.en.login.submit);
		expect(switchOf(html)?.button?.slice(1)).toEqual(['ru', 'Русский']);
	});

	it('keeps the choice in a cookie the browser holds for a year, unreadable by scripts', async () => {
		const browser = new Browser('ru');
		const { uid } = await browser.startSignIn();

		await switchTo(browser, uid, 'en');

		const set = browser.setCookies.find((c) => c.startsWith('_lang='));
		expect(set).toBeDefined();
		expect(set).toContain('_lang=en');
		expect(set).toContain('Path=/');
		expect(set).toContain('Max-Age=31536000');
		expect(set).toContain('HttpOnly');
		expect(set).toContain('Secure');
		expect(set).toContain('SameSite=Lax');
	});

	it('returns to Russian when the visitor switches back', async () => {
		const browser = new Browser('ru');
		const { uid } = await browser.startSignIn();
		await switchTo(browser, uid, 'en');

		await switchTo(browser, uid, 'ru');

		const { html } = await browser.page(`/ui/${uid}/login`);
		expect(langOf(html)).toBe('ru');
	});

	it('keeps English on the next sign-in and on the sign-out page after switching', async () => {
		const browser = new Browser('ru');
		const { uid } = await browser.startSignIn();
		await switchTo(browser, uid, 'en');

		const next = await browser.startSignIn();
		const { html } = await browser.page(next.location);
		const signOut = await browser.page('/logout');

		expect(langOf(html)).toBe('en');
		expect(langOf(signOut.html)).toBe('en');
	});

	it('shows English and offers Russian to a person whose account says English but whose browser says Russian', async () => {
		const browser = new Browser('ru');
		const email = `stored-en-${Math.random()}@x.io`;
		const user = await getUserStore(DEFAULT_BUCKET_ID).create(
			email,
			await Bun.password.hash('correct horse battery'),
			true
		);
		await getUserStore(DEFAULT_BUCKET_ID).update(user._id, {
			profile: { locale: 'en' }
		});
		const first = await browser.startSignIn();
		const signedIn = await browser.post(`/ui/${first.uid}/login`, {
			username: email,
			password: 'correct horse battery'
		});
		await browser.follow(signedIn);

		const again = await browser.startSignIn({ prompt: 'consent' });
		const { html } = await browser.page(again.location);

		expect(again.location).toMatch(/\/consent$/);
		expect(langOf(html)).toBe('en');
		expect(switchOf(html)?.button?.slice(1)).toEqual(['ru', 'Русский']);
	});
});
