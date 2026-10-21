/*
 * A person signs in and consents in the language their browser asks for, decided once for the whole sign-in.
 */

import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap, { bindClientToBucket, type Setup } from '../test_helper.js';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { withCookies } from '../consent_page/flow.ts';
import {
	getBucketStore,
	getUserStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { ISSUER } from 'lib/configs/env.js';
import { elysia } from 'lib/index.ts';
import { CONSENT_TEXTS } from 'lib/i18n/texts/consent/index.ts';
import { SIGN_IN_TEXTS } from 'lib/i18n/texts/signIn/index.ts';

const CLIENT_ID = 'i18n-app';
const PASSWORD = 'correct horse battery';

let setup: Setup;
let bucketId: string;

function langOf(html: string): string | undefined {
	return /<html lang="([^"]+)"/.exec(html)?.[1];
}

async function get(path: string, cookie: string) {
	const response = await elysia.handle(
		new Request(`${ISSUER}${path}`, { headers: { cookie } })
	);
	return { response, html: await response.clone().text() };
}

/* Starts a sign-in from a browser sending `headers`, and opens the page it is sent to. */
async function startSignIn(
	headers: Record<string, string>,
	params: Record<string, string> = {}
) {
	const auth = new AuthorizationRequest({
		client_id: CLIENT_ID,
		scope: 'openid',
		...params
	});
	const started = await auth.authorize({ headers });
	expect(started.status).toBe(303);
	const location = started.headers.get('location') ?? '';
	const cookie = withCookies(
		'cookie' in headers ? headers.cookie : '',
		started
	);
	const page = await get(location, cookie);
	return { location, uid: location.split('/')[2], cookie, ...page };
}

async function registered(email: string): Promise<string> {
	const { uid, cookie } = await startSignIn({});
	const response = await elysia.handle(
		new Request(`${ISSUER}/ui/${uid}/registration`, {
			method: 'POST',
			headers: {
				cookie,
				'content-type': 'application/x-www-form-urlencoded'
			},
			body: new URLSearchParams({
				email,
				password: PASSWORD,
				confirmPassword: PASSWORD
			})
		})
	);
	expect(response.status).toBe(303);
	const user = (await getUserStore(bucketId).list()).find(
		(u) => u.email === email
	);
	if (!user) throw new Error('registration created no account');
	return user._id;
}

async function setStoredLocale(accountId: string, locale: string) {
	const user = await getUserStore(bucketId).find(accountId);
	await getUserStore(bucketId).update(accountId, {
		profile: { ...user?.profile, locale }
	});
}

/* Follows redirects inside this server until a page answers, carrying the cookies a browser would. */
async function follow(response: Response, cookie: string) {
	let jar = withCookies(cookie, response);
	let location = response.headers.get('location') ?? '';
	for (let hop = 0; hop < 5 && location.startsWith('/'); hop++) {
		const next = await elysia.handle(
			new Request(`${ISSUER}${location}`, { headers: { cookie: jar } })
		);
		jar = withCookies(jar, next);
		if (next.status !== 303 && next.status !== 302) {
			return { location, html: await next.text(), cookie: jar };
		}
		location = next.headers.get('location') ?? '';
	}
	return { location, html: '', cookie: jar };
}

/**
 * @proves An end user whose browser asks for Russian or Simplified Chinese is shown every sign-in page in
 * that language, a browser asking for a language this server does not speak gets English without an error,
 * and a sign-in never changes language between its own pages.
 */
describe('the language of the sign-in pages', () => {
	beforeAll(async () => {
		setup = await bootstrap(import.meta.url);
		resetAdminMemoryStores();
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Languages',
			emailVerificationRequired: false
		});
		bucketId = bucket._id;
		await bindClientToBucket(CLIENT_ID, bucketId);
	});

	it('shows the sign-in page in Russian and says so when the browser asks for Russian', async () => {
		const page = await startSignIn({
			'accept-language': 'ru-RU,ru;q=0.9,en;q=0.8'
		});

		expect(langOf(page.html)).toBe('ru');
		expect(page.response.headers.get('content-language')).toBe('ru');
		expect(page.html).toContain(
			`<title>${SIGN_IN_TEXTS.ru.titles.login}</title>`
		);
		expect(page.html).toContain(SIGN_IN_TEXTS.ru.login.submit);
	});

	for (const asked of ['zh', 'zh-CN', 'zh-SG', 'zh-Hans-CN']) {
		it(`shows the sign-in page in Simplified Chinese when the browser asks for ${asked}`, async () => {
			const page = await startSignIn({ 'accept-language': asked });

			expect(langOf(page.html)).toBe('zh-Hans');
			expect(page.html).toContain(SIGN_IN_TEXTS['zh-Hans'].login.submit);
		});
	}

	it('shows English, not Simplified Chinese, when the browser asks only for Traditional Chinese', async () => {
		const page = await startSignIn({ 'accept-language': 'zh-TW' });

		expect(page.response.status).toBe(200);
		expect(langOf(page.html)).toBe('en');
	});

	it('shows English without an error when the browser asks for a language this server does not speak', async () => {
		const page = await startSignIn({ 'accept-language': 'de-DE,de;q=0.9' });

		expect(page.response.status).toBe(200);
		expect(langOf(page.html)).toBe('en');
	});

	it('chooses the language the browser weighs higher, whatever order it lists them in', async () => {
		const page = await startSignIn({ 'accept-language': 'ru;q=0.5, zh;q=0.9' });

		expect(langOf(page.html)).toBe('zh-Hans');
	});

	it('shows the registration page in the sign-in’s language', async () => {
		const { uid, cookie } = await startSignIn({ 'accept-language': 'ru' });

		const page = await get(`/ui/${uid}/registration`, cookie);

		expect(langOf(page.html)).toBe('ru');
		expect(page.html).toContain(SIGN_IN_TEXTS.ru.registration.submit);
	});

	it('keeps the consent page in the language the sign-in started in, even when the account’s stored language differs', async () => {
		const accountId = await registered('stays-russian@example.com');
		await setStoredLocale(accountId, 'zh-Hans');
		const { uid, cookie } = await startSignIn({ 'accept-language': 'ru' });

		const signedIn = await elysia.handle(
			new Request(`${ISSUER}/ui/${uid}/login`, {
				method: 'POST',
				headers: {
					cookie,
					'content-type': 'application/x-www-form-urlencoded'
				},
				body: new URLSearchParams({
					username: 'stays-russian@example.com',
					password: PASSWORD
				})
			})
		);
		const consent = await follow(signedIn, cookie);

		expect(consent.location).toMatch(/\/consent$/);
		expect(langOf(consent.html)).toBe('ru');
		expect(consent.html).toContain(CONSENT_TEXTS.ru.buttons.allow);
	});

	it('uses the account’s stored language for a person already signed in when nothing else names one', async () => {
		const accountId = 'stored-russian';
		const session = await setup.login({ accountId, bucketId });
		await setStoredLocale(accountId, 'ru-RU');

		const page = await startSignIn({ cookie: session }, { prompt: 'consent' });

		expect(page.location).toMatch(/\/consent$/);
		expect(langOf(page.html)).toBe('ru');
	});
});
