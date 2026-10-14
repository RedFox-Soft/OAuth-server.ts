/*
 * A person's explicit choice of language is remembered on their account; nothing else is.
 */

import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.js';
import { Browser, PASSWORD } from './switch_flow.ts';
import { getUserStore } from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';

async function person(
	fields: { locale?: string; provisionedBy?: string } = {}
) {
	const store = getUserStore(DEFAULT_BUCKET_ID);
	const email = `person-${Math.random()}@x.io`;
	const user = await store.create(
		email,
		await Bun.password.hash(PASSWORD),
		true
	);
	await store.update(user._id, {
		...(fields.locale ? { profile: { locale: fields.locale } } : {}),
		...(fields.provisionedBy ? { provisionedBy: fields.provisionedBy } : {})
	});
	return { email, id: user._id };
}

/* Signs in through the pages, switching to `switchTo` first when given; answers the stored locale after. */
async function signInAndRead(
	acceptLanguage: string,
	account: { email: string; id: string },
	switchTo?: string
) {
	const browser = new Browser(acceptLanguage);
	const { uid } = await browser.startSignIn();
	if (switchTo) {
		await browser.post(`/ui/${uid}/language`, {
			lang: switchTo,
			page: 'login'
		});
	}
	const signedIn = await browser.post(`/ui/${uid}/login`, {
		username: account.email,
		password: PASSWORD
	});
	await browser.follow(signedIn);
	return (await getUserStore(DEFAULT_BUCKET_ID).find(account.id))?.profile
		?.locale;
}

/**
 * @proves An end user who chooses a language with the switch and then signs in finds their account set to it,
 * so emails follow; the browser's language is never written to an account, a directory-owned account is left
 * to its directory, and a stored locale that already means the chosen language is not rewritten.
 */
describe('the language remembered on an account', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('is English after the person switches to English and signs in', async () => {
		const account = await person();

		expect(await signInAndRead('ru', account, 'en')).toBe('en');
	});

	it('is unchanged after a sign-in without the switch, whatever the browser asks for', async () => {
		const account = await person();

		expect(await signInAndRead('ru', account)).toBeUndefined();
	});

	it('is left to the directory for an account a directory provisions', async () => {
		const account = await person({ locale: 'ru-RU', provisionedBy: 'conn-1' });

		expect(await signInAndRead('ru', account, 'en')).toBe('ru-RU');
	});

	it('keeps a stored ru-RU when the person chooses Russian again', async () => {
		const account = await person({ locale: 'ru-RU' });
		const browser = new Browser('ru');
		const { uid } = await browser.startSignIn();
		await browser.post(`/ui/${uid}/language`, { lang: 'en', page: 'login' });
		await browser.post(`/ui/${uid}/language`, { lang: 'ru', page: 'login' });
		const signedIn = await browser.post(`/ui/${uid}/login`, {
			username: account.email,
			password: PASSWORD
		});
		await browser.follow(signedIn);

		expect(
			(await getUserStore(DEFAULT_BUCKET_ID).find(account.id))?.profile?.locale
		).toBe('ru-RU');
	});
});
