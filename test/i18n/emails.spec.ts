/*
 * End-user emails, and the pages their links open, in the person's language.
 */

import {
	afterAll,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it
} from 'bun:test';

import bootstrap from '../test_helper.js';
import { Browser, PASSWORD, langOf } from './switch_flow.ts';
import {
	emailsTo,
	extractResetUrl,
	extractVerifyUrl,
	resetSentEmails
} from '../mail_capture.ts';
import { adminCall, withMail } from '../end_user_lifecycle/admin_call.ts';
import { adminCookie, defaultBucket } from '../end_user_lifecycle/fixtures.ts';
import {
	getBucketStore,
	getSmtpSettingsStore,
	getUserStore
} from 'lib/adapters/index.ts';
import type { SmtpSettings } from 'lib/adapters/types.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { elysia } from 'lib/index.ts';
import { text as fill } from 'lib/i18n/message.tsx';
import { EMAIL_TEXTS } from 'lib/i18n/texts/email/index.ts';
import type { Language } from 'lib/i18n/languages.ts';

let previousMail: SmtpSettings | null;
let appName: string;

async function account({
	locale,
	verified = true
}: { locale?: string; verified?: boolean } = {}) {
	const store = getUserStore(DEFAULT_BUCKET_ID);
	const email = `mail-${Math.random()}@x.io`;
	const user = await store.create(
		email,
		await Bun.password.hash(PASSWORD),
		verified
	);
	if (locale) await store.update(user._id, { profile: { locale } });
	return { email, id: user._id };
}

async function verificationBy(method: 'link' | 'code') {
	await getBucketStore().update(DEFAULT_BUCKET_ID, {
		emailVerificationRequired: true,
		verificationMethod: method
	});
}

/* A password sign-in of an unverified account, which sends it a verification message. */
async function signInUnverified(acceptLanguage: string, email: string) {
	const browser = new Browser(acceptLanguage);
	const { uid } = await browser.startSignIn();
	await browser.post(`/ui/${uid}/login`, {
		username: email,
		password: PASSWORD
	});
}

async function askForReset(acceptLanguage: string, email: string) {
	const browser = new Browser(acceptLanguage);
	const { uid } = await browser.startSignIn();
	await browser.post(`/ui/${uid}/forgot-password`, { email });
	// The reset email is sent off the request path.
	await Bun.sleep(20);
}

function only(email: string) {
	const sent = emailsTo(email);
	expect(sent).toHaveLength(1);
	return sent[0];
}

function expectWrittenIn(
	message: ReturnType<typeof only>,
	language: Language,
	subject: string
) {
	expect(message.language).toBe(language);
	expect(message.subject).toBe(subject);
	expect(message.html).toContain(`<div lang="${language}"`);
}

/* Opens a link from an email in a browser that asks for English and holds no language choice. */
async function openInEnglishBrowser(url: string) {
	const response = await elysia.handle(
		new Request(url, { headers: { 'accept-language': 'en-US,en;q=0.9' } })
	);
	return { response, html: await response.text() };
}

/**
 * @proves An end user receives every end-user email in their own language — the one stored on their account,
 * else the one of the page they asked from, else English — with the language declared, and the page the
 * email's link opens is in the same language even in a browser that asks for another.
 */
describe('end-user emails in the person’s language', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		const bucket = await defaultBucket();
		appName = bucket.name || 'the application';
		previousMail = await withMail();
	});

	afterAll(async () => {
		if (previousMail) await getSmtpSettingsStore().set(previousMail);
	});

	beforeEach(() => {
		resetSentEmails();
	});

	it('sends the verification link in the account’s stored language, not the browser’s', async () => {
		await verificationBy('link');
		const person = await account({ locale: 'zh-Hans', verified: false });

		await signInUnverified('en', person.email);

		expectWrittenIn(
			only(person.email),
			'zh-Hans',
			fill(EMAIL_TEXTS['zh-Hans'].verification.link.subject, { app: appName })
		);
	});

	it('sends the verification code in the account’s stored language', async () => {
		await verificationBy('code');
		const person = await account({ locale: 'zh-Hans', verified: false });

		await signInUnverified('en', person.email);

		expectWrittenIn(
			only(person.email),
			'zh-Hans',
			fill(EMAIL_TEXTS['zh-Hans'].verification.code.subject, { app: appName })
		);
	});

	it('sends the reset email in the language of the page it was asked from when the account has none', async () => {
		const person = await account();

		await askForReset('ru', person.email);

		expectWrittenIn(
			only(person.email),
			'ru',
			fill(EMAIL_TEXTS.ru.passwordReset.subject, { app: appName })
		);
	});

	for (const [stored, expected] of [
		['fr-CA', 'en'],
		['ru-RU', 'ru']
	] as const) {
		it(`sends the reset email in ${expected} for an account whose stored locale is ${stored}`, async () => {
			const person = await account({ locale: stored });

			await askForReset('en', person.email);

			expect(only(person.email).language).toBe(expected);
		});
	}

	for (const [stored, expected] of [
		['zh-Hans', 'zh-Hans'],
		[undefined, 'en']
	] as const) {
		it(`sends an administrator’s invitation in ${expected} when the account’s stored locale is ${stored ?? 'absent'}`, async () => {
			const cookie = await adminCookie();
			const email = `invited-${Math.random()}@x.io`;
			const created = await adminCall(
				cookie,
				'POST',
				`/admin/api/projects/${DEFAULT_BUCKET_ID}/users`,
				{ email }
			);
			const id =
				(created.body as { _id?: string; id?: string })._id ??
				(created.body as { id?: string }).id;
			if (!id) throw new Error('the person was not created');
			if (stored) {
				await getUserStore(DEFAULT_BUCKET_ID).update(id, {
					profile: { locale: stored }
				});
			}

			await adminCall(
				cookie,
				'POST',
				`/admin/api/projects/${DEFAULT_BUCKET_ID}/users/${id}/invitation`
			);

			expect(only(email).language).toBe(expected);
		});
	}

	it('opens the verification link’s page in the email’s language in an English browser', async () => {
		await verificationBy('link');
		const person = await account({ locale: 'ru', verified: false });
		await signInUnverified('en', person.email);
		const url = extractVerifyUrl(only(person.email));
		if (!url) throw new Error('no verification link');

		const page = await openInEnglishBrowser(url);

		expect(langOf(page.html)).toBe('ru');
	});

	it('opens the code-entry page in the email’s language in an English browser', async () => {
		await verificationBy('code');
		const person = await account({ locale: 'ru', verified: false });
		const browser = new Browser('ru');
		const { uid } = await browser.startSignIn();
		const signedIn = await browser.post(`/ui/${uid}/login`, {
			username: person.email,
			password: PASSWORD
		});
		const codePage = signedIn.headers.get('location') ?? '';
		expect(codePage).toMatch(/^\/verify-email\/code\?ref=/);

		const page = await openInEnglishBrowser(`http://localhost${codePage}`);

		expect(langOf(page.html)).toBe('ru');
	});

	it('opens the reset link’s page in the email’s language in an English browser', async () => {
		const person = await account({ locale: 'ru' });
		await askForReset('en', person.email);
		const url = extractResetUrl(only(person.email));
		if (!url) throw new Error('no reset link');

		const page = await openInEnglishBrowser(url);

		expect(langOf(page.html)).toBe('ru');
	});

	it('shows a failed link’s page in the browser’s language, having no email to follow', async () => {
		const page = await openInEnglishBrowser(
			'http://localhost/reset-password?token=nonsense'
		);

		expect(langOf(page.html)).toBe('en');
	});
});
