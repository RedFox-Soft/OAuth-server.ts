import { beforeAll, beforeEach, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.js';
import { getBucketStore } from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { accountPageClientId } from 'lib/account_page/client.ts';
import { formatAgo } from 'lib/i18n/format.ts';
import { FORMAT_LOCALE } from 'lib/i18n/languages.ts';
import { ACCOUNT_TEXTS } from 'lib/i18n/texts/account/index.ts';
import { text as fill } from 'lib/i18n/message.tsx';
import { provider } from '../scim/helpers.ts';
import {
	appBehindProxy,
	defaultBucket,
	itemsOf,
	minutesAgo,
	openPage,
	seed,
	sessionOf,
	signedIn,
	signInRow
} from './helpers.ts';

const T = ACCOUNT_TEXTS.en;

/**
 * @proves A person opens Recent sign-ins on their account page and reads their own ten newest sign-ins, newest
 * first: the application by today's name, when in UTC and how long ago, how they signed in, the browser on the
 * system and the country, in their own language, with the sign-in of this browser marked.
 */
describe('a person reading their recent sign-ins', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'own_sign_ins' });
	});

	beforeEach(async () => {
		await defaultBucket();
		await getBucketStore().update(DEFAULT_BUCKET_ID, {
			federation: [provider('corp', { displayName: 'Acme SSO' })]
		});
	});

	it('lists the ten newest sign-ins, newest first, with app, time, method, browser and country', async () => {
		const { browser, accountId } = await signedIn();
		await seed(
			Array.from({ length: 12 }, (_, i) =>
				signInRow(accountId, minutesAgo(30 + i * 60), {
					method: i === 0 ? 'password_code' : 'password',
					device: { browser: 'firefox', system: 'macos' },
					facts: { country: 'DE', categories: [] }
				})
			)
		);

		const items = itemsOf((await openPage(browser)).html);

		expect(items).toHaveLength(10);
		const [newest, second] = items;
		expect(newest).toContain('Timesheets');
		expect(newest).toContain(T.methodPasswordCode);
		expect(newest).toContain(
			fill(T.browserOn, { browser: 'Firefox', system: 'macOS' })
		);
		expect(newest).toContain('Germany');
		expect(newest).toContain('UTC');
		expect(newest).toContain(formatAgo('en', minutesAgo(30).getTime()) ?? '');
		expect(second).toContain(T.methodPassword);
		expect(second).toContain(formatAgo('en', minutesAgo(90).getTime()) ?? '');
	});

	it('reads a sign-in to a deleted application as one that no longer exists', async () => {
		const { browser, accountId } = await signedIn();
		await seed([
			signInRow(accountId, minutesAgo(30), {
				place: { clientId: 'gone-client' }
			})
		]);

		const [item] = itemsOf((await openPage(browser)).html);

		expect(item).toContain(T.deletedApp);
	});

	it('names the app behind the proxy a sign-in went through', async () => {
		const { browser, accountId } = await signedIn();
		await appBehindProxy('Acme wiki', 'https://wiki.acme.test');
		await seed([
			signInRow(accountId, minutesAgo(30), {
				place: {
					clientId: `proxy.${DEFAULT_BUCKET_ID}`,
					appOrigin: 'https://wiki.acme.test'
				}
			})
		]);

		const [item] = itemsOf((await openPage(browser)).html);

		expect(item).toContain('Acme wiki');
	});

	it('reads a sign-in to the account page itself as the account page', async () => {
		const { browser, accountId } = await signedIn();
		await seed([
			signInRow(accountId, minutesAgo(30), {
				place: { clientId: accountPageClientId(DEFAULT_BUCKET_ID) }
			})
		]);

		const [item] = itemsOf((await openPage(browser)).html);

		expect(item).toContain(T.accountPageName);
	});

	it('names the provider a sign-in went through', async () => {
		const { browser, accountId } = await signedIn();
		await seed([
			signInRow(accountId, minutesAgo(30), {
				method: 'provider',
				place: { clientId: 'own-app', providerId: 'corp' }
			})
		]);

		const [item] = itemsOf((await openPage(browser)).html);

		expect(item).toContain(fill(T.methodProvider, { provider: 'Acme SSO' }));
	});

	it('reads a sign-in through a provider since removed as one that no longer exists', async () => {
		const { browser, accountId } = await signedIn();
		await seed([
			signInRow(accountId, minutesAgo(30), {
				method: 'provider',
				place: { clientId: 'own-app', providerId: 'retired' }
			})
		]);

		const [item] = itemsOf((await openPage(browser)).html);

		expect(item).toContain(T.methodProviderGone);
	});

	it('shows no browser for a sign-in whose browser reported none', async () => {
		const { browser, accountId } = await signedIn();
		const row = signInRow(accountId, minutesAgo(30));
		delete row.device;
		await seed([row]);

		const [item] = itemsOf((await openPage(browser)).html);

		expect(item).not.toContain('Chrome');
		expect(item).not.toContain(T.otherBrowser);
	});

	it('shows no country for a code the page does not know', async () => {
		const { browser, accountId } = await signedIn();
		await seed([
			signInRow(accountId, minutesAgo(30), {
				facts: { country: 'ZZ', categories: [] }
			})
		]);

		const [item] = itemsOf((await openPage(browser)).html);

		expect(item).not.toContain('ZZ');
	});

	it('marks the sign-in of this browser', async () => {
		const { browser, accountId } = await signedIn();
		const loginTs = (await sessionOf(browser)).payload.loginTs ?? 0;
		await seed([
			signInRow(accountId, new Date(loginTs * 1000 + 800)),
			signInRow(accountId, minutesAgo(120))
		]);

		const [current, older] = itemsOf((await openPage(browser)).html);

		expect(current).toContain(T.thisBrowser);
		expect(older).not.toContain(T.thisBrowser);
	});

	for (const language of ['ru', 'zh-Hans'] as const) {
		it(`reads in ${language}, how long ago included`, async () => {
			const { browser, accountId } = await signedIn();
			await seed([
				signInRow(accountId, minutesAgo(180), {
					method: 'password_code',
					facts: { country: 'DE', categories: [] }
				})
			]);
			const L = ACCOUNT_TEXTS[language];

			const response = await browser.request('/account/sign-ins', {
				headers: { 'accept-language': language }
			});
			const html = await response.text();
			const [item] = itemsOf(html);

			expect(html).toContain(L.signInsTitle);
			expect(item).toContain(L.methodPasswordCode);
			expect(item).toContain(
				formatAgo(language, minutesAgo(180).getTime()) ?? ''
			);
			expect(item).toContain(
				new Intl.DisplayNames([FORMAT_LOCALE[language]], {
					type: 'region'
				}).of('DE') ?? ''
			);
		});
	}
});
