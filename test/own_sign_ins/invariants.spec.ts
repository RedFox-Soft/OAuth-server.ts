import { beforeAll, describe, expect, it } from 'bun:test';
import fc from 'fast-check';

import bootstrap from '../test_helper.js';
import {
	adminAuditStore,
	getPersonActivityStore,
	getUserStore
} from 'lib/adapters/index.ts';
import type { ActivityCategory } from 'lib/adapters/types.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { SUPPORTED_LANGUAGES } from 'lib/i18n/languages.ts';
import { Session } from 'lib/models/session.ts';
import { resetSentEmails, sentEmails } from '../mail_capture.ts';
import {
	Browser,
	itemsOf,
	minutesAgo,
	openPage,
	PAGE,
	person,
	reshapeSession,
	sessionIdOf,
	seed,
	signedIn,
	signInRow,
	STALE,
	textOf,
	xsrfFrom
} from './helpers.ts';

const octet = fc.integer({ min: 1, max: 254 });
const ipv4 = fc
	.tuple(octet, octet, octet, octet)
	.map((parts) => parts.join('.'));
const ipv6 = fc
	.array(fc.integer({ min: 0x1000, max: 0xffff }), {
		minLength: 8,
		maxLength: 8
	})
	.map((groups) => groups.map((g) => g.toString(16)).join(':'));
const address = fc.oneof(
	ipv4,
	ipv6,
	ipv4.map((v4) => `::ffff:${v4}`)
);
const categories = fc.subarray<ActivityCategory>(['tor', 'vpn', 'hosting'], {
	minLength: 1
});
/* Text that cannot appear on the page by chance: what a caller could have written into a request. */
const callerText = fc.stringMatching(/^[A-Za-z0-9]{24,40}$/);

/* The parts of an address someone could recognise it by: the whole, and its leading part. */
function tracesOf(value: string): string[] {
	const bare = value.replace(/^::ffff:/, '');
	if (bare.includes(':')) return [bare, bare.split(':').slice(0, 3).join(':')];
	return [bare, `${bare.split('.').slice(0, 3).join('.')}.`];
}

/**
 * @proves Whatever a person's sign-ins recorded (a full address, network categories, a rule or a tool name a request
 * might have carried), Recent sign-ins shows none of it, in any language; and it shows only that person's own
 * sign-ins of the project they signed in to, never in the administrators' project.
 */
describe('what recent sign-ins never shows', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'own_sign_ins' });
	});

	it('shows no address and no network category, in any language', async () => {
		const { browser, accountId } = await signedIn();
		await fc.assert(
			fc.asyncProperty(
				address,
				categories,
				callerText,
				fc.constantFrom(...SUPPORTED_LANGUAGES),
				async (value, cats, marker, language) => {
					await getPersonActivityStore().destroyPerson(
						DEFAULT_BUCKET_ID,
						accountId
					);
					await seed([
						signInRow(accountId, minutesAgo(5), {
							address: value,
							addressFrom: 'sign_in',
							facts: { country: 'DE', categories: cats },
							place: { clientId: 'own-app', rule: marker, tool: marker }
						})
					]);
					const response = await browser.request('/account/sign-ins', {
						headers: { 'accept-language': language }
					});
					const html = await response.text();
					const shown = textOf(html);

					expect(itemsOf(html)).toHaveLength(1);
					for (const trace of tracesOf(value)) {
						expect(html).not.toContain(trace);
					}
					expect(html).not.toContain(marker);
					expect(shown).not.toMatch(/\b(tor|vpn|hosting)\b/i);
				}
			),
			{ numRuns: 25 }
		);
	});

	it('shows only the person’s own sign-ins of the project they signed in to', async () => {
		const { browser, accountId } = await signedIn();
		const other = await person();
		await seed([
			signInRow(accountId, minutesAgo(10), { place: { clientId: 'own-app' } }),
			signInRow(other.accountId, minutesAgo(5)),
			signInRow(accountId, minutesAgo(3), { bucketId: 'another-project' })
		]);

		const items = itemsOf((await openPage(browser)).html);

		expect(items).toHaveLength(1);
	});

	it('has no recent sign-ins in the administrators’ project', async () => {
		const { response } = await openPage(new Browser(), '', '/admin');

		/* The console owns every /admin address; whatever it answers, it is not this page. */
		expect(response.status).not.toBe(200);
		expect(response.headers.get('location') ?? '').not.toContain('account.');
	});
});

async function formValue(browser: Browser): Promise<string> {
	return xsrfFrom((await openPage(browser, '?confirm=1')).html);
}

async function sessionStillThere(browser: Browser): Promise<boolean> {
	return (await Session.tryFind(await sessionIdOf(browser))) !== undefined;
}

/**
 * @proves Signing out everywhere happens only as the person's own confirmed act on this page, in a browser that
 * signed in moments ago; it changes nothing else about the account, and no email the server sends can do it.
 */
describe('what signing out everywhere never does', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'own_sign_ins' });
	});

	it('changes nothing when the request comes from another site', async () => {
		const { browser } = await signedIn();
		const xsrf = await formValue(browser);

		const response = await browser.post(
			PAGE,
			{ xsrf },
			{ 'sec-fetch-site': 'cross-site' }
		);

		expect(response.status).toBe(403);
		expect(await sessionStillThere(browser)).toBe(true);
	});

	it('changes nothing when the request names another origin', async () => {
		const { browser } = await signedIn();
		const xsrf = await formValue(browser);

		const response = await browser.post(
			PAGE,
			{ xsrf },
			{ origin: 'https://evil.example.net' }
		);

		expect(response.status).toBe(403);
		expect(await sessionStillThere(browser)).toBe(true);
	});

	it('changes nothing without the form value', async () => {
		const { browser } = await signedIn();
		await formValue(browser);

		const response = await browser.post(PAGE, {});

		expect(response.status).toBe(403);
		expect(await sessionStillThere(browser)).toBe(true);
	});

	it('asks a stale session to sign in again instead of signing out', async () => {
		const { browser } = await signedIn();
		const xsrf = await formValue(browser);
		await reshapeSession(browser, { ageSeconds: STALE });

		const response = await browser.post(PAGE, { xsrf });

		expect(response.status).toBe(303);
		expect(response.headers.get('location')).toContain('prompt=login');
		expect(await sessionStillThere(browser)).toBe(true);
	});

	it('never locks, deactivates or removes the authenticator', async () => {
		const { browser, accountId } = await signedIn();
		const users = getUserStore(DEFAULT_BUCKET_ID);
		await users.update(accountId, {
			totp: { secret: 'JBSWY3DPEHPK3PXP', enrolledAt: new Date(), lastStep: 0 }
		});
		const before = await users.find(accountId);

		await browser.post(PAGE, { xsrf: await formValue(browser) });
		const after = await users.find(accountId);

		expect(after?.active).toBe(before?.active);
		expect(after?.lockedLocally).toBeUndefined();
		expect(after?.totp).toBeDefined();
	});

	it('never puts the act in the email it sends', async () => {
		const { browser } = await signedIn();
		resetSentEmails();

		await browser.post(PAGE, { xsrf: await formValue(browser) });

		expect(sentEmails.length).toBeGreaterThan(0);
		for (const mail of sentEmails) {
			expect(`${mail.text}${mail.html}`).not.toContain('/account/sign-ins');
		}
	});

	it('changes nothing more when confirmed a second time', async () => {
		const { browser, accountId } = await signedIn();
		const xsrf = await formValue(browser);
		await browser.post(PAGE, { xsrf });

		const again = await browser.post(PAGE, { xsrf });
		const entries = (await adminAuditStore.list({ targetId: accountId }))
			.entries;

		expect(again.status).toBe(303);
		expect(
			entries.filter((entry) => entry.action === 'enduser.signout')
		).toHaveLength(1);
	});
});
