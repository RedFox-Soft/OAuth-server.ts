import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap, { changeClient } from '../test_helper.js';
import { adapter } from 'lib/adapters/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ACCOUNT_TEXTS } from 'lib/i18n/texts/account/index.ts';
import { text as fill } from 'lib/i18n/message.tsx';

const T = ACCOUNT_TEXTS.en;
import { CONSENT_TEXTS as CONSENT_CATALOGUE } from 'lib/i18n/texts/consent/index.ts';

const CONSENT_TEXTS = CONSENT_CATALOGUE.en;
import { OFFLINE_KEY } from 'lib/interactions/consentChoices.ts';
import { writeLogo } from 'lib/models/client/logo.ts';
import { PNG } from '../consent_branding/consent_branding.config.ts';
import {
	Browser,
	defaultBucket,
	giveAccess,
	pageOf,
	person,
	signInThroughPage,
	textOf
} from './helpers.ts';

function capitalised(text: string): string {
	return text.charAt(0).toUpperCase() + text.slice(1);
}

/* The page's section for one application, by the name it is listed under. */
function sectionOf(html: string, name: string): string {
	const sections = html.split('<section').slice(1);
	const found = sections.find((s) => textOf(`<x${s}`).includes(name));
	if (!found) throw new Error(`no section for ${name}`);
	return `<section${found.split('</section>')[0]}</section>`;
}

async function signedIn(phone?: string): Promise<Browser> {
	const { email } = await person(undefined, phone ? { phone } : {});
	const browser = new Browser();
	await signInThroughPage(browser, email);
	return browser;
}

async function listHtml(browser: Browser): Promise<string> {
	const res = await browser.request(pageOf());
	expect(res.status).toBe(200);
	return res.text();
}

/**
 * @proves The page lists every application holding access to the person — whether or not it ever asked —
 * describes what each can do in the consent page's own words and only what was actually granted, marks the
 * one that keeps access offline, and shows a picture only for the organization's own applications.
 */
describe('the list of connected applications', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'connected_apps' });
		await ensureAdminSeed();
		await defaultBucket();
	});

	it('lists each application the person allowed with what it can see and when access was given', async () => {
		const browser = await signedIn();
		await giveAccess(browser, 'own-app', 'openid email');
		await giveAccess(browser, 'offline-app', 'openid offline_access');

		const html = await listHtml(browser);

		const own = textOf(sectionOf(html, 'Timesheets'));
		expect(own).toContain(T.canSee);
		expect(own).toContain(capitalised(CONSENT_TEXTS.categories.email));
		expect(own).toContain(fill(T.given, { date: '' }).trim());
		expect(own).toContain(fill(T.lastToken, { date: '' }).trim());
		expect(own).toContain(fill(T.signsInAt, { hosts: 'time.acme.test' }));
		expect(textOf(html)).toContain('Mail Sync');
	});

	it('marks only the application holding offline access as keeping it after sign-out', async () => {
		const browser = await signedIn();
		await giveAccess(browser, 'own-app', 'openid email');
		await giveAccess(browser, 'offline-app', 'openid offline_access');

		const html = await listHtml(browser);

		expect(textOf(sectionOf(html, 'Mail Sync'))).toContain(T.keepsAccess);
		expect(textOf(sectionOf(html, 'Timesheets'))).not.toContain(T.keepsAccess);
	});

	it('lists an application that never asked for consent, saying it gets what it asks for', async () => {
		const browser = await signedIn();
		await giveAccess(browser, 'waived-app');

		const html = await listHtml(browser);

		expect(textOf(sectionOf(html, 'Intranet'))).toContain(
			fill(T.trusted, { service: new URL(browser.origin).host })
		);
	});

	it('does not list as granted a permission the person declined', async () => {
		const undo = await changeClient('own-app', {
			'consent.partial': true,
			scope: 'openid email phone offline_access'
		});
		try {
			const browser = await signedIn('+1 555 0100');
			await giveAccess(
				browser,
				'own-app',
				'openid email phone offline_access',
				[OFFLINE_KEY]
			);

			const section = textOf(sectionOf(await listHtml(browser), 'Timesheets'));

			expect(section).toContain(capitalised(CONSENT_TEXTS.categories.email));
			expect(section).not.toContain(
				capitalised(CONSENT_TEXTS.categories.phone)
			);
		} finally {
			await undo();
		}
	});

	it('shows a self-registered application under its cleaned name with the address it signs people in at', async () => {
		const browser = await signedIn();
		await giveAccess(browser, 'dcr-app');

		const html = await listHtml(browser);

		const section = textOf(sectionOf(html, 'Google'));
		expect(section).not.toContain('✅');
		expect(section).toContain(fill(T.signsInAt, { hosts: 'evil.example.net' }));
	});

	it('shows the logo of the organization’s own application, named for a screen reader', async () => {
		await writeLogo('own-app', PNG);
		const browser = await signedIn();
		await giveAccess(browser, 'own-app', 'openid email');

		const section = sectionOf(await listHtml(browser), 'Timesheets');

		expect(section).toMatch(
			/<img src="data:image\/png;base64,[^"]+" alt="Timesheets"/
		);
	});

	it('shows no picture for a self-registered application, even with one stored', async () => {
		await writeLogo('dcr-app', PNG);
		const browser = await signedIn();
		await giveAccess(browser, 'dcr-app');

		const section = sectionOf(await listHtml(browser), 'Google');

		expect(section).not.toContain('<img');
	});

	it('says no application has access when none has, and never lists its own sign-in', async () => {
		const browser = await signedIn();

		const html = await listHtml(browser);

		expect(textOf(html)).toContain(T.empty);
		expect(html).not.toContain('<section');
		expect(html).not.toContain(T.clientName);
	});

	it('lists what an application that no longer exists still holds, under a neutral name', async () => {
		const browser = await signedIn();
		await giveAccess(browser, 'gone-app');
		await adapter('Client').destroy('gone-app');

		const html = await listHtml(browser);

		expect(textOf(sectionOf(html, T.deletedApp))).toContain(T.remove);
	});
});
