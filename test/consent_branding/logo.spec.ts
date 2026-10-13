import { describe, it, expect, beforeAll, type Mock } from 'bun:test';

import bootstrap, { type Setup } from '../test_helper.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { openConsent, type ConsentPage } from '../consent_page/flow.ts';
import { PNG, WEBP } from './consent_branding.config.ts';
import { giveLogo, tenantProject } from './seed.ts';

/* Every `<img>` on the page, as the browser would read its source and text alternative. */
function images(html: string): { src: string; alt: string }[] {
	return [...html.matchAll(/<img\b[^>]*>/g)].map(([tag]) => ({
		src: /\ssrc="([^"]*)"/.exec(tag)?.[1] ?? '',
		alt: /\salt="([^"]*)"/.exec(tag)?.[1] ?? ''
	}));
}

/* The images a client could have put there — everything but the server's own header logo. */
function clientImages(page: ConsentPage) {
	return images(page.html).filter((image) => image.alt !== '');
}

/**
 * @proves The consent page shows a client's logo only where an operator chose it and the organization the
 * person belongs to stands behind the app, embedded in the page and named by the app's name — and an app
 * that registered itself, belongs to another tenant, or cannot prove where the answer goes never shows a
 * picture, whatever it says about itself.
 */
describe('the client logo on the consent page', () => {
	let setup: Setup;
	let cookie: string;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'consent_branding' });
		await ensureAdminSeed();
		await tenantProject(['tenant-app']);
		for (const clientId of [
			'own-app',
			'own-loopback',
			'tenant-app',
			'self-registered'
		]) {
			await giveLogo(clientId, PNG);
		}
		await giveLogo('own-native', WEBP);
		cookie = await setup.login({ scope: 'openid' });
	});

	/* `prompt=consent`: the session already allowed `openid`, and the page is what is under test. */
	function open(clientId: string, scope: string) {
		return openConsent(
			{ client_id: clientId, scope, prompt: 'consent' },
			cookie
		);
	}

	it('shows the logo of an app of this organization, named by the app, on a sign-in', async () => {
		const page = await open('own-app', 'openid');

		expect(page.view.client.logo).toBe(PNG);
		expect(clientImages(page)).toEqual([{ src: PNG, alt: 'Timesheets' }]);
	});

	it('shows the logo when the app asks for more than a sign-in', async () => {
		const page = await open('own-native', 'openid billing');

		expect(page.view.mode).not.toBe('sign-in');
		expect(clientImages(page)).toEqual([{ src: WEBP, alt: 'Acme Mobile' }]);
	});

	it('keeps the logo out of the server header and out of the headline', async () => {
		const page = await open('own-app', 'openid');

		const service = page.view.service.displayName ?? page.view.service.host;
		const header = page.html.indexOf(`>${service}<`);
		const logo = page.html.indexOf(`alt="Timesheets"`);
		expect(header).toBeGreaterThan(-1);
		expect(logo).toBeGreaterThan(header);
		const headline = /<h1\b[\s\S]*?<\/h1>/.exec(page.html)?.[0] ?? '';
		expect(headline).not.toContain('<img');
	});

	it('embeds the logo in the page, so the page’s image policy stays its own origin and data', async () => {
		const page = await open('own-app', 'openid');

		expect(page.response.headers.get('content-security-policy')).toContain(
			"img-src 'self' data:"
		);
	});

	it('shows no image and no placeholder for an app of this organization without a logo', async () => {
		const page = await open('own-other-host', 'openid');

		expect(page.view.client.logo).toBeUndefined();
		expect(clientImages(page)).toEqual([]);
	});

	it('never shows a logo for an app that registered itself, and never fetches the one it registered', async () => {
		const page = await open('self-registered', 'openid');

		expect(page.view.client.logo).toBeUndefined();
		expect(clientImages(page)).toEqual([]);
		const fetched = (globalThis.fetch as unknown as Mock<typeof fetch>).mock
			.calls;
		expect(
			fetched.filter(([input]) =>
				(input instanceof Request ? input.url : input.toString()).includes(
					'payroll.example.net'
				)
			)
		).toEqual([]);
	});

	it('never shows a logo for another tenant’s app', async () => {
		const page = await open('tenant-app', 'openid');

		expect(page.view.client.tier).toBe('operator-registered');
		expect(page.view.client.logo).toBeUndefined();
		expect(clientImages(page)).toEqual([]);
	});

	it('never shows a logo for an app whose answer goes only to a program on this computer', async () => {
		const page = await open('own-loopback', 'openid');

		expect(page.view.warning?.kind).toBe('loopback');
		expect(page.view.client.logo).toBeUndefined();
		expect(clientImages(page)).toEqual([]);
	});
});
