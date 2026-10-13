import { describe, it, expect, beforeAll } from 'bun:test';

import bootstrap, { type Setup } from '../test_helper.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ISSUER } from 'lib/configs/env.js';
import { CONSENT_TEXTS as T } from 'lib/interactions/consentTexts.js';
import { openConsent, type ConsentPage } from '../consent_page/flow.ts';
import { tenantProject } from './seed.ts';

const NBSP = String.fromCharCode(0xa0);

/* Every link on the page, with what a reader and the browser get from it. */
function links(page: ConsentPage) {
	return [...page.html.matchAll(/<a\b([^>]*)>([\s\S]*?)<\/a>/g)].map(
		([, attributes, body]) => ({
			href: /\shref="([^"]*)"/.exec(attributes)?.[1] ?? '',
			target: /\starget="([^"]*)"/.exec(attributes)?.[1],
			rel: /\srel="([^"]*)"/.exec(attributes)?.[1],
			text: body.replace(/<[^>]+>/g, '')
		})
	);
}

/* The links that lead away to a site the server does not control. */
/* Links leaving this server: the page's own link to the connected-apps page (specs/095) is not one. */
function external(page: ConsentPage) {
	return links(page).filter(
		(link) =>
			/^https?:/.test(link.href) &&
			new URL(link.href).origin !== new URL(ISSUER).origin
	);
}

/**
 * @proves The consent page links an app's privacy policy and terms only for an app this organization
 * stands behind and only when the link is https on the app's own redirect host, opened in a new tab that
 * learns nothing about the page — and never links anywhere an app merely said it lives.
 */
describe('the privacy policy and terms links on the consent page', () => {
	let setup: Setup;
	let cookie: string;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'consent_branding' });
		await ensureAdminSeed();
		await tenantProject(['tenant-app']);
		cookie = await setup.login({ scope: 'openid' });
	});

	function open(clientId: string) {
		return openConsent(
			{ client_id: clientId, scope: 'openid', prompt: 'consent' },
			cookie
		);
	}

	it('links both for an app of this organization whose links are on its redirect host', async () => {
		const page = await open('own-app');

		expect(page.view.links).toEqual({
			policy: 'https://app.acme.test/privacy',
			terms: 'https://app.acme.test/terms'
		});
		expect(external(page)).toEqual([
			{
				href: 'https://app.acme.test/privacy',
				target: '_blank',
				rel: 'noopener noreferrer',
				text: `Timesheets${T.links.policyAfter}${NBSP}↗${T.links.external}`
			},
			{
				href: 'https://app.acme.test/terms',
				target: '_blank',
				rel: 'noopener noreferrer',
				text: `Timesheets${T.links.termsAfter}${NBSP}↗${T.links.external}`
			}
		]);
		expect(page.html).toContain(`aria-label="${T.links.label('Timesheets')}"`);
	});

	it('links only the one that is on the redirect host', async () => {
		const page = await open('own-policy-only');

		expect(page.view.links).toEqual({
			policy: 'https://rota.acme.test/privacy'
		});
		expect(external(page).map((link) => link.href)).toEqual([
			'https://rota.acme.test/privacy'
		]);
	});

	it.each([
		['links on another host', 'own-other-host'],
		['links over http', 'own-http-links'],
		['a native app with no redirect host', 'own-native']
	])('links nothing for %s', async (_, clientId) => {
		const page = await open(clientId);

		expect(page.view.links).toBeUndefined();
		expect(external(page)).toEqual([]);
		expect(page.text).not.toContain(T.links.policyAfter);
	});

	it.each([
		['an app that registered itself', 'self-registered'],
		['another tenant’s app', 'tenant-app']
	])(
		'links nothing for %s, though its links are on its redirect host',
		async (_, clientId) => {
			const page = await open(clientId);

			expect(page.view.links).toBeUndefined();
			expect(external(page)).toEqual([]);
		}
	);
});
