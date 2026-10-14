import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.js';
import {
	consentServer,
	loginServer,
	totpServer
} from 'lib/interactions/serverRender.tsx';
import { emptyConsentView } from 'lib/interactions/consentView.ts';
import { themeHead } from 'lib/html/theme/head.ts';
import { FOX_PALETTE, MARK_MONO_CLASS } from 'lib/html/theme/palette.ts';
import { listPage } from 'lib/account_page/html.ts';
import { APPLICATION_ROW } from '../end_user_pages.ts';

const LOGO = 'data:image/png;base64,iVBORw0KGgo=';

/**
 * @proves On a dark page a person can still see every sign-in provider's mark and the organization's own
 * application's logo: a black mark is drawn light, Google's button takes Google's own dark colours, and a logo
 * drawn for a white page stays on a light plate (specs/096 FR-010, FR-011).
 */
describe('marks and logos on a dark page', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('draws a monochrome provider mark light in the dark scheme', async () => {
		const html = await (
			await loginServer('uid-1', {
				providers: [{ id: 'gh', displayName: 'GitHub', brand: 'github' }]
			})
		).text();

		expect(html).toMatch(new RegExp(`<svg[^>]*class="${MARK_MONO_CLASS}"`));
		const dark = themeHead().slice(
			themeHead().indexOf('@media (prefers-color-scheme: dark){')
		);
		expect(dark).toContain(
			`.${MARK_MONO_CLASS} [fill]{fill:var(--fox-mark-mono)}`
		);
		expect(FOX_PALETTE['mark-mono'].dark).toBe('#ffffff');
	});

	it('gives a recognised provider’s button Google’s colours for the scheme', async () => {
		const html = await (
			await loginServer('uid-1', {
				providers: [{ id: 'gg', displayName: 'Google', brand: 'google' }]
			})
		).text();

		for (const role of ['provider-bg', 'provider-border', 'provider-text'])
			expect(html).toContain(`var(--fox-${role})`);
	});

	it('keeps the organization’s own application’s logo on a light plate', async () => {
		const html = await (
			await consentServer({
				...emptyConsentView('uid-1'),
				client: { name: 'Acme Notes', tier: 'this-organization', logo: LOGO }
			})
		).text();

		const image = html.indexOf(`src="${LOGO}"`);
		const tile = html.slice(html.lastIndexOf('<span', image), image);
		expect(image).toBeGreaterThan(-1);
		expect(tile).toContain('background:var(--fox-logo-plate)');
		expect(FOX_PALETTE['logo-plate'].dark).toBe(
			FOX_PALETTE['logo-plate'].light
		);
	});

	it('keeps an application’s logo on the connected-applications page on a light plate', async () => {
		const html = await listPage(
			{
				service: 'Acme ID',
				logoSrc: '/public/logo.svg',
				path: '/account/apps',
				signOutHref: '/session/end',
				email: 'person@example.com',
				language: 'en'
			},
			[{ ...APPLICATION_ROW, logo: LOGO }]
		).text();

		const image = html.indexOf(`src="${LOGO}"`);
		const tile = html.slice(html.lastIndexOf('<span', image), image);
		expect(image).toBeGreaterThan(-1);
		expect(tile).toContain('background:var(--fox-logo-plate)');
	});

	it('draws the authenticator QR code black on white in either scheme', async () => {
		const html = await (
			await totpServer('uid-1', {
				mode: 'enroll',
				otpauthUri: 'otpauth://totp/x?secret=ABC',
				secretText: 'ABC'
			})
		).text();

		const code = html.slice(html.indexOf('<svg'), html.indexOf('</svg>'));
		const plate = html.slice(
			html.lastIndexOf('background:', html.indexOf('<svg')),
			html.indexOf('<svg')
		);
		expect(code).toContain('fill="#000000"');
		expect(html.slice(0, html.indexOf('<svg'))).toContain(
			'background:var(--fox-qr-plate)'
		);
		expect(plate).not.toContain('var(--fox-card)');
		expect(FOX_PALETTE['qr-plate']).toEqual({
			light: '#ffffff',
			dark: '#ffffff',
			kind: 'surface'
		});
	});
});
