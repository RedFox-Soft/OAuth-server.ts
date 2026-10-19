import { beforeAll, describe, expect, it } from 'bun:test';
import { theme } from 'antd';

import bootstrap, { type Setup } from '../test_helper.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { paintedAccent } from 'lib/html/theme/accent.ts';
import { DARK_TOKENS, LIGHT_TOKENS } from 'lib/html/theme/tokens.ts';
import { changeClient } from '../test_helper.js';
import { signedInElsewhere } from '../consent_branding/seed.ts';
import {
	ACME,
	ENROLLED,
	MEMBER,
	UNENROLLED,
	consentPage,
	devicePages,
	giveColour,
	ownProjects,
	painted,
	registrationPage,
	signInPage,
	twoStepPage,
	type Page
} from './seed.ts';

const GREEN = '#2f7d32';
const PALE = '#ffe066';
const green = paintedAccent(GREEN);
const DEFAULT_DARK_PRIMARY = theme.getDesignToken({
	algorithm: theme.darkAlgorithm,
	token: DARK_TOKENS
}).colorPrimary;

// Everything antd paints that is not the primary family: what an application's colour must leave alone.
const UNTOUCHED =
	/--ant-color-(?:error|warning|success|text|bg|border)[a-z-]*:[^;}]+/g;

/**
 * @proves An application of the organization's own project shows its colour on every page of its sign-in —
 * sign-in, registration, both two-step pages and consent — in the light and the dark scheme and in what the
 * browser hydrates from, shifted where needed to stay legible, and changes nothing else; and an application
 * without a colour keeps the server's. An application the organization does not stand behind — one that
 * registered itself, another tenant's, a device's sign-in, one whose answers go to a program on this computer —
 * never shows a colour, whatever is stored, and a stored value that is not a colour never reaches a page.
 */
describe('an application’s colour on the pages of its sign-in', () => {
	let setup: Setup;
	let member: string;
	let stranger: string;
	let elsewhere: { cookie: string; resource: string[] };

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url);
		await ensureAdminSeed();
		await ownProjects();
		elsewhere = await signedInElsewhere(setup, 'tenant-app');
		for (const clientId of [
			'own-app',
			'own-two-step',
			'own-loopback',
			'own-device',
			'tenant-app',
			'self-registered'
		])
			await giveColour(clientId, GREEN);
		member = await setup.login({ accountId: 'acme-member', bucketId: ACME });
		stranger = await setup.login();
	});

	/* What a page of the server's own palette carries: no colour block, no colour to hydrate, the server's blue. */
	function expectServerPalette(html: string) {
		const page = painted(html);
		expect(page.foxLink).toBeUndefined();
		expect(page.props.accent).toBeUndefined();
		expect(page.lightPrimary).toBe(LIGHT_TOKENS.colorPrimary);
	}

	describe('an own application with a colour', () => {
		const pages: Array<[string, () => Promise<Page>]> = [
			['the sign-in page', () => signInPage('own-app')],
			['the registration page', () => registrationPage('own-app')],
			['the two-step code page', () => twoStepPage(ENROLLED)],
			['the two-step enrolment page', () => twoStepPage(UNENROLLED)],
			['the consent page', () => consentPage('own-app', member)]
		];

		for (const [name, openPage] of pages) {
			it(`paints ${name} in the colour in both schemes`, async () => {
				const page = painted((await openPage()).html);

				expect(page.lightPrimary).toBe(green?.light.primary);
				expect(page.darkPrimary).toBe(green?.dark.primary);
			});
		}

		it('paints the server’s own links in the colour in both schemes', async () => {
			const page = painted((await consentPage('own-app', member)).html);

			expect(page.foxLink).toEqual({
				light: green?.light.primary ?? '',
				dark: green?.dark.link ?? ''
			});
		});

		it('hands the browser the colour it hydrates the page with', async () => {
			const page = painted((await signInPage('own-app')).html);

			expect(page.props.accent).toEqual(green);
		});

		it('paints a colour too light for a white label in a darker shade of it', async () => {
			const undo = await giveColour('own-second', PALE);
			const page = painted((await signInPage('own-second')).html);
			await undo();

			expect(page.lightPrimary).toBe(paintedAccent(PALE)?.light.primary);
			expect(page.lightPrimary).not.toBe(PALE);
		});

		it('leaves every colour that is not the primary as the server paints it', async () => {
			const branded = painted((await signInPage('own-app')).html);
			const plain = painted((await signInPage('own-plain')).html);

			expect(branded.light.match(UNTOUCHED)).toEqual(
				plain.light.match(UNTOUCHED)
			);
			expect(branded.dark.match(UNTOUCHED)).toEqual(
				plain.dark.match(UNTOUCHED)
			);
		});
	});

	describe('an own application without a colour', () => {
		it('keeps the server’s palette after a coloured page was served', async () => {
			await signInPage('own-app');
			const page = painted((await signInPage('own-plain')).html);

			expect(page.foxLink).toBeUndefined();
			expect(page.props.accent).toBeUndefined();
			expect(page.lightPrimary).toBe(LIGHT_TOKENS.colorPrimary);
			expect(page.darkPrimary).toBe(DEFAULT_DARK_PRIMARY);
		});
	});

	describe('an application the organization does not stand behind', () => {
		it('shows no colour on the sign-in page of an app that registered itself', async () => {
			expectServerPalette((await signInPage('self-registered')).html);
		});

		it('shows no colour on the consent page of an app that registered itself', async () => {
			expectServerPalette(
				(await consentPage('self-registered', stranger)).html
			);
		});

		it('shows no colour on the sign-in page of another tenant’s app', async () => {
			expectServerPalette(
				(await signInPage('tenant-app', { resource: elsewhere.resource })).html
			);
		});

		it('shows no colour on the consent page of another tenant’s app', async () => {
			expectServerPalette(
				(
					await consentPage('tenant-app', elsewhere.cookie, {
						resource: elsewhere.resource
					})
				).html
			);
		});

		it('shows no colour on the sign-in page of an own app whose answers go to a program on this computer', async () => {
			expectServerPalette((await signInPage('own-loopback')).html);
		});

		it('shows no colour on the consent page of an own app whose answers go to a program on this computer', async () => {
			expectServerPalette((await consentPage('own-loopback', member)).html);
		});

		it('shows no colour on the sign-in page of a device’s sign-in, even for an own app', async () => {
			expectServerPalette(
				(await devicePages('own-device', MEMBER)).signIn.html
			);
		});

		it('shows no colour on the consent page of a device’s sign-in, even for an own app', async () => {
			expectServerPalette(
				(await devicePages('own-device', MEMBER)).consent.html
			);
		});
	});

	describe('a stored value that is not a colour', () => {
		for (const stored of ['#2f7d32;}body{x:y', 'green']) {
			it(`reaches no page when the record holds ${JSON.stringify(stored)}`, async () => {
				const undo = await changeClient('own-plain', { primaryColor: stored });
				const { html } = await signInPage('own-plain');
				await undo();

				expectServerPalette(html);
			});
		}

		it('keeps a stored value that would break out of a style rule out of the page', async () => {
			const stored = '#2f7d32;}body{x:y';
			const undo = await changeClient('own-plain', { primaryColor: stored });
			const { html } = await signInPage('own-plain');
			await undo();

			expect(html).not.toContain(stored);
		});
	});
});
