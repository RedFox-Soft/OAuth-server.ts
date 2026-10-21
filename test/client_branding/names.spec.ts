import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap, { type Setup } from '../test_helper.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getBucketStore } from 'lib/adapters/index.ts';
import { ISSUER } from 'lib/configs/env.js';
import { writeLogo } from 'lib/models/client/logo.ts';
import type { SignInFace } from 'lib/interactions/signInMasthead.tsx';
import { changeClient } from '../test_helper.js';
import { PNG } from '../consent_branding/consent_branding.config.ts';
import { signedInElsewhere } from '../consent_branding/seed.ts';
import {
	ACME,
	ENROLLED,
	MEMBER,
	devicePages,
	ownProjects,
	registrationPage,
	signInPage,
	twoStepPage
} from './seed.ts';

/* What the page says, as a person reads it: the heading and the line above it, and what the browser hydrates. */
function read(html: string) {
	const words = (fragment: string | undefined) =>
		(fragment ?? '')
			.replace(/<!-- -->/g, '')
			.replace(/<[^>]+>/g, '')
			.trim();
	const props = JSON.parse(
		/window\.PROPS=(.*?)<\/script>/s.exec(html)?.[1] ?? '{}'
	) as { face?: SignInFace };
	return {
		heading: words(/<h1[^>]*>(.*?)<\/h1>/s.exec(html)?.[1]),
		service: words(/<strong>(.*?)<\/strong>/s.exec(html)?.[1]),
		face: props.face
	};
}

/**
 * @proves Every page of a sign-in says where it leads: the project's display name, else the host people sign in
 * at, and — for an application its project stands behind — the application's name and logo, in the markup and in
 * what the browser hydrates from. An application the project does not stand behind (one that registered itself,
 * another tenant's, a device's sign-in, one whose answers go to a program on this computer) is never named and its
 * logo never reaches the page, whatever it calls itself — so "Sign in to Acme Payroll" is a claim only the
 * project's own administrators can make.
 */
describe('where a sign-in leads, on its pages', () => {
	let setup: Setup;
	let elsewhere: { cookie: string; resource: string[] };

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'client_branding' });
		await ensureAdminSeed();
		await ownProjects();
		await getBucketStore().update(ACME, { displayName: 'Acme' });
		elsewhere = await signedInElsewhere(setup, 'tenant-app');
		for (const clientId of [
			'own-app',
			'own-loopback',
			'own-device',
			'tenant-app',
			'self-registered'
		])
			await writeLogo(clientId, PNG);
	});

	describe('an application the project stands behind', () => {
		it('names the application and the project on the sign-in page', async () => {
			const page = read((await signInPage('own-app')).html);

			expect(page.service).toBe('Acme');
			expect(page.heading).toBe('Sign in to Timesheets');
			expect(page.face).toEqual({
				service: 'Acme',
				app: { name: 'Timesheets', logo: PNG }
			});
		});

		it('shows the application’s logo on the sign-in page', async () => {
			const { html } = await signInPage('own-app');

			expect(html).toContain(`src="${PNG}" alt="Timesheets"`);
		});

		it('names the application on the registration page', async () => {
			const page = read((await registrationPage('own-app')).html);

			expect(page.service).toBe('Acme');
			expect(page.heading).toBe('Create an account for Timesheets');
		});

		it('names the application and the project on the two-step page', async () => {
			const page = read((await twoStepPage(ENROLLED)).html);

			expect(page.face?.app?.name).toBe('Payroll');
			expect(page.service).toBe(new URL(ISSUER).host);
		});

		it('names the account, not the application, when the application has no name', async () => {
			const undo = await changeClient('own-plain', { client_name: undefined });
			const page = read((await signInPage('own-plain')).html);
			await undo();

			expect(page.heading).toBe('Sign in to your Acme account');
			expect(page.face).toEqual({ service: 'Acme' });
		});

		it('strips what would make the name lie about its surroundings', async () => {
			const undo = await changeClient('own-plain', {
				client_name: '✅ Rota‮'
			});
			const page = read((await signInPage('own-plain')).html);
			await undo();

			expect(page.heading).toBe('Sign in to Rota');
		});
	});

	describe('an application the project does not stand behind', () => {
		const cases: Array<[string, string, () => Promise<string>]> = [
			[
				'one that registered itself',
				'Acme Payroll',
				async () => (await signInPage('self-registered')).html
			],
			[
				'another tenant’s',
				'Partner Tool',
				async () =>
					(await signInPage('tenant-app', { resource: elsewhere.resource }))
						.html
			],
			[
				'one whose answers go to a program on this computer',
				'Acme CLI',
				async () => (await signInPage('own-loopback')).html
			],
			[
				'a device’s sign-in, even for an own app',
				'Acme TV',
				async () => (await devicePages('own-device', MEMBER)).signIn.html
			]
		];

		for (const [shape, name, open] of cases) {
			it(`never names ${shape} or shows its logo`, async () => {
				const html = await open();
				const page = read(html);

				expect(page.face?.app).toBeUndefined();
				expect(page.heading).toStartWith('Sign in to your ');
				expect(html).not.toContain(name);
				expect(html).not.toContain(PNG);
			});
		}
	});
});
