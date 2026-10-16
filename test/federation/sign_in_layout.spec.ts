import { describe, it, expect, beforeAll } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.ts';
import { getBucketStore, resetAdminMemoryStores } from 'lib/adapters/index.ts';
import { SIGN_IN_TEXTS } from 'lib/i18n/texts/signIn/index.ts';
import { get, provider, seedBucket, startInteraction } from './harness.ts';
import { shaped } from 'test/shape.ts';

/*
 * How a project's provider buttons are laid out on its sign-in page (specs/105): one frame for every
 * provider, a fold for a long list that never hides a brand, a second line telling two connections of one
 * brand apart, and the fold opened again after a cancelled provider sign-in.
 *
 * Every case reads the markup AND the hydration props. The page hydrates, so a button or a fold present in one
 * and absent from the other is rebuilt away in a browser, silently.
 */

const MIXED = 'layout-mixed-app';
const NOPASS = 'layout-nopass-app';
const MANY = 'layout-many-app';
const TWINS = 'layout-twins-app';
const CSP = 'layout-csp-app';

const GOOGLE_ISSUER = 'https://accounts.google.com';
const microsoft = (tenant: string) =>
	`https://login.microsoftonline.com/${tenant}/v2.0`;
const T = SIGN_IN_TEXTS.en.login;

const generic = (n: number) =>
	provider(`https://idp-${String(n)}.layout.test`, {
		id: `g${String(n)}`,
		displayName: `Directory ${String(n)}`
	});

const Props = Type.Object({
	providersOpen: Type.Optional(Type.Boolean()),
	providers: Type.Array(
		Type.Object({
			id: Type.String(),
			displayName: Type.String(),
			brand: Type.Optional(Type.String()),
			folded: Type.Optional(Type.Literal(true)),
			subtitle: Type.Optional(Type.String())
		})
	)
});

function props(text: string) {
	const match = text.match(/window\.PROPS=(\{.*?\})<\/script>/s);
	if (!match) throw new Error('the login page carried no props script');
	return shaped(Props, JSON.parse(match[1].replace(/\\u003c/g, '<')));
}

async function loginPage(clientId: string, query = '') {
	const { uid, cookie } = await startInteraction(clientId);
	const page = await get(`/ui/${uid}/login${query}`, cookie);
	const at = (id: string) => page.text.indexOf(`/federation/${id}/start`);
	return { ...page, uid, at };
}

/* The policy with every hash replaced, so two pages whose inline scripts differ only in data compare equal. */
const policyShape = (csp: string | null) =>
	(csp ?? '').replace(/'sha256-[^']+'/g, "'sha256'");

/**
 * @proves An end user meets every provider as one full-width button of one kind, sees every brand however
 * many providers a project offers, can reach folded providers without scripts, finds the fold open after
 * cancelling at a provider, and can tell two connections of one brand apart.
 */
describe('the provider buttons on a sign-in page', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'sign_in_layout' });
		resetAdminMemoryStores();

		await seedBucket(MIXED, {
			federation: [
				provider(GOOGLE_ISSUER, { id: 'google', displayName: 'Google' }),
				generic(1)
			]
		});
		await seedBucket(NOPASS, {
			passwordLogin: false,
			federation: [generic(1)]
		});
		/*
		 * Eight providers in an order an administrator chose that interleaves brands and directories, so a page
		 * that moved the brands to the top, or kept the first five whatever they were, fails.
		 */
		const many = await seedBucket(MANY, {
			federation: [
				provider(GOOGLE_ISSUER, { id: 'google', displayName: 'Google' }),
				provider(microsoft('contoso.example'), {
					id: 'microsoft',
					displayName: 'Microsoft'
				}),
				...[1, 2, 3, 4, 5, 6].map(generic)
			]
		});
		// An order is set on an existing project, never at creation, exactly as the console's move does it.
		await getBucketStore().update(many, {
			signInOrder: ['g1', 'google', 'g2', 'microsoft', 'g3', 'g4', 'g5', 'g6']
		});
		await seedBucket(TWINS, {
			federation: [
				provider(microsoft('contoso.example'), {
					id: 'contoso',
					displayName: 'Contoso staff'
				}),
				provider(microsoft('fabrikam.example'), {
					id: 'fabrikam',
					displayName: 'Fabrikam staff'
				}),
				provider(GOOGLE_ISSUER, { id: 'google', displayName: 'Google' })
			]
		});
	});

	describe('whatever their number', () => {
		it('gives a provider it does not recognise a mark of its own beside a branded one', async () => {
			const page = await loginPage(MIXED);

			expect(page.status).toBe(200);
			expect(page.text).toContain('data-mark="generic"');
			expect(page.text).toContain(
				T.signInWith.replace('{provider}', 'Directory 1')
			);
			expect(page.text).toContain(T.signInWith.replace('{provider}', 'Google'));
		});

		it('separates the password form from the providers with a divider', async () => {
			const page = await loginPage(MIXED);

			const divider = page.text.search(/class="ant-divider /);
			expect(divider).toBeGreaterThan(page.text.indexOf('name="password"'));
			expect(divider).toBeLessThan(page.at('google'));
			expect(page.text).toContain(`>${T.providersDivider}<`);
		});

		it('puts the providers first, with no divider, when the project takes no password', async () => {
			const page = await loginPage(NOPASS);

			expect(page.at('g1')).toBeGreaterThan(-1);
			expect(page.at('g1')).toBeLessThan(page.text.indexOf('<form'));
			expect(page.text).not.toMatch(/class="ant-divider /);
		});

		it('folds nothing for a project with only a few providers', async () => {
			const page = await loginPage(MIXED);

			expect(page.text).not.toContain('<details');
			expect(props(page.text).providers.some((p) => p.folded)).toBe(false);
		});
	});

	describe('with many providers', () => {
		it('shows every brand and the first directories before the fold, in the administrator’s order', async () => {
			const page = await loginPage(MANY);
			const fold = page.text.indexOf('<details');

			expect(fold).toBeGreaterThan(-1);
			const visible = ['g1', 'google', 'g2', 'microsoft', 'g3'];
			for (const id of visible) {
				expect(page.at(id), id).toBeGreaterThan(-1);
				expect(page.at(id), id).toBeLessThan(fold);
			}
			expect(visible.map(page.at)).toEqual(
				[...visible.map(page.at)].sort((a, b) => a - b)
			);
		});

		it('keeps the remaining directories inside the fold as plain links, in order', async () => {
			const page = await loginPage(MANY);
			const fold = page.text.indexOf('<details');
			const folded = ['g4', 'g5', 'g6'];

			// Links in the served markup are what a browser without scripts can follow.
			for (const id of folded) {
				expect(page.text).toContain(
					`href="/ui/${page.uid}/federation/${id}/start"`
				);
				expect(page.at(id), id).toBeGreaterThan(fold);
			}
			expect(page.text).toContain(`>${T.moreProviders}</summary>`);
			expect(
				props(page.text)
					.providers.filter((p) => p.folded)
					.map((p) => p.id)
			).toEqual(folded);
		});

		it('renders the fold closed on an ordinary visit', async () => {
			const page = await loginPage(MANY);

			expect(page.text).toMatch(/<details(?![^>]*\bopen\b)[^>]*>/);
			expect(props(page.text).providersOpen ?? false).toBe(false);
		});

		it('renders the fold open after a provider sign-in was cancelled', async () => {
			const page = await loginPage(MANY, '?notice=federation_aborted');

			expect(page.text).toMatch(/<details[^>]*\bopen\b[^>]*>/);
			expect(props(page.text).providersOpen).toBe(true);
		});
	});

	describe('with two connections to one brand', () => {
		it('labels each with its own name under the brand’s wording', async () => {
			const page = await loginPage(TWINS);
			const rendered = props(page.text).providers;

			expect(page.text).toContain('Contoso staff');
			expect(page.text).toContain('Fabrikam staff');
			expect(rendered.find((p) => p.id === 'contoso')?.subtitle).toBe(
				'Contoso staff'
			);
			expect(rendered.find((p) => p.id === 'fabrikam')?.subtitle).toBe(
				'Fabrikam staff'
			);
		});

		it('adds no second line to a brand connected once', async () => {
			const page = await loginPage(TWINS);

			expect(
				props(page.text).providers.find((p) => p.id === 'google')?.subtitle
			).toBeUndefined();
		});
	});

	/*
	 * The buttons and the fold are navigation and a native disclosure: they need no script, so the policy the
	 * page derives from its own markup must not loosen for them. Hashes are compared by position only, since the
	 * hydration props differ between the two pages by design.
	 */
	it('serves a folded list under the same content security policy as no providers at all', async () => {
		await seedBucket(CSP, {
			federation: [
				provider(GOOGLE_ISSUER, { id: 'google', displayName: 'Google' }),
				...[1, 2, 3, 4, 5, 6, 7].map(generic)
			]
		});
		const folded = await loginPage(CSP);
		await seedBucket(CSP, {});
		const bare = await loginPage(CSP);

		expect(folded.text).toContain('<details');
		expect(folded.text).not.toMatch(/\son[a-z]+=/i);
		expect(policyShape(folded.csp)).toBe(policyShape(bare.csp));
	});
});
