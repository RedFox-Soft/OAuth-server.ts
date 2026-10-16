import { describe, it, expect, beforeAll, afterAll } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { getBucketStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import type { FederationProvider } from 'lib/federation/types.ts';
import { loginOptionsForBucket } from 'lib/interactions/loginOptions.ts';
import { previewOptions } from 'lib/admin/ui/pages/signin/previewOptions.ts';
import { shaped } from 'test/shape.ts';
import { adminCookie } from '../end_user_lifecycle/fixtures.ts';
import { admin } from '../provisioning/helpers.ts';
import { get, provider, seedBucket, startInteraction } from './harness.ts';

const GOOGLE = 'https://accounts.google.com';

const BucketRead = Type.Object({
	passwordLogin: Type.Boolean(),
	registrationOpen: Type.Boolean(),
	totpRequired: Type.Boolean()
});
const SummaryRead = Type.Object({ federationEnabled: Type.Boolean() });
const PageProps = Type.Object({
	passwordLogin: Type.Boolean(),
	registrationOpen: Type.Boolean(),
	passwordReset: Type.Boolean(),
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

/*
 * What the Sign-in tab's card would show for a bucket's stored settings: read through the admin API exactly as
 * the tab reads it — the bucket, its provider list and its summary — and assembled by the tab's own function.
 */
async function previewFor(bucketId: string, cookie: string) {
	const base = `/admin/api/projects/${encodeURIComponent(bucketId)}`;
	const [bucket, providers, summary] = await Promise.all([
		admin('GET', base, cookie),
		admin('GET', `${base}/federation`, cookie),
		admin('GET', `${base}/summary`, cookie)
	]);
	expect([bucket.status, providers.status, summary.status]).toEqual([
		200, 200, 200
	]);
	const settings = shaped(BucketRead, bucket.body);
	const { federationEnabled } = shaped(SummaryRead, summary.body);
	const options = previewOptions({
		bucketId,
		draft: {
			passwordLogin: settings.passwordLogin,
			registrationOpen: settings.registrationOpen,
			totpRequired: settings.totpRequired
		},
		providers: providers.body as FederationProvider[],
		federationOn: federationEnabled
	});
	return {
		passwordLogin: options.passwordLogin,
		registrationOpen: options.registrationOpen,
		passwordReset: options.passwordReset,
		providers: options.providers
	};
}

/* What the real sign-in page of the bucket is rendered with: the props a browser hydrates it from. */
async function pageFor(clientId: string) {
	const { uid, cookie } = await startInteraction(clientId);
	const page = await get(`/ui/${uid}/login`, cookie);
	const match = page.text.match(/window\.PROPS=(\{.*?\})<\/script>/s);
	if (!match) throw new Error('the login page carried no props script');
	const props = shaped(
		PageProps,
		JSON.parse(match[1].replace(/\\u003c/g, '<'))
	);
	return {
		passwordLogin: props.passwordLogin,
		registrationOpen: props.registrationOpen,
		passwordReset: props.passwordReset,
		providers: props.providers
	};
}

/* Every configuration the first screen depends on, each a bucket of its own with a client signing into it. */
const CASES: {
	name: string;
	fields: Record<string, unknown>;
	/* Set after creation, as a move sets it: a new bucket starts with no order of its own. */
	order?: string[];
}[] = [
	{ name: 'password and sign-up open, no providers', fields: {} },
	{
		name: 'sign-up closed',
		fields: { registrationOpen: false }
	},
	{
		name: 'two enabled providers, one recognised',
		fields: {
			federation: [
				provider('https://acme.idp.test', { id: 'acme', displayName: 'Acme' }),
				provider(GOOGLE, { id: 'google', displayName: 'Google' })
			]
		}
	},
	{
		name: 'password off, one enabled and one disabled provider',
		fields: {
			passwordLogin: false,
			federation: [
				provider('https://on.idp.test', { id: 'on', displayName: 'On' }),
				provider('https://off.idp.test', {
					id: 'off',
					displayName: 'Off',
					enabled: false
				})
			]
		}
	},
	{
		/* Reversed from the catalogue's ranking, which a preview that dropped the order would fall back to. */
		name: 'providers reordered against the catalogue',
		order: ['zeta', 'google', 'alpha'],
		fields: {
			federation: [
				provider(GOOGLE, { id: 'google', displayName: 'Google' }),
				provider('https://alpha.idp.test', { id: 'alpha' }),
				provider('https://zeta.idp.test', { id: 'zeta' })
			]
		}
	},
	{
		/*
		 * Enough providers to fold, two of one brand: what is folded and which buttons carry a second line are
		 * decided with the rest, and a preview that worked them out its own way would disagree here (specs/105).
		 */
		name: 'eight providers, two of one brand, folded',
		order: ['d1', 'contoso', 'd2', 'fabrikam', 'd3', 'd4', 'd5', 'd6'],
		fields: {
			federation: [
				provider('https://login.microsoftonline.com/contoso.example/v2.0', {
					id: 'contoso',
					displayName: 'Contoso staff'
				}),
				provider('https://login.microsoftonline.com/fabrikam.example/v2.0', {
					id: 'fabrikam',
					displayName: 'Fabrikam staff'
				}),
				...[1, 2, 3, 4, 5, 6].map((n) =>
					provider(`https://d${String(n)}.idp.test`, { id: `d${String(n)}` })
				)
			]
		}
	},
	{
		name: 'password off and sign-up closed, providers only',
		fields: {
			passwordLogin: false,
			registrationOpen: false,
			federation: [provider('https://only.idp.test', { id: 'only' })]
		}
	}
];

/**
 * @proves The Sign-in tab's preview never disagrees with the sign-in page people see: for every
 * configuration of password sign-in, self-service sign-up and identity providers — enabled, disabled,
 * reordered, recognised, with federation on and off, and for the console's own bucket — the options the
 * console draws from its own reads equal the options the real page is rendered with (spec 091, US2, SC-001).
 */
describe('the sign-in page preview', () => {
	let cookie: string;
	const seeded: { name: string; clientId: string; bucketId: string }[] = [];

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'signin_preview' });
		cookie = await adminCookie();
		for (const [i, entry] of CASES.entries()) {
			const clientId = `preview-app-${String(i)}`;
			const bucketId = await seedBucket(clientId, entry.fields);
			if (entry.order) {
				await getBucketStore().update(bucketId, { signInOrder: entry.order });
			}
			seeded.push({ name: entry.name, clientId, bucketId });
		}
	});

	afterAll(() => {
		ApplicationConfig['federation.enabled'] = true;
	});

	it('draws what each bucket’s real sign-in page shows', async () => {
		for (const { name, clientId, bucketId } of seeded) {
			expect({ name, options: await previewFor(bucketId, cookie) }).toEqual({
				name,
				options: await pageFor(clientId)
			});
		}
	});

	it('draws no provider buttons when federation is off, as the page does', async () => {
		ApplicationConfig['federation.enabled'] = false;
		try {
			for (const { name, clientId, bucketId } of seeded) {
				const preview = await previewFor(bucketId, cookie);
				expect({ name, options: preview }).toEqual({
					name,
					options: await pageFor(clientId)
				});
				expect(preview.providers).toEqual([]);
			}
		} finally {
			ApplicationConfig['federation.enabled'] = true;
		}
	});

	it('offers no password reset on the console’s own bucket, as its sign-in page does not', async () => {
		const preview = await previewFor(ADMIN_BUCKET_ID, cookie);
		const page = await loginOptionsForBucket(ADMIN_BUCKET_ID);

		expect(preview).toEqual({
			passwordLogin: page.passwordLogin,
			registrationOpen: page.registrationOpen,
			passwordReset: page.passwordReset,
			providers: page.providers
		});
		expect(preview.passwordReset).toBe(false);
	});
});
