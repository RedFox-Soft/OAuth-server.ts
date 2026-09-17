import { describe, it, expect, beforeAll } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { resetAdminMemoryStores } from 'lib/adapters/index.ts';
import { elysia } from 'lib/index.ts';
import {
	KNOWN_PROVIDERS,
	issuerForKnownProvider
} from 'lib/consts/known_providers.ts';
import { get, provider, seedBucket } from './harness.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { agent, getHeader } from '../test_helper.ts';

const GOOGLE = KNOWN_PROVIDERS.find((entry) => entry.catalogueId === 'google')!;
/* Through the entry's rule rather than a literal, so the case follows the catalogue if the value moves. */
const googleIssuer = () => issuerForKnownProvider(GOOGLE, {})!;

const BRANDED = 'brand-google-app';
const PLAIN = 'brand-plain-app';
const ALL = 'brand-all-app';
const NONE = 'brand-none-app';

/* Every recognised provider, so a provider added later is covered without editing a list here. */
const RECOGNISED = KNOWN_PROVIDERS.map((entry) => ({
	entry,
	issuer: issuerForKnownProvider(entry, {
		/* Only one entry needs it; the rest ignore it. */
		tenant: '11112222-bbbb-3333-cccc-4444dddd5555'
	})!
}));

async function startInteractionFor(clientId: string) {
	const auth = new AuthorizationRequest({
		client_id: clientId,
		scope: 'openid'
	});
	const { response } = await agent.auth.get({ query: auth.params });
	const uid = getHeader(response, 'location').split('/')[2];
	const cookie = response.headers.get('set-cookie');
	if (!cookie) throw new Error('expected an interaction cookie from /auth');
	return { uid, cookie };
}

async function loginPageFor(clientId: string) {
	const { uid, cookie } = await startInteractionFor(clientId);
	return get(`/ui/${uid}/login`, cookie);
}

async function postLogin(clientId: string, fields: Record<string, string>) {
	const { uid, cookie } = await startInteractionFor(clientId);
	const res = await elysia.handle(
		new Request(`http://e.ly/ui/${uid}/login`, {
			method: 'POST',
			headers: {
				cookie,
				'content-type': 'application/x-www-form-urlencoded'
			},
			body: new URLSearchParams(fields).toString()
		})
	);
	return { status: res.status, text: await res.text() };
}

/*
 * The props script is half of a hydrated page. A button rendered into the markup but absent from the props
 * appears and then vanishes the instant React takes over — silently, in a browser only, with nothing
 * logged and no server-side assertion on the markup able to see it. So every case here reads both.
 */
function props(text: string): Record<string, unknown> {
	const match = text.match(/window\.PROPS=(\{.*?\})<\/script>/s);
	if (!match) throw new Error('the login page carried no props script');
	return JSON.parse(match[1].replace(/\\u003c/g, '<'));
}

function providerProps(text: string): Record<string, unknown>[] {
	return (props(text).providers ?? []) as Record<string, unknown>[];
}

/**
 * @proves A bucket offering a recognised upstream shows an end user that provider's own branded button,
 * on every render of the login page, and a bucket offering none shows nothing about it.
 */
describe('a recognised provider on the login page', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'branded_button' });
		resetAdminMemoryStores();

		await seedBucket(BRANDED, {
			federation: [
				provider(googleIssuer(), { id: 'google', displayName: 'Google' })
			]
		});
		await seedBucket(PLAIN, {
			federation: [provider('https://idp-unbranded.test', { id: 'acme-sso' })]
		});
		/*
		 * Seeded in reverse catalogue order deliberately. Stored order is connection order, so a page that
		 * simply rendered the array would come out backwards — which is the defect the ordering rule exists
		 * for, and an in-order fixture could not detect.
		 */
		await seedBucket(ALL, {
			federation: [...RECOGNISED].reverse().map(({ entry, issuer }) =>
				provider(issuer, {
					id: entry.defaultProviderId,
					displayName: entry.displayName
				})
			)
		});
		await seedBucket(NONE, {});
	});

	it('offers one branded button per enabled provider when a bucket has several', async () => {
		const page = await loginPageFor(ALL);

		expect(page.status).toBe(200);
		const rendered = providerProps(page.text);
		expect(rendered).toHaveLength(RECOGNISED.length);

		for (const { entry } of RECOGNISED) {
			// Identifiable by the provider's own name, in the wording its branding rules fix.
			expect(page.text).toContain(entry.buttonText);
			expect(
				rendered.some((row) => row.brand === entry.catalogueId),
				`${entry.catalogueId} rendered no branded button`
			).toBe(true);
		}
	});

	it('offers the buttons in the same order however they were connected', async () => {
		const page = await loginPageFor(ALL);

		/*
		 * The catalogue's order, not the bucket's. The fixture connected them backwards, so this failing
		 * would mean the page still follows whichever provider an administrator happened to add last —
		 * rearranging a page end users already know every time one is added.
		 */
		expect(providerProps(page.text).map((row) => row.brand)).toEqual(
			RECOGNISED.map(({ entry }) => entry.catalogueId)
		);
	});

	it('fetches nothing from any provider to render a login page', async () => {
		/*
		 * Proved by the outbound-fetch mock rather than by an assertion about the markup: it refuses any
		 * request to an origin nobody registered, by name. No origin is registered in this suite, so a mark
		 * served from a provider's CDN — which would tell that provider somebody is on the page before they
		 * have chosen anything, and would fail with no network — fails this case loudly.
		 */
		const page = await loginPageFor(ALL);

		expect(page.status).toBe(200);
		expect(page.text).toContain('<svg');
		// Inline, so the bytes are in the document rather than at a URL somebody else serves.
		expect(page.text).not.toMatch(/<img[^>]+https?:\/\//);
	});

	it('offers a Google button when the bucket has an enabled provider at Google issuer', async () => {
		const page = await loginPageFor(BRANDED);

		expect(page.status).toBe(200);
		expect(page.text).toContain(GOOGLE.buttonText);
		// The mark, inline rather than fetched: an outbound request here would tell Google about every
		// visitor before they have chosen anything, and would fail with no network.
		expect(page.text).toContain('<svg');
		expect(providerProps(page.text)[0]?.brand).toBe('google');
	});

	it('offers no Google button when the bucket has none', async () => {
		const page = await loginPageFor(NONE);

		expect(page.status).toBe(200);
		expect(page.text).not.toContain('Google');
		expect(providerProps(page.text)).toEqual([]);
	});

	it('offers an unbranded button for a provider it does not recognise', async () => {
		const page = await loginPageFor(PLAIN);

		expect(page.status).toBe(200);
		expect(page.text).toContain('Acme SSO');
		expect(page.text).not.toContain('Google');
		expect(providerProps(page.text)[0]?.brand).toBeUndefined();
	});

	it('offers the same buttons on a re-rendered login page as on a first render', async () => {
		const first = await loginPageFor(BRANDED);
		const rerendered = await postLogin(BRANDED, {
			username: 'nobody@example.com',
			password: 'wrong'
		});

		expect(rerendered.status).toBe(400);
		expect(rerendered.text).toContain(GOOGLE.buttonText);
		expect(providerProps(rerendered.text)).toEqual(providerProps(first.text));
	});
});
