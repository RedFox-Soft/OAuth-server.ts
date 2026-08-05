import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { getUserStore, resetAdminMemoryStores } from 'lib/adapters/index.ts';
import { TestAdapter } from 'test/models.ts';
import { assertNoPendingInterceptors } from '../fetch_mock.ts';
import { idpStub } from './idp_stub.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { eventBus } from 'lib/event_bus.ts';
import {
	CLIENT,
	get,
	provider,
	seedBucket,
	signedInAccountIds,
	startInteraction,
	walk
} from './harness.ts';

/*
 * The federated sign-in succeeding, end to end, against a stub upstream provider. Its refusals live in
 * ./refusals.spec.ts; the scaffolding both share is ./harness.ts.
 *
 * Every case gets its **own** stub origin. The metadata and JWKS caches are keyed by URL and jose's
 * RemoteJWKSet adds a freshness window of its own, so two cases sharing an origin would have the second
 * silently skip a fetch — and because the mock's interceptors are single-use and an unhit one throws, that
 * failure would land on an unrelated case. One origin per case keeps each fetch count local.
 */

describe('federated sign-in', () => {
	beforeAll(async () => {
		// Named explicitly: bootstrap defaults to the directory name, and this suite's config is `signin`
		// so the doors suite beside it can carry its own.
		await bootstrap(import.meta.url, { config: 'signin' });
	});

	beforeEach(() => {
		// Top-level resets do not reach describe-nested tests in bun, so this lives inside the describe.
		resetAdminMemoryStores();
	});

	it('signs in an account that already holds the upstream identity, writing nothing new', async () => {
		const idp = await idpStub('https://idp-existing.test');
		const bucketId = await seedBucket(CLIENT, {
			federation: [provider(idp.origin)]
		});
		const store = getUserStore(bucketId);
		const existing = await store.create(
			'linked@acme.test',
			'irrelevant-hash',
			[],
			true
		);
		await store.update(existing._id, {
			federated: [
				{
					providerId: 'acme-sso',
					sub: 'upstream-subject-1',
					linkedAt: new Date()
				}
			]
		});

		idp.expectDiscovery();
		const { uid, cookie } = await startInteraction();
		const { authorizeUrl, complete } = await walk(uid, cookie, {
			idp,
			claims: { email: 'someone-else@acme.test' }
		});

		// The provider the button named is the provider the user was sent to (the T014 spike's permanent pin).
		expect(authorizeUrl.origin).toBe(idp.origin);
		expect(authorizeUrl.pathname).toBe('/authorize');
		expect(authorizeUrl.searchParams.get('client_id')).toBe('stub-client');
		expect(authorizeUrl.searchParams.get('redirect_uri')).toContain(
			'/federation/callback'
		);

		expect(complete?.status).toBe(303);
		expect(signedInAccountIds()).toContain(existing._id);

		// The existing link decides the sign-in; the assertion's address is not adopted, and no second
		// account appears for it.
		const all = await store.list();
		expect(all).toHaveLength(1);
		expect(all[0]?.email).toBe('linked@acme.test');
		assertNoPendingInterceptors();
	});

	it('links a trusted, verified assertion to the existing password account rather than making a second', async () => {
		const idp = await idpStub('https://idp-trusted.test');
		const bucketId = await seedBucket(CLIENT, {
			federation: [provider(idp.origin, { emailTrusted: true })]
		});
		const store = getUserStore(bucketId);
		const existing = await store.create(
			'both@acme.test',
			'password-hash',
			[],
			true
		);

		idp.expectDiscovery();
		const { uid, cookie } = await startInteraction();
		const { complete } = await walk(uid, cookie, {
			idp,
			claims: { email: 'both@acme.test', email_verified: true }
		});

		expect(complete?.status).toBe(303);
		expect(signedInAccountIds()).toContain(existing._id);

		const all = await store.list();
		expect(all).toHaveLength(1);
		expect(all[0]?.federated).toEqual([
			expect.objectContaining({
				providerId: 'acme-sso',
				sub: 'upstream-subject-1'
			})
		]);
		assertNoPendingInterceptors();
	});

	it('provisions an account for an unknown address, with no usable password and no roles', async () => {
		const idp = await idpStub('https://idp-jit.test');
		const bucketId = await seedBucket(CLIENT, {
			federation: [provider(idp.origin, { emailTrusted: true })]
		});
		const store = getUserStore(bucketId);

		idp.expectDiscovery();
		const { uid, cookie } = await startInteraction();
		const { complete } = await walk(uid, cookie, {
			idp,
			claims: {
				email: 'new@acme.test',
				email_verified: true,
				name: 'New Person',
				given_name: 'New'
			}
		});

		expect(complete?.status).toBe(303);

		const all = await store.list();
		expect(all).toHaveLength(1);
		const created = all[0]!;
		expect(created.email).toBe('new@acme.test');
		expect(created.roles).toEqual([]);
		// Trusted provider + verified assertion, so the account is verified by the same test that allowed
		// the link.
		expect(created.verified).toBe(true);
		expect(signedInAccountIds()).toContain(created._id);
		// The profile claims the assertion carried are copied; nothing else is invented.
		expect(created.claims).toMatchObject({
			name: 'New Person',
			given_name: 'New'
		});

		/*
		 * No password can ever verify against the stored hash — it is a digest of bytes that were discarded,
		 * not a sentinel someone could eventually type.
		 */
		for (const attempt of ['', 'password', created.password]) {
			expect(await Bun.password.verify(attempt, created.password)).toBe(false);
		}
		assertNoPendingInterceptors();
	});

	it('discards the upstream access and refresh tokens', async () => {
		const idp = await idpStub('https://idp-tokens.test');
		const bucketId = await seedBucket(CLIENT, {
			federation: [provider(idp.origin, { emailTrusted: true })]
		});

		idp.expectDiscovery();
		const { uid, cookie } = await startInteraction();
		await walk(uid, cookie, {
			idp,
			claims: { email: 'tokens@acme.test', email_verified: true }
		});

		/*
		 * The stub always returns both tokens, so this distinguishes "discarded" from "never received".
		 * Asserted across every stored record rather than one area, because the claim is that nothing
		 * anywhere holds them.
		 */
		const everything = JSON.stringify([
			await getUserStore(bucketId).list(),
			TestAdapter.for('FederationState').syncFind('any') ?? null,
			TestAdapter.for('Interaction').syncFind(uid) ?? null,
			TestAdapter.for('Session').syncFind(uid) ?? null
		]);
		expect(everything).not.toContain(
			'upstream-access-token-must-not-be-stored'
		);
		expect(everything).not.toContain(
			'upstream-refresh-token-must-not-be-stored'
		);
		assertNoPendingInterceptors();
	});

	it('sets no cookie on the callback and hands back through a same-site redirect', async () => {
		const idp = await idpStub('https://idp-nocookie.test');
		await seedBucket(CLIENT, {
			federation: [provider(idp.origin, { emailTrusted: true })]
		});

		idp.expectDiscovery();
		const { uid, cookie } = await startInteraction();
		const { callback } = await walk(uid, cookie, {
			idp,
			claims: { email: 'nocookie@acme.test', email_verified: true }
		});

		// No new cookie anywhere in the flow: the round trip is carried by a server-side record instead.
		expect(callback.setCookie).toBeNull();
		// Relative, so the strict interaction cookie applies on the next hop.
		expect(callback.status).toBe(303);
		expect(callback.location.startsWith(`/ui/${uid}/federation/complete`)).toBe(
			true
		);
		assertNoPendingInterceptors();
	});

	it('sends a byte-identical redirect_uri across two different interactions', async () => {
		const idp = await idpStub('https://idp-fixed.test');
		await seedBucket(CLIENT, {
			federation: [provider(idp.origin, { emailTrusted: true })]
		});

		// One interceptor for two starts: the metadata cache is keyed by issuer, so the second start must
		// not fetch again — and an unhit interceptor would fail this case anyway.
		idp.expectDiscovery();
		const first = await startInteraction();
		const second = await startInteraction();
		const a = await get(
			`/ui/${first.uid}/federation/acme-sso/start`,
			first.cookie
		);
		const b = await get(
			`/ui/${second.uid}/federation/acme-sso/start`,
			second.cookie
		);

		const redirectOf = (location: string) =>
			new URL(location).searchParams.get('redirect_uri');
		// An upstream matches redirect_uri by exact string, so this cannot vary per interaction.
		expect(redirectOf(a.location)).toBe(redirectOf(b.location));
		// And each round trip carries its own state and nonce.
		expect(new URL(a.location).searchParams.get('state')).not.toBe(
			new URL(b.location).searchParams.get('state')
		);
	});
	it('renders one control per enabled provider, in the markup and in the hydration props', async () => {
		const idp = await idpStub('https://idp-surface.test');
		await seedBucket(CLIENT, {
			federation: [
				provider(idp.origin, { id: 'acme-sso', displayName: 'Acme SSO' }),
				provider(idp.origin, { id: 'other-sso', displayName: 'Other SSO' })
			]
		});
		const { uid, cookie } = await startInteraction();

		const page = await get(`/ui/${uid}/login`, cookie);

		expect(page.status).toBe(200);
		// Server-rendered.
		expect(page.text).toContain(`/ui/${uid}/federation/acme-sso/start`);
		expect(page.text).toContain(`/ui/${uid}/federation/other-sso/start`);
		/*
		 * The label and the phrase are asserted apart because React's server renderer puts a `<!-- -->` text
		 * separator between a literal and an interpolation, so "Sign in with Acme SSO" never appears as one
		 * string in the markup. Asserting the parts is also what a reader actually cares about.
		 */
		expect(page.text).toContain('Sign in with ');
		expect(page.text).toContain('Acme SSO');
		expect(page.text).toContain('Other SSO');
		/*
		 * And in the props — the half that fails in a browser only. Without this the buttons render, then
		 * React rebuilds the tree from props that never mentioned them and they vanish, with nothing logged
		 * and no server-side assertion able to see it.
		 */
		expect(page.text).toContain('"providers"');
		expect(page.text).toContain('"displayName":"Acme SSO"');
		// A navigation, so no inline handler and nothing new for the content security policy to authorise.
		expect(page.text).not.toContain('onclick');
		expect(page.csp).toBeTruthy();
	});

	it('offers nothing for a disabled provider, and answers its start route as unserved', async () => {
		const idp = await idpStub('https://idp-disabled.test');
		await seedBucket(CLIENT, {
			federation: [provider(idp.origin, { enabled: false })]
		});
		const { uid, cookie } = await startInteraction();

		const page = await get(`/ui/${uid}/login`, cookie);
		expect(page.text).not.toContain('Acme SSO');
		expect(page.text).not.toContain('/federation/acme-sso/start');

		// Disabling keeps the credentials but takes the door away entirely.
		const start = await get(`/ui/${uid}/federation/acme-sso/start`, cookie);
		expect(start.status).toBe(404);
	});

	it('serves no federation route and renders no control while the deployment switch is off', async () => {
		const idp = await idpStub('https://idp-off.test');
		await seedBucket(CLIENT, {
			federation: [provider(idp.origin, { emailTrusted: true })]
		});
		const { uid, cookie } = await startInteraction();

		const disabled: { flag?: string }[] = [];
		const listener = (event: { flag?: string }) => disabled.push(event);
		eventBus.on('feature_disabled', listener);
		ApplicationConfig['federation.enabled'] = false;
		try {
			const page = await get(`/ui/${uid}/login`, cookie);
			// Whatever the bucket holds.
			expect(page.text).not.toContain('Acme SSO');
			expect(page.text).not.toContain('/federation/acme-sso/start');

			for (const path of [
				`/ui/${uid}/federation/acme-sso/start`,
				`/ui/${uid}/federation/complete?ref=anything`,
				`/federation/callback?state=anything`
			]) {
				const res = await get(path, cookie);
				// Exactly as the server answers a path it does not serve.
				expect(res.status).toBe(404);
			}
		} finally {
			ApplicationConfig['federation.enabled'] = true;
			eventBus.off('feature_disabled', listener);
		}

		// The operator's only way to diagnose the 404s, since the responses deliberately say nothing.
		expect(disabled.map((e) => e.flag)).toEqual([
			'federation.enabled',
			'federation.enabled',
			'federation.enabled'
		]);
	});
});
