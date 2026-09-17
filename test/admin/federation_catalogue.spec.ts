import { describe, it, expect, beforeEach, afterEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';

import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { federationAdminRoutes } from 'lib/admin/federation/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	getBucketStore,
	getUserStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { SECRET_MASK } from 'lib/federation/consts.ts';
import {
	KNOWN_PROVIDERS,
	issuerForKnownProvider
} from 'lib/consts/known_providers.ts';
import {
	assertEmailDomains,
	assertIssuer,
	assertProviderId,
	assertScopes
} from 'lib/admin/federation/validate.ts';
import { mock } from '../fetch_mock.ts';
import { idpStub } from '../federation/idp_stub.ts';
import { sessionFor } from '../admin_session.ts';

/*
 * Google's issuer is fixed, so every case here stubs the same origin rather than taking its own as the
 * federation harness rule asks. That rule exists because the discovery and JWKS caches are module-level
 * and keyed by URL — and it does not bite here, because `assertIssuerResolves` calls `forgetDiscovery`
 * before every check. Each case therefore registers its own discovery interceptor and consumes it.
 */
const GOOGLE_ISSUER = 'https://accounts.google.com';
const GOOGLE_CLIENT_ID = '1234567890-abcdef.apps.googleusercontent.com';

const app = new Elysia().use(resolveAdmin).use(federationAdminRoutes);
const client = treaty(app);

async function cookieFor(roles: string[] = ['super_admin']) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`${roles.join('-')}-${Math.random()}@x.io`,
		'hash',
		roles
	);
	const session = await sessionFor(user);
	return `${ADMIN_SESSION_COOKIE}=${session._id}`;
}

async function seedBucket(fields: Record<string, unknown> = {}) {
	return getBucketStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name: `bucket-${Math.random()}`,
		...fields
	});
}

async function stubGoogle() {
	const idp = await idpStub(GOOGLE_ISSUER);
	idp.expectDiscovery();
	return idp;
}

function guidanceFor(payload: unknown, catalogueId = 'google') {
	const providers = (payload as { providers?: Record<string, unknown>[] })
		?.providers;
	return providers?.find((entry) => entry.catalogueId === catalogueId);
}

/**
 * @proves An administrator is told exactly where to go and which callback address to register, and can
 * then connect a recognised provider with the two credentials it issued and nothing else.
 */
describe('connecting a recognised provider', () => {
	beforeEach(async () => {
		resetAdminMemoryStores();
		await ensureAdminSeed();
	});

	afterEach(() => {
		mock.restore();
	});

	/*
	 * Enumerated from the running catalogue rather than from a list written here: the defect this closes is
	 * the entry somebody adds later without checking it against the rules a hand-configured provider must
	 * satisfy, and an example naming Google cannot close that.
	 */
	it('supplies values that pass the validation a hand-configured provider must pass, for every recognised provider', () => {
		expect(KNOWN_PROVIDERS.length).toBeGreaterThan(0);

		for (const entry of KNOWN_PROVIDERS) {
			assertProviderId(entry.defaultProviderId, []);
			/*
			 * Through the entry's own rule, because one entry's issuer names an organisation and so has no
			 * single value. A sample parameter is enough: the claim is that whatever an entry would store is
			 * a valid issuer, not that any particular organisation exists.
			 */
			const issuer = issuerForKnownProvider(entry, { tenant: 'sample-tenant' });
			expect(issuer).toBeDefined();
			assertIssuer(issuer as string);
			assertScopes([...entry.scopes], entry.protocol.kind);
			assertEmailDomains([]);

			expect(entry.steps.length).toBeGreaterThan(0);
			expect(entry.consoleUrl).toStartWith('https://');
			expect(entry.buttonText.length).toBeGreaterThan(0);
			expect(entry.emailClaim.length).toBeGreaterThan(0);
		}

		const ids = KNOWN_PROVIDERS.map((entry) => entry.catalogueId);
		expect(new Set(ids).size).toBe(ids.length);
	});

	it('returns the callback address to register for this bucket', async () => {
		const cookie = await cookieFor();
		const bucket = await seedBucket({ slug: 'acme' });

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.catalogue.get({ headers: { cookie } });

		expect(res.status).toBe(200);
		const google = guidanceFor(res.data);
		expect(google?.callbackUri).toBe('http://e.ly/acme/federation/callback');
		expect(google?.consoleUrl).toStartWith('https://console.cloud.google.com');
		expect((google?.steps as string[]).length).toBeGreaterThan(0);
		// Google's form asks for these; this flow is server-side and needs none, so the guidance says so.
		expect(google?.javascriptOrigins).toEqual([]);
	});

	it('names the bucket own address when the bucket is served beneath one', async () => {
		const cookie = await cookieFor();
		const first = await seedBucket({ slug: 'tenant-one' });
		const second = await seedBucket({ slug: 'tenant-two' });

		const one = await client.admin.api
			.buckets({ id: first._id })
			.federation.catalogue.get({ headers: { cookie } });
		const two = await client.admin.api
			.buckets({ id: second._id })
			.federation.catalogue.get({ headers: { cookie } });

		expect(guidanceFor(one.data)?.callbackUri).toBe(
			'http://e.ly/tenant-one/federation/callback'
		);
		expect(guidanceFor(two.data)?.callbackUri).toBe(
			'http://e.ly/tenant-two/federation/callback'
		);
	});

	it('warns that the callback address is provisional when the bucket has no slug', async () => {
		const cookie = await cookieFor();
		const bucket = await seedBucket();

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.catalogue.get({ headers: { cookie } });

		const google = guidanceFor(res.data);
		expect(google?.callbackStability).toBe('provisional');
		// Built from the record id, which is what assigning a slug later invalidates.
		expect(google?.callbackUri).toContain(bucket._id);
	});

	it('reports a stable callback address when the bucket has a slug', async () => {
		const cookie = await cookieFor();
		const bucket = await seedBucket({ slug: 'stable-co' });

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.catalogue.get({ headers: { cookie } });

		expect(guidanceFor(res.data)?.callbackStability).toBe('stable');
	});

	it('connects a recognised provider from its name and two credentials alone', async () => {
		const cookie = await cookieFor();
		await stubGoogle();
		const bucket = await seedBucket({ slug: 'connect-co' });

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.post(
				{
					catalogueId: 'google',
					clientId: GOOGLE_CLIENT_ID,
					clientSecret: 'upstream-secret'
				},
				{ headers: { cookie } }
			);

		expect(res.status).toBe(201);
		const created = res.data as Record<string, unknown>;
		expect(created.id).toBe('google');
		expect(created.issuer).toBe(GOOGLE_ISSUER);
		expect(created.displayName).toBe('Google');
		expect(created.scopes).toEqual(['openid', 'email', 'profile']);
		expect(created.emailClaim).toBe('email');
		expect(created.emailTrusted).toBe(true);
		expect(created.clientSecret).toBe(SECRET_MASK);
	});

	it('stores a provider indistinguishable from a hand-configured one with the same values', async () => {
		const cookie = await cookieFor();
		await stubGoogle();
		const guided = await seedBucket({ slug: 'guided-co' });
		await stubGoogle();
		const manual = await seedBucket({ slug: 'manual-co' });

		await client.admin.api.buckets({ id: guided._id }).federation.post(
			{
				catalogueId: 'google',
				clientId: GOOGLE_CLIENT_ID,
				clientSecret: 'upstream-secret'
			},
			{ headers: { cookie } }
		);
		await client.admin.api.buckets({ id: manual._id }).federation.post(
			{
				id: 'google',
				displayName: 'Google',
				issuer: GOOGLE_ISSUER,
				clientId: GOOGLE_CLIENT_ID,
				clientSecret: 'upstream-secret',
				scopes: ['openid', 'email', 'profile'],
				emailTrusted: true,
				emailClaim: 'email'
			},
			{ headers: { cookie } }
		);

		const [guidedStored] = (await getBucketStore().find(guided._id))!
			.federation!;
		const [manualStored] = (await getBucketStore().find(manual._id))!
			.federation!;

		expect(guidedStored).toEqual(manualStored);
		// The field that selected the defaults is consumed, never stored — nothing downstream can branch on it.
		expect(guidedStored).not.toHaveProperty('catalogueId');
	});

	it('applies an explicitly supplied value over the one the catalogue would have supplied', async () => {
		const cookie = await cookieFor();
		await stubGoogle();
		const bucket = await seedBucket({ slug: 'narrow-co' });

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.post(
				{
					catalogueId: 'google',
					clientId: GOOGLE_CLIENT_ID,
					clientSecret: 'upstream-secret',
					allowedEmailDomains: ['acme.com'],
					emailTrusted: false,
					displayName: 'Acme Google'
				},
				{ headers: { cookie } }
			);

		expect(res.status).toBe(201);
		const created = res.data as Record<string, unknown>;
		expect(created.allowedEmailDomains).toEqual(['acme.com']);
		expect(created.emailTrusted).toBe(false);
		expect(created.displayName).toBe('Acme Google');
		// Untouched by the override, so the merge is per field rather than all-or-nothing.
		expect(created.issuer).toBe(GOOGLE_ISSUER);
	});

	it('refuses a client identifier that is not of the form the named provider issues', async () => {
		const cookie = await cookieFor();
		const bucket = await seedBucket({ slug: 'wrong-id-co' });

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.post(
				{
					catalogueId: 'google',
					clientId: 'AIzaSyNotAClientIdAtAll',
					clientSecret: 'upstream-secret'
				},
				{ headers: { cookie } }
			);

		expect(res.status).toBe(422);
		expect(JSON.stringify(res.error?.value ?? '')).toContain(
			'apps.googleusercontent.com'
		);
		expect((await getBucketStore().find(bucket._id))?.federation ?? []).toEqual(
			[]
		);
	});

	it('refuses an unknown catalogue name', async () => {
		const cookie = await cookieFor();
		const bucket = await seedBucket({ slug: 'unknown-co' });

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.post(
				{
					catalogueId: 'gogle',
					clientId: GOOGLE_CLIENT_ID,
					clientSecret: 'upstream-secret'
				},
				{ headers: { cookie } }
			);

		expect(res.status).toBe(422);
		// Names what could have been said instead, so the refusal is actionable.
		expect(JSON.stringify(res.error?.value ?? '')).toContain('google');
	});

	it('refuses a second connection of a provider already on the bucket', async () => {
		const cookie = await cookieFor();
		await stubGoogle();
		const bucket = await seedBucket({ slug: 'twice-co' });
		const body = {
			catalogueId: 'google',
			clientId: GOOGLE_CLIENT_ID,
			clientSecret: 'upstream-secret'
		};

		const first = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.post(body, { headers: { cookie } });
		expect(first.status).toBe(201);

		const second = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.post(body, { headers: { cookie } });

		expect(second.status).toBe(422);
		expect((await getBucketStore().find(bucket._id))!.federation!.length).toBe(
			1
		);
	});

	it('reports an already connected provider in the guidance', async () => {
		const cookie = await cookieFor();
		await stubGoogle();
		const bucket = await seedBucket({ slug: 'already-co' });

		await client.admin.api.buckets({ id: bucket._id }).federation.post(
			{
				catalogueId: 'google',
				clientId: GOOGLE_CLIENT_ID,
				clientSecret: 'upstream-secret'
			},
			{ headers: { cookie } }
		);

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.catalogue.get({ headers: { cookie } });

		const google = guidanceFor(res.data);
		expect(google?.alreadyConnected).toBe(true);
		expect(google?.existingProviderId).toBe('google');
	});

	it('refuses a connection whose upstream metadata cannot be retrieved', async () => {
		const cookie = await cookieFor();
		const idp = await idpStub(GOOGLE_ISSUER);
		idp.expectDiscoveryFailure(503);
		const bucket = await seedBucket({ slug: 'unreachable-co' });

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.post(
				{
					catalogueId: 'google',
					clientId: GOOGLE_CLIENT_ID,
					clientSecret: 'upstream-secret'
				},
				{ headers: { cookie } }
			);

		// The other side's failure, not the administrator's mistake — and nothing half-configured is kept.
		expect(res.status).toBe(502);
		expect((await getBucketStore().find(bucket._id))?.federation ?? []).toEqual(
			[]
		);
	});

	it('returns no credential in the guidance', async () => {
		const cookie = await cookieFor();
		await stubGoogle();
		const bucket = await seedBucket({ slug: 'secrecy-co' });

		await client.admin.api.buckets({ id: bucket._id }).federation.post(
			{
				catalogueId: 'google',
				clientId: GOOGLE_CLIENT_ID,
				clientSecret: 'a-secret-nobody-should-see'
			},
			{ headers: { cookie } }
		);

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.catalogue.get({ headers: { cookie } });

		expect(JSON.stringify(res.data)).not.toContain(
			'a-secret-nobody-should-see'
		);
	});
});
