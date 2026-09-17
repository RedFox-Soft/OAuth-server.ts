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
import { mock } from '../fetch_mock.ts';
import {
	appleStub,
	githubStub,
	microsoftStub
} from '../federation/recognised_stubs.ts';
import { sessionFor } from '../admin_session.ts';

/*
 * Connecting Microsoft, Apple and GitHub through the administrative surface: what each asks for, and what
 * it refuses.
 *
 * Google's own cases live in ./federation_catalogue.spec.ts. These three are here because each asks for
 * something Google does not — an organisation, a signing key, or nothing verifiable at all — and each
 * therefore refuses differently.
 */

/* A real organisation identifier: Microsoft names one by directory GUID or verified domain. */
const TENANT = '11112222-bbbb-3333-cccc-4444dddd5555';

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
		slug: `b-${Math.random().toString(36).slice(2, 10)}`,
		...fields
	});
}

function guidanceFor(payload: unknown, catalogueId: string) {
	const providers = (payload as { providers?: Record<string, unknown>[] })
		?.providers;
	return providers?.find((entry) => entry.catalogueId === catalogueId);
}

/**
 * @proves An administrator connects Microsoft, Apple or GitHub supplying only the values that provider
 * issues, is told which values those are and — for Microsoft — asked who may sign in before saving;
 * and a value that cannot be that provider's, or a key that cannot produce the credential it
 * requires, is refused naming the value at fault with nothing stored.
 */
describe('connecting Microsoft, Apple or GitHub', () => {
	beforeEach(async () => {
		resetAdminMemoryStores();
		await ensureAdminSeed();
	});

	afterEach(() => {
		// The outbound stub is per-case: each create consumes its own single-use interceptor.
		mock.restore();
	});

	/* ------------------------------------------------------------- guidance */

	it('tells an administrator which values each provider asks for, in the wording that provider uses', async () => {
		const cookie = await cookieFor();
		const bucket = await seedBucket();

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.catalogue.get({ headers: { cookie } });

		const counts = {
			github: 2,
			microsoft: 3,
			apple: 4
		};
		for (const [catalogueId, expected] of Object.entries(counts)) {
			const entry = guidanceFor(res.data, catalogueId) as {
				requiredValues?: { label: string; secret: boolean }[];
			};
			expect(
				entry?.requiredValues,
				`${catalogueId} published no required values`
			).toBeDefined();
			expect(entry!.requiredValues!.length).toBe(expected);
			// Every value carries the label the provider itself uses, so nobody is translating.
			for (const value of entry!.requiredValues!) {
				expect(value.label.length).toBeGreaterThan(0);
			}
		}
	});

	it('asks who may sign in with Microsoft, stating the consequence of each answer and preselecting neither', async () => {
		const cookie = await cookieFor();
		const bucket = await seedBucket();

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.catalogue.get({ headers: { cookie } });

		const microsoft = guidanceFor(res.data, 'microsoft') as {
			choices?: {
				name: string;
				question: string;
				options: { value: string | null; consequence: string }[];
			}[];
		};
		expect(microsoft?.choices).toHaveLength(1);
		const choice = microsoft!.choices![0]!;
		expect(choice.name).toBe('tenant');
		expect(choice.options).toHaveLength(2);
		// Each answer says what it means. The broad one must say so in the administrator's own terms.
		for (const option of choice.options) {
			expect(option.consequence.length).toBeGreaterThan(20);
		}
		expect(
			choice.options.some((option) =>
				/anyone in the world/i.test(option.consequence)
			)
		).toBe(true);

		// The other three ask nothing, so a console rendering choices generically shows none for them.
		for (const catalogueId of ['google', 'apple', 'github']) {
			expect(
				(guidanceFor(res.data, catalogueId) as { choices?: unknown[] })?.choices
			).toHaveLength(0);
		}
	});

	/* ------------------------------------------------------------ Microsoft */

	it('connects Microsoft from an organisation and the two values it issues', async () => {
		const cookie = await cookieFor();
		const idp = await microsoftStub(TENANT);
		idp.expectDiscovery();
		const bucket = await seedBucket();

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.post(
				{
					catalogueId: 'microsoft',
					tenant: TENANT,
					clientId: idp.clientId,
					clientSecret: 'upstream-secret'
				},
				{ headers: { cookie } }
			);

		expect(res.status).toBe(201);
		const created = res.data as Record<string, unknown>;
		expect(created.issuer).toBe(idp.issuer);
		expect(created.tenant).toBe(TENANT);
		expect(created.displayName).toBe('Microsoft');
		// Indistinguishable from one configured field by field: nothing records the route that made it.
		expect(created.catalogueId).toBeUndefined();
	});

	it('refuses an organisation identifier that cannot be one, naming it, and stores nothing', async () => {
		const cookie = await cookieFor();
		const bucket = await seedBucket();

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.post(
				{
					catalogueId: 'microsoft',
					tenant: 'not a tenant!',
					clientId: '00001111-aaaa-2222-bbbb-3333cccc4444',
					clientSecret: 'upstream-secret'
				},
				{ headers: { cookie } }
			);

		expect(res.status).toBe(422);
		expect(JSON.stringify(res.error?.value)).toMatch(/organisation/i);
		const stored = await getBucketStore().find(bucket._id);
		expect(stored?.federation ?? []).toHaveLength(0);
	});

	it('refuses a Microsoft application id that is not one, describing a correct one', async () => {
		const cookie = await cookieFor();
		const bucket = await seedBucket();

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.post(
				{
					catalogueId: 'microsoft',
					tenant: TENANT,
					// A secret pasted into the identifier field, which is the mistake this catches.
					clientId: 'some-client-secret-value',
					clientSecret: 'upstream-secret'
				},
				{ headers: { cookie } }
			);

		expect(res.status).toBe(422);
		expect(JSON.stringify(res.error?.value)).toMatch(/GUID/i);
		const stored = await getBucketStore().find(bucket._id);
		expect(stored?.federation ?? []).toHaveLength(0);
	});

	/* ---------------------------------------------------------------- Apple */

	it('connects Apple from the four values its developer account issues, and no client secret', async () => {
		const cookie = await cookieFor();
		const idp = await appleStub();
		idp.expectDiscovery();
		const bucket = await seedBucket();

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.post(
				{
					catalogueId: 'apple',
					clientId: idp.clientId,
					teamId: idp.teamId,
					keyId: idp.keyId,
					signingKey: idp.signingKey
				},
				{ headers: { cookie } }
			);

		expect(res.status).toBe(201);
		const created = res.data as Record<string, unknown>;
		expect(created.issuer).toBe(idp.issuer);
		// Readable, so an administrator whose key was revoked can tell which one to replace.
		expect(created.keyId).toBe(idp.keyId);
		expect(created.teamId).toBe(idp.teamId);
		// The key itself never comes back, on any read, for any role.
		expect(created.signingKey).toBe(SECRET_MASK);
		expect(JSON.stringify(created)).not.toContain(
			idp.signingKey.split('\n')[1] ?? 'unreachable'
		);
	});

	it('refuses a key that cannot produce the credential Apple requires, and stores nothing', async () => {
		const cookie = await cookieFor();
		const idp = await appleStub();
		const bucket = await seedBucket();

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.post(
				{
					catalogueId: 'apple',
					clientId: idp.clientId,
					teamId: idp.teamId,
					keyId: idp.keyId,
					// Well-formed enough to reach the check, and not a key.
					signingKey:
						'-----BEGIN PRIVATE KEY-----\nbm90LWEta2V5\n-----END PRIVATE KEY-----'
				},
				{ headers: { cookie } }
			);

		expect(res.status).toBe(422);
		// Named, and told what a correct one is — the failure would otherwise appear on Apple's own page.
		expect(JSON.stringify(res.error?.value)).toMatch(/\.p8|key/i);
		const stored = await getBucketStore().find(bucket._id);
		expect(stored?.federation ?? []).toHaveLength(0);
	});

	it('refuses an Apple connection that omits the key entirely, naming what is missing', async () => {
		const cookie = await cookieFor();
		const idp = await appleStub();
		const bucket = await seedBucket();

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.post(
				{
					catalogueId: 'apple',
					clientId: idp.clientId,
					teamId: idp.teamId,
					keyId: idp.keyId
				},
				{ headers: { cookie } }
			);

		expect(res.status).toBe(422);
		expect(JSON.stringify(res.error?.value)).toMatch(/key file|\.p8/i);
	});

	/* --------------------------------------------------------------- GitHub */

	it('connects GitHub from two values, without reporting its absent metadata as unreachable', async () => {
		const cookie = await cookieFor();
		const idp = githubStub();
		const bucket = await seedBucket();

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.post(
				{
					catalogueId: 'github',
					clientId: idp.clientId,
					clientSecret: 'upstream-secret'
				},
				{ headers: { cookie } }
			);

		/*
		 * No discovery stub is registered, and none is wanted: GitHub publishes no metadata for signing a
		 * person in. A 502 here would mean its absence was being reported as a network fault, which would
		 * send an administrator looking for something that does not exist.
		 */
		expect(res.status).toBe(201);
		const created = res.data as Record<string, unknown>;
		expect(created.issuer).toBe('https://github.com');
		expect(created.scopes).toEqual(['read:user', 'user:email']);
	});

	it('refuses a GitHub client secret pasted into the identifier field', async () => {
		const cookie = await cookieFor();
		const bucket = await seedBucket();

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.post(
				{
					catalogueId: 'github',
					// A GitHub secret is 40 hex characters; an identifier is shorter.
					clientId: '0123456789abcdef0123456789abcdef01234567',
					clientSecret: 'upstream-secret'
				},
				{ headers: { cookie } }
			);

		expect(res.status).toBe(422);
		const stored = await getBucketStore().find(bucket._id);
		expect(stored?.federation ?? []).toHaveLength(0);
	});

	/* ------------------------------------------------------- shared refusals */

	it('refuses a value the named provider does not use rather than storing it', async () => {
		const cookie = await cookieFor();
		const idp = githubStub();
		const bucket = await seedBucket();

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.post(
				{
					catalogueId: 'github',
					clientId: idp.clientId,
					clientSecret: 'upstream-secret',
					// GitHub has no signing key. Offering one means the administrator is on the wrong screen,
					// and storing it would leave a credential nothing will ever present.
					signingKey: 'should-not-be-stored'
				},
				{ headers: { cookie } }
			);

		expect(res.status).toBe(422);
		const stored = await getBucketStore().find(bucket._id);
		expect(stored?.federation ?? []).toHaveLength(0);
	});

	it('refuses an unreachable upstream as an upstream problem, distinguishably from a wrong value', async () => {
		const cookie = await cookieFor();
		const idp = await microsoftStub(TENANT);
		// Registered, but answering as a broken upstream would.
		mock('https://login.microsoftonline.com')
			.intercept({
				path: `/${TENANT}/v2.0/.well-known/openid-configuration`
			})
			.reply(503, 'unavailable');
		const bucket = await seedBucket();

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.post(
				{
					catalogueId: 'microsoft',
					tenant: TENANT,
					clientId: idp.clientId,
					clientSecret: 'upstream-secret'
				},
				{ headers: { cookie } }
			);

		// 502, not 422: the administrator supplied nothing wrong, and telling them otherwise would send
		// them re-checking correct values.
		expect(res.status).toBe(502);
		const stored = await getBucketStore().find(bucket._id);
		expect(stored?.federation ?? []).toHaveLength(0);
	});

	it('puts no secret and no key into any refusal', async () => {
		const cookie = await cookieFor();
		const idp = await appleStub();
		const bucket = await seedBucket();
		const keyLine = idp.signingKey.split('\n')[1] ?? 'unreachable';

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.post(
				{
					catalogueId: 'apple',
					// Wrong shape, so the refusal is about the identifier while a key is in hand.
					clientId: 'NOTREVERSEDOMAIN',
					teamId: idp.teamId,
					keyId: idp.keyId,
					signingKey: idp.signingKey
				},
				{ headers: { cookie } }
			);

		expect(res.status).toBe(422);
		const body = JSON.stringify(res.error?.value ?? '');
		expect(body).not.toContain(keyLine);
		expect(body).not.toContain('upstream-secret');
	});
});
