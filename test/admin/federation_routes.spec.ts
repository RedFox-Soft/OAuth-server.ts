import { describe, it, expect, beforeEach, afterEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';

import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { federationAdminRoutes } from 'lib/admin/federation/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminAuditStore,
	adminSessionStore,
	getBucketStore,
	getUserStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import {
	ADMIN_BUCKET_ID,
	ADMIN_SESSION_COOKIE,
	UNASSIGNED_GROUP_ID
} from 'lib/admin/consts.ts';
import { SECRET_MASK } from 'lib/federation/consts.ts';
import { mock } from '../fetch_mock.ts';
import { idpStub } from '../federation/idp_stub.ts';
import { sessionFor } from '../admin_session.ts';

/*
 * Configuring providers, and severing an account's link to one.
 *
 * Every case needs the outbound stub, because creating a provider validates its issuer by fetching the
 * discovery document — deliberately, so a mistyped issuer is caught at configuration time rather than at
 * somebody's first sign-in.
 */

const app = new Elysia().use(resolveAdmin).use(federationAdminRoutes);
const client = treaty(app);

async function cookieFor(roles: string[]) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`${roles.join('-')}-${Math.random()}@x.io`,
		'hash',
		roles
	);
	const session = await sessionFor(user);
	return { cookie: `${ADMIN_SESSION_COOKIE}=${session._id}`, user };
}

const body = (origin: string, overrides: Record<string, unknown> = {}) => ({
	id: 'acme-sso',
	displayName: 'Acme SSO',
	issuer: origin,
	clientId: 'upstream-client',
	clientSecret: 'upstream-secret',
	...overrides
});

describe('provider management', () => {
	beforeEach(async () => {
		resetAdminMemoryStores();
		await ensureAdminSeed();
	});

	afterEach(() => {
		mock.restore();
	});

	it('creates a provider with the cautious defaults and never returns its secret', async () => {
		const { cookie } = await cookieFor(['super_admin']);
		const idp = await idpStub('https://idp-admin-create.test');
		idp.expectDiscovery();
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'b'
		});

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.post(body(idp.origin), { headers: { cookie } });

		expect(res.status).toBe(201);
		const created = res.data as Record<string, unknown>;
		// Opt-in, both of them: trusting a provider's addresses and narrowing domains are decisions.
		expect(created.emailTrusted).toBe(false);
		expect(created.provisioning).toBe('jit');
		expect(created.allowedEmailDomains).toEqual([]);
		expect(created.emailClaim).toBe('email');
		expect(created.enabled).toBe(true);
		expect(created.scopes).toEqual(['openid', 'email', 'profile']);
		// Write-only: masked even in the response to the request that just set it.
		expect(created.clientSecret).toBe(SECRET_MASK);

		// Stored intact, though.
		const stored = (await getBucketStore().find(bucket._id))?.federation ?? [];
		expect(stored[0]?.clientSecret).toBe('upstream-secret');
	});

	it('masks the secret on every read', async () => {
		const { cookie } = await cookieFor(['super_admin']);
		const idp = await idpStub('https://idp-admin-read.test');
		idp.expectDiscovery();
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'b'
		});
		await client.admin.api
			.buckets({ id: bucket._id })
			.federation.post(body(idp.origin), { headers: { cookie } });

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.get({ headers: { cookie } });

		const list = res.data as Record<string, unknown>[];
		expect(list).toHaveLength(1);
		// For every role, super-admin included: there is no reader this value is for.
		expect(list[0]?.clientSecret).toBe(SECRET_MASK);
	});

	it('keeps the stored secret when an update omits it, and when it echoes the mask', async () => {
		const { cookie } = await cookieFor(['super_admin']);
		const idp = await idpStub('https://idp-admin-keep.test');
		idp.expectDiscovery();
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'b'
		});
		await client.admin.api
			.buckets({ id: bucket._id })
			.federation.post(body(idp.origin), { headers: { cookie } });

		// Renaming a provider must not require re-typing a secret.
		await client.admin.api
			.buckets({ id: bucket._id })
			.federation({ providerId: 'acme-sso' })
			.patch({ displayName: 'Acme Single Sign-On' }, { headers: { cookie } });

		let stored = (await getBucketStore().find(bucket._id))?.federation ?? [];
		expect(stored[0]?.displayName).toBe('Acme Single Sign-On');
		expect(stored[0]?.clientSecret).toBe('upstream-secret');

		/*
		 * And the mask submitted *as* the secret means the same thing, following the SMTP settings precedent.
		 * A console that renders the masked value into a form and posts the form back would otherwise store
		 * the placeholder, breaking sign-in in a way that looks like an upstream outage.
		 */
		await client.admin.api
			.buckets({ id: bucket._id })
			.federation({ providerId: 'acme-sso' })
			.patch({ clientSecret: SECRET_MASK }, { headers: { cookie } });

		stored = (await getBucketStore().find(bucket._id))?.federation ?? [];
		expect(stored[0]?.clientSecret).toBe('upstream-secret');
	});

	it('replaces the secret when a real one is supplied', async () => {
		const { cookie } = await cookieFor(['super_admin']);
		const idp = await idpStub('https://idp-admin-rotate.test');
		idp.expectDiscovery();
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'b'
		});
		await client.admin.api
			.buckets({ id: bucket._id })
			.federation.post(body(idp.origin), { headers: { cookie } });

		await client.admin.api
			.buckets({ id: bucket._id })
			.federation({ providerId: 'acme-sso' })
			.patch({ clientSecret: 'rotated' }, { headers: { cookie } });

		const stored = (await getBucketStore().find(bucket._id))?.federation ?? [];
		expect(stored[0]?.clientSecret).toBe('rotated');
	});

	it('records an audit entry naming the fields and never their values', async () => {
		const { cookie } = await cookieFor(['super_admin']);
		const idp = await idpStub('https://idp-admin-audit.test');
		idp.expectDiscovery();
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'b'
		});

		await client.admin.api
			.buckets({ id: bucket._id })
			.federation.post(body(idp.origin), { headers: { cookie } });

		/*
		 * Filtered by target, not merely by action: the trail is append-only and never reset between cases, so
		 * an unscoped count would measure every provider this file has created.
		 */
		const { entries } = await adminAuditStore.list({
			action: 'federation.provider.create',
			targetId: bucket._id
		});
		expect(entries).toHaveLength(1);
		expect(entries[0]?.targetId).toBe(bucket._id);
		expect(entries[0]?.targetType).toBe('UserBucket');
		expect(entries[0]?.attributes).toContain('clientSecret');
		// The name is useful; the value must be nowhere near the trail.
		expect(JSON.stringify(entries[0])).not.toContain('upstream-secret');
	});

	it('deletes a provider and records it', async () => {
		const { cookie } = await cookieFor(['super_admin']);
		const idp = await idpStub('https://idp-admin-delete.test');
		idp.expectDiscovery();
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'b'
		});
		await client.admin.api
			.buckets({ id: bucket._id })
			.federation.post(body(idp.origin), { headers: { cookie } });

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.federation({ providerId: 'acme-sso' })
			.delete(undefined, { headers: { cookie } });

		expect(res.status).toBe(200);
		expect((await getBucketStore().find(bucket._id))?.federation).toEqual([]);
		const { entries } = await adminAuditStore.list({
			action: 'federation.provider.delete',
			targetId: bucket._id
		});
		expect(entries).toHaveLength(1);
	});

	it('refuses a provider whose issuer cannot be reached', async () => {
		const { cookie } = await cookieFor(['super_admin']);
		const idp = await idpStub('https://idp-admin-down.test');
		idp.expectDiscoveryFailure(500);
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'b'
		});

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.post(body(idp.origin), { headers: { cookie } });

		// Not the caller's mistake, so not a 4xx.
		expect(res.status).toBe(502);
		expect((await getBucketStore().find(bucket._id))?.federation).toEqual([]);
	});

	it('refuses an issuer whose document names a different one', async () => {
		const { cookie } = await cookieFor(['super_admin']);
		// The document claims to be somebody else — a copy-pasted tenant URL, a redirect, a trailing slash.
		const idp = await idpStub('https://idp-admin-mismatch.test', {
			issuer: 'https://somebody-else.test'
		});
		idp.expectDiscovery();
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'b'
		});

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.post(body(idp.origin), { headers: { cookie } });

		// The submitted value is the wrong thing, which is what 422 says.
		expect(res.status).toBe(422);
	});

	it('refuses a non-https issuer without reaching for it', async () => {
		const { cookie } = await cookieFor(['super_admin']);
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'b'
		});

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.post(body('http://insecure.test'), { headers: { cookie } });

		// No interceptor is registered, so this also proves nothing was fetched.
		expect(res.status).toBe(422);
	});

	it('refuses a malformed id, a duplicate id, missing openid, and a bad domain', async () => {
		const { cookie } = await cookieFor(['super_admin']);
		const idp = await idpStub('https://idp-admin-validate.test');
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'b'
		});

		const badId = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.post(body(idp.origin, { id: 'Not A Slug' }), {
				headers: { cookie }
			});
		expect(badId.status).toBe(422);

		const noOpenid = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.post(body(idp.origin, { scopes: ['email'] }), {
				headers: { cookie }
			});
		expect(noOpenid.status).toBe(422);

		const badDomain = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.post(
				body(idp.origin, { allowedEmailDomains: ['@acme.test'] }),
				{ headers: { cookie } }
			);
		// Refused rather than normalised, so an operator learns now instead of wondering later.
		expect(badDomain.status).toBe(422);

		// Only now a valid one, so the duplicate below is the only thing being tested.
		idp.expectDiscovery();
		const first = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.post(body(idp.origin), { headers: { cookie } });
		expect(first.status).toBe(201);

		const duplicate = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.post(body(idp.origin), { headers: { cookie } });
		expect(duplicate.status).toBe(422);
	});

	it('refuses disabling or deleting the last enabled provider of a federated-only bucket', async () => {
		const { cookie } = await cookieFor(['super_admin']);
		const idp = await idpStub('https://idp-admin-lockout.test');
		idp.expectDiscovery();
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'b'
		});
		await client.admin.api
			.buckets({ id: bucket._id })
			.federation.post(body(idp.origin), { headers: { cookie } });
		await getBucketStore().update(bucket._id, { passwordLogin: false });

		const disabled = await client.admin.api
			.buckets({ id: bucket._id })
			.federation({ providerId: 'acme-sso' })
			.patch({ enabled: false }, { headers: { cookie } });
		expect(disabled.status).toBe(409);

		const deleted = await client.admin.api
			.buckets({ id: bucket._id })
			.federation({ providerId: 'acme-sso' })
			.delete(undefined, { headers: { cookie } });
		expect(deleted.status).toBe(409);

		// Both refused, so the bucket is still reachable — the same rule the bucket PATCH enforces.
		const stored = (await getBucketStore().find(bucket._id))?.federation ?? [];
		expect(stored[0]?.enabled).toBe(true);
	});

	it('keeps two buckets on the same issuer entirely separate', async () => {
		const { cookie } = await cookieFor(['super_admin']);
		const idp = await idpStub('https://idp-admin-shared.test');
		idp.expectDiscovery();
		const a = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'a'
		});
		const b = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'b'
		});

		await client.admin.api
			.buckets({ id: a._id })
			.federation.post(body(idp.origin, { clientId: 'client-a' }), {
				headers: { cookie }
			});
		/*
		 * A second interceptor, because write-time validation deliberately drops any cached copy before
		 * fetching: an issuer being configured must be checked against a live document, not against the answer
		 * a previous request happened to leave behind.
		 */
		idp.expectDiscovery();
		await client.admin.api
			.buckets({ id: b._id })
			.federation.post(body(idp.origin, { clientId: 'client-b' }), {
				headers: { cookie }
			});

		const providersA = (await getBucketStore().find(a._id))?.federation ?? [];
		const providersB = (await getBucketStore().find(b._id))?.federation ?? [];
		// Same upstream, different applications: tenant isolation is total.
		expect(providersA[0]?.clientId).toBe('client-a');
		expect(providersB[0]?.clientId).toBe('client-b');
	});

	it('refuses provider writes to the reserved admin bucket', async () => {
		const { cookie } = await cookieFor(['super_admin']);
		const idp = await idpStub('https://idp-admin-reserved.test');

		const res = await client.admin.api
			.buckets({ id: ADMIN_BUCKET_ID })
			.federation.post(body(idp.origin), { headers: { cookie } });

		/*
		 * Inherited from `loadBucketForEdit`, not written in this handler. Pinned because
		 * `resolveBucketForClient` maps the reserved console client straight to this bucket, so every /ui
		 * surface is operator-reachable unless something says otherwise.
		 */
		expect(res.status).toBe(403);
	});

	it('refuses a caller who does not manage the bucket', async () => {
		const { cookie } = await cookieFor(['project_admin']);
		const idp = await idpStub('https://idp-admin-outsider.test');
		const bucket = await getBucketStore().create({
			name: 'someone-elses',
			ownerGroupId: 'a-group-nobody-here-belongs-to'
		});

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.federation.post(body(idp.origin), { headers: { cookie } });

		expect(res.status).toBe(403);
	});
});

describe("an account's upstream identities", () => {
	beforeEach(async () => {
		resetAdminMemoryStores();
		await ensureAdminSeed();
	});

	afterEach(() => {
		mock.restore();
	});

	async function seedLinkedUser(bucketId: string) {
		const store = getUserStore(bucketId);
		const user = await store.create('linked@acme.test', 'hash', [], true);
		await store.update(user._id, {
			federated: [
				{
					providerId: 'acme-sso',
					sub: 'upstream-subject-1',
					linkedAt: new Date()
				}
			]
		});
		return user;
	}

	it('lists which providers an account is linked to', async () => {
		const { cookie } = await cookieFor(['super_admin']);
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'b'
		});
		const user = await seedLinkedUser(bucket._id);

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.users({ uid: user._id })
			.identities.get({ headers: { cookie } });

		// Through `unknown`: the typed client's union includes the admin error body, which does not overlap.
		const links = res.data as unknown as Record<string, unknown>[];
		expect(links).toHaveLength(1);
		expect(links[0]?.providerId).toBe('acme-sso');
		expect(links[0]?.sub).toBe('upstream-subject-1');
		expect(links[0]?.linkedAt).toBeDefined();
	});

	it('severs a link, records it with the bucket as scope, and leaves the account', async () => {
		const { cookie } = await cookieFor(['super_admin']);
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'b'
		});
		const user = await seedLinkedUser(bucket._id);

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.users({ uid: user._id })
			.identities({ providerId: 'acme-sso' })
			.delete(undefined, { headers: { cookie } });

		expect(res.status).toBe(200);
		// The link is gone; the account is not.
		const reloaded = await getUserStore(bucket._id).find(user._id);
		expect(reloaded?.federated).toEqual([]);
		expect(reloaded?.email).toBe('linked@acme.test');

		const { entries } = await adminAuditStore.list({
			action: 'federation.identity.delete',
			targetId: user._id
		});
		expect(entries).toHaveLength(1);
		expect(entries[0]?.targetId).toBe(user._id);
		// Without the bucket, a bare per-bucket user id resolves to nobody.
		expect(entries[0]?.targetScope).toBe(bucket._id);
	});

	it('answers 404 for a link the account does not hold', async () => {
		const { cookie } = await cookieFor(['super_admin']);
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'b'
		});
		const user = await seedLinkedUser(bucket._id);

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.users({ uid: user._id })
			.identities({ providerId: 'never-linked' })
			.delete(undefined, { headers: { cookie } });

		expect(res.status).toBe(404);
		// And nothing was recorded for a severance that did not happen.
		const { entries } = await adminAuditStore.list({
			action: 'federation.identity.delete',
			targetId: user._id
		});
		expect(entries).toEqual([]);
	});

	it('refuses a caller who does not manage the bucket', async () => {
		const { cookie } = await cookieFor(['project_admin']);
		const bucket = await getBucketStore().create({
			name: 'someone-elses',
			ownerGroupId: 'a-group-nobody-here-belongs-to'
		});
		const user = await seedLinkedUser(bucket._id);

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.users({ uid: user._id })
			.identities.get({ headers: { cookie } });

		expect(res.status).toBe(403);
	});
});
