import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';

import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { bucketRoutes } from 'lib/admin/buckets/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
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
import type { FederationProvider } from 'lib/federation/types.ts';
import { sessionFor } from '../admin_session.ts';

/*
 * A bucket nobody can sign into must not be reachable through the management API.
 *
 * The rule is one shared function called from two directions — this file drives the bucket PATCH; the
 * provider routes drive the other side. Both are tested because two entry points that disagree about whether
 * a bucket is reachable is exactly the state one shared rule exists to prevent.
 */

const app = new Elysia().use(resolveAdmin).use(bucketRoutes);
const client = treaty(app);

async function superCookie() {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`super-${Math.random()}@x.io`,
		'hash',
		['super_admin']
	);
	const session = await sessionFor(user);
	return `${ADMIN_SESSION_COOKIE}=${session._id}`;
}

function provider(
	overrides: Partial<FederationProvider> = {}
): FederationProvider {
	return {
		id: 'acme-sso',
		displayName: 'Acme SSO',
		enabled: true,
		issuer: 'https://idp.example.test',
		clientId: 'client',
		clientSecret: 'secret',
		scopes: ['openid'],
		emailTrusted: false,
		provisioning: 'jit',
		allowedEmailDomains: [],
		emailClaim: 'email',
		...overrides
	};
}

describe('a bucket must keep some way to sign in', () => {
	beforeEach(async () => {
		resetAdminMemoryStores();
		await ensureAdminSeed();
	});

	it('refuses to switch password sign-in off when no provider is enabled', async () => {
		const cookie = await superCookie();
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'no-providers'
		});

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.patch({ passwordLogin: false }, { headers: { cookie } });

		expect(res.status).toBe(409);
		// And nothing changed, so the bucket is still usable.
		expect((await getBucketStore().find(bucket._id))?.passwordLogin).toBe(true);
	});

	it('refuses when the only provider present is disabled', async () => {
		const cookie = await superCookie();
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'disabled-provider',
			federation: [provider({ enabled: false })]
		});

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.patch({ passwordLogin: false }, { headers: { cookie } });

		// A kept-but-disabled provider is not a way in.
		expect(res.status).toBe(409);
	});

	it('allows it once an enabled provider exists', async () => {
		const cookie = await superCookie();
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'federated',
			federation: [provider()]
		});

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.patch({ passwordLogin: false }, { headers: { cookie } });

		expect(res.status).toBe(200);
		expect((await getBucketStore().find(bucket._id))?.passwordLogin).toBe(
			false
		);
	});

	it('lets a federated-only bucket turn password sign-in back on', async () => {
		const cookie = await superCookie();
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'reopening',
			passwordLogin: false,
			federation: [provider()]
		});

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.patch({ passwordLogin: true }, { headers: { cookie } });

		// Opening a door is never a lockout, so nothing guards this direction.
		expect(res.status).toBe(200);
	});

	it('refuses to create a bucket that would be unreachable from birth', async () => {
		const cookie = await superCookie();

		const res = await client.admin.api.buckets.post(
			{ name: 'stillborn', passwordLogin: false },
			{ headers: { cookie } }
		);

		// Providers are added through their own routes, so a new bucket has none — `false` here is always a
		// lockout, and refusing it beats creating something that has to be repaired.
		expect(res.status).toBe(409);
	});

	it('creates a bucket with password sign-in available by default', async () => {
		const cookie = await superCookie();

		const res = await client.admin.api.buckets.post(
			{ name: 'ordinary' },
			{ headers: { cookie } }
		);

		expect(res.status).toBe(201);
		expect((res.data as { passwordLogin?: boolean })?.passwordLogin).toBe(true);
	});

	it('refuses password sign-in changes on the reserved admin bucket', async () => {
		const cookie = await superCookie();

		const res = await client.admin.api
			.buckets({ id: ADMIN_BUCKET_ID })
			.patch({ passwordLogin: false }, { headers: { cookie } });

		/*
		 * 403 from the reserved-bucket guard, not 409 from the lockout rule — the console is a relying party
		 * on this server's own issuer, and a second identity source for operators is a separate decision.
		 * Inherited from loadBucketForEdit rather than written here, and pinned because `resolveBucketForClient`
		 * maps the console client straight to this bucket.
		 */
		expect(res.status).toBe(403);
	});
});
