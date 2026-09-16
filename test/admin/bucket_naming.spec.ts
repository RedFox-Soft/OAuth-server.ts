import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { bucketRoutes } from 'lib/admin/buckets/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getBucketStore, getUserStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { sessionFor } from '../admin_session.ts';

const app = new Elysia().use(resolveAdmin).use(bucketRoutes);
const client = treaty(app);

async function superCookie() {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`naming-${Math.random()}@x.io`,
		'hash',
		['super_admin']
	);
	const s = await sessionFor(user);
	return `${ADMIN_SESSION_COOKIE}=${s._id}`;
}

function create(cookie: string, slug: string, name = 'Some users') {
	return client.admin.api.buckets.post({ name, slug }, { headers: { cookie } });
}

/**
 * @proves A bucket's address is refused before it can shadow one of this server's own endpoints,
 * collide with another bucket, or be silently moved to an address the operator did not type.
 */
describe('naming a bucket', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('accepts a slug that is free and well formed', async () => {
		const res = await create(await superCookie(), 'acme');

		expect(res.status).toBe(201);
		expect((res.data as { slug?: string } | undefined)?.slug).toBe('acme');
	});

	/*
	 * `auth` stands for the whole reserved set rather than being interesting in itself: it is the
	 * endpoint an operator is likeliest to reach for, and the one whose loss would be hardest to
	 * diagnose — every authorization request in the default bucket would start resolving to a tenant.
	 */
	it('refuses a slug that this server uses for one of its own addresses', async () => {
		const res = await create(await superCookie(), 'auth');

		expect(res.status).toBe(409);
	});

	it('refuses a slug another bucket already holds', async () => {
		const cookie = await superCookie();
		await create(cookie, 'duplicated');

		const res = await create(cookie, 'duplicated', 'Another set of users');

		expect(res.status).toBe(409);
	});

	/*
	 * Refused rather than lowercased. URL paths are case-sensitive and issuer identifiers are compared
	 * by exact string, so normalising would put the bucket at an address the operator never typed and
	 * never learn them the rule.
	 */
	it('refuses a slug that differs from a valid one only by case', async () => {
		const res = await create(await superCookie(), 'Acme');

		expect(res.status).toBe(422);
	});

	it('refuses a slug outside the permitted character set', async () => {
		const cookie = await superCookie();

		for (const slug of ['-acme', 'acme-', 'ac me', 'acmé', 'acme_corp']) {
			const res = await create(cookie, slug, `Users of ${slug}`);
			expect(res.status).toBe(422);
		}
	});

	/*
	 * A bucket's address is fixed once chosen, so an edit that names one changes nothing. Asserted on
	 * the stored slug rather than on a status: the body schema simply has no such field, so the request
	 * is answered without ever reaching a rule that could refuse it by name, and a status assertion
	 * would be proving which layer shrugged rather than that the address held.
	 */
	it('leaves the address of a bucket unchanged when an edit names one', async () => {
		const cookie = await superCookie();
		const created = await create(cookie, 'immutable');
		const id = (created.data as { _id: string })._id;

		await client.admin.api
			.buckets({ id })
			.patch({ name: 'Renamed', slug: 'something-else' } as never, {
				headers: { cookie }
			});

		expect((await getBucketStore().find(id))?.slug).toBe('immutable');
	});
});
