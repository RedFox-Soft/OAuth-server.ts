import { beforeAll, describe, expect, it } from 'bun:test';
import { Elysia } from 'elysia';

import bootstrap from '../test_helper.ts';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { bucketRoutes } from 'lib/admin/buckets/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { getBucketKeysStore, getBucketStore } from 'lib/adapters/index.ts';
import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { decode } from 'lib/helpers/jwt.ts';
import { sessionFor } from '../admin_session.ts';
import { addresses, machineToken, tenant } from './tenants.ts';
import { createAdministrator, type AdminKind } from '../administrators.ts';

const admin = new Elysia({ normalize: false })
	.use(resolveAdmin)
	.use(bucketRoutes);

async function cookieFor(kind: AdminKind) {
	const user = await createAdministrator(
		kind,
		`first-${kind}-${Math.random()}@x.io`
	);
	return `${ADMIN_SESSION_COOKIE}=${(await sessionFor(user))._id}`;
}

function send(method: string, path: string, cookie: string, body: unknown) {
	return admin.handle(
		new Request(`http://e.ly${path}`, {
			method,
			headers: { 'content-type': 'application/json', cookie },
			body: JSON.stringify(body)
		})
	);
}

async function kidsOf(bucketId: string) {
	return (await getBucketKeysStore().listByBucket(bucketId)).map((k) => k.kid);
}

const { slug, pathOrigin, pathClient } = addresses('first');

/**
 * @proves An addressable bucket has a signing key of its own from the moment it can sign — created
 * with the bucket, on first use for a bucket that predates bucket keys, or when a legacy bucket gains
 * an address — exactly one however many requests race for it, and kept across a change of address.
 */
describe('an addressable bucket without keys of its own', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'bucket_keys' });
		await ensureAdminSeed();
		forgetBucketAddresses();
	});

	it('signs with a key of its own on first use', async () => {
		const bucketId = await tenant({ slug }, pathClient);

		const token = await machineToken(pathOrigin, pathClient);

		expect(await kidsOf(bucketId)).toEqual([String(decode(token).header.kid)]);
	});

	it('creates exactly one key when two first uses race', async () => {
		const bucket = await getBucketStore().create({
			ownerGroupId: 'unassigned',
			name: 'Racing',
			slug: `racing${Math.random().toString(36).slice(2, 8)}`
		});
		forgetBucketAddresses();
		const { keysFor } = await import('lib/keys/issuer_keys.ts');

		await Promise.all([keysFor(bucket), keysFor(bucket), keysFor(bucket)]);

		expect(await kidsOf(bucket._id)).toHaveLength(1);
	});

	it('has its key before it issues anything when created through the console', async () => {
		const cookie = await cookieFor('plain');

		const res = await send('POST', '/admin/api/buckets', cookie, {
			name: 'Console made',
			slug: `console${Math.random().toString(36).slice(2, 8)}`
		});

		expect(res.status).toBe(201);
		const { _id } = (await res.json()) as { _id: string };
		expect(await kidsOf(_id)).toHaveLength(1);
	});

	it('has a key of its own once a legacy bucket gains an address', async () => {
		const cookie = await cookieFor('super');
		const legacy = await getBucketStore().create({
			ownerGroupId: 'unassigned',
			name: 'Legacy'
		});

		const res = await send(
			'POST',
			`/admin/api/buckets/${legacy._id}/address`,
			cookie,
			{
				slug: `legacy${Math.random().toString(36).slice(2, 8)}`,
				confirm: true
			}
		);

		expect(res.status).toBe(200);
		expect(await kidsOf(legacy._id)).toHaveLength(1);
	});

	it('keeps its keys when its address changes', async () => {
		const cookie = await cookieFor('super');
		const bucket = await getBucketStore().create({
			ownerGroupId: 'unassigned',
			name: 'Moving keys',
			slug: `movekeys${Math.random().toString(36).slice(2, 8)}`
		});
		const { keysFor } = await import('lib/keys/issuer_keys.ts');
		await keysFor(bucket);
		const before = await kidsOf(bucket._id);

		await send('POST', `/admin/api/buckets/${bucket._id}/address`, cookie, {
			slug: `moved${Math.random().toString(36).slice(2, 8)}`,
			confirm: true
		});

		expect(await kidsOf(bucket._id)).toEqual(before);
	});
});
