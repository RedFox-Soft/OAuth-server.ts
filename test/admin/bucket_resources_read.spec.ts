import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { Type } from '@sinclair/typebox';

import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { resourceRoutes } from 'lib/admin/resources/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	getBucketStore,
	getProtectedResourceStore
} from 'lib/adapters/index.ts';
import { ROOT_NAMESPACE } from 'lib/resources/namespace.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { shaped } from 'test/shape.ts';
import { createAdministrator } from '../administrators.ts';
import {
	bucketWithClients,
	cookieFor,
	regularGroup
} from './ownership_fixtures.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';

const app = new Elysia({ normalize: false })
	.use(resolveAdmin)
	.use(resourceRoutes);

async function read(
	bucketId: string,
	cookie: string
): Promise<{ status: number; body: unknown }> {
	const response = await app.handle(
		new Request(`http://e.ly/admin/api/buckets/${bucketId}/resources`, {
			headers: { cookie }
		})
	);
	return { status: response.status, body: await response.json() };
}

const Namespace = Type.Object({
	namespace: Type.Union([Type.Literal('bucket'), Type.Literal('root')]),
	resources: Type.Array(
		Type.Object({
			identifier: Type.String(),
			name: Type.String(),
			bucketId: Type.String()
		})
	)
});

function identifier(label: string): string {
	return `https://${label}-${nanoid()
		.toLowerCase()
		.replace(/[^a-z0-9]/g, '')
		.slice(0, 8)}.example.com/`;
}

async function declare(namespace: string, bucketId: string, id: string) {
	await getProtectedResourceStore().create({
		namespace,
		identifier: id,
		bucketId,
		name: `Resource ${id}`,
		scopes: ['read']
	});
}

/**
 * @proves A bucket's APIs list every declaration the bucket makes, by identifier — and a bucket served at
 * the root lists only its own declarations, never the rest of the shared root, and nothing to a caller who
 * cannot read the bucket.
 */
describe("a bucket's resource namespace", () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('lists every declaration of an addressed bucket, by identifier', async () => {
		const owner = await createAdministrator('plain');
		const team = await regularGroup([owner]);
		const { bucket } = await bucketWithClients(team._id, 0);
		const b = identifier('b');
		const a = identifier('a');
		await declare(bucket._id, bucket._id, b);
		await declare(bucket._id, bucket._id, a);

		const res = await read(bucket._id, await cookieFor(owner));

		expect(res.status).toBe(200);
		const listed = shaped(Namespace, res.body);
		expect(listed.namespace).toBe('bucket');
		expect(listed.resources.map((r) => [r.identifier, r.bucketId])).toEqual([
			[a, bucket._id],
			[b, bucket._id]
		]);
	});

	it('lists only its own declarations for a bucket served at the root', async () => {
		const owner = await createAdministrator('plain');
		const team = await regularGroup([owner]);
		const legacy = await getBucketStore().create({
			name: 'Legacy',
			ownerGroupId: team._id
		});
		const mine = identifier('mine');
		await declare(ROOT_NAMESPACE, legacy._id, mine);
		await declare(ROOT_NAMESPACE, DEFAULT_BUCKET_ID, identifier('theirs'));

		const res = await read(legacy._id, await cookieFor(owner));

		const listed = shaped(Namespace, res.body);
		expect(listed.namespace).toBe('root');
		expect(listed.resources.map((r) => r.identifier)).toEqual([mine]);
	});

	it('refuses a caller who cannot read the bucket', async () => {
		const owner = await createAdministrator('plain');
		const team = await regularGroup([owner]);
		const { bucket } = await bucketWithClients(team._id, 0);
		await declare(bucket._id, bucket._id, identifier('hidden'));
		const outsider = await createAdministrator('plain');

		const res = await read(bucket._id, await cookieFor(outsider));

		expect([403, 404]).toContain(res.status);
		expect(JSON.stringify(res.body)).not.toContain('hidden');
	});
});
