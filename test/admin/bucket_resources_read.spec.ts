import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { Type } from '@sinclair/typebox';

import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { bucketRoutes } from 'lib/admin/buckets/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	getBucketStore,
	getProjectStore,
	getProtectedResourceStore
} from 'lib/adapters/index.ts';
import { ROOT_NAMESPACE } from 'lib/resources/namespace.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { shaped } from 'test/shape.ts';
import { createAdministrator } from '../administrators.ts';
import {
	bucketWithProjects,
	cookieFor,
	regularGroup
} from './ownership_fixtures.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';

const app = new Elysia({ normalize: false })
	.use(resolveAdmin)
	.use(bucketRoutes);

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
			projectId: Type.String(),
			projectName: Type.String()
		})
	)
});

function identifier(label: string): string {
	return `https://${label}-${nanoid()
		.toLowerCase()
		.replace(/[^a-z0-9]/g, '')
		.slice(0, 8)}.example.com/`;
}

async function declare(namespace: string, projectId: string, id: string) {
	await getProtectedResourceStore().create({
		namespace,
		identifier: id,
		projectId,
		name: `Resource ${id}`,
		scopes: ['read']
	});
}

/**
 * @proves A bucket's resource namespace lists every declaration its projects make in it, each with the
 * project that makes it — and a bucket served at the root lists only its own projects' declarations, never
 * the rest of the shared root, and nothing to a caller who cannot read the bucket.
 */
describe("a bucket's resource namespace", () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('lists the declarations of every project using an addressed bucket, with their projects, by identifier', async () => {
		const owner = await createAdministrator('plain');
		const team = await regularGroup([owner]);
		const {
			bucket,
			projects: [first, second]
		} = await bucketWithProjects(team._id, 2);
		const b = identifier('b');
		const a = identifier('a');
		await declare(bucket._id, first._id, b);
		await declare(bucket._id, second._id, a);

		const res = await read(bucket._id, await cookieFor(owner));

		expect(res.status).toBe(200);
		const listed = shaped(Namespace, res.body);
		expect(listed.namespace).toBe('bucket');
		expect(listed.resources.map((r) => [r.identifier, r.projectName])).toEqual([
			[a, second.name],
			[b, first.name]
		]);
	});

	it("lists only its own projects' declarations for a bucket served at the root", async () => {
		const owner = await createAdministrator('plain');
		const team = await regularGroup([owner]);
		const legacy = await getBucketStore().create({
			name: 'Legacy',
			ownerGroupId: team._id
		});
		const own = await getProjectStore().create({
			name: 'Own',
			slug: `own-${nanoid()
				.toLowerCase()
				.replace(/[^a-z0-9]/g, '')}`,
			ownerGroupId: team._id,
			bucketId: legacy._id
		});
		const stranger = await getProjectStore().create({
			bucketId: DEFAULT_BUCKET_ID,
			name: 'Stranger',
			slug: `str-${nanoid()
				.toLowerCase()
				.replace(/[^a-z0-9]/g, '')}`,
			ownerGroupId: `group-${nanoid()}`
		});
		const mine = identifier('mine');
		await declare(ROOT_NAMESPACE, own._id, mine);
		await declare(ROOT_NAMESPACE, stranger._id, identifier('theirs'));

		const res = await read(legacy._id, await cookieFor(owner));

		const listed = shaped(Namespace, res.body);
		expect(listed.namespace).toBe('root');
		expect(listed.resources.map((r) => r.identifier)).toEqual([mine]);
	});

	it('refuses a caller who cannot read the bucket', async () => {
		const owner = await createAdministrator('plain');
		const team = await regularGroup([owner]);
		const {
			bucket,
			projects: [project]
		} = await bucketWithProjects(team._id, 1);
		await declare(bucket._id, project._id, identifier('hidden'));
		const outsider = await createAdministrator('plain');

		const res = await read(bucket._id, await cookieFor(outsider));

		expect([403, 404]).toContain(res.status);
		expect(JSON.stringify(res.body)).not.toContain('hidden');
	});
});
