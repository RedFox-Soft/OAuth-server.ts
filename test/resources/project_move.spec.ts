import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';

import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { projectRoutes } from 'lib/admin/projects/routes.ts';
import { bucketRoutes } from 'lib/admin/buckets/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ensurePersonalGroup } from 'lib/admin/groups/personal.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import {
	getBucketStore,
	getProjectStore,
	getProtectedResourceStore
} from 'lib/adapters/index.ts';
import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { ROOT_NAMESPACE } from 'lib/resources/namespace.ts';
import { sessionFor } from '../admin_session.ts';
import { createAdministrator, type AdminKind } from '../administrators.ts';

const app = new Elysia({ normalize: false })
	.use(resolveAdmin)
	.use(projectRoutes)
	.use(bucketRoutes);

const AUDIENCE = 'https://mcp.moving.example/mcp';

async function administrator(kind: AdminKind) {
	const user = await createAdministrator(
		kind,
		`move-${kind}-${Math.random()}@x.io`
	);
	const group = await ensurePersonalGroup(user._id, user.email);
	const session = await sessionFor(user);
	return {
		groupId: group._id,
		cookie: `${ADMIN_SESSION_COOKIE}=${session._id}`
	};
}

async function bucket(ownerGroupId: string, slug?: string) {
	return getBucketStore().create({
		ownerGroupId,
		name: `bucket ${slug ?? 'unaddressed'}`,
		...(slug ? { slug } : {})
	});
}

async function projectIn(ownerGroupId: string, bucketId: string | null) {
	return getProjectStore().create({
		ownerGroupId,
		name: 'Moving',
		slug: `moving-${Math.random().toString(36).slice(2)}`,
		bucketId
	});
}

async function declare(namespace: string, projectId: string) {
	await getProtectedResourceStore().create({
		namespace,
		identifier: AUDIENCE,
		projectId,
		name: 'Moving MCP',
		scopes: ['mcp:tools-basic']
	});
}

function send(method: string, path: string, cookie: string, body?: unknown) {
	return app.handle(
		new Request(`http://e.ly${path}`, {
			method,
			headers: { 'content-type': 'application/json', cookie },
			body: body === undefined ? undefined : JSON.stringify(body)
		})
	);
}

function unique(prefix: string) {
	return `${prefix}${Math.random().toString(36).slice(2, 8)}`;
}

/**
 * @proves A project's declared resources follow it into the namespace of the bucket it moves to, all
 * of them or none, and never into the shared root namespace on a group administrator's say-so.
 */
describe('a project with declarations changing bucket', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
		forgetBucketAddresses();
		const store = getProtectedResourceStore();
		for (const resource of await store.list()) {
			await store.destroy(resource.namespace, resource.identifier);
		}
	});

	it('is refused, and nothing moves, when an identifier is taken in the target bucket', async () => {
		const { cookie, groupId } = await administrator('plain');
		const from = await bucket(groupId, unique('from'));
		const to = await bucket(groupId, unique('to'));
		const moving = await projectIn(groupId, from._id);
		const resident = await projectIn(groupId, to._id);
		await declare(from._id, moving._id);
		await declare(to._id, resident._id);

		const res = await send(
			'PUT',
			`/admin/api/projects/${moving._id}/bucket`,
			cookie,
			{ bucketId: to._id }
		);

		expect(res.status).toBe(409);
		expect(((await res.json()) as { conflicts?: string[] }).conflicts).toEqual([
			AUDIENCE
		]);
		expect((await getProjectStore().find(moving._id))?.bucketId).toBe(from._id);
		expect(
			(await getProtectedResourceStore().find(from._id, AUDIENCE))?.projectId
		).toBe(moving._id);
		expect(
			(await getProtectedResourceStore().find(to._id, AUDIENCE))?.projectId
		).toBe(resident._id);
	});

	it('refuses a group administrator clearing the bucket of a project that declares resources', async () => {
		const { cookie, groupId } = await administrator('plain');
		const from = await bucket(groupId, unique('clear'));
		const project = await projectIn(groupId, from._id);
		await declare(from._id, project._id);

		const res = await send(
			'DELETE',
			`/admin/api/projects/${project._id}/bucket`,
			cookie
		);

		expect(res.status).toBe(403);
		expect((await getProjectStore().find(project._id))?.bucketId).toBe(
			from._id
		);
		expect(
			await getProtectedResourceStore().find(ROOT_NAMESPACE, AUDIENCE)
		).toBeNull();
	});

	it('moves the declarations with the project into its new bucket', async () => {
		const { cookie, groupId } = await administrator('plain');
		const from = await bucket(groupId, unique('old'));
		const to = await bucket(groupId, unique('new'));
		const project = await projectIn(groupId, from._id);
		await declare(from._id, project._id);

		const res = await send(
			'PUT',
			`/admin/api/projects/${project._id}/bucket`,
			cookie,
			{ bucketId: to._id }
		);

		expect(res.status).toBe(200);
		expect(
			await getProtectedResourceStore().find(from._id, AUDIENCE)
		).toBeNull();
		expect(
			(await getProtectedResourceStore().find(to._id, AUDIENCE))?.projectId
		).toBe(project._id);
	});

	it('moves a legacy bucket declarations out of the root when it gains an address', async () => {
		const { cookie, groupId } = await administrator('super');
		const legacy = await bucket(groupId);
		const project = await projectIn(groupId, legacy._id);
		await declare(ROOT_NAMESPACE, project._id);

		const res = await send(
			'POST',
			`/admin/api/buckets/${legacy._id}/address`,
			cookie,
			{ slug: unique('legacy'), confirm: true }
		);

		expect(res.status).toBe(200);
		expect(
			await getProtectedResourceStore().find(ROOT_NAMESPACE, AUDIENCE)
		).toBeNull();
		expect(
			(await getProtectedResourceStore().find(legacy._id, AUDIENCE))?.projectId
		).toBe(project._id);
	});
});
