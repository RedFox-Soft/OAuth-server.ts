import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { projectRoutes } from 'lib/admin/projects/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminSessionStore,
	getUserStore,
	getProjectStore,
	getBucketStore
} from 'lib/adapters/index.ts';
import {
	ADMIN_BUCKET_ID,
	ADMIN_PROJECT_ID,
	ADMIN_SESSION_COOKIE
} from 'lib/admin/consts.ts';
import type { Project } from 'lib/adapters/types.ts';

const app = new Elysia().use(resolveAdmin).use(projectRoutes);
const client = treaty(app);

async function sessionCookieFor(roles: string[]) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`${roles.join('-')}-${Math.random()}@x.io`,
		'hash',
		roles
	);
	const s = await adminSessionStore.create({
		userId: user._id,
		bucketId: ADMIN_BUCKET_ID,
		tokens: {},
		ttlSeconds: 60,
		absoluteTtlSeconds: 3600
	});
	return { cookie: `${ADMIN_SESSION_COOKIE}=${s._id}`, userId: user._id };
}

describe('projects API', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('rejects anonymous access with 401', async () => {
		const res = await client.admin.api.projects.get();
		expect(res.status).toBe(401);
	});

	it('super_admin creates and lists projects', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const created = await client.admin.api.projects.post(
			{ name: 'Acme', slug: 'acme' },
			{ headers: { cookie } }
		);
		expect(created.status).toBe(201);
		const list = await client.admin.api.projects.get({ headers: { cookie } });
		const projects = list.data as Project[] | undefined;
		expect(projects?.some((p) => p.slug === 'acme')).toBe(true);
	});

	it('project_admin sees only managed projects and cannot create', async () => {
		const superSession = await sessionCookieFor(['super_admin']);
		const pa = await sessionCookieFor(['project_admin']);
		await client.admin.api.projects.post(
			{ name: 'Mine', slug: 'mine', managedBy: [pa.userId] },
			{ headers: { cookie: superSession.cookie } }
		);
		await client.admin.api.projects.post(
			{ name: 'Other', slug: 'other' },
			{ headers: { cookie: superSession.cookie } }
		);
		const list = await client.admin.api.projects.get({
			headers: { cookie: pa.cookie }
		});
		const projects = list.data as Project[] | undefined;
		expect(projects?.map((p) => p.slug)).toEqual(['mine']);
		const denied = await client.admin.api.projects.post(
			{ name: 'X', slug: 'x' },
			{ headers: { cookie: pa.cookie } }
		);
		expect(denied.status).toBe(403);
	});

	it('never lists the admin project, even for a manager of it', async () => {
		const pa = await sessionCookieFor(['project_admin']);
		await getProjectStore().update(ADMIN_PROJECT_ID, {
			managedBy: [pa.userId]
		});
		const list = await client.admin.api.projects.get({
			headers: { cookie: pa.cookie }
		});
		const projects = list.data as Project[] | undefined;
		expect(
			projects?.some((p) => p.type === 'admin' || p._id === ADMIN_PROJECT_ID)
		).toBe(false);
	});

	it('rejects modifying the admin project even for super_admin', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const res = await client.admin.api
			.projects({ id: ADMIN_PROJECT_ID })
			.patch({ name: 'Hacked' }, { headers: { cookie } });
		expect(res.status).toBe(403);
	});

	it('denies assigning a bucket the project_admin does not manage', async () => {
		const superSession = await sessionCookieFor(['super_admin']);
		const pa = await sessionCookieFor(['project_admin']);
		const proj = await getProjectStore().create({
			name: 'PA Project',
			slug: `pa-${Math.random()}`,
			managedBy: [pa.userId]
		});
		// Bucket managed by someone else — the project_admin must not attach it.
		const bucket = await getBucketStore().create({
			name: 'Foreign bucket',
			managedBy: ['someone-else']
		});
		const denied = await client.admin.api
			.projects({ id: proj._id })
			.bucket.put({ bucketId: bucket._id }, { headers: { cookie: pa.cookie } });
		expect(denied.status).toBe(403);
		// super_admin can assign any bucket.
		const ok = await client.admin.api
			.projects({ id: proj._id })
			.bucket.put(
				{ bucketId: bucket._id },
				{ headers: { cookie: superSession.cookie } }
			);
		expect(ok.status).toBe(200);
	});
});
