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

	/*
	 * CORS origins. Validated in the handler rather than by the body schema so a rejection returns the
	 * admin_error shape and can name the offending value — a list that looks right but grants nothing is
	 * the failure mode worth spending a message on.
	 */
	describe('corsOrigins', () => {
		it('accepts origins on create and returns them', async () => {
			const { cookie } = await sessionCookieFor(['super_admin']);
			const created = await client.admin.api.projects.post(
				{
					name: 'Browser app',
					slug: `browser-${Math.random().toString(36).slice(2)}`,
					corsOrigins: ['https://app.example.com']
				},
				{ headers: { cookie } }
			);

			expect(created.status).toBe(201);
			expect((created.data as Project).corsOrigins).toEqual([
				'https://app.example.com'
			]);
		});

		it('defaults to an empty list when omitted', async () => {
			const { cookie } = await sessionCookieFor(['super_admin']);
			const created = await client.admin.api.projects.post(
				{
					name: 'No origins',
					slug: `none-${Math.random().toString(36).slice(2)}`
				},
				{ headers: { cookie } }
			);

			expect((created.data as Project).corsOrigins).toEqual([]);
		});

		it('replaces the list on patch, and clears it with an empty array', async () => {
			const { cookie } = await sessionCookieFor(['super_admin']);
			const project = await getProjectStore().create({
				name: 'Patch me',
				slug: `patch-${Math.random().toString(36).slice(2)}`,
				corsOrigins: ['https://old.example.com']
			});

			const replaced = await client.admin.api
				.projects({ id: project._id })
				.patch(
					{ corsOrigins: ['https://new.example.com'] },
					{ headers: { cookie } }
				);
			expect(replaced.status).toBe(200);
			expect((replaced.data as Project).corsOrigins).toEqual([
				'https://new.example.com'
			]);

			const cleared = await client.admin.api
				.projects({ id: project._id })
				.patch({ corsOrigins: [] }, { headers: { cookie } });
			expect((cleared.data as Project).corsOrigins).toEqual([]);
		});

		it('leaves the list untouched when the key is omitted', async () => {
			const { cookie } = await sessionCookieFor(['super_admin']);
			const project = await getProjectStore().create({
				name: 'Rename only',
				slug: `rename-${Math.random().toString(36).slice(2)}`,
				corsOrigins: ['https://keep.example.com']
			});

			const renamed = await client.admin.api
				.projects({ id: project._id })
				.patch({ name: 'Renamed' }, { headers: { cookie } });

			expect((renamed.data as Project).corsOrigins).toEqual([
				'https://keep.example.com'
			]);
		});

		it('normalizes host case and collapses duplicates', async () => {
			const { cookie } = await sessionCookieFor(['super_admin']);
			const created = await client.admin.api.projects.post(
				{
					name: 'Normalize',
					slug: `norm-${Math.random().toString(36).slice(2)}`,
					corsOrigins: ['https://APP.Example.com', 'https://app.example.com']
				},
				{ headers: { cookie } }
			);

			expect((created.data as Project).corsOrigins).toEqual([
				'https://app.example.com'
			]);
		});

		it.each([
			['https://app.example.com/', 'a trailing slash'],
			['https://app.example.com/cb', 'a path'],
			['https://app.example.com:443', 'a written default port'],
			['ftp://app.example.com', 'a non-web scheme'],
			['*', 'the any-origin wildcard'],
			['https://*.example.com', 'a wildcard subdomain'],
			['null', 'the null origin'],
			['app.example.com', 'no scheme'],
			['', 'the empty string']
		])('rejects %s (%s) and names the value', async (origin) => {
			const { cookie } = await sessionCookieFor(['super_admin']);
			const project = await getProjectStore().create({
				name: 'Guarded',
				slug: `guard-${Math.random().toString(36).slice(2)}`,
				corsOrigins: ['https://kept.example.com']
			});

			const res = await client.admin.api
				.projects({ id: project._id })
				.patch({ corsOrigins: [origin] }, { headers: { cookie } });

			expect(res.status).toBe(400);
			expect(res.error?.value).toMatchObject({ error: 'admin_error' });
			expect((res.error?.value as { message: string }).message).toContain(
				JSON.stringify(origin)
			);
			// All-or-nothing: the stored list must be exactly as it was.
			expect((await getProjectStore().find(project._id))?.corsOrigins).toEqual([
				'https://kept.example.com'
			]);
		});

		it('rejects the whole list when only one entry is invalid', async () => {
			const { cookie } = await sessionCookieFor(['super_admin']);
			const project = await getProjectStore().create({
				name: 'Partial',
				slug: `partial-${Math.random().toString(36).slice(2)}`
			});

			const res = await client.admin.api
				.projects({ id: project._id })
				.patch(
					{
						corsOrigins: [
							'https://good.example.com',
							'https://bad.example.com/'
						]
					},
					{ headers: { cookie } }
				);

			expect(res.status).toBe(400);
			expect((await getProjectStore().find(project._id))?.corsOrigins).toEqual(
				[]
			);
		});

		it('refuses an unauthenticated caller', async () => {
			const project = await getProjectStore().create({
				name: 'Anon',
				slug: `anon-${Math.random().toString(36).slice(2)}`
			});

			const res = await client.admin.api
				.projects({ id: project._id })
				.patch({ corsOrigins: ['https://app.example.com'] });

			expect(res.status).toBe(401);
		});

		it('refuses a project_admin who does not manage the project', async () => {
			const pa = await sessionCookieFor(['project_admin']);
			const project = await getProjectStore().create({
				name: 'Foreign',
				slug: `foreign-${Math.random().toString(36).slice(2)}`,
				managedBy: ['someone-else']
			});

			const res = await client.admin.api
				.projects({ id: project._id })
				.patch(
					{ corsOrigins: ['https://app.example.com'] },
					{ headers: { cookie: pa.cookie } }
				);

			expect(res.status).toBe(403);
		});

		it('lets a project_admin who manages the project set origins', async () => {
			const pa = await sessionCookieFor(['project_admin']);
			const project = await getProjectStore().create({
				name: 'Mine',
				slug: `mine-${Math.random().toString(36).slice(2)}`,
				managedBy: [pa.userId]
			});

			const res = await client.admin.api
				.projects({ id: project._id })
				.patch(
					{ corsOrigins: ['https://app.example.com'] },
					{ headers: { cookie: pa.cookie } }
				);

			expect(res.status).toBe(200);
		});

		// The admin project is refused before validation runs, so the guard cannot be probed by
		// submitting a deliberately invalid origin to it.
		it('refuses the admin project even for a super_admin', async () => {
			const { cookie } = await sessionCookieFor(['super_admin']);

			const res = await client.admin.api
				.projects({ id: ADMIN_PROJECT_ID })
				.patch(
					{ corsOrigins: ['https://app.example.com'] },
					{ headers: { cookie } }
				);

			expect(res.status).toBe(403);
			expect((res.error?.value as { message: string }).message).toBe(
				'cannot modify admin project'
			);
		});
	});
});
