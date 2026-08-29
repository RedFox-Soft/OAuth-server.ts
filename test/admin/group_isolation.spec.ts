import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { projectRoutes } from 'lib/admin/projects/routes.ts';
import { bucketRoutes } from 'lib/admin/buckets/routes.ts';
import { groupRoutes } from 'lib/admin/groups/routes.ts';
import { scopeRoutes } from 'lib/admin/scope/routes.ts';
import { adminUserRoutes } from 'lib/admin/users/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getUserStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import type { Project, UserBucket } from 'lib/adapters/types.ts';
import { sessionFor, personalGroupId } from '../admin_session.ts';

/*
 * The suite that has to hold for this feature to be safe to ship.
 *
 * Every other spec asks whether an administrator can do what they should. This one asks the opposite
 * question — whether anything at all belonging to another tenant is observable — because that is the
 * failure moving ownership from a per-container list to a group can introduce, and it is the failure
 * nobody notices until it is somebody else's data.
 *
 * "Observable" is deliberately broad: not only a 200 that should have been a 403, but a listing that
 * includes a foreign id, an error message that names one, or a refusal that distinguishes "exists but
 * forbidden" from "does not exist".
 */

const app = new Elysia()
	.use(resolveAdmin)
	.use(projectRoutes)
	.use(bucketRoutes)
	.use(groupRoutes)
	.use(scopeRoutes)
	.use(adminUserRoutes);
const client = treaty(app);

/*
 * A slug the route will accept. `Math.random()` alone yields a dot, which `^[a-z0-9-]+$` refuses —
 * invisible in specs that seed through the store, because the store does not validate.
 */
function slug(prefix: string): string {
	return `${prefix}-${Math.random().toString(36).slice(2)}`;
}

async function tenant(label: string) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`${label}-${Math.random()}@x.io`,
		'hash',
		['project_admin']
	);
	const session = await sessionFor(user);
	return {
		userId: user._id,
		cookie: `${ADMIN_SESSION_COOKIE}=${session._id}`,
		groupId: await personalGroupId(user._id)
	};
}

describe('group isolation', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('creates a project into the creator’s own group, reachable by nobody else', async () => {
		const a = await tenant('a');
		const b = await tenant('b');

		const created = await client.admin.api.projects.post(
			{ name: 'A project', slug: slug('a') },
			{ headers: { cookie: a.cookie } }
		);
		expect(created.status).toBe(201);
		const project = created.data as Project;
		expect(project.ownerGroupId).toBe(a.groupId);

		// B's listing must not mention it, and B's read of it must be refused.
		const bList = await client.admin.api.projects.get({
			headers: { cookie: b.cookie }
		});
		expect((bList.data as Project[]).map((p) => p._id)).not.toContain(
			project._id
		);

		const bRead = await client.admin.api
			.projects({ id: project._id })
			.get({ headers: { cookie: b.cookie } });
		expect(bRead.status).toBe(403);
	});

	it('refuses a foreign project identically to one that does not exist', async () => {
		const a = await tenant('a');
		const b = await tenant('b');

		const created = await client.admin.api.projects.post(
			{ name: 'A project', slug: slug('a') },
			{ headers: { cookie: a.cookie } }
		);
		const project = created.data as Project;

		const foreign = await client.admin.api
			.projects({ id: project._id })
			.get({ headers: { cookie: b.cookie } });
		const absent = await client.admin.api
			.projects({ id: 'does-not-exist-at-all' })
			.get({ headers: { cookie: b.cookie } });

		/*
		 * Currently these differ — 403 for a project that exists, 404 for one that does not — which tells
		 * an outsider whether an id is real. Asserted as the property rather than the present behaviour,
		 * because probing for existence is exactly what tenant isolation must not allow.
		 */
		expect(foreign.status).toBe(absent.status);
	});

	it('keeps a foreign bucket out of both the listing and the detail read', async () => {
		const a = await tenant('a');
		const b = await tenant('b');

		const created = await client.admin.api.buckets.post(
			{ name: 'A users' },
			{ headers: { cookie: a.cookie } }
		);
		expect(created.status).toBe(201);
		const bucket = created.data as UserBucket;
		expect(bucket.ownerGroupId).toBe(a.groupId);

		const bList = await client.admin.api.buckets.get({
			headers: { cookie: b.cookie }
		});
		expect((bList.data as UserBucket[]).map((x) => x._id)).not.toContain(
			bucket._id
		);

		const bRead = await client.admin.api
			.buckets({ id: bucket._id })
			.get({ headers: { cookie: b.cookie } });
		expect(bRead.status).toBe(403);
	});

	it('refuses to back one group’s project with another group’s bucket', async () => {
		const a = await tenant('a');
		const b = await tenant('b');

		const projectRes = await client.admin.api.projects.post(
			{ name: 'A project', slug: slug('a') },
			{ headers: { cookie: a.cookie } }
		);
		const project = projectRes.data as Project;

		const bucketRes = await client.admin.api.buckets.post(
			{ name: 'B users' },
			{ headers: { cookie: b.cookie } }
		);
		const bucket = bucketRes.data as UserBucket;

		/*
		 * A owns the project, B owns the bucket, and neither may join them — otherwise A's clients would
		 * authenticate against a pool of end-users administered by somebody with no access to A at all.
		 */
		const byA = await client.admin.api
			.projects({ id: project._id })
			.bucket.put({ bucketId: bucket._id }, { headers: { cookie: a.cookie } });
		expect(byA.status).toBe(403);

		const byB = await client.admin.api
			.projects({ id: project._id })
			.bucket.put({ bucketId: bucket._id }, { headers: { cookie: b.cookie } });
		expect(byB.status).toBe(403);
	});

	it('lets a group back its own project with its own bucket', async () => {
		const a = await tenant('a');

		const projectRes = await client.admin.api.projects.post(
			{ name: 'A project', slug: slug('a') },
			{ headers: { cookie: a.cookie } }
		);
		const project = projectRes.data as Project;

		const bucketRes = await client.admin.api.buckets.post(
			{ name: 'A users' },
			{ headers: { cookie: a.cookie } }
		);
		const bucket = bucketRes.data as UserBucket;

		const assigned = await client.admin.api
			.projects({ id: project._id })
			.bucket.put({ bucketId: bucket._id }, { headers: { cookie: a.cookie } });
		expect(assigned.status).toBe(200);
	});

	it('names no foreign id in a refusal body', async () => {
		const a = await tenant('a');
		const b = await tenant('b');

		const created = await client.admin.api.projects.post(
			{ name: 'A project', slug: slug('a') },
			{ headers: { cookie: a.cookie } }
		);
		const project = created.data as Project;

		const denied = await client.admin.api
			.projects({ id: project._id })
			.patch({ name: 'Renamed' }, { headers: { cookie: b.cookie } });

		expect(denied.status).toBe(403);
		// The refusal may say access was denied; it must not echo back anything about the target.
		expect(JSON.stringify(denied.error?.value ?? denied.data)).not.toContain(
			'A project'
		);
	});

	it('does not let a project administrator reach the reserved admin containers', async () => {
		const a = await tenant('a');

		const adminProject = await client.admin.api
			.projects({ id: 'admin' })
			.get({ headers: { cookie: a.cookie } });
		expect(adminProject.status).toBe(403);

		const adminBucket = await client.admin.api
			.buckets({ id: ADMIN_BUCKET_ID })
			.get({ headers: { cookie: a.cookie } });
		expect(adminBucket.status).toBe(403);
	});

	/*
	 * FR-026: a project administrator must not be able to widen their own access. Structurally this
	 * falls out of the role gates and the membership check, but "it follows from the design" is exactly
	 * the claim that stops being true after a refactor — so each route is asked directly.
	 */
	describe('no self-escalation', () => {
		it('cannot grant itself the super-administrator role', async () => {
			const a = await tenant('a');

			const res = await client.admin.api
				.admins({ id: a.userId })
				.patch(
					{ roles: ['super_admin', 'project_admin'] },
					{ headers: { cookie: a.cookie } }
				);
			expect(res.status).toBe(403);
		});

		it('cannot switch into a group it does not belong to', async () => {
			const a = await tenant('a');
			const b = await tenant('b');

			const res = await client.admin.api.scope.put(
				{ groupId: b.groupId },
				{ headers: { cookie: a.cookie } }
			);
			expect(res.status).toBe(403);
		});

		it('cannot add itself to another group', async () => {
			const a = await tenant('a');
			const b = await tenant('b');

			const res = await client.admin.api
				.groups({ id: b.groupId })
				.members.post(
					{ userId: a.userId, role: 'owner' },
					{ headers: { cookie: a.cookie } }
				);
			expect(res.status).toBe(403);
		});

		it('cannot move a container into its own group by updating it', async () => {
			const a = await tenant('a');
			const b = await tenant('b');
			const theirs = (
				await client.admin.api.projects.post(
					{ name: 'Theirs', slug: slug('t') },
					{ headers: { cookie: b.cookie } }
				)
			).data as Project;

			const res = await client.admin.api.projects({ id: theirs._id }).patch(
				// `ownerGroupId` is not in the update body at all; submitted as an unknown field it is
				// either refused or ignored, and either way the project must not move.
				{ ownerGroupId: a.groupId } as never,
				{ headers: { cookie: a.cookie } }
			);
			expect([403, 422]).toContain(res.status);

			const after = await client.admin.api
				.projects({ id: theirs._id })
				.get({ headers: { cookie: b.cookie } });
			expect((after.data as Project).ownerGroupId).toBe(b.groupId);
		});
	});
});
