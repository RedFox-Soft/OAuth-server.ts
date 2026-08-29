import { describe, it, expect, beforeEach, afterEach, spyOn } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { projectRoutes } from 'lib/admin/projects/routes.ts';
import { bucketRoutes } from 'lib/admin/buckets/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminAuditStore,
	adminSessionStore,
	getUserStore,
	getProjectStore,
	getBucketStore
} from 'lib/adapters/index.ts';
import {
	ADMIN_BUCKET_ID,
	ADMIN_SESSION_COOKIE,
	UNASSIGNED_GROUP_ID
} from 'lib/admin/consts.ts';
import { sessionFor } from '../admin_session.ts';

/*
 * What an operator sees when the trail itself refuses a write, and what the deployment does about it.
 *
 * The audit entry precedes the mutation, so a refused write must abort the request — otherwise the one
 * guarantee the trail offers (nothing changes without a record) is decorative. Two things are asserted
 * beyond the status: the change did NOT take effect, and the failure was logged. A trail that has
 * stopped accepting entries is otherwise invisible until someone goes looking for records that were
 * never written, which is the failure mode with the longest gap between cause and discovery.
 *
 * One creating, one updating and one deleting operation, because the three differ in where the id comes
 * from and therefore in how much has already happened by the time the write is attempted.
 */
const app = new Elysia().use(resolveAdmin).use(projectRoutes).use(bucketRoutes);

const client = treaty(app);

let seq = 0;
const unique = (prefix: string) => `${prefix}-${Date.now()}-${(seq += 1)}`;

async function superCookie() {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`${unique('super')}@x.io`,
		'hash',
		['super_admin']
	);
	const session = await sessionFor(user);
	return `${ADMIN_SESSION_COOKIE}=${session._id}`;
}

interface AdminErrorBody {
	error: string;
	message: string;
}

describe('admin audit write failure', () => {
	let logged: unknown[][];

	beforeEach(async () => {
		await ensureAdminSeed();
		// Spies live in beforeEach, not beforeAll: mock.restore() in another suite's afterEach clears
		// anything set once at file scope.
		spyOn(adminAuditStore, 'record').mockImplementation(() => {
			throw new Error('trail is unavailable');
		});
		logged = [];
		spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
			logged.push(args);
		});
	});

	afterEach(() => {
		// Not mock.restore(): that would also clear the console spy other suites rely on being absent.
		(
			adminAuditStore.record as unknown as { mockRestore(): void }
		).mockRestore();
		(console.error as unknown as { mockRestore(): void }).mockRestore();
	});

	function expectAuditFailure(status: number, body: unknown) {
		expect(status).toBe(500);
		const parsed = body as AdminErrorBody;
		expect(parsed.error).toBe('admin_error');
		// Distinguishable from any other failure, and it states the outcome the operator needs.
		expect(parsed.message).toContain('audit unavailable');
		expect(parsed.message).toContain('not applied');
		expect(
			logged.some((args) =>
				args.some((arg) => String(arg).includes('admin audit write failed'))
			)
		).toBeTrue();
	}

	it('refuses a creation and creates nothing', async () => {
		const cookie = await superCookie();
		const slug = unique('never');
		const before = (await getProjectStore().list()).length;

		const res = await client.admin.api.projects.post(
			{ name: 'Never created', slug },
			{ headers: { cookie } }
		);

		expectAuditFailure(res.status, res.error?.value ?? res.data);
		expect(await getProjectStore().findBySlug(slug)).toBeNull();
		expect((await getProjectStore().list()).length).toBe(before);
	});

	it('refuses an update and changes nothing', async () => {
		const cookie = await superCookie();
		const project = await getProjectStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Original',
			slug: unique('p')
		});

		const res = await client.admin.api
			.projects({ id: project._id })
			.patch({ name: 'Renamed' }, { headers: { cookie } });

		expectAuditFailure(res.status, res.error?.value ?? res.data);
		expect((await getProjectStore().find(project._id))?.name).toBe('Original');
	});

	it('refuses a deletion and deletes nothing', async () => {
		const cookie = await superCookie();
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Survives'
		});

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.delete(undefined, { headers: { cookie } });

		expectAuditFailure(res.status, res.error?.value ?? res.data);
		expect(await getBucketStore().find(bucket._id)).not.toBeNull();
	});
});
