import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { clientRoutes } from 'lib/admin/clients/routes.ts';
import { bucketRoutes } from 'lib/admin/buckets/routes.ts';
import { groupRoutes } from 'lib/admin/groups/routes.ts';
import { scopeRoutes } from 'lib/admin/scope/routes.ts';
import { adminUserRoutes } from 'lib/admin/users/routes.ts';
import { endUserRoutes } from 'lib/admin/users-end/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	ADMIN_BUCKET_ID,
	ADMIN_SESSION_COOKIE,
	DEFAULT_BUCKET_ID
} from 'lib/admin/consts.ts';
import { getBucketStore } from 'lib/adapters/index.ts';
import { sessionFor, personalGroupId } from '../admin_session.ts';
import { answered } from './answered.ts';
import { createAdministrator, type AdminKind } from '../administrators.ts';

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
	.use(clientRoutes)
	.use(bucketRoutes)
	.use(groupRoutes)
	.use(scopeRoutes)
	.use(adminUserRoutes)
	.use(endUserRoutes);
const client = treaty(app);
const superAdminOf = (id: string) =>
	client.admin.api.admins({ id })['super-admin'];

async function tenant(label: string, kind: AdminKind = 'plain') {
	const user = await createAdministrator(
		kind,
		`${label}-${Math.random()}@x.io`
	);
	const session = await sessionFor(user);
	const groupId = await personalGroupId(user._id);
	/* Each tenant starts with a bucket of its own, where its applications are created. */
	const bucket = await getBucketStore().create({
		name: `${label} users`,
		ownerGroupId: groupId
	});
	return {
		userId: user._id,
		cookie: `${ADMIN_SESSION_COOKIE}=${session._id}`,
		groupId,
		bucketId: bucket._id
	};
}

/* An application the tenant creates in its own bucket, named so a leak of it is recognisable. */
async function applicationOf(owner: { cookie: string; bucketId: string }) {
	const created = await client.admin.api
		.buckets({ id: owner.bucketId })
		.clients.post(
			{
				clientName: 'A application',
				grantTypes: ['client_credentials'],
				tokenEndpointAuthMethod: 'client_secret_basic'
			},
			{ headers: { cookie: owner.cookie } }
		);
	expect(created.status).toBe(201);
	return answered(created.data);
}

/**
 * @proves An administrator can reach only what their own groups own — buckets and the applications in
 * them — cannot escalate into another group or the reserved containers, and learns nothing about what it
 * cannot reach.
 */
describe('group isolation', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('creates an application in the creator’s own bucket, listed to nobody else', async () => {
		const a = await tenant('a');
		const b = await tenant('b');
		const application = await applicationOf(a);
		expect(application.bucketId).toBe(a.bucketId);

		const bList = await client.admin.api
			.buckets({ id: a.bucketId })
			.clients.get({ headers: { cookie: b.cookie } });

		expect(bList.status).toBe(403);
	});

	it('refuses a foreign application identically to one in a bucket that does not exist', async () => {
		const a = await tenant('a');
		const b = await tenant('b');
		const application = await applicationOf(a);

		const foreign = await client.admin.api
			.buckets({ id: a.bucketId })
			.clients({ clientId: application.clientId })
			.get({ headers: { cookie: b.cookie } });
		const absent = await client.admin.api
			.buckets({ id: 'does-not-exist-at-all' })
			.clients({ clientId: application.clientId })
			.get({ headers: { cookie: b.cookie } });

		/*
		 * A 403 for a bucket that exists and a 404 for one that does not would tell an outsider whether an
		 * id is real; probing for existence is exactly what tenant isolation must not allow.
		 */
		expect(foreign.status).toBe(absent.status);
	});

	it('refuses a foreign application addressed through the caller’s own bucket as one that does not exist', async () => {
		const a = await tenant('a');
		const b = await tenant('b');
		const application = await applicationOf(a);

		const foreign = await client.admin.api
			.buckets({ id: b.bucketId })
			.clients({ clientId: application.clientId })
			.get({ headers: { cookie: b.cookie } });
		const absent = await client.admin.api
			.buckets({ id: b.bucketId })
			.clients({ clientId: 'does-not-exist-at-all' })
			.get({ headers: { cookie: b.cookie } });

		expect(foreign.status).toBe(404);
		expect(foreign.error?.value).toEqual(absent.error?.value);
	});

	it('keeps a foreign bucket out of both the listing and the detail read', async () => {
		const a = await tenant('a');
		const b = await tenant('b');

		const created = await client.admin.api.buckets.post(
			{ name: 'A users', slug: 'a-users-1' },
			{ headers: { cookie: a.cookie } }
		);
		expect(created.status).toBe(201);
		const bucket = answered(created.data);
		expect(bucket.ownerGroupId).toBe(a.groupId);

		const bList = await client.admin.api.buckets.get({
			headers: { cookie: b.cookie }
		});
		expect(answered(bList.data).map((x) => x._id)).not.toContain(bucket._id);

		const bRead = await client.admin.api
			.buckets({ id: bucket._id })
			.get({ headers: { cookie: b.cookie } });
		expect(bRead.status).toBe(403);
	});

	/*
	 * An application authenticates end users against its bucket's pool, so moving one into a pool another
	 * group administers would let A's application sign in people A has no access to. The bucket is not a
	 * field of the update: submitted as one it is either refused or ignored, and the application stays put.
	 */
	it('keeps an application in its bucket when an update names another group’s bucket', async () => {
		const a = await tenant('a');
		const b = await tenant('b');
		const application = await applicationOf(a);

		await client.admin.api
			.buckets({ id: a.bucketId })
			.clients({ clientId: application.clientId })
			.patch(
				// @ts-expect-error an unknown field; the update schema does not declare it
				{ bucketId: b.bucketId },
				{ headers: { cookie: a.cookie } }
			);

		const after = await client.admin.api
			.buckets({ id: a.bucketId })
			.clients({ clientId: application.clientId })
			.get({ headers: { cookie: a.cookie } });
		expect(answered(after.data).bucketId).toBe(a.bucketId);
	});

	it('names no foreign id in a refusal body', async () => {
		const a = await tenant('a');
		const b = await tenant('b');
		const application = await applicationOf(a);

		const denied = await client.admin.api
			.buckets({ id: a.bucketId })
			.clients({ clientId: application.clientId })
			.patch({ clientName: 'Renamed' }, { headers: { cookie: b.cookie } });

		expect(denied.status).toBe(403);
		// The refusal may say access was denied; it must not echo back anything about the target.
		const body = JSON.stringify(denied.error?.value ?? denied.data);
		expect(body).not.toContain('A application');
		expect(body).not.toContain(application.clientId);
	});

	/*
	 * The Default bucket holds the people of every tenant that signs in there. No plain administrator's
	 * group reaches it: reach over it would be reach over everybody else's.
	 */
	it('gives a plain administrator no reach over the Default bucket', async () => {
		const a = await tenant('a');

		const listed = await client.admin.api.buckets.get({
			headers: { cookie: a.cookie }
		});
		const read = await client.admin.api
			.buckets({ id: DEFAULT_BUCKET_ID })
			.get({ headers: { cookie: a.cookie } });
		const people = await app.handle(
			new Request(
				`http://localhost/admin/api/buckets/${DEFAULT_BUCKET_ID}/users`,
				{
					headers: { cookie: a.cookie }
				}
			)
		);
		const applications = await client.admin.api
			.buckets({ id: DEFAULT_BUCKET_ID })
			.clients.get({ headers: { cookie: a.cookie } });

		expect(answered(listed.data).map((b) => b._id)).not.toContain(
			DEFAULT_BUCKET_ID
		);
		expect([read.status, people.status, applications.status]).toEqual([
			403, 403, 403
		]);
	});

	it('does not let a plain administrator reach the reserved admin bucket', async () => {
		const a = await tenant('a');

		const adminBucket = await client.admin.api
			.buckets({ id: ADMIN_BUCKET_ID })
			.get({ headers: { cookie: a.cookie } });
		expect(adminBucket.status).toBe(403);
	});

	/*
	 * FR-026: a plain administrator must not be able to widen their own access. Structurally this
	 * falls out of the role gates and the membership check, but "it follows from the design" is exactly
	 * the claim that stops being true after a refactor — so each route is asked directly.
	 */
	describe('no self-escalation', () => {
		it('cannot make itself a super administrator', async () => {
			const a = await tenant('a');

			const res = await superAdminOf(a.userId).post(undefined, {
				headers: { cookie: a.cookie }
			});
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

			const res = await client.admin.api.buckets({ id: b.bucketId }).patch(
				// `ownerGroupId` is not in the update body at all; submitted as an unknown field it is
				// either refused or ignored, and either way the bucket must not move.
				// @ts-expect-error an unknown field; the update schema does not declare it
				{ ownerGroupId: a.groupId },
				{ headers: { cookie: a.cookie } }
			);
			expect([403, 422]).toContain(res.status);

			expect((await getBucketStore().find(b.bucketId))?.ownerGroupId).toBe(
				b.groupId
			);
		});
	});

	/*
	 * The one limit that also binds a super administrator. Their bypass exists so support and recovery
	 * are possible — reading a foreign container, or taking over a group whose owners have gone. Acting
	 * *as* somebody's personal group is neither, and it is the scope where nothing has been shared with
	 * anyone: asked here rather than only in the scope spec because this is the file that asks whether a
	 * boundary holds against the caller who can cross every other one.
	 */
	it("refuses even a super administrator the scope of somebody's personal group", async () => {
		const root = await tenant('root', 'super');
		const a = await tenant('a');

		const res = await client.admin.api.scope.put(
			{ groupId: a.groupId },
			{ headers: { cookie: root.cookie } }
		);
		expect(res.status).toBe(403);

		// And the same for a group that does not exist, so the refusal cannot be read as "this one is
		// personal" — the switcher does not offer it either way.
		const invented = await client.admin.api.scope.put(
			{ groupId: 'no-such-group' },
			{ headers: { cookie: root.cookie } }
		);
		expect(invented.status).toBe(403);
	});
});
