import { describe, it, expect, beforeAll, beforeEach, spyOn } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';

import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { activityRoutes } from 'lib/admin/activity/routes.ts';
import { bucketRoutes } from 'lib/admin/buckets/routes.ts';
import { endUserRoutes } from 'lib/admin/users-end/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	getActivityStore,
	getBucketStore,
	getUserStore
} from 'lib/adapters/index.ts';
import type { User } from 'lib/adapters/types.ts';
import { monthOf } from 'lib/activity/periods.ts';
import { createAdministrator } from '../administrators.ts';
import {
	bucketWithProjects,
	cookieFor,
	regularGroup
} from '../admin/ownership_fixtures.ts';
import { present } from 'test/shape.ts';
import { settled, startCounting } from './fixtures.ts';

const app = new Elysia()
	.use(resolveAdmin)
	.use(bucketRoutes)
	.use(endUserRoutes)
	.use(activityRoutes);
const client = treaty(app);

let owner: User;
let superAdmin: User;
let bucketId: string;
let endUserId: string;

const month = () => monthOf(new Date());

/* This month's total as the owning group's console reads it. Plain JSON, for the reason activity_routes gives. */
async function monthTotal(
	id: string,
	reader: User
): Promise<{ status: number; total?: number }> {
	const res = await app.handle(
		new Request(
			`http://e.ly/admin/api/buckets/${encodeURIComponent(id)}/activity`,
			{
				headers: { cookie: await cookieFor(reader) }
			}
		)
	);
	if (res.status !== 200) return { status: res.status };
	const body = (await res.json()) as { month: { total: number } | null };
	return { status: 200, total: body.month?.total };
}

async function overviewRow(id: string) {
	const res = await client.admin.api.activity.get({
		headers: { cookie: await cookieFor(superAdmin) }
	});
	const body = present(res.data, 'an overview');
	if (!('buckets' in body)) throw new Error('expected an overview');
	return body.buckets.find((row) => row.bucketId === id);
}

/**
 * @proves A bucket's usage history is evidence and ordinary administration does not change it: deleting,
 * locking or signing out a person, renaming the bucket, changing its address or moving it to another group
 * leaves every counted month as it was, and deleting the bucket keeps its history readable — or does not
 * happen at all.
 */
describe('active users after the bucket and its people change', () => {
	beforeAll(async () => {
		await ensureAdminSeed();
		superAdmin = await createAdministrator(
			'super',
			`history-super-${Math.random()}@x.io`
		);
	});

	beforeEach(async () => {
		await startCounting();
		owner = await createAdministrator(
			'plain',
			`history-owner-${Math.random()}@x.io`
		);
		bucketId = (await bucketWithProjects((await regularGroup([owner]))._id, 0))
			.bucket._id;
		endUserId = (
			await getUserStore(bucketId).create(
				`history-${Math.random()}@x.io`,
				'hash',
				true
			)
		)._id;
		await getActivityStore().mark({
			bucketId,
			accountId: endUserId,
			kind: 'local',
			provisioned: false,
			at: new Date()
		});
		await settled();
	});

	it('leaves the months an end user counted in unchanged when the end user is deleted', async () => {
		const cookie = await cookieFor(owner);

		const res = await client.admin.api
			.buckets({ id: bucketId })
			.users({ uid: endUserId })
			.delete(undefined, {
				headers: { cookie }
			});

		expect(res.status).toBe(200);
		expect(await getUserStore(bucketId).find(endUserId)).toBeNull();
		expect(await monthTotal(bucketId, owner)).toEqual({
			status: 200,
			total: 1
		});
	});

	it('leaves the months an end user counted in unchanged when the end user is locked', async () => {
		const cookie = await cookieFor(owner);

		const res = await client.admin.api
			.buckets({ id: bucketId })
			.users({ uid: endUserId })
			.lock.post({ reason: 'history case' }, { headers: { cookie } });

		expect(res.status).toBe(200);
		expect(await monthTotal(bucketId, owner)).toEqual({
			status: 200,
			total: 1
		});
	});

	it('leaves the months an end user counted in unchanged when the end user is signed out everywhere', async () => {
		const cookie = await cookieFor(owner);

		const user = client.admin.api
			.buckets({ id: bucketId })
			.users({ uid: endUserId });

		const res = await user['sign-out'].post(undefined, { headers: { cookie } });

		expect(res.status).toBe(200);
		expect(await monthTotal(bucketId, owner)).toEqual({
			status: 200,
			total: 1
		});
	});

	it("leaves the bucket's history unchanged after its name changes", async () => {
		const res = await client.admin.api
			.buckets({ id: bucketId })
			.patch(
				{ name: 'Renamed for history' },
				{ headers: { cookie: await cookieFor(owner) } }
			);

		expect(res.status).toBe(200);
		expect(await monthTotal(bucketId, owner)).toEqual({
			status: 200,
			total: 1
		});
	});

	it("leaves the bucket's history unchanged after its address changes", async () => {
		const res = await client.admin.api
			.buckets({ id: bucketId })
			.address.post(
				{ slug: `history-${String(Date.now())}`, confirm: true },
				{ headers: { cookie: await cookieFor(superAdmin) } }
			);

		expect(res.status).toBe(200);
		expect(await monthTotal(bucketId, owner)).toEqual({
			status: 200,
			total: 1
		});
	});

	it("hands a bucket's history to the group it moves to and refuses it to the group it left", async () => {
		const formerMember = await createAdministrator(
			'plain',
			`history-former-${Math.random()}@x.io`
		);
		const newMember = await createAdministrator(
			'plain',
			`history-new-${Math.random()}@x.io`
		);
		const source = present(
			await getBucketStore().find(bucketId),
			'the bucket'
		).ownerGroupId;
		const { getGroupStore } = await import('lib/adapters/index.ts');
		await getGroupStore().update(source, {
			members: [
				{ userId: owner._id, role: 'owner' },
				{ userId: formerMember._id, role: 'member' }
			]
		});
		const destination = await regularGroup([owner], [newMember]);

		const moved = await client.admin.api
			.buckets({ id: bucketId })
			.owner.put(
				{ groupId: destination._id, confirm: true },
				{ headers: { cookie: await cookieFor(owner) } }
			);

		expect(moved.status).toBe(200);
		expect(await monthTotal(bucketId, newMember)).toEqual({
			status: 200,
			total: 1
		});
		expect((await monthTotal(bucketId, formerMember)).status).toBe(403);
	});

	it("keeps a deleted bucket's history readable in the overview, marked deleted, the deletion month included", async () => {
		const res = await client.admin.api
			.buckets({ id: bucketId })
			.delete(undefined, {
				headers: { cookie: await cookieFor(owner) },
				query: { cascade: 'endusers', expect: 1 }
			});

		expect(res.status).toBe(200);
		const row = await overviewRow(bucketId);
		expect(row?.deleted).not.toBeNull();
		expect(row?.current).toMatchObject({
			period: month(),
			total: 1,
			final: true
		});
	});

	it('does not delete a bucket whose history cannot be kept, and its end users remain', async () => {
		const retire = spyOn(getActivityStore(), 'retire').mockRejectedValue(
			new Error('the activity datastore is unavailable')
		);
		const log = spyOn(console, 'error').mockImplementation(() => undefined);

		try {
			const res = await client.admin.api
				.buckets({ id: bucketId })
				.delete(undefined, {
					headers: { cookie: await cookieFor(owner) },
					query: { cascade: 'endusers', expect: 1 }
				});

			expect(res.status).toBe(500);
			expect(await getBucketStore().find(bucketId)).not.toBeNull();
			expect(await getUserStore(bucketId).find(endUserId)).not.toBeNull();
		} finally {
			retire.mockRestore();
			log.mockRestore();
		}
	});
});
