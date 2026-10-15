import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	spyOn
} from 'bun:test';
import { Elysia } from 'elysia';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.js';
import { adminApiRoutes } from 'lib/admin/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adapter,
	adminAuditStore,
	getActivityStore,
	getBucketGroupStore,
	getBucketKeysStore,
	getBucketStore,
	getProtectedResourceStore,
	getProvisioningConnectionStore,
	getUserStore
} from 'lib/adapters/index.ts';
import type { User, UserBucket } from 'lib/adapters/types.ts';
import { ADMIN_BUCKET_ID, DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { ensureBucketKey } from 'lib/keys/issuer_keys.ts';
import { setClockForTests } from 'lib/activity/clock.ts';
import { purgeDueBuckets } from 'lib/admin/buckets/purge_pass.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { present, shaped } from 'test/shape.ts';
import { createAdministrator } from '../administrators.ts';
import { cookieFor, regularGroup } from './ownership_fixtures.ts';

const app = new Elysia().use(adminApiRoutes);

const DAY_MS = 24 * 60 * 60 * 1000;

async function request(
	method: string,
	path: string,
	cookie: string
): Promise<{ status: number; body: unknown }> {
	const response = await app.handle(
		new Request(`http://e.ly${path}`, { method, headers: { cookie } })
	);
	const text = await response.text();
	return {
		status: response.status,
		body: text ? (JSON.parse(text) as unknown) : null
	};
}

const Scheduled = Type.Object({
	scheduled: Type.Object({
		scheduledAt: Type.String(),
		purgeAt: Type.String()
	})
});
const Listed = Type.Array(
	Type.Object({
		_id: Type.String(),
		deletion: Type.Optional(Type.Object({ purgeAt: Type.String() }))
	})
);
const Blockers = Type.Object({
	blockers: Type.Array(
		Type.Object({ kind: Type.String(), count: Type.Number() })
	)
});
const Refusal = Type.Object({
	message: Type.String(),
	blockers: Type.Array(
		Type.Object({
			kind: Type.String(),
			count: Type.Number(),
			ids: Type.Optional(Type.Array(Type.String()))
		})
	)
});

interface World {
	owner: User;
	member: User;
	ownerCookie: string;
	memberCookie: string;
	groupId: string;
}

async function world(): Promise<World> {
	await ensureAdminSeed();
	const owner = await createAdministrator();
	const member = await createAdministrator();
	const group = await regularGroup([owner], [member]);
	return {
		owner,
		member,
		ownerCookie: await cookieFor(owner),
		memberCookie: await cookieFor(member),
		groupId: group._id
	};
}

async function bucketOf(groupId: string, accounts = 0): Promise<UserBucket> {
	const id = nanoid()
		.toLowerCase()
		.replace(/[^a-z0-9]/g, '');
	const bucket = await getBucketStore().create({
		name: `soft ${id}`,
		slug: `sd-${id}`,
		ownerGroupId: groupId
	});
	for (let i = 0; i < accounts; i += 1) {
		await getUserStore(bucket._id).create(`p${String(i)}-${id}@x.io`, 'h');
	}
	return bucket;
}

/* An application stored in the bucket, as creating it in the bucket's Applications stores it. */
async function applicationIn(
	bucket: UserBucket,
	fields: Record<string, unknown> = {}
): Promise<string> {
	const clientId = `app-${nanoid()}`;
	await adapter('Client').upsert(clientId, {
		clientId,
		bucketId: bucket._id,
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['https://app.example.com/cb'],
		token_endpoint_auth_method: 'none',
		...fields
	});
	return clientId;
}

function scheduleAs(cookie: string, bucket: UserBucket, query = '') {
	return request('DELETE', `/admin/api/projects/${bucket._id}${query}`, cookie);
}

async function entries(targetId: string, action: string) {
	return (await adminAuditStore.list({ targetId })).entries.filter(
		(entry) => entry.action === action
	);
}

/**
 * @proves An administrator's deletion of a bucket switches it off and schedules its destruction thirty days
 * out with every check a deletion applied before, keeping everything it holds; a restore puts it back as it
 * was; and Delete now destroys a scheduled bucket at once — each refused to whoever may not delete it, and
 * each recorded once in the owning group's trail.
 */
describe('deleting a bucket', () => {
	let w: World;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		w = await world();
	});

	describe('schedules it', () => {
		it('schedules an empty bucket deleted by a member for thirty days later, and keeps it listed', async () => {
			const bucket = await bucketOf(w.groupId);

			const res = await scheduleAs(w.memberCookie, bucket);
			const { scheduled } = shaped(Scheduled, res.body);
			const superAdmin = await cookieFor(await createAdministrator('super'));
			const listed = shaped(
				Listed,
				(await request('GET', '/admin/api/projects', superAdmin)).body
			);

			expect(res.status).toBe(200);
			expect(
				new Date(scheduled.purgeAt).getTime() -
					new Date(scheduled.scheduledAt).getTime()
			).toBe(30 * DAY_MS);
			expect(
				listed.find((row) => row._id === bucket._id)?.deletion?.purgeAt
			).toBe(scheduled.purgeAt);
		});

		it('records the deletion with its date in the trail of the group that owns it', async () => {
			const bucket = await bucketOf(w.groupId);

			const res = await scheduleAs(w.memberCookie, bucket);
			const entry = present(
				(await entries(bucket._id, 'bucket.delete')).at(0),
				'the bucket.delete entry'
			);

			expect(entry.ownerGroupId).toBe(w.groupId);
			expect(entry.purgeAt?.toISOString()).toBe(
				shaped(Scheduled, res.body).scheduled.purgeAt
			);
		});

		it('keeps every account, key, group and connection of a bucket an owner deleted with the reviewed count', async () => {
			const bucket = await bucketOf(w.groupId, 2);
			await ensureBucketKey(bucket._id);
			const group = await getBucketGroupStore().create({
				_id: nanoid(),
				bucketId: bucket._id,
				displayName: 'Staff'
			});
			const connection = await getProvisioningConnectionStore().create({
				_id: nanoid(),
				bucketId: bucket._id,
				displayName: 'Directory',
				enabled: true,
				providerId: 'none',
				correlation: { claim: 'oid', attribute: 'externalId' },
				emailTrust: 'untrusted',
				oauthCredential: null
			});

			const res = await scheduleAs(
				w.ownerCookie,
				bucket,
				'?cascade=endusers&expect=2'
			);

			expect(res.status).toBe(200);
			expect(await getUserStore(bucket._id).list()).toHaveLength(2);
			expect(
				(await getBucketKeysStore().listByBucket(bucket._id)).length
			).toBeGreaterThan(0);
			expect(await getBucketGroupStore().find(group._id)).not.toBeNull();
			expect(
				await getProvisioningConnectionStore().find(connection._id)
			).not.toBeNull();
		});

		it('refuses a member who is not an owner a bucket holding accounts', async () => {
			const bucket = await bucketOf(w.groupId, 1);

			const res = await scheduleAs(
				w.memberCookie,
				bucket,
				'?cascade=endusers&expect=1'
			);

			expect(res.status).toBe(403);
			expect(
				(await getBucketStore().find(bucket._id))?.deletion
			).toBeUndefined();
		});

		it('refuses a count that is not the one the bucket holds, naming the count', async () => {
			const bucket = await bucketOf(w.groupId, 2);

			const res = await scheduleAs(
				w.ownerCookie,
				bucket,
				'?cascade=endusers&expect=1'
			);

			expect(res.status).toBe(409);
			expect(shaped(Blockers, res.body).blockers).toEqual([
				{ kind: 'enduser', count: 2 }
			]);
		});

		it('refuses a bucket holding an application an administrator created, naming it, and leaves it unscheduled', async () => {
			const bucket = await bucketOf(w.groupId);
			const clientId = await applicationIn(bucket);

			const res = await scheduleAs(w.ownerCookie, bucket);

			expect(res.status).toBe(409);
			expect(shaped(Refusal, res.body)).toMatchObject({
				message: 'project still holds applications or APIs',
				blockers: [{ kind: 'client', count: 1, ids: [clientId] }]
			});
			expect(
				(await getBucketStore().find(bucket._id))?.deletion
			).toBeUndefined();
		});

		it('refuses a bucket that declares an API, counting it', async () => {
			const bucket = await bucketOf(w.groupId);
			await getProtectedResourceStore().create({
				namespace: bucket._id,
				identifier: `https://api-${bucket._id}.example.com/`,
				bucketId: bucket._id,
				name: 'Orders API',
				scopes: ['read']
			});

			const res = await scheduleAs(w.ownerCookie, bucket);

			expect(res.status).toBe(409);
			expect(shaped(Refusal, res.body).blockers).toEqual([
				{ kind: 'resource', count: 1 }
			]);
		});

		it('schedules a bucket whose only application registered itself', async () => {
			const bucket = await bucketOf(w.groupId);
			await applicationIn(bucket, { registeredDynamically: true });

			const res = await scheduleAs(w.ownerCookie, bucket);

			expect(res.status).toBe(200);
			shaped(Scheduled, res.body);
		});

		it.each([
			['administrators', ADMIN_BUCKET_ID],
			['default', DEFAULT_BUCKET_ID]
		])('refuses the %s bucket', async (_, id) => {
			const superAdmin = await cookieFor(await createAdministrator('super'));

			const res = await request(
				'DELETE',
				`/admin/api/projects/${id}`,
				superAdmin
			);

			expect(res.status).toBe(403);
		});

		it('refuses a bucket already scheduled, keeping its date', async () => {
			const bucket = await bucketOf(w.groupId);
			await scheduleAs(w.ownerCookie, bucket);
			const before = (await getBucketStore().find(bucket._id))?.deletion
				?.purgeAt;

			const again = await scheduleAs(w.ownerCookie, bucket);

			expect(again.status).toBe(409);
			expect(
				(await getBucketStore().find(bucket._id))?.deletion?.purgeAt
			).toEqual(present(before, 'the first date'));
		});
	});

	describe('restores it', () => {
		it('answers the bucket without a deletion, and records the schedule it cancelled', async () => {
			const bucket = await bucketOf(w.groupId);
			await scheduleAs(w.ownerCookie, bucket);
			const scheduledAt = (await getBucketStore().find(bucket._id))?.deletion
				?.scheduledAt;

			const res = await request(
				'POST',
				`/admin/api/projects/${bucket._id}/restore`,
				w.ownerCookie
			);
			const entry = present(
				(await entries(bucket._id, 'bucket.restore')).at(0),
				'the bucket.restore entry'
			);

			expect(res.status).toBe(200);
			expect(res.body).not.toHaveProperty('deletion');
			expect(entry.ownerGroupId).toBe(w.groupId);
			expect(entry.scheduledAt).toEqual(present(scheduledAt, 'the schedule'));
		});

		it('refuses a bucket that is not scheduled, recording nothing', async () => {
			const bucket = await bucketOf(w.groupId);

			const res = await request(
				'POST',
				`/admin/api/projects/${bucket._id}/restore`,
				w.ownerCookie
			);

			expect(res.status).toBe(409);
			expect(await entries(bucket._id, 'bucket.restore')).toEqual([]);
		});

		it('refuses a member who is not an owner a bucket holding accounts', async () => {
			const bucket = await bucketOf(w.groupId, 1);
			await scheduleAs(w.ownerCookie, bucket, '?cascade=endusers&expect=1');

			const res = await request(
				'POST',
				`/admin/api/projects/${bucket._id}/restore`,
				w.memberCookie
			);

			expect(res.status).toBe(403);
		});

		it('refuses while its destruction is under way', async () => {
			const bucket = await bucketOf(w.groupId);
			await scheduleAs(w.ownerCookie, bucket);
			const now = new Date();
			await getBucketStore().claimPurge(
				bucket._id,
				now,
				new Date(now.getTime() + 60_000),
				{ due: false }
			);

			const res = await request(
				'POST',
				`/admin/api/projects/${bucket._id}/restore`,
				w.ownerCookie
			);

			expect(res.status).toBe(409);
			expect(
				shaped(Type.Object({ message: Type.String() }), res.body).message
			).toBe('This project is already being deleted.');
		});

		describe('and deleted again', () => {
			let restoreClock: (() => void) | undefined;

			afterEach(() => {
				restoreClock?.();
				restoreClock = undefined;
			});

			it('gives it a new date', async () => {
				const bucket = await bucketOf(w.groupId);
				const first = shaped(
					Scheduled,
					(await scheduleAs(w.ownerCookie, bucket)).body
				).scheduled.purgeAt;
				await request(
					'POST',
					`/admin/api/projects/${bucket._id}/restore`,
					w.ownerCookie
				);
				const later = new Date(Date.now() + 2 * DAY_MS);
				restoreClock = setClockForTests(() => later);

				const second = shaped(
					Scheduled,
					(await scheduleAs(w.ownerCookie, bucket)).body
				).scheduled.purgeAt;

				expect(second).not.toBe(first);
				expect(new Date(second).getTime()).toBe(later.getTime() + 30 * DAY_MS);
			});
		});
	});

	describe('Delete now', () => {
		it('destroys a scheduled bucket an owner confirms with the reviewed count, keeping its usage history', async () => {
			const bucket = await bucketOf(w.groupId, 1);
			await scheduleAs(w.ownerCookie, bucket, '?cascade=endusers&expect=1');

			const res = await request(
				'POST',
				`/admin/api/projects/${bucket._id}/purge?cascade=endusers&expect=1`,
				w.ownerCookie
			);

			expect(res.status).toBe(200);
			expect(res.body).toEqual({ ok: true, endUsersDestroyed: 1 });
			expect(await getBucketStore().find(bucket._id)).toBeNull();
			expect(await getActivityStore().tombstone(bucket._id)).not.toBeNull();
		});

		it('records the destruction once, naming the administrator, in the owning group’s trail', async () => {
			const bucket = await bucketOf(w.groupId, 1);
			await scheduleAs(w.ownerCookie, bucket, '?cascade=endusers&expect=1');

			await request(
				'POST',
				`/admin/api/projects/${bucket._id}/purge?cascade=endusers&expect=1`,
				w.ownerCookie
			);
			const recorded = await entries(bucket._id, 'bucket.purge');

			expect(
				recorded.map((e) => [e.actorId, e.ownerGroupId, e.cascade])
			).toEqual([[w.owner._id, w.groupId, { endusers: 1 }]]);
		});

		it('can be retried at once after it failed part-way, still recording one destruction', async () => {
			const bucket = await bucketOf(w.groupId, 1);
			await scheduleAs(w.ownerCookie, bucket, '?cascade=endusers&expect=1');
			const log = spyOn(console, 'error').mockImplementation(() => undefined);
			const failing = spyOn(
				getBucketGroupStore(),
				'destroyByBucket'
			).mockRejectedValueOnce(new Error('the datastore went away'));
			const path = `/admin/api/projects/${bucket._id}/purge?cascade=endusers&expect=0`;

			// Read raw: this app has no shared error handler, so the fault is not a JSON body.
			const first = await app.handle(
				new Request(
					`http://e.ly/admin/api/projects/${bucket._id}/purge?cascade=endusers&expect=1`,
					{ method: 'POST', headers: { cookie: w.ownerCookie } }
				)
			);
			failing.mockRestore();
			const retry = await request('POST', path, w.ownerCookie);
			log.mockRestore();

			expect(first.status).toBe(500);
			expect(retry.status).toBe(200);
			expect(await getBucketStore().find(bucket._id)).toBeNull();
			expect(await entries(bucket._id, 'bucket.purge')).toHaveLength(1);
		});

		it('refuses a bucket that is not scheduled', async () => {
			const bucket = await bucketOf(w.groupId);

			const res = await request(
				'POST',
				`/admin/api/projects/${bucket._id}/purge`,
				w.ownerCookie
			);

			expect(res.status).toBe(409);
			expect(await getBucketStore().find(bucket._id)).not.toBeNull();
		});

		it('refuses a member who is not an owner a bucket holding accounts', async () => {
			const bucket = await bucketOf(w.groupId, 1);
			await scheduleAs(w.ownerCookie, bucket, '?cascade=endusers&expect=1');

			const res = await request(
				'POST',
				`/admin/api/projects/${bucket._id}/purge?cascade=endusers&expect=1`,
				w.memberCookie
			);

			expect(res.status).toBe(403);
			expect(await getBucketStore().find(bucket._id)).not.toBeNull();
		});

		it('refuses a count that changed since it was reviewed', async () => {
			const bucket = await bucketOf(w.groupId, 1);
			await scheduleAs(w.ownerCookie, bucket, '?cascade=endusers&expect=1');
			await getUserStore(bucket._id).create(`late-${nanoid()}@x.io`, 'h');

			const res = await request(
				'POST',
				`/admin/api/projects/${bucket._id}/purge?cascade=endusers&expect=1`,
				w.ownerCookie
			);

			expect(res.status).toBe(409);
			expect(shaped(Blockers, res.body).blockers).toEqual([
				{ kind: 'enduser', count: 2 }
			]);
		});

		it('answers not found once the hourly pass has destroyed it', async () => {
			const bucket = await bucketOf(w.groupId);
			await scheduleAs(w.ownerCookie, bucket);
			await purgeDueBuckets(new Date(Date.now() + 31 * DAY_MS));
			const superAdmin = await cookieFor(await createAdministrator('super'));

			const res = await request(
				'POST',
				`/admin/api/projects/${bucket._id}/purge`,
				superAdmin
			);

			expect(res.status).toBe(404);
		});
	});
});
