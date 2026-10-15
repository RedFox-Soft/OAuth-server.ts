import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import {
	adapter,
	adminAuditStore,
	getBucketStore,
	getProtectedResourceStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	ADMIN_BUCKET_ID,
	ADMIN_SESSION_COOKIE,
	DEFAULT_BUCKET_ID,
	UNASSIGNED_GROUP_ID
} from 'lib/admin/consts.ts';
import { Client } from 'lib/models/client.js';
import { ROOT_NAMESPACE } from 'lib/resources/namespace.ts';
import { userAreaFor } from 'lib/consts/storage_inventory.js';
import { sessionFor } from '../admin_session.ts';
import { createAdministrator } from '../administrators.ts';

// User Story 3 — a container refuses deletion while it still holds something.
//
// The line between guarding and cascading is drawn by visibility: an operator can see and name a
// bucket's applications and APIs, which are somebody's integrations, so refusing tells them exactly what
// they are about to break and keeps one audit entry per entity destroyed. Nobody can be asked to enumerate
// the tokens an application issued.
//
// The *shape* of the refusal body belongs to User Story 4; here the claims are that the refusal happens,
// that it changes nothing, and that an emptied container then deletes cleanly.

/**
 * @proves A bucket holding accounts is not deleted unless they were reviewed and consented to, one
 * holding applications or APIs an administrator put there is not deleted at all until they are removed,
 * a refusal changes nothing, an emptied bucket takes its per-bucket area with it, and the two buckets the
 * instance is built on are refused to everyone.
 */
describe('deletion guards: buckets', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		await ensureAdminSeed();
	});

	async function superAdminCookie(): Promise<string> {
		const admin = await createAdministrator(
			'super',
			`sa-${Math.random()}@x.io`
		);
		const session = await sessionFor(admin);
		return `${ADMIN_SESSION_COOKIE}=${session._id}`;
	}

	/* An application an administrator created in `bucketId`, or one that registered itself there. */
	async function liveClient(
		bucketId: string,
		registeredDynamically = false
	): Promise<string> {
		const clientId = `held-${Math.random().toString(36).slice(2)}`;
		await adapter('Client').upsert(clientId, {
			clientId,
			clientSecret: 'secret',
			grantTypes: ['authorization_code'],
			responseTypes: ['code'],
			redirectUris: [`https://${clientId}.example.com/cb`],
			bucketId,
			...(registeredDynamically ? { registeredDynamically } : {})
		});
		return clientId;
	}

	async function declaredApi(bucketId: string) {
		await getProtectedResourceStore().create({
			namespace: ROOT_NAMESPACE,
			identifier: `https://api-${Math.random().toString(36).slice(2)}.example/`,
			bucketId,
			name: 'API',
			scopes: ['api:read']
		});
	}

	async function bucket() {
		return getBucketStore().create({
			name: `b-${Math.random()}`,
			ownerGroupId: UNASSIGNED_GROUP_ID
		});
	}

	async function deleteBucket(id: string, query?: Record<string, unknown>) {
		const cookie = await superAdminCookie();
		return agent.admin.api
			.projects({ id })
			.delete(undefined, { headers: { cookie }, ...(query ? { query } : {}) });
	}

	async function deleteClient(bucketId: string, clientId: string) {
		const cookie = await superAdminCookie();
		return agent.admin.api
			.projects({ id: bucketId })
			.clients({ clientId })
			.delete(undefined, { headers: { cookie } });
	}

	it('refuses a bucket that still holds users (scenario 5)', async () => {
		const held = await bucket();
		await getUserStore(held._id).create('someone@example.com', 'hash');

		const res = await deleteBucket(held._id);

		expect(res.status).toBe(409);
		expect(await getBucketStore().find(held._id)).not.toBeNull();
	});

	// Deactivation is a sign-in decision, not absence — the account is still there to be destroyed.
	it('counts deactivated accounts as blockers (scenario 6)', async () => {
		const held = await bucket();
		const store = getUserStore(held._id);
		const user = await store.create('dormant@example.com', 'hash');
		await store.update(user._id, { active: false });

		const res = await deleteBucket(held._id);

		expect(res.status).toBe(409);
	});

	it('refuses a bucket that still holds an application an administrator created (scenario 7)', async () => {
		const holding = await bucket();
		await liveClient(holding._id);

		const res = await deleteBucket(holding._id);

		expect(res.status).toBe(409);
		expect(
			(await getBucketStore().find(holding._id))?.deletion
		).toBeUndefined();
	});

	it('refuses a bucket that still declares an API', async () => {
		const holding = await bucket();
		await declaredApi(holding._id);

		const res = await deleteBucket(holding._id);

		expect(res.status).toBe(409);
		expect(
			(await getBucketStore().find(holding._id))?.deletion
		).toBeUndefined();
	});

	it('deletes the bucket once its applications are gone', async () => {
		const holding = await bucket();
		const clientId = await liveClient(holding._id);

		expect((await deleteBucket(holding._id)).status).toBe(409);
		expect((await deleteClient(holding._id, clientId)).status).toBe(200);
		const res = await deleteBucket(holding._id);

		expect(res.status).toBe(200);
		expect((await getBucketStore().find(holding._id))?.deletion).toBeDefined();
	});

	/* Nobody here vouched for an application that registered itself, so it is nobody's integration to break. */
	it('does not count an application that registered itself as holding the bucket', async () => {
		const holding = await bucket();
		await liveClient(holding._id, true);

		const res = await deleteBucket(holding._id);

		expect(res.status).toBe(200);
	});

	it('destroys an emptied bucket and drops its user area (scenario 8)', async () => {
		const held = await bucket();
		const store = getUserStore(held._id);
		const user = await store.create('leaving@example.com', 'hash');
		await store.destroy(user._id);

		/* A deletion schedules (specs/090); Delete now is the destruction. */
		await deleteBucket(held._id);
		const res = await agent.admin.api
			.projects({ id: held._id })
			.purge.post(undefined, { headers: { cookie: await superAdminCookie() } });

		expect(res.status).toBe(200);
		expect(await getBucketStore().find(held._id)).toBeNull();
		// In memory there is no collection to drop, so the area's emptiness is the observable half; the
		// MongoDB drop is covered by the manual procedure in quickstart § 4.4.
		expect(await getUserStore(held._id).list()).toEqual([]);
		expect(userAreaFor(held._id)).toBe(`user_${held._id}`);
	});

	// A conflict is not a partial deletion: nothing is written, including the audit trail.
	it('changes nothing when it refuses', async () => {
		const holding = await bucket();
		const clientId = await liveClient(holding._id);
		const held = await bucket();
		await getUserStore(held._id).create('stays@example.com', 'hash');

		expect((await deleteBucket(holding._id)).status).toBe(409);
		expect((await deleteBucket(held._id)).status).toBe(409);

		expect(await Client.tryFind(clientId)).toBeDefined();
		for (const { _id } of [holding, held]) {
			const trail = await adminAuditStore.list({ targetId: _id });
			expect(trail.entries.filter((e) => e.action === 'bucket.delete')).toEqual(
				[]
			);
		}
	});

	/*
	 * The two buckets the instance is built on.
	 *
	 * Both are refused before the bucket is even loaded, so the answer cannot depend on whether they
	 * happen to be empty — which matters because emptiness is reachable: the administrators' bucket
	 * holds exactly the accounts an operator could remove one at a time, and the default bucket starts
	 * empty on a fresh install. A super administrator is used deliberately, because there is no higher
	 * authority left to argue the refusal is merely a scoping accident.
	 */
	it('refuses to delete the administrators bucket, whatever is elected', async () => {
		expect((await deleteBucket(ADMIN_BUCKET_ID)).status).toBe(403);
		expect(
			(await deleteBucket(ADMIN_BUCKET_ID, { cascade: 'endusers', expect: 0 }))
				.status
		).toBe(403);
		expect(await getBucketStore().find(ADMIN_BUCKET_ID)).not.toBeNull();
	});

	it('refuses to delete the default bucket, whatever is elected', async () => {
		expect((await deleteBucket(DEFAULT_BUCKET_ID)).status).toBe(403);
		expect(
			(
				await deleteBucket(DEFAULT_BUCKET_ID, {
					cascade: 'endusers',
					expect: 0
				})
			).status
		).toBe(403);
		expect(await getBucketStore().find(DEFAULT_BUCKET_ID)).not.toBeNull();
	});

	/*
	 * An application or API is the one blocker no election clears, because what it protects is outside
	 * the bucket: an integration somebody built on it breaks, and it is removed on purpose, one by one,
	 * never as a side effect of the people in the bucket going.
	 */
	it('refuses a bucket holding an application even when the accounts are consented to', async () => {
		const assigned = await bucket();
		await getUserStore(assigned._id).create('inside@example.com', 'hash');
		await liveClient(assigned._id);

		const res = await deleteBucket(assigned._id, {
			cascade: 'endusers',
			expect: 1
		});

		expect(res.status).toBe(409);
		expect(await getBucketStore().find(assigned._id)).not.toBeNull();
		expect((await getUserStore(assigned._id).list()).length).toBe(1);
	});

	/*
	 * Consent is given for what was on the screen: the election carries the reviewed count rather than
	 * only the word "yes", so an administrator who reviewed one account does not authorise destroying a
	 * second that arrived while they were reading.
	 */
	it('refuses a bucket cascade when it holds more accounts than were consented to', async () => {
		const held = await bucket();
		await getUserStore(held._id).create('reviewed@example.com', 'hash');
		await getUserStore(held._id).create('arrived-later@example.com', 'hash');

		const res = await deleteBucket(held._id, {
			cascade: 'endusers',
			expect: 1
		});

		expect(res.status).toBe(409);
		expect(await getBucketStore().find(held._id)).not.toBeNull();
		expect((await getUserStore(held._id).list()).length).toBe(2);
	});
});
