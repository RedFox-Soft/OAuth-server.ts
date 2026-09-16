import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import {
	adapter,
	adminAuditStore,
	adminSessionStore,
	getBucketStore,
	getProjectStore,
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
import { userAreaFor } from 'lib/consts/storage_inventory.js';
import { sessionFor } from '../admin_session.ts';

// User Story 3 — a container refuses deletion while it still holds something.
//
// The line between guarding and cascading is drawn by visibility: an operator can see and name a
// project's clients, so refusing tells them exactly what they are about to destroy and keeps one audit
// entry per entity destroyed. Nobody can be asked to enumerate the tokens a client issued.
//
// The *shape* of the refusal body belongs to User Story 4; here the claims are that the refusal happens,
// that it changes nothing, and that an emptied container then deletes cleanly.

/**
 * @proves A container holding anything is not deleted unless its contents were reviewed and
 * consented to, a refusal changes nothing, an emptied container takes its per-bucket area with it,
 * and the two buckets the instance is built on are refused to everyone.
 */
describe('deletion guards: containers', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		await ensureAdminSeed();
	});

	async function superAdminCookie(): Promise<string> {
		const admin = await getUserStore(ADMIN_BUCKET_ID).create(
			`sa-${Math.random()}@x.io`,
			'hash',
			['super_admin']
		);
		const session = await sessionFor(admin);
		return `${ADMIN_SESSION_COOKIE}=${session._id}`;
	}

	async function liveClient(): Promise<string> {
		const clientId = `held-${Math.random().toString(36).slice(2)}`;
		await adapter('Client').upsert(clientId, {
			clientId,
			clientSecret: 'secret',
			grantTypes: ['authorization_code'],
			responseTypes: ['code'],
			redirectUris: [`https://${clientId}.example.com/cb`]
		});
		return clientId;
	}

	async function project(clientIds: string[], bucketId?: string) {
		return getProjectStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'P',
			slug: `p-${Math.random()}`,
			clientIds,
			...(bucketId ? { bucketId } : {})
		});
	}

	async function bucket() {
		return getBucketStore().create({
			name: `b-${Math.random()}`,
			roles: [],
			ownerGroupId: UNASSIGNED_GROUP_ID
		});
	}

	async function deleteProject(id: string, query?: Record<string, unknown>) {
		const cookie = await superAdminCookie();
		return agent.admin.api
			.projects({ id })
			.delete(undefined, { headers: { cookie }, ...(query ? { query } : {}) });
	}

	async function deleteBucket(id: string, query?: Record<string, unknown>) {
		const cookie = await superAdminCookie();
		return agent.admin.api
			.buckets({ id })
			.delete(undefined, { headers: { cookie }, ...(query ? { query } : {}) });
	}

	async function deleteClient(projectId: string, clientId: string) {
		const cookie = await superAdminCookie();
		return agent.admin.api
			.projects({ id: projectId })
			.clients({ clientId })
			.delete(undefined, { headers: { cookie } });
	}

	it('refuses a project that still holds clients (scenario 1)', async () => {
		const clientId = await liveClient();
		const proj = await project([clientId]);

		const res = await deleteProject(proj._id);

		expect(res.status).toBe(409);
		expect(await getProjectStore().find(proj._id)).not.toBeNull();
	});

	it('deletes the project once its clients are gone (scenario 2)', async () => {
		const clientId = await liveClient();
		const proj = await project([clientId]);

		expect((await deleteProject(proj._id)).status).toBe(409);
		expect((await deleteClient(proj._id, clientId)).status).toBe(200);
		const res = await deleteProject(proj._id);

		expect(res.status).toBe(200);
		expect(await getProjectStore().find(proj._id)).toBeNull();
	});

	// An id left in `clientIds` after its client vanished must never make a project undeletable.
	it('deletes a project whose client ids no longer resolve (scenario 3)', async () => {
		const proj = await project(['ghost-a', 'ghost-b']);

		const res = await deleteProject(proj._id);

		expect(res.status).toBe(200);
		expect(await getProjectStore().find(proj._id)).toBeNull();
	});

	it('does not treat an assigned bucket as a blocker (scenario 4)', async () => {
		const assigned = await bucket();
		const proj = await project([], assigned._id);

		const res = await deleteProject(proj._id);

		expect(res.status).toBe(200);
	});

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

	it('keeps the existing refusal for a bucket assigned to a project (scenario 7)', async () => {
		const assigned = await bucket();
		await project([], assigned._id);

		const res = await deleteBucket(assigned._id);

		expect(res.status).toBe(409);
	});

	it('deletes an emptied bucket and drops its user area (scenario 8)', async () => {
		const held = await bucket();
		const store = getUserStore(held._id);
		const user = await store.create('leaving@example.com', 'hash');
		await store.destroy(user._id);

		const res = await deleteBucket(held._id);

		expect(res.status).toBe(200);
		expect(await getBucketStore().find(held._id)).toBeNull();
		// In memory there is no collection to drop, so the area's emptiness is the observable half; the
		// MongoDB drop is covered by the manual procedure in quickstart § 4.4.
		expect(await getUserStore(held._id).list()).toEqual([]);
		expect(userAreaFor(held._id)).toBe(`user_${held._id}`);
	});

	// A conflict is not a partial deletion: nothing is written, including the audit trail.
	it('changes nothing when it refuses', async () => {
		const clientId = await liveClient();
		const proj = await project([clientId, 'ghost']);
		const held = await bucket();
		await getUserStore(held._id).create('stays@example.com', 'hash');

		expect((await deleteProject(proj._id)).status).toBe(409);
		expect((await deleteBucket(held._id)).status).toBe(409);

		const stillThere = await getProjectStore().find(proj._id);
		// The unresolvable id is not tidied up either — a refused request changes nothing at all.
		expect(stillThere?.clientIds).toEqual([clientId, 'ghost']);

		const trail = await adminAuditStore.list({
			targetId: proj._id
		});
		expect(trail.entries.filter((e) => e.action === 'project.delete')).toEqual(
			[]
		);
		const bucketTrail = await adminAuditStore.list({ targetId: held._id });
		expect(
			bucketTrail.entries.filter((e) => e.action === 'bucket.delete')
		).toEqual([]);
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
	 * A bucket assigned to a project is the one blocker no election clears, because what it protects
	 * is outside the bucket: a project left pointing at a bucket that no longer exists is a broken
	 * tenant, not a tidy-up.
	 */
	it('refuses an assigned bucket even when the accounts are consented to', async () => {
		const assigned = await bucket();
		await getUserStore(assigned._id).create('inside@example.com', 'hash');
		await project([], assigned._id);

		const res = await deleteBucket(assigned._id, {
			cascade: 'endusers',
			expect: 1
		});

		expect(res.status).toBe(409);
		expect(await getBucketStore().find(assigned._id)).not.toBeNull();
		expect((await getUserStore(assigned._id).list()).length).toBe(1);
	});

	/*
	 * Consent is given for what was on the screen. These two cases are the reason the election carries
	 * the reviewed set rather than only the word "yes": without them, an administrator who reviewed two
	 * clients authorises destroying a third that arrived while they were reading.
	 */
	it('refuses a project cascade when its clients are not the ones consented to', async () => {
		const reviewed = await liveClient();
		const arrivedLater = await liveClient();
		const proj = await project([reviewed, arrivedLater]);

		const res = await deleteProject(proj._id, {
			cascade: 'clients',
			client: [reviewed]
		});

		expect(res.status).toBe(409);
		expect(await getProjectStore().find(proj._id)).not.toBeNull();
		expect(await Client.tryFind(reviewed)).toBeDefined();
		expect(await Client.tryFind(arrivedLater)).toBeDefined();
	});

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
