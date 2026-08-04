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
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { userAreaFor } from 'lib/consts/storage_inventory.js';

// User Story 3 — a container refuses deletion while it still holds something.
//
// The line between guarding and cascading is drawn by visibility: an operator can see and name a
// project's clients, so refusing tells them exactly what they are about to destroy and keeps one audit
// entry per entity destroyed. Nobody can be asked to enumerate the tokens a client issued.
//
// The *shape* of the refusal body belongs to User Story 4; here the claims are that the refusal happens,
// that it changes nothing, and that an emptied container then deletes cleanly.

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
		const session = await adminSessionStore.create({
			userId: admin._id,
			bucketId: ADMIN_BUCKET_ID,
			tokens: {},
			ttlSeconds: 60,
			absoluteTtlSeconds: 3600
		});
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
			managedBy: []
		});
	}

	async function deleteProject(id: string) {
		const cookie = await superAdminCookie();
		return agent.admin.api
			.projects({ id })
			.delete(undefined, { headers: { cookie } });
	}

	async function deleteBucket(id: string) {
		const cookie = await superAdminCookie();
		return agent.admin.api
			.buckets({ id })
			.delete(undefined, { headers: { cookie } });
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
});
