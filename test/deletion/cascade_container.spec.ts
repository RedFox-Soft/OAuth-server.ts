import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import {
	adapter,
	adminAuditStore,
	getBucketStore,
	getProjectStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	ADMIN_BUCKET_ID,
	ADMIN_SESSION_COOKIE,
	UNASSIGNED_GROUP_ID
} from 'lib/admin/consts.ts';
import { Client } from 'lib/models/client.js';
import { sessionFor } from '../admin_session.ts';

// A container may take its contents with it, on an election the administrator makes separately from
// confirming the deletion.
//
// The claims worth proving here are the ones an operator would be wrong about if they guessed. That a
// cascaded client is destroyed as completely as one deleted on its own — the shallow version, where the
// record goes and the tokens do not, is the failure mode that looks correct from the console. That a
// project never reaches its bucket, because buckets are shared and hold people the project never knew
// about. And that one deletion leaves one entry, because a trail nobody can read is not a record.

/**
 * @proves A container deleted with its contents destroys each of them as completely as deleting
 * that one thing would, never reaches a bucket it merely pointed at, and leaves exactly one entry
 * in the trail whatever it destroyed.
 */
describe('deletion cascade: containers', () => {
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

	async function entriesFor(targetId: string, action: string) {
		const trail = await adminAuditStore.list({ targetId });
		return trail.entries.filter((e) => e.action === action);
	}

	it('removes a project and its clients when the administrator consents to their destruction', async () => {
		const first = await liveClient();
		const second = await liveClient();
		const proj = await project([first, second]);

		const res = await deleteProject(proj._id, {
			cascade: 'clients',
			client: [first, second]
		});

		expect(res.status).toBe(200);
		expect((res.data as { clientsDestroyed: number }).clientsDestroyed).toBe(2);
		expect(await getProjectStore().find(proj._id)).toBeNull();
		expect(await Client.tryFind(first)).toBeUndefined();
		expect(await Client.tryFind(second)).toBeUndefined();
	});

	/*
	 * The shallow cascade is the one that looks right from the console: the client is gone from the
	 * list and from the project, so the operator concludes the deletion took effect — while the
	 * registration access token it holds may carry no expiry at all, so its residue is not even bounded
	 * by a TTL. A cascaded client has to be destroyed the way a directly deleted one is, not almost.
	 */
	it('destroys a cascaded client records as completely as deleting that client alone would', async () => {
		const clientId = await liveClient();
		await adapter('RegistrationAccessToken').upsert(`rat-${clientId}`, {
			jti: `rat-${clientId}`,
			kind: 'RegistrationAccessToken',
			clientId,
			iat: Math.floor(Date.now() / 1000)
		});
		const proj = await project([clientId]);

		expect(
			(
				await deleteProject(proj._id, {
					cascade: 'clients',
					client: [clientId]
				})
			).status
		).toBe(200);

		expect(
			await adapter('RegistrationAccessToken').find(`rat-${clientId}`)
		).toBe(undefined);
	});

	/*
	 * The instruction that is easy to be helpful about and wrong. A bucket is shared between projects
	 * and holds people who have no relationship with any one of them, so no project deletion reaches
	 * one — not even the bucket that project alone was pointing at, and not under any election.
	 */
	it('leaves a projects bucket and every account in it intact when the project is deleted', async () => {
		const backing = await bucket();
		const account = await getUserStore(backing._id).create(
			'resident@example.com',
			'hash'
		);
		const clientId = await liveClient();
		const proj = await project([clientId], backing._id);

		expect(
			(
				await deleteProject(proj._id, {
					cascade: 'clients',
					client: [clientId]
				})
			).status
		).toBe(200);

		expect(await getBucketStore().find(backing._id)).not.toBeNull();
		expect(await getUserStore(backing._id).find(account._id)).not.toBeNull();
	});

	it('removes a bucket and its end-user accounts when the administrator consents to their destruction', async () => {
		const held = await bucket();
		await getUserStore(held._id).create('one@example.com', 'hash');
		await getUserStore(held._id).create('two@example.com', 'hash');

		const res = await deleteBucket(held._id, {
			cascade: 'endusers',
			expect: 2
		});

		expect(res.status).toBe(200);
		expect((res.data as { endUsersDestroyed: number }).endUsersDestroyed).toBe(
			2
		);
		expect(await getBucketStore().find(held._id)).toBeNull();
		expect(await getUserStore(held._id).list()).toEqual([]);
	});

	/*
	 * The email-scoped areas are addressed by `${bucketId}:${email}` and nothing else records the
	 * email, so a cascade that destroys the account row first reaches none of them — silently, with no
	 * error anywhere, looking correct in every test that does not assert exactly this.
	 */
	it('destroys the email-addressed records of a cascaded account', async () => {
		const held = await bucket();
		await getUserStore(held._id).create('scoped@example.com', 'hash');
		const scopedId = `${held._id}:scoped@example.com`;
		const now = Math.floor(Date.now() / 1000);
		const ttl = 3600;
		await adapter('VerificationResend').upsert(
			scopedId,
			{
				lastSentAt: now,
				dayCount: 1,
				windowStart: now,
				exp: now + ttl
			},
			ttl
		);

		expect(
			(await deleteBucket(held._id, { cascade: 'endusers', expect: 1 })).status
		).toBe(200);

		expect(await adapter('VerificationResend').find(scopedId)).toBe(undefined);
	});

	/*
	 * For every container deletion, the trail grows by exactly one entry — checked against a container
	 * holding one thing and one holding several, because a per-item trail passes the single-item case
	 * and only diverges as the deletion gets big enough to matter.
	 */
	it('writes exactly one entry per deletion, whether the container held one thing or several', async () => {
		const one = await project([await liveClient()]);
		const oneId = one.clientIds[0] as string;
		expect(
			(await deleteProject(one._id, { cascade: 'clients', client: [oneId] }))
				.status
		).toBe(200);
		expect((await entriesFor(one._id, 'project.delete')).length).toBe(1);

		const clients = [
			await liveClient(),
			await liveClient(),
			await liveClient()
		];
		const several = await project(clients);
		expect(
			(
				await deleteProject(several._id, {
					cascade: 'clients',
					client: clients
				})
			).status
		).toBe(200);
		expect((await entriesFor(several._id, 'project.delete')).length).toBe(1);

		const held = await bucket();
		await getUserStore(held._id).create('a@example.com', 'hash');
		await getUserStore(held._id).create('b@example.com', 'hash');
		await getUserStore(held._id).create('c@example.com', 'hash');
		expect(
			(await deleteBucket(held._id, { cascade: 'endusers', expect: 3 })).status
		).toBe(200);
		expect((await entriesFor(held._id, 'bucket.delete')).length).toBe(1);
	});

	/*
	 * A count says what went; an identifier would say who. The trail already holds field names and
	 * never their values for exactly this reason, and a cascade must not be the exception that
	 * introduces personal data to an append-only store nobody can edit afterwards.
	 */
	it('records what a deletion destroyed as counts, carrying no identifier of it', async () => {
		const clientId = await liveClient();
		const proj = await project([clientId]);
		await deleteProject(proj._id, { cascade: 'clients', client: [clientId] });

		const [projectEntry] = await entriesFor(proj._id, 'project.delete');
		expect(projectEntry?.cascade).toEqual({ clients: 1 });
		expect(JSON.stringify(projectEntry)).not.toContain(clientId);

		const held = await bucket();
		const account = await getUserStore(held._id).create(
			'private@example.com',
			'hash'
		);
		await deleteBucket(held._id, { cascade: 'endusers', expect: 1 });

		const [bucketEntry] = await entriesFor(held._id, 'bucket.delete');
		expect(bucketEntry?.cascade).toEqual({ endusers: 1 });
		const serialised = JSON.stringify(bucketEntry);
		expect(serialised).not.toContain('private@example.com');
		expect(serialised).not.toContain(account._id);
	});

	/*
	 * An empty container says nothing rather than saying zero: an entry from before cascades existed
	 * and an entry for a deletion that took nothing with it are the same fact, and should read as one.
	 */
	it('records no cascade for a deletion that destroyed only the container', async () => {
		const empty = await project([]);
		await deleteProject(empty._id);

		const [entry] = await entriesFor(empty._id, 'project.delete');
		expect(entry?.cascade ?? null).toBeNull();
	});
});
