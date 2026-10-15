import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import {
	adapter,
	adminAuditStore,
	getBucketStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ADMIN_SESSION_COOKIE, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { sessionFor } from '../admin_session.ts';
import { answered } from '../admin/answered.ts';
import { createAdministrator } from '../administrators.ts';
import { present, shaped } from '../shape.ts';
import { elysia } from 'lib/index.ts';
import { Type } from '@sinclair/typebox';
import { regularGroup } from '../admin/ownership_fixtures.ts';

// A bucket may take its accounts with it, on an election the administrator makes separately from
// confirming the deletion.
//
// The claims worth proving here are the ones an operator would be wrong about if they guessed. That a
// cascaded account is destroyed as completely as one deleted on its own — including the records addressed
// by its email, which nothing else points at. And that one deletion leaves one entry, because a trail
// nobody can read is not a record.

/**
 * @proves A bucket deleted with its accounts destroys each of them completely and leaves exactly one
 * entry in the trail whatever it destroyed — an entry the group that owned the bucket can read. A bucket
 * holding accounts is deleted only by an owner of its group or a super administrator.
 */
describe('deletion cascade: containers', () => {
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

	/* A deletion and then Delete now: the destruction itself, since a deletion only schedules it (specs/090). */
	async function destroyBucketNow(id: string, query: Record<string, unknown>) {
		await deleteBucket(id, query);
		const cookie = await superAdminCookie();
		return agent.admin.api
			.projects({ id })
			.purge.post(undefined, { headers: { cookie }, query });
	}

	async function entriesFor(targetId: string, action: string) {
		const trail = await adminAuditStore.list({ targetId });
		return trail.entries.filter((e) => e.action === action);
	}

	it('removes a bucket and its end-user accounts when the administrator consents to their destruction', async () => {
		const held = await bucket();
		await getUserStore(held._id).create('one@example.com', 'hash');
		await getUserStore(held._id).create('two@example.com', 'hash');

		const res = await destroyBucketNow(held._id, {
			cascade: 'endusers',
			expect: 2
		});

		expect(res.status).toBe(200);
		expect(answered(res.data).endUsersDestroyed).toBe(2);
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
			(await destroyBucketNow(held._id, { cascade: 'endusers', expect: 1 }))
				.status
		).toBe(200);

		expect(await adapter('VerificationResend').find(scopedId)).toBe(undefined);
	});

	/*
	 * For every bucket deletion, the trail grows by exactly one entry — checked against a bucket holding
	 * one account and one holding several, because a per-item trail passes the single-item case and only
	 * diverges as the deletion gets big enough to matter.
	 */
	it('writes exactly one entry per deletion, whether the bucket held one account or several', async () => {
		const one = await bucket();
		await getUserStore(one._id).create('only@example.com', 'hash');
		expect(
			(await deleteBucket(one._id, { cascade: 'endusers', expect: 1 })).status
		).toBe(200);
		expect((await entriesFor(one._id, 'bucket.delete')).length).toBe(1);

		const several = await bucket();
		await getUserStore(several._id).create('a@example.com', 'hash');
		await getUserStore(several._id).create('b@example.com', 'hash');
		await getUserStore(several._id).create('c@example.com', 'hash');
		expect(
			(await deleteBucket(several._id, { cascade: 'endusers', expect: 3 }))
				.status
		).toBe(200);
		expect((await entriesFor(several._id, 'bucket.delete')).length).toBe(1);
	});

	/*
	 * A count says what went; an identifier would say who. The trail already holds field names and
	 * never their values for exactly this reason, and a cascade must not be the exception that
	 * introduces personal data to an append-only store nobody can edit afterwards.
	 */
	it('records what a deletion destroyed as counts, carrying no identifier of it', async () => {
		const held = await bucket();
		const account = await getUserStore(held._id).create(
			'private@example.com',
			'hash'
		);
		await deleteBucket(held._id, { cascade: 'endusers', expect: 1 });

		const bucketEntry = present(
			(await entriesFor(held._id, 'bucket.delete')).at(0),
			'the bucket.delete entry'
		);
		expect(bucketEntry.cascade).toEqual({ endusers: 1 });
		const serialised = JSON.stringify(bucketEntry);
		expect(serialised).not.toContain('private@example.com');
		expect(serialised).not.toContain(account._id);
	});

	/*
	 * An empty bucket says nothing rather than saying zero: an entry from before cascades existed and an
	 * entry for a deletion that took nothing with it are the same fact, and should read as one.
	 */
	it('records no cascade for a deletion that destroyed only the bucket', async () => {
		const empty = await bucket();
		await deleteBucket(empty._id);

		// Present first: with no entry at all, `cascade` would read as absent and the case would pass.
		const entry = present(
			(await entriesFor(empty._id, 'bucket.delete')).at(0),
			'the bucket.delete entry'
		);
		expect(entry.cascade ?? null).toBeNull();
	});

	describe('by a member of the group that owns the bucket', () => {
		async function asMember(
			user: Awaited<ReturnType<typeof createAdministrator>>
		) {
			const session = await sessionFor(user);
			return `${ADMIN_SESSION_COOKIE}=${session._id}`;
		}

		async function call(method: string, path: string, cookie: string) {
			const response = await elysia.handle(
				new Request(`http://e.ly${path}`, { method, headers: { cookie } })
			);
			return {
				status: response.status,
				body: shaped(
					Type.Record(Type.String(), Type.Unknown()),
					await response.json()
				)
			};
		}

		it('shows the deletion in the trail of the group that owned the bucket', async () => {
			const owner = await createAdministrator('plain');
			const team = await regularGroup([owner]);
			const held = await getBucketStore().create({
				name: `b-${Math.random()}`,
				ownerGroupId: team._id
			});
			await getUserStore(held._id).create('leaving@example.com', 'hash');
			const cookie = await asMember(owner);

			const deleted = await call(
				'DELETE',
				`/admin/api/projects/${held._id}?cascade=endusers&expect=1`,
				cookie
			);
			const trail = await call(
				'GET',
				`/admin/api/audit?targetId=${encodeURIComponent(held._id)}`,
				cookie
			);

			expect(deleted.status).toBe(200);
			expect(
				shaped(
					Type.Array(Type.Object({ action: Type.String() })),
					trail.body.entries
				).map((e) => e.action)
			).toContain('project.delete');
		});

		it('refuses a member who is not an owner a bucket holding accounts, and says why', async () => {
			const owner = await createAdministrator('plain');
			const member = await createAdministrator('plain');
			const team = await regularGroup([owner], [member]);
			const held = await getBucketStore().create({
				name: `b-${Math.random()}`,
				ownerGroupId: team._id
			});
			await getUserStore(held._id).create('staying@example.com', 'hash');
			await getUserStore(held._id).create('also@example.com', 'hash');

			const refused = await call(
				'DELETE',
				`/admin/api/projects/${held._id}?cascade=endusers&expect=2`,
				await asMember(member)
			);

			expect(refused.status).toBe(403);
			expect(refused.body.message).toBe(
				'This project holds 2 accounts: only an owner of its team can delete it.'
			);
			expect((await getUserStore(held._id).list()).length).toBe(2);
		});

		it('lets a member who is not an owner schedule the deletion of a bucket holding no accounts', async () => {
			const owner = await createAdministrator('plain');
			const member = await createAdministrator('plain');
			const team = await regularGroup([owner], [member]);
			const empty = await getBucketStore().create({
				name: `b-${Math.random()}`,
				ownerGroupId: team._id
			});

			const deleted = await call(
				'DELETE',
				`/admin/api/projects/${empty._id}`,
				await asMember(member)
			);

			expect(deleted.status).toBe(200);
			expect((await getBucketStore().find(empty._id))?.deletion).toBeDefined();
		});
	});
});
