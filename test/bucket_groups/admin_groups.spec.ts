import { describe, it, beforeAll, expect } from 'bun:test';

import {
	getBucketGroupStore,
	getBucketStore,
	getUserStore
} from 'lib/adapters/index.js';
import { ADMIN_BUCKET_ID, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import bootstrap from '../test_helper.js';
import { adminCookie } from '../end_user_lifecycle/fixtures.ts';
import { connect, scim, scimBucket, scimUser } from '../scim/helpers.ts';
import { shaped } from '../shape.ts';
import { Type } from '@sinclair/typebox';
import {
	addMembers,
	admin,
	auditOf,
	endUser,
	group,
	memberIds,
	outsiderCookie
} from './helpers.ts';

async function bucket(): Promise<string> {
	return (
		await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: `groups-${Math.random()}`
		})
	)._id;
}

/**
 * @proves An administrator keeps a bucket's groups of end users by hand — creates, renames and deletes them and
 * decides who is in them — every change audited, names unique per bucket in any letter case, and no group
 * reachable in the administrators' bucket or by an administrator without authority over the bucket
 * (spec 071, User Story 3).
 */
describe('a bucket group kept by an administrator', () => {
	let cookie: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		cookie = await adminCookie();
	});

	it('records the creation of a group in the audit trail', async () => {
		const gid = await group(cookie, await bucket(), 'Editors');

		expect((await auditOf(cookie, gid)).map((e) => e.action)).toEqual([
			'bucketgroup.create'
		]);
	});

	it('keeps the id of a renamed group, and records the rename', async () => {
		const b = await bucket();
		const gid = await group(cookie, b, 'Editors');

		const renamed = await admin(
			'PATCH',
			`/admin/api/buckets/${b}/groups/${gid}`,
			cookie,
			{ displayName: 'Editors-EU' }
		);

		expect(renamed.status).toBe(200);
		expect(renamed.json).toMatchObject({ id: gid, displayName: 'Editors-EU' });
		expect((await auditOf(cookie, gid)).map((e) => e.action)).toContain(
			'bucketgroup.update'
		);
	});

	it('answers 404 for a deleted group, and records the deletion', async () => {
		const b = await bucket();
		const gid = await group(cookie, b, 'Editors');

		const deleted = await admin(
			'DELETE',
			`/admin/api/buckets/${b}/groups/${gid}`,
			cookie
		);
		const after = await admin(
			'GET',
			`/admin/api/buckets/${b}/groups/${gid}`,
			cookie
		);

		expect(deleted.status).toBe(204);
		expect(after.status).toBe(404);
		expect((await auditOf(cookie, gid)).map((e) => e.action)).toContain(
			'bucketgroup.delete'
		);
	});

	it('refuses a second name differing only in letter case within the bucket', async () => {
		const b = await bucket();
		await group(cookie, b, 'Editors');

		const res = await admin('POST', `/admin/api/buckets/${b}/groups`, cookie, {
			displayName: 'editors'
		});

		expect(res.status).toBe(409);
	});

	it('accepts the same name in another bucket', async () => {
		await group(cookie, await bucket(), 'Editors');

		const res = await admin(
			'POST',
			`/admin/api/buckets/${await bucket()}/groups`,
			cookie,
			{ displayName: 'Editors' }
		);

		expect(res.status).toBe(201);
	});

	it('writes no second membership and no audit entry when an existing member is added again', async () => {
		const b = await bucket();
		const gid = await group(cookie, b, 'Readers');
		const uid = await endUser(cookie, b);
		await addMembers(cookie, b, gid, [uid]);
		const before = (await auditOf(cookie, gid)).length;

		const again = await addMembers(cookie, b, gid, [uid]);

		expect(again.status).toBe(200);
		expect(await memberIds(cookie, b, gid)).toEqual([uid]);
		expect((await auditOf(cookie, gid)).length).toBe(before);
	});

	it('records a membership change by attribute name, never the member', async () => {
		const b = await bucket();
		const gid = await group(cookie, b, 'Readers');
		const uid = await endUser(cookie, b);

		await addMembers(cookie, b, gid, [uid]);

		const entry = (await auditOf(cookie, gid)).find(
			(e) => e.action === 'bucketgroup.member.add'
		);
		expect(entry?.attributes).toEqual(['members']);
		expect(JSON.stringify(entry)).not.toContain(uid);
	});

	it('removes a member', async () => {
		const b = await bucket();
		const gid = await group(cookie, b, 'Readers');
		const [u1, u2] = [await endUser(cookie, b), await endUser(cookie, b)];
		await addMembers(cookie, b, gid, [u1, u2]);

		const res = await admin(
			'DELETE',
			`/admin/api/buckets/${b}/groups/${gid}/members/${u1}`,
			cookie
		);

		expect(res.status).toBe(200);
		expect(await memberIds(cookie, b, gid)).toEqual([u2]);
	});

	it('refuses a member who is not an end user of the bucket', async () => {
		const b = await bucket();
		const gid = await group(cookie, b, 'Readers');
		const elsewhere = await endUser(cookie, await bucket());

		const res = await addMembers(cookie, b, gid, [elsewhere]);

		expect(res.status).toBe(422);
		expect(await memberIds(cookie, b, gid)).toEqual([]);
	});

	it('takes a provisioned user as a member and leaves the user as provisioned', async () => {
		const c = await connect(await scimBucket());
		const made = await scim('POST', `${c.base}/Users`, {
			token: c.token,
			body: scimUser('ann@contoso.com')
		});
		const uid = made.json.id as string;
		const gid = await group(cookie, c.bucket._id, 'Local reviewers');

		const res = await addMembers(cookie, c.bucket._id, gid, [uid]);

		expect(res.status).toBe(200);
		expect(await memberIds(cookie, c.bucket._id, gid)).toEqual([uid]);
		const user = await getUserStore(c.bucket._id).find(uid);
		expect(user?.provisionedBy).toBe(c.connection._id);
	});

	it('shows an end user the groups they are in', async () => {
		const b = await bucket();
		const gid = await group(cookie, b, 'Readers');
		const uid = await endUser(cookie, b);
		await addMembers(cookie, b, gid, [uid]);

		const res = await admin('GET', `/admin/api/buckets/${b}/users`, cookie);

		const listed = shaped(
			Type.Array(Type.Object({ _id: Type.String(), groups: Type.Unknown() })),
			res.body
		).find((u) => u._id === uid);
		expect(listed?.groups).toEqual([{ id: gid, displayName: 'Readers' }]);
	});

	it('keeps a deactivated user in their groups', async () => {
		const b = await bucket();
		const gid = await group(cookie, b, 'Readers');
		const uid = await endUser(cookie, b);
		await addMembers(cookie, b, gid, [uid]);

		await admin('PATCH', `/admin/api/buckets/${b}/users/${uid}`, cookie, {
			active: false
		});

		expect(await memberIds(cookie, b, gid)).toEqual([uid]);
	});

	it('takes a deleted user out of every group', async () => {
		const b = await bucket();
		const gid = await group(cookie, b, 'Readers');
		const uid = await endUser(cookie, b);
		await addMembers(cookie, b, gid, [uid]);

		await admin('DELETE', `/admin/api/buckets/${b}/users/${uid}`, cookie);

		expect(await memberIds(cookie, b, gid)).toEqual([]);
	});

	it('is deleted with its bucket', async () => {
		const b = await bucket();
		const gid = await group(cookie, b, 'Readers');

		const res = await admin('DELETE', `/admin/api/buckets/${b}`, cookie);

		expect(res.status).toBe(200);
		expect(await getBucketGroupStore().find(gid)).toBeNull();
	});

	it('cannot be read or changed by an administrator without authority over the bucket', async () => {
		const b = await bucket();
		const gid = await group(cookie, b, 'Readers');
		const outsider = await outsiderCookie();

		const read = await admin('GET', `/admin/api/buckets/${b}/groups`, outsider);
		const write = await admin(
			'PATCH',
			`/admin/api/buckets/${b}/groups/${gid}`,
			outsider,
			{ displayName: 'Mine' }
		);

		expect([403, 404]).toContain(read.status);
		expect([403, 404]).toContain(write.status);
	});

	it('does not exist in the administrators bucket', async () => {
		const res = await admin(
			'POST',
			`/admin/api/buckets/${ADMIN_BUCKET_ID}/groups`,
			cookie,
			{ displayName: 'Operators' }
		);
		const list = await admin(
			'GET',
			`/admin/api/buckets/${ADMIN_BUCKET_ID}/groups`,
			cookie
		);

		expect([403, 404]).toContain(res.status);
		expect([403, 404]).toContain(list.status);
	});
});
