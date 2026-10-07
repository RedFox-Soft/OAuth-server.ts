import { describe, it, beforeAll, expect } from 'bun:test';

import { getBucketGroupStore } from 'lib/adapters/index.js';
import { SCIM_GROUP_SCHEMA } from 'lib/consts/scim.js';
import bootstrap from '../test_helper.js';
import { adminCookie } from '../end_user_lifecycle/fixtures.ts';
import {
	connect,
	patchOf,
	scim,
	scimBucket,
	scimUser,
	type Connected
} from '../scim/helpers.ts';
import { admin } from './helpers.ts';

/**
 * @proves A bucket whose groups already carry a directory's names can start provisioning them without deleting
 * anything: the directory's create of a taken name is refused, an administrator hands the existing group over
 * explicitly — never with someone the connection does not manage inside it — and from then on the group is the
 * directory's alone; a connection that owns groups cannot be deleted (spec 071, User Story 5, FR-008, FR-010,
 * FR-012).
 */
describe('handing an administrator-kept group to a provisioning connection', () => {
	let cookie: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'provisioning' });
		cookie = await adminCookie();
	});

	async function keptGroup(c: Connected, displayName: string): Promise<string> {
		const res = await admin(
			'POST',
			`/admin/api/buckets/${c.bucket._id}/groups`,
			cookie,
			{ displayName }
		);
		expect(res.status).toBe(201);
		return res.json.id as string;
	}

	async function provisionedUser(c: Connected): Promise<string> {
		return (
			await scim('POST', `${c.base}/Users`, {
				token: c.token,
				body: scimUser(`p-${Math.random().toString(36).slice(2)}@contoso.com`)
			})
		).json.id as string;
	}

	function assign(c: Connected, gid: string) {
		return admin(
			'POST',
			`/admin/api/buckets/${c.bucket._id}/groups/${gid}/connection`,
			cookie,
			{ connectionId: c.connection._id }
		);
	}

	it('refuses the directory’s create of a name an administrator-kept group holds', async () => {
		const c = await connect(await scimBucket());
		await keptGroup(c, 'Finance');

		const res = await scim('POST', `${c.base}/Groups`, {
			token: c.token,
			body: { schemas: [SCIM_GROUP_SCHEMA], displayName: 'finance' }
		});

		expect(res.status).toBe(409);
		expect(res.json.scimType).toBe('uniqueness');
	});

	it('lets the connection find an assigned group by name, with its id and members kept', async () => {
		const c = await connect(await scimBucket());
		const gid = await keptGroup(c, 'Finance');
		const member = await provisionedUser(c);
		await admin(
			'POST',
			`/admin/api/buckets/${c.bucket._id}/groups/${gid}/members`,
			cookie,
			{ userIds: [member] }
		);

		const assigned = await assign(c, gid);
		const found = await scim(
			'GET',
			`${c.base}/Groups?filter=${encodeURIComponent('displayName eq "Finance"')}`,
			{ token: c.token }
		);

		expect(assigned.status).toBe(200);
		const [group] = found.json.Resources as {
			id: string;
			members: { value: string }[];
		}[];
		expect(group.id).toBe(gid);
		expect(group.members.map((m) => m.value)).toEqual([member]);
	});

	it('makes an assigned group read-only to administrators', async () => {
		const c = await connect(await scimBucket());
		const gid = await keptGroup(c, 'Finance');
		await assign(c, gid);

		const renamed = await admin(
			'PATCH',
			`/admin/api/buckets/${c.bucket._id}/groups/${gid}`,
			cookie,
			{ displayName: 'Mine' }
		);
		const deleted = await admin(
			'DELETE',
			`/admin/api/buckets/${c.bucket._id}/groups/${gid}`,
			cookie
		);

		expect(renamed.status).toBe(409);
		expect(deleted.status).toBe(409);
		expect((await getBucketGroupStore().find(gid))?.displayName).toBe(
			'Finance'
		);
	});

	it('lets the connection change an assigned group', async () => {
		const c = await connect(await scimBucket());
		const gid = await keptGroup(c, 'Finance');
		await assign(c, gid);

		const res = await scim('PATCH', `${c.base}/Groups/${gid}`, {
			token: c.token,
			body: patchOf([
				{ op: 'replace', path: 'displayName', value: 'Finance EU' }
			])
		});

		expect(res.status).toBe(204);
		expect((await getBucketGroupStore().find(gid))?.displayName).toBe(
			'Finance EU'
		);
	});

	it('refuses to assign a group holding someone the connection does not manage', async () => {
		const c = await connect(await scimBucket());
		const gid = await keptGroup(c, 'Finance');
		const local = await admin(
			'POST',
			`/admin/api/buckets/${c.bucket._id}/users`,
			cookie,
			{ email: 'local@contoso.com', password: 'a password that is long enough' }
		);
		await admin(
			'POST',
			`/admin/api/buckets/${c.bucket._id}/groups/${gid}/members`,
			cookie,
			{ userIds: [local.json._id] }
		);

		const res = await assign(c, gid);

		expect(res.status).toBe(409);
		expect(
			(await getBucketGroupStore().find(gid))?.provisionedBy
		).toBeUndefined();
	});

	it('refuses to delete a connection that owns a group, counting users and groups', async () => {
		const c = await connect(await scimBucket());
		await scim('POST', `${c.base}/Groups`, {
			token: c.token,
			body: { schemas: [SCIM_GROUP_SCHEMA], displayName: 'Owned' }
		});

		const res = await admin(
			'DELETE',
			`/admin/api/buckets/${c.bucket._id}/provisioning-connections/${c.connection._id}`,
			cookie
		);

		expect(res.status).toBe(409);
		expect(res.json.blockers).toEqual([{ kind: 'bucketgroup', count: 1 }]);
	});
});
