import { describe, it, beforeAll, expect } from 'bun:test';

import { getBucketGroupStore } from 'lib/adapters/index.js';
import bootstrap from '../test_helper.js';
import {
	connect,
	patchOf,
	scim,
	scimBucket,
	scimUser,
	type Connected
} from './helpers.ts';

const SIZE = 10_000;

/**
 * @proves A directory can keep a large group — 10,000 members — over SCIM: read it, list it without its
 * members, and change it by PATCH with the rest of the group left as it was (spec 071, SC-004). How long that
 * takes on a real database is measured by the database verification scripts, not here.
 */
describe('a 10,000-member group over SCIM', () => {
	let c: Connected;
	let gid: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'scim' });
		c = await connect(await scimBucket());
		/* Seeded through the store: the property is about reading and changing a large group, not building one. */
		const seeded = Array.from(
			{ length: SIZE },
			(_, i) => `seed${i.toString().padStart(6, '0')}`
		);
		gid = (
			await getBucketGroupStore().create(
				{
					_id: 'large-group',
					bucketId: c.bucket._id,
					displayName: 'Everyone',
					provisionedBy: c.connection._id
				},
				seeded
			)
		)._id;
	});

	it('reads every member of the group by id', async () => {
		const res = await scim('GET', `${c.base}/Groups/${gid}`, {
			token: c.token
		});

		expect((res.json.members as unknown[]).length).toBe(SIZE);
	});

	it('lists the group without its members when members are excluded', async () => {
		const res = await scim(
			'GET',
			`${c.base}/Groups?excludedAttributes=members&filter=${encodeURIComponent('displayName eq "Everyone"')}`,
			{ token: c.token }
		);

		const [group] = res.json.Resources as Record<string, unknown>[];
		expect(group.id).toBe(gid);
		expect(group.members).toBeUndefined();
	});

	it('adds a member by PATCH and leaves the other members as they were', async () => {
		const added = (
			await scim('POST', `${c.base}/Users`, {
				token: c.token,
				body: scimUser('newcomer@contoso.com')
			})
		).json.id as string;

		const res = await scim('PATCH', `${c.base}/Groups/${gid}`, {
			token: c.token,
			body: patchOf([{ op: 'add', path: 'members', value: [{ value: added }] }])
		});

		expect(res.status).toBe(204);
		const after = await getBucketGroupStore().memberIds(gid);
		expect(after.length).toBe(SIZE + 1);
		expect(after).toContain(added);
		expect(after).toContain('seed000000');
	});
});
