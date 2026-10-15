import { describe, it, beforeAll, expect } from 'bun:test';
import { Type } from '@sinclair/typebox';

import { getBucketStore, getUserStore } from 'lib/adapters/index.js';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import bootstrap from '../test_helper.js';
import { adminCookie } from '../end_user_lifecycle/fixtures.ts';
import { shaped } from '../shape.ts';
import { addMembers, admin, group } from './helpers.ts';

const Page = Type.Object({
	totalResults: Type.Number(),
	members: Type.Array(
		Type.Object({
			id: Type.String(),
			email: Type.Union([Type.String(), Type.Null()])
		})
	)
});

/* Thirty ordinary members, three whose address starts with "ann", and one known by a username. */
const ORDINARY = Array.from(
	{ length: 30 },
	(_, i) => `member${String(i).padStart(2, '0')}@x.io`
);
const ANNS = ['anna.member@x.io', 'anne.member@x.io', 'annie.member@x.io'];

/**
 * @proves An administrator finds a member of a large bucket group by the start of their email or username, in
 * any letter case: only members match, never a matching non-member, the total is the matching members', and
 * the result pages like the whole list does.
 */
describe('searching a bucket group’s members', () => {
	let cookie: string;
	let bucketId: string;
	let gid: string;

	async function search(
		q: string,
		paging: { startIndex?: number; count?: number } = {}
	) {
		const params = new URLSearchParams({ q });
		if (paging.startIndex) params.set('startIndex', String(paging.startIndex));
		if (paging.count) params.set('count', String(paging.count));
		const res = await admin(
			'GET',
			`/admin/api/projects/${bucketId}/groups/${gid}/members?${params.toString()}`,
			cookie
		);
		expect(res.status).toBe(200);
		return shaped(Page, res.body);
	}

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		cookie = await adminCookie();
		bucketId = (
			await getBucketStore().create({
				ownerGroupId: UNASSIGNED_GROUP_ID,
				name: `member-search-${Math.random()}`
			})
		)._id;
		const store = getUserStore(bucketId);
		const members: string[] = [];
		for (const email of [...ORDINARY, ...ANNS]) {
			members.push((await store.create(email, 'h', true))._id);
		}
		members.push(
			(
				await store.create('z@x.io', 'h', true, undefined, {
					userName: 'Zed.Member'
				})
			)._id
		);
		/* Matching addresses outside the group. */
		await store.create('anna.outsider@x.io', 'h', true);
		await store.create('member99@x.io', 'h', true);

		gid = await group(cookie, bucketId, 'Large group');
		expect((await addMembers(cookie, bucketId, gid, members)).status).toBe(200);
	});

	it('finds the members whose email starts with the text, in any letter case, and no one outside', async () => {
		const page = await search('ANN');

		expect(page.members.map((m) => m.email).sort()).toEqual(ANNS);
		expect(page.totalResults).toBe(ANNS.length);
	});

	it('finds a member by the start of their username', async () => {
		const page = await search('zed');

		expect(page.members.map((m) => m.email)).toEqual(['z@x.io']);
	});

	it('pages through the matching members with the total of all of them', async () => {
		const first = await search('member', { count: 20 });
		const second = await search('member', { startIndex: 21, count: 20 });

		const seen = [...first.members, ...second.members].map((m) => m.email);
		expect(first.totalResults).toBe(ORDINARY.length);
		expect(seen.sort()).toEqual([...ORDINARY].sort());
	});

	it('answers an empty page when nobody matches', async () => {
		expect(await search('nobody-starts-like-this')).toEqual({
			totalResults: 0,
			members: []
		});
	});
});
