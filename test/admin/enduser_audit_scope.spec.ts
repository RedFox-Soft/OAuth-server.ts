import { beforeEach, describe, expect, it } from 'bun:test';

import { elysia } from 'lib/index.ts';
import { ISSUER } from 'lib/configs/env.js';
import { getUserStore } from 'lib/adapters/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { createAdministrator } from '../administrators.ts';
import {
	bucketWithProjects,
	cookieFor,
	regularGroup
} from './ownership_fixtures.ts';

async function call(
	cookie: string,
	method: string,
	path: string,
	body?: unknown
): Promise<Response> {
	return elysia.handle(
		new Request(`${ISSUER}${path}`, {
			method,
			headers: {
				cookie,
				...(body === undefined ? {} : { 'content-type': 'application/json' })
			},
			...(body === undefined ? {} : { body: JSON.stringify(body) })
		})
	);
}

async function trailOf(cookie: string, bucketId: string, uid: string) {
	const res = await call(
		cookie,
		'GET',
		`/admin/api/audit?targetId=${uid}&targetScope=${bucketId}`
	);
	expect(res.status).toBe(200);
	return ((await res.json()) as { entries: Array<{ action: string }> }).entries;
}

/**
 * @proves An administrator of the group that owns a bucket reads, in the audit trail, what was done to that
 * bucket's people — by them or by anyone — just as they read what was done to the bucket itself.
 */
describe('the trail of a bucket’s people, for the group that owns it', () => {
	let cookie: string;
	let bucketId: string;

	beforeEach(async () => {
		await ensureAdminSeed();
		const admin = await createAdministrator('plain', `a-${Math.random()}@x.io`);
		const group = await regularGroup([admin]);
		bucketId = (await bucketWithProjects(group._id, 0)).bucket._id;
		cookie = await cookieFor(admin);
	});

	it('shows the group’s administrator a change made to one person', async () => {
		const created = await call(
			cookie,
			'POST',
			`/admin/api/buckets/${bucketId}/users`,
			{
				email: `p-${Math.random()}@x.io`,
				password: 'a long enough password'
			}
		);
		expect(created.status).toBe(201);
		const { _id: id } = (await created.json()) as { _id: string };

		const entries = await trailOf(cookie, bucketId, id);

		expect(entries.map((e) => e.action)).toContain('enduser.create');
	});

	it('shows the group’s administrator each person a bulk act reached', async () => {
		const person = await getUserStore(bucketId).create(
			`p-${Math.random()}@x.io`,
			'hash',
			true
		);

		const res = await call(
			cookie,
			'POST',
			`/admin/api/buckets/${bucketId}/users/bulk/deactivate`,
			{
				userIds: [person._id]
			}
		);
		expect(res.status).toBe(200);

		const entries = await trailOf(cookie, bucketId, person._id);
		expect(entries.map((e) => e.action)).toEqual(['enduser.bulk.deactivate']);
	});
});
