import { describe, it, beforeAll, expect } from 'bun:test';

import { getUserStore } from 'lib/adapters/index.js';
import bootstrap from '../test_helper.js';
import { adminCookie } from '../end_user_lifecycle/fixtures.ts';
import {
	connect,
	provider,
	scim,
	scimBucket,
	scimUser
} from '../scim/helpers.ts';
import { admin } from './helpers.ts';

/**
 * @proves A bucket that already holds people can start provisioning without duplicating them: an
 * administrator hands a local user to the connection, and nothing else — least of all a matching email —
 * hands one over (spec 070, User Story 2, scenario 11; FR-007a; Edge Cases).
 */
describe('handing a local user to a provisioning connection', () => {
	let cookie: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		cookie = await adminCookie();
	});

	async function localUser(bucketId: string, email: string): Promise<string> {
		const res = await admin(
			'POST',
			`/admin/api/buckets/${bucketId}/users`,
			cookie,
			{
				email,
				password: 'a password that is long enough'
			}
		);
		expect(res.status).toBe(201);
		return res.json._id as string;
	}

	it('lets the connection find the user by its next filter, and makes the user read-only to administrators', async () => {
		const c = await connect(await scimBucket());
		const uid = await localUser(c.bucket._id, 'olga@contoso.com');

		const assigned = await admin(
			'POST',
			`/admin/api/buckets/${c.bucket._id}/users/${uid}/connection`,
			cookie,
			{ connectionId: c.connection._id, userName: 'olga@contoso.com' }
		);
		const found = await scim(
			'GET',
			`${c.base}/Users?filter=${encodeURIComponent('userName eq "olga@contoso.com"')}`,
			{ token: c.token }
		);
		const edited = await admin(
			'PATCH',
			`/admin/api/buckets/${c.bucket._id}/users/${uid}`,
			cookie,
			{ active: false }
		);

		expect(assigned.status).toBe(200);
		expect(found.json).toMatchObject({ totalResults: 1 });
		expect((found.json.Resources as { id: string }[])[0].id).toBe(uid);
		expect(edited.status).toBe(409);
	});

	it('refuses to hand over a user another connection already provisioned', async () => {
		const bucket = await scimBucket([provider('one'), provider('two')]);
		const a = await connect(bucket, { providerId: 'one' });
		const b = await connect(bucket, { providerId: 'two' });
		const made = await scim('POST', `${a.base}/Users`, {
			token: a.token,
			body: scimUser('pete@contoso.com')
		});

		const res = await admin(
			'POST',
			`/admin/api/buckets/${bucket._id}/users/${made.json.id}/connection`,
			cookie,
			{ connectionId: b.connection._id, userName: 'pete2@contoso.com' }
		);

		expect(res.status).toBe(409);
		const user = await getUserStore(bucket._id).find(made.json.id as string);
		expect(user?.provisionedBy).toBe(a.connection._id);
	});

	it('refuses a SCIM create that matches a local user’s email, and leaves that user local', async () => {
		const c = await connect(await scimBucket());
		const uid = await localUser(c.bucket._id, 'quinn@contoso.com');

		const res = await scim('POST', `${c.base}/Users`, {
			token: c.token,
			body: scimUser('quinn@contoso.com')
		});

		expect(res.status).toBe(409);
		expect(res.json).toMatchObject({ scimType: 'uniqueness' });
		const user = await getUserStore(c.bucket._id).find(uid);
		expect(user?.provisionedBy).toBeUndefined();
	});
});
