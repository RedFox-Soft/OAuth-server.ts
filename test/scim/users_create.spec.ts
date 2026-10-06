import { describe, it, beforeAll, expect } from 'bun:test';

import { getUserStore } from 'lib/adapters/index.js';
import bootstrap from '../test_helper.js';
import {
	connect,
	scim,
	scimBucket,
	scimUser,
	type Connected
} from './helpers.ts';

/**
 * @proves An identity system creates a bucket's users over SCIM: the server issues the id, refuses a
 * duplicate without leaving anything behind, and never keeps a password it was sent (spec 070, User Story 1,
 * scenarios 3, 9 and 10; FR-030).
 */
describe('creating a user over SCIM', () => {
	let c: Connected;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'scim' });
		c = await connect(await scimBucket());
	});

	it('returns the user with a server-generated id, timestamps, and a location that reads it back', async () => {
		const created = await scim('POST', `${c.base}/Users`, {
			token: c.token,
			body: scimUser('alice@contoso.com', {
				externalId: 'oid-alice',
				name: { givenName: 'Alice', familyName: 'Liddell' }
			})
		});

		expect(created.status).toBe(201);
		const id = created.json.id as string;
		expect(id).not.toBe('oid-alice');
		expect(created.json.meta).toMatchObject({
			resourceType: 'User',
			created: expect.any(String),
			lastModified: expect.any(String)
		});
		const location = created.headers.get('location') ?? '';
		expect(location).toBe(`http://e.ly${c.base}/Users/${id}`);

		const read = await scim('GET', new URL(location).pathname, {
			token: c.token
		});
		expect(read.status).toBe(200);
		expect(read.json).toMatchObject({
			id,
			userName: 'alice@contoso.com',
			externalId: 'oid-alice',
			name: { givenName: 'Alice', familyName: 'Liddell' },
			active: true
		});
	});

	it('neither stores nor accepts a password sent with the user', async () => {
		const created = await scim('POST', `${c.base}/Users`, {
			token: c.token,
			body: scimUser('bob@contoso.com', { password: 'Hunter2!Hunter2!' })
		});

		expect(created.status).toBe(201);
		expect(JSON.stringify(created.json)).not.toContain('Hunter2');
		const stored = await getUserStore(c.bucket._id).find(
			created.json.id as string
		);
		expect(
			await Bun.password.verify('Hunter2!Hunter2!', stored?.password ?? '')
		).toBe(false);
	});

	it('refuses a userName already held in another letter case with 409 uniqueness and creates nothing', async () => {
		await scim('POST', `${c.base}/Users`, {
			token: c.token,
			body: scimUser('carol@contoso.com')
		});

		const duplicate = await scim('POST', `${c.base}/Users`, {
			token: c.token,
			body: scimUser('CAROL@contoso.com', {
				emails: [{ value: 'carol.other@contoso.com', primary: true }]
			})
		});

		expect(duplicate.status).toBe(409);
		expect(duplicate.json).toMatchObject({ scimType: 'uniqueness' });
		expect(
			await getUserStore(c.bucket._id).findByEmail('carol.other@contoso.com')
		).toBeNull();
	});

	it('leaves no half-created account when the external identifier is already held', async () => {
		await scim('POST', `${c.base}/Users`, {
			token: c.token,
			body: scimUser('dave@contoso.com', { externalId: 'oid-shared' })
		});

		const collision = await scim('POST', `${c.base}/Users`, {
			token: c.token,
			body: scimUser('erin@contoso.com', { externalId: 'oid-shared' })
		});
		const retry = await scim('POST', `${c.base}/Users`, {
			token: c.token,
			body: scimUser('erin@contoso.com', { externalId: 'oid-erin' })
		});

		expect(collision.status).toBe(409);
		expect(retry.status).toBe(201);
	});
});
