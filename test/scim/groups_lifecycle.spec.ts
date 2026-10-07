import { describe, it, beforeAll, expect } from 'bun:test';

import { SCIM_GROUP_SCHEMA, SCIM_MAX_BODY_BYTES } from 'lib/consts/scim.js';
import bootstrap from '../test_helper.js';
import {
	connect,
	patchOf,
	scim,
	scimBucket,
	scimUser,
	type Connected
} from './helpers.ts';

/**
 * @proves An enterprise directory keeps a bucket's groups over SCIM the way Entra and Okta send it: creates
 * them empty, adds and removes members in batches, renames, replaces and deletes them — every refused request
 * changing nothing, groups flat, and a deleted user leaving every group (spec 071, User Story 1; IPSIE AL SCIM
 * §6.2).
 */
describe('a directory keeping groups over SCIM', () => {
	let c: Connected;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'scim' });
		c = await connect(await scimBucket());
	});

	async function user(): Promise<string> {
		const res = await scim('POST', `${c.base}/Users`, {
			token: c.token,
			body: scimUser(`m-${Math.random().toString(36).slice(2)}@contoso.com`)
		});
		expect(res.status).toBe(201);
		return res.json.id as string;
	}

	async function users(n: number): Promise<string[]> {
		const ids: string[] = [];
		for (let i = 0; i < n; i++) ids.push(await user());
		return ids;
	}

	async function group(
		displayName = `g-${Math.random().toString(36).slice(2)}`,
		extra: Record<string, unknown> = {}
	): Promise<string> {
		const res = await scim('POST', `${c.base}/Groups`, {
			token: c.token,
			body: { schemas: [SCIM_GROUP_SCHEMA], displayName, ...extra }
		});
		expect(res.status).toBe(201);
		return res.json.id as string;
	}

	async function members(id: string): Promise<string[]> {
		const res = await scim('GET', `${c.base}/Groups/${id}`, { token: c.token });
		return ((res.json.members as { value: string }[] | undefined) ?? [])
			.map((m) => m.value)
			.sort();
	}

	function patch(id: string, operations: unknown[]) {
		return scim('PATCH', `${c.base}/Groups/${id}`, {
			token: c.token,
			body: patchOf(operations)
		});
	}

	it('creates an empty group with a server-issued id, its externalId and a location that reads it back', async () => {
		const res = await scim('POST', `${c.base}/Groups`, {
			token: c.token,
			body: {
				schemas: [SCIM_GROUP_SCHEMA],
				displayName: 'Finance',
				externalId: 'entra-object-1'
			}
		});
		const location = res.headers.get('location') ?? '';
		const read = await scim('GET', location.replace(/^https?:\/\/[^/]+/, ''), {
			token: c.token
		});

		expect(res.status).toBe(201);
		expect(res.json).toMatchObject({
			displayName: 'Finance',
			externalId: 'entra-object-1',
			members: [],
			meta: { resourceType: 'Group' }
		});
		expect(read.json.id).toBe(res.json.id);
	});

	it('adds fifty members in one patch', async () => {
		const id = await group();
		const ids = await users(50);

		const res = await patch(id, [
			{ op: 'add', path: 'members', value: ids.map((value) => ({ value })) }
		]);

		expect(res.status).toBe(204);
		expect(await members(id)).toEqual([...ids].sort());
	});

	it('treats adding an existing member and removing a non-member as nothing to do', async () => {
		const id = await group();
		const [a, b] = await users(2);
		await patch(id, [{ op: 'add', path: 'members', value: [{ value: a }] }]);

		const res = await patch(id, [
			{ op: 'add', path: 'members', value: [{ value: a }] },
			{ op: 'remove', path: `members[value eq "${b}"]` }
		]);

		expect(res.status).toBe(204);
		expect(await members(id)).toEqual([a]);
	});

	it('removes only the member a filtered path names', async () => {
		const id = await group();
		const [a, b] = await users(2);
		await patch(id, [
			{ op: 'add', path: 'members', value: [{ value: a }, { value: b }] }
		]);

		await patch(id, [{ op: 'remove', path: `members[value eq "${a}"]` }]);

		expect(await members(id)).toEqual([b]);
	});

	it('removes each member Entra lists in a remove with a value', async () => {
		const id = await group();
		const [a, b, d] = await users(3);
		await patch(id, [
			{
				op: 'add',
				path: 'members',
				value: [{ value: a }, { value: b }, { value: d }]
			}
		]);

		await patch(id, [
			{ op: 'Remove', path: 'members', value: [{ value: a }, { value: d }] }
		]);

		expect(await members(id)).toEqual([b]);
	});

	it('sets exactly the listed members on a replace of members', async () => {
		const id = await group();
		const [a, b, d] = await users(3);
		await patch(id, [
			{ op: 'add', path: 'members', value: [{ value: a }, { value: b }] }
		]);

		await patch(id, [
			{ op: 'replace', path: 'members', value: [{ value: b }, { value: d }] }
		]);

		expect(await members(id)).toEqual([b, d].sort());
	});

	it('empties the group on a remove of members without a filter', async () => {
		const id = await group();
		const ids = await users(2);
		await patch(id, [
			{ op: 'add', path: 'members', value: ids.map((value) => ({ value })) }
		]);

		await patch(id, [{ op: 'remove', path: 'members' }]);

		expect(await members(id)).toEqual([]);
	});

	it('keeps the id of a group renamed by patch', async () => {
		const id = await group();

		await patch(id, [{ op: 'replace', path: 'displayName', value: 'Renamed' }]);
		const read = await scim('GET', `${c.base}/Groups/${id}`, {
			token: c.token
		});

		expect(read.json).toMatchObject({ id, displayName: 'Renamed' });
	});

	it('sets exactly the given name, members and externalId on a replace, and advances lastModified', async () => {
		const id = await group('Before', { externalId: 'old' });
		const [a] = await users(1);
		const before = await scim('GET', `${c.base}/Groups/${id}`, {
			token: c.token
		});
		await new Promise((resolve) => setTimeout(resolve, 5));

		const res = await scim('PUT', `${c.base}/Groups/${id}`, {
			token: c.token,
			body: {
				schemas: [SCIM_GROUP_SCHEMA],
				displayName: 'After',
				externalId: 'new',
				members: [{ value: a }]
			}
		});

		expect(res.status).toBe(200);
		expect(res.json).toMatchObject({
			id,
			displayName: 'After',
			externalId: 'new',
			members: [{ value: a }]
		});
		expect(
			Date.parse((res.json.meta as { lastModified: string }).lastModified)
		).toBeGreaterThan(
			Date.parse((before.json.meta as { lastModified: string }).lastModified)
		);
	});

	it('deletes a group and leaves its members as they were', async () => {
		const id = await group();
		const [a] = await users(1);
		await patch(id, [{ op: 'add', path: 'members', value: [{ value: a }] }]);

		const res = await scim('DELETE', `${c.base}/Groups/${id}`, {
			token: c.token
		});
		const gone = await scim('GET', `${c.base}/Groups/${id}`, {
			token: c.token
		});
		const member = await scim('GET', `${c.base}/Users/${a}`, {
			token: c.token
		});

		expect(res.status).toBe(204);
		expect(gone.status).toBe(404);
		expect(member.status).toBe(200);
	});

	it('takes a deleted user out of every group', async () => {
		const [g1, g2] = [await group(), await group()];
		const [a] = await users(1);
		await patch(g1, [{ op: 'add', path: 'members', value: [{ value: a }] }]);
		await patch(g2, [{ op: 'add', path: 'members', value: [{ value: a }] }]);

		await scim('DELETE', `${c.base}/Users/${a}`, { token: c.token });

		expect(await members(g1)).toEqual([]);
		expect(await members(g2)).toEqual([]);
	});

	it('refuses a member that is itself a group', async () => {
		const id = await group();
		const other = await group();

		const res = await patch(id, [
			{ op: 'add', path: 'members', value: [{ value: other, type: 'Group' }] }
		]);

		expect(res.status).toBe(400);
		expect(res.json.scimType).toBe('invalidValue');
		expect(await members(id)).toEqual([]);
	});

	it('refuses a create, replace or members replace larger than the body limit, and changes nothing', async () => {
		const id = await group('Big');
		const huge = Array.from({ length: SCIM_MAX_BODY_BYTES / 40 }, (_, i) => ({
			value: `u${i.toString().padStart(30, '0')}`
		}));

		const res = await scim('PUT', `${c.base}/Groups/${id}`, {
			token: c.token,
			body: { schemas: [SCIM_GROUP_SCHEMA], displayName: 'Big', members: huge }
		});

		expect(res.status).toBe(413);
		expect(await members(id)).toEqual([]);
	});
});
