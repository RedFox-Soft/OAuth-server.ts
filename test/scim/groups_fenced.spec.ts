import { describe, it, beforeAll, afterEach, expect } from 'bun:test';

import { ApplicationConfig } from 'lib/configs/application.js';
import { getBucketGroupStore } from 'lib/adapters/index.js';
import { SCIM_GROUP_SCHEMA } from 'lib/consts/scim.js';
import bootstrap from '../test_helper.js';
import { adminCookie } from '../end_user_lifecycle/fixtures.ts';
import { admin } from '../provisioning/helpers.ts';
import {
	connect,
	patchOf,
	provider,
	scim,
	scimBucket,
	scimUser,
	type Connected
} from './helpers.ts';

/**
 * @proves A connection's groups are its own: it cannot see, change or learn about another connection's or the
 * administrators' groups, cannot put a user it does not manage into one of its groups, and a refused request
 * changes nothing (spec 071, User Story 1 scenario 4, FR-023, FR-024, FR-029).
 */
describe('a provisioning connection’s groups are fenced in', () => {
	let a: Connected;
	let b: Connected;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'scim' });
		const bucket = await scimBucket([provider('one'), provider('two')]);
		a = await connect(bucket, { providerId: 'one' });
		b = await connect(bucket, { providerId: 'two' });
	});

	afterEach(() => {
		ApplicationConfig['scim.strict'] = false;
	});

	async function userOf(c: Connected): Promise<string> {
		return (
			await scim('POST', `${c.base}/Users`, {
				token: c.token,
				body: scimUser(`u-${Math.random().toString(36).slice(2)}@contoso.com`)
			})
		).json.id as string;
	}

	async function groupOf(c: Connected, displayName: string): Promise<string> {
		return (
			await scim('POST', `${c.base}/Groups`, {
				token: c.token,
				body: { schemas: [SCIM_GROUP_SCHEMA], displayName }
			})
		).json.id as string;
	}

	it('refuses the whole patch when one member is another connection’s user', async () => {
		const gid = await groupOf(a, `a-${Math.random()}`);
		const mine = await userOf(a);
		const theirs = await userOf(b);

		const res = await scim('PATCH', `${a.base}/Groups/${gid}`, {
			token: a.token,
			body: patchOf([
				{
					op: 'add',
					path: 'members',
					value: [{ value: mine }, { value: theirs }]
				}
			])
		});

		expect(res.status).toBe(400);
		expect(res.json.scimType).toBe('invalidValue');
		expect(await getBucketGroupStore().memberIds(gid)).toEqual([]);
	});

	it('answers 404 to read, replace, patch and delete of another connection’s group', async () => {
		const theirs = await groupOf(b, `b-${Math.random()}`);
		const path = `${a.base}/Groups/${theirs}`;

		const statuses = [
			(await scim('GET', path, { token: a.token })).status,
			(
				await scim('PUT', path, {
					token: a.token,
					body: { schemas: [SCIM_GROUP_SCHEMA], displayName: 'Mine' }
				})
			).status,
			(
				await scim('PATCH', path, {
					token: a.token,
					body: patchOf([{ op: 'replace', path: 'displayName', value: 'Mine' }])
				})
			).status,
			(await scim('DELETE', path, { token: a.token })).status
		];

		expect(statuses).toEqual([404, 404, 404, 404]);
		expect((await getBucketGroupStore().find(theirs))?.displayName).not.toBe(
			'Mine'
		);
	});

	it('lists only its own groups', async () => {
		await groupOf(b, `b-only-${Math.random()}`);

		const res = await scim('GET', `${a.base}/Groups?count=1000`, {
			token: a.token
		});

		for (const g of res.json.Resources as { id: string }[]) {
			expect((await getBucketGroupStore().find(g.id))?.provisionedBy).toBe(
				a.connection._id
			);
		}
	});

	it('answers a name taken by a group it cannot see with 409, naming neither the group nor its owner', async () => {
		const cookie = await adminCookie();
		const kept = await admin(
			'POST',
			`/admin/api/buckets/${a.bucket._id}/groups`,
			cookie,
			{ displayName: 'Executives' }
		);

		const res = await scim('POST', `${a.base}/Groups`, {
			token: a.token,
			body: { schemas: [SCIM_GROUP_SCHEMA], displayName: 'executives' }
		});

		expect(res.status).toBe(409);
		expect(res.json.scimType).toBe('uniqueness');
		expect(JSON.stringify(res.json)).not.toContain(kept.json.id as string);
	});

	it('refuses a path-less group patch and a capitalised op in strict mode, changing nothing', async () => {
		const gid = await groupOf(a, `strict-${Math.random()}`);
		ApplicationConfig['scim.strict'] = true;

		const pathless = await scim('PATCH', `${a.base}/Groups/${gid}`, {
			token: a.token,
			body: patchOf([{ op: 'replace', value: { displayName: 'Changed' } }])
		});
		const capitalised = await scim('PATCH', `${a.base}/Groups/${gid}`, {
			token: a.token,
			body: patchOf([{ op: 'Replace', path: 'displayName', value: 'Changed' }])
		});

		expect(pathless.status).toBe(400);
		expect(capitalised.status).toBe(400);
		expect((await getBucketGroupStore().find(gid))?.displayName).not.toBe(
			'Changed'
		);
	});
});
