import { describe, it, beforeAll, expect } from 'bun:test';

import { SCIM_GROUP_SCHEMA } from 'lib/consts/scim.js';
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
 * @proves A directory finds the groups it keeps the way IPSIE AL SCIM §6.2 says it will look — by name in any
 * letter case, by its own id, by member, by Entra's membership check — lists them without their members when
 * it asks to, and reads a user's groups from the user (spec 071, User Story 1, scenarios 8 and 10).
 */
describe('a directory finding its groups over SCIM', () => {
	let c: Connected;
	let financeId: string;
	let memberId: string;
	let outsiderId: string;

	function list(query: string) {
		return scim('GET', `${c.base}/Groups?${query}`, { token: c.token });
	}

	function filter(expression: string) {
		return list(`filter=${encodeURIComponent(expression)}`);
	}

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'scim' });
		c = await connect(await scimBucket());
		memberId = (
			await scim('POST', `${c.base}/Users`, {
				token: c.token,
				body: scimUser('member@contoso.com')
			})
		).json.id as string;
		outsiderId = (
			await scim('POST', `${c.base}/Users`, {
				token: c.token,
				body: scimUser('outsider@contoso.com')
			})
		).json.id as string;
		financeId = (
			await scim('POST', `${c.base}/Groups`, {
				token: c.token,
				body: {
					schemas: [SCIM_GROUP_SCHEMA],
					displayName: 'Finance',
					externalId: 'ext-finance',
					members: [{ value: memberId }]
				}
			})
		).json.id as string;
		await scim('POST', `${c.base}/Groups`, {
			token: c.token,
			body: { schemas: [SCIM_GROUP_SCHEMA], displayName: 'Legal' }
		});
	});

	it('lists groups without their members when members are excluded', async () => {
		const res = await list('excludedAttributes=members');

		const resources = res.json.Resources as Record<string, unknown>[];
		expect(resources.length).toBeGreaterThan(0);
		for (const resource of resources) expect(resource.members).toBeUndefined();
	});

	it('finds a group by displayName in any letter case', async () => {
		const res = await filter('displayName eq "finance"');

		expect(res.json.totalResults).toBe(1);
		expect((res.json.Resources as { id: string }[])[0].id).toBe(financeId);
	});

	it('finds a group by its externalId', async () => {
		const res = await filter('externalId eq "ext-finance"');

		expect((res.json.Resources as { id: string }[]).map((r) => r.id)).toEqual([
			financeId
		]);
	});

	it('finds the groups a user is a member of', async () => {
		const res = await filter(`members[value eq "${memberId}"]`);

		expect((res.json.Resources as { id: string }[]).map((r) => r.id)).toEqual([
			financeId
		]);
	});

	it('answers Entra’s membership check with one result for a member', async () => {
		const res = await filter(
			`id eq "${financeId}" and members[value eq "${memberId}"]`
		);

		expect(res.json.totalResults).toBe(1);
	});

	it('answers Entra’s membership check with no result for a non-member', async () => {
		const res = await filter(
			`id eq "${financeId}" and members[value eq "${outsiderId}"]`
		);

		expect(res.json.totalResults).toBe(0);
	});

	it('refuses a filter outside the supported set with invalidFilter', async () => {
		const res = await filter('displayName sw "Fin"');

		expect(res.status).toBe(400);
		expect(res.json.scimType).toBe('invalidFilter');
	});

	it('shows a user the connection’s groups they are in', async () => {
		const res = await scim('GET', `${c.base}/Users/${memberId}`, {
			token: c.token
		});

		expect(res.json.groups).toMatchObject([
			{ value: financeId, display: 'Finance', type: 'direct' }
		]);
	});

	it('ignores a groups value a client sends for a user', async () => {
		await scim('PATCH', `${c.base}/Users/${outsiderId}`, {
			token: c.token,
			body: patchOf([
				{ op: 'add', path: 'groups', value: [{ value: financeId }] }
			])
		});

		const res = await scim('GET', `${c.base}/Users/${outsiderId}`, {
			token: c.token
		});
		expect(res.json.groups).toBeUndefined();
	});
});
