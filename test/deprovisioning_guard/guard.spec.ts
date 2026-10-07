import { describe, it, beforeAll, expect, setSystemTime } from 'bun:test';

import { SCIM_GROUP_SCHEMA } from 'lib/consts/scim.js';
import { present } from '../shape.ts';
import bootstrap from '../test_helper.js';
import {
	deactivate,
	deactivateAll,
	guarded,
	HOUR,
	patchOf,
	provision,
	scim,
	scimUser,
	storedUser,
	tripped
} from './helpers.ts';

/**
 * @proves A directory that runs away cannot deprovision a whole bucket: a connection with a threshold
 * accepts that many deprovisionings in its window, refuses the next with an error the directory retries,
 * and while held refuses every deprovisioning — and nothing else — leaving the refused users their access
 * (spec 072, User Story 4, scenarios 1–4; FR-019–FR-021).
 */
describe('a provisioning connection with a mass-deprovisioning threshold', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('accepts deactivations up to the threshold', async () => {
		const g = await guarded({ count: 3, windowSeconds: HOUR });
		const ids = await provision(g, 3);

		const statuses: number[] = [];
		for (const id of ids) statuses.push((await deactivate(g, id)).status);

		expect(statuses).toEqual([200, 200, 200]);
	});

	it('answers the deactivation beyond the threshold with 429 and a retry delay', async () => {
		const g = await guarded({ count: 3, windowSeconds: HOUR });
		const ids = await provision(g, 4);
		await deactivateAll(g, ids.slice(0, 3));

		const res = await deactivate(g, present(ids[3], 'a fourth user'));

		expect(res.status).toBe(429);
		expect(res.headers.get('retry-after')).toBe('300');
		expect(res.json).toMatchObject({
			schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
			status: '429'
		});
		expect(res.json.scimType).toBeUndefined();
		expect(String(res.json.detail)).toContain('mass-deprovisioning guard');
	});

	it('leaves the user refused beyond the threshold active', async () => {
		const g = await guarded({ count: 1, windowSeconds: HOUR });
		const [first, second] = await provision(g, 2);
		await deactivateAll(g, [present(first, 'a user')]);

		await deactivate(g, present(second, 'a user'));

		expect((await storedUser(g, present(second, 'a user')))?.active).toBe(true);
	});

	it('refuses a deletion from a held connection and keeps the user', async () => {
		const g = await tripped({ count: 1, windowSeconds: HOUR });
		const [kept] = await provision(g, 1);

		const res = await scim('DELETE', `${g.base}/Users/${kept}`, {
			token: g.token
		});

		expect(res.status).toBe(429);
		expect(res.headers.get('retry-after')).toBe('300');
		expect(await storedUser(g, present(kept, 'a user'))).not.toBeNull();
	});

	it('refuses a deactivation from a held connection however long ago its window began', async () => {
		const g = await tripped({ count: 1, windowSeconds: 300 });
		const [later] = await provision(g, 1);
		setSystemTime(new Date(Date.now() + 2 * HOUR * 1000));
		try {
			const res = await deactivate(g, present(later, 'a user'));

			expect(res.status).toBe(429);
		} finally {
			setSystemTime();
		}
	});

	it('still creates users while held', async () => {
		const g = await tripped({ count: 1, windowSeconds: HOUR });

		const res = await scim('POST', `${g.base}/Users`, {
			token: g.token,
			body: scimUser('newcomer@contoso.com')
		});

		expect(res.status).toBe(201);
	});

	it('still updates a profile while held', async () => {
		const g = await tripped({ count: 1, windowSeconds: HOUR });
		const [id] = await provision(g, 1);

		const res = await scim('PATCH', `${g.base}/Users/${id}`, {
			token: g.token,
			body: patchOf([{ op: 'replace', path: 'displayName', value: 'Renamed' }])
		});

		expect(res.status).toBe(200);
		expect(res.json.displayName).toBe('Renamed');
	});

	it('still reactivates a user while held', async () => {
		const g = await guarded({ count: 1, windowSeconds: HOUR });
		const [left, refused] = await provision(g, 2);
		await deactivateAll(g, [present(left, 'a user')]);
		expect((await deactivate(g, present(refused, 'a user'))).status).toBe(429);

		const res = await scim('PATCH', `${g.base}/Users/${left}`, {
			token: g.token,
			body: patchOf([{ op: 'replace', path: 'active', value: true }])
		});

		expect(res.status).toBe(200);
		expect((await storedUser(g, present(left, 'a user')))?.active).toBe(true);
	});

	it('still changes groups while held', async () => {
		const g = await tripped({ count: 1, windowSeconds: HOUR });
		const [member] = await provision(g, 1);

		const res = await scim('POST', `${g.base}/Groups`, {
			token: g.token,
			body: {
				schemas: [SCIM_GROUP_SCHEMA],
				displayName: 'Engineering',
				members: [{ value: member }]
			}
		});

		expect(res.status).toBe(201);
	});

	it('applies nothing of a refused replace that also changed the profile', async () => {
		const g = await tripped({ count: 1, windowSeconds: HOUR });
		const [id] = await provision(g, 1);
		const before = await storedUser(g, present(id, 'a user'));

		const res = await scim('PUT', `${g.base}/Users/${id}`, {
			token: g.token,
			body: scimUser(before?.userName ?? '', {
				displayName: 'Changed In The Same Request',
				active: false
			})
		});

		expect(res.status).toBe(429);
		const after = await storedUser(g, present(id, 'a user'));
		expect(after?.active).toBe(true);
		expect(after?.profile?.displayName).toBe(before?.profile?.displayName);
	});
});
