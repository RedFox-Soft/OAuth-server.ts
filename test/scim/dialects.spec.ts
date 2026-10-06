import { describe, it, beforeAll, afterEach, expect } from 'bun:test';

import { getUserStore } from 'lib/adapters/index.js';
import { ApplicationConfig } from 'lib/configs/application.js';
import bootstrap from '../test_helper.js';
import {
	connect,
	patchOf,
	scim,
	scimBucket,
	scimUser,
	type Connected
} from './helpers.ts';

const ENTERPRISE = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';

/**
 * @proves Microsoft Entra ID and Okta provision a bucket with the requests they really send, and an
 * operator certifying against the profiles can switch every one of those tolerances off (spec 070, User
 * Story 4; FR-034, FR-034a).
 */
describe('real SCIM clients’ request forms', () => {
	let c: Connected;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'scim' });
		c = await connect(await scimBucket());
	});

	afterEach(() => {
		ApplicationConfig['scim.strict'] = false;
	});

	async function create(userName: string, extra: Record<string, unknown> = {}) {
		const res = await scim('POST', `${c.base}/Users`, {
			token: c.token,
			body: scimUser(userName, extra)
		});
		expect(res.status).toBe(201);
		return res.json.id as string;
	}

	function patch(id: string, operations: unknown[], contentType?: string) {
		return scim('PATCH', `${c.base}/Users/${id}`, {
			token: c.token,
			body: patchOf(operations),
			contentType
		});
	}

	it('deactivates a user on Entra’s capitalised op with a string boolean', async () => {
		const id = await create('entra.one@contoso.com');

		const res = await patch(id, [
			{ op: 'Replace', path: 'active', value: 'False' }
		]);

		expect(res.status).toBe(200);
		expect(res.json).toMatchObject({ active: false });
	});

	it('updates every attribute named by a path-less replace with dotted and URN keys', async () => {
		const id = await create('entra.two@contoso.com');

		const res = await patch(id, [
			{
				op: 'replace',
				value: {
					'name.givenName': 'Ada',
					'name.familyName': 'Lovelace',
					[`${ENTERPRISE}:department`]: 'Engines',
					[`${ENTERPRISE}:manager.value`]: 'mgr-1'
				}
			}
		]);

		expect(res.status).toBe(200);
		expect(res.json).toMatchObject({
			name: { givenName: 'Ada', familyName: 'Lovelace' },
			[ENTERPRISE]: { department: 'Engines', manager: { value: 'mgr-1' } }
		});
	});

	it('changes the login email on a replace of the work email’s value', async () => {
		const id = await create('entra.three@contoso.com');

		const res = await patch(id, [
			{
				op: 'replace',
				path: 'emails[type eq "work"].value',
				value: 'entra.three.new@contoso.com'
			}
		]);

		expect(res.status).toBe(200);
		const stored = await getUserStore(c.bucket._id).find(id);
		expect(stored?.email).toBe('entra.three.new@contoso.com');
	});

	it('sets, replaces and clears the manager the way Entra sends it', async () => {
		const id = await create('entra.four@contoso.com');
		const path = `${ENTERPRISE}:manager`;

		const added = await patch(id, [{ op: 'Add', path, value: 'mgr-1' }]);
		const replaced = await patch(id, [{ op: 'Replace', path, value: 'mgr-2' }]);
		const cleared = await patch(id, [{ op: 'Replace', path, value: '' }]);

		expect(added.status).toBe(200);
		expect(added.json[ENTERPRISE]).toMatchObject({
			manager: { value: 'mgr-1' }
		});
		expect(replaced.json[ENTERPRISE]).toMatchObject({
			manager: { value: 'mgr-2' }
		});
		expect(cleared.status).toBe(200);
		expect(cleared.json[ENTERPRISE]).not.toHaveProperty('manager');
	});

	it('deactivates a user on Okta’s path-less replace', async () => {
		const id = await create('okta.one@contoso.com');

		const res = await patch(id, [{ op: 'replace', value: { active: false } }]);

		expect(res.status).toBe(200);
		expect(res.json).toMatchObject({ active: false });
	});

	it('accepts a request sent as application/json and answers as application/scim+json', async () => {
		const id = await create('json.one@contoso.com');

		const res = await patch(
			id,
			[{ op: 'replace', path: 'displayName', value: 'Jay' }],
			'application/json'
		);

		expect(res.status).toBe(200);
		expect(res.headers.get('content-type')).toStartWith(
			'application/scim+json'
		);
		expect(res.json).toMatchObject({ displayName: 'Jay' });
	});

	describe('in strict mode', () => {
		it('refuses each tolerated form with 400 and changes nothing', async () => {
			const id = await create('strict.one@contoso.com');
			ApplicationConfig['scim.strict'] = true;

			const refused = [
				await patch(id, [{ op: 'replace', value: { active: false } }]),
				await patch(id, [{ op: 'Replace', path: 'active', value: false }]),
				await patch(id, [{ op: 'replace', path: 'active', value: 'False' }]),
				await patch(id, [{ op: 'replace', path: 'addresses', value: [] }]),
				await patch(id, [
					{ op: 'replace', path: `${ENTERPRISE}:manager`, value: 'mgr-1' }
				]),
				await patch(id, [
					{ op: 'replace', path: `${ENTERPRISE}:manager`, value: '' }
				]),
				await scim('POST', `${c.base}/Users`, {
					token: c.token,
					body: scimUser('strict.two@contoso.com', { password: 'x' })
				})
			];

			for (const res of refused) expect(res.status).toBe(400);
			const stored = await getUserStore(c.bucket._id).find(id);
			expect(stored?.active).toBe(true);
			expect(
				await getUserStore(c.bucket._id).findByEmail('strict.two@contoso.com')
			).toBeNull();
		});

		it('declares interop-profile conformance only while it is on', async () => {
			const lenient = await scim('GET', `${c.base}/ServiceProviderConfig`, {
				token: c.token
			});
			ApplicationConfig['scim.strict'] = true;
			const strict = await scim('GET', `${c.base}/ServiceProviderConfig`, {
				token: c.token
			});

			expect(lenient.json.interopProfileConformant).toBeUndefined();
			expect(strict.json.interopProfileConformant).toBe(true);
		});
	});
});
