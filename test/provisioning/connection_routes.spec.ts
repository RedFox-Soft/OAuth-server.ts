import { describe, it, beforeAll, expect } from 'bun:test';

import { getUserStore } from 'lib/adapters/index.js';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import bootstrap from '../test_helper.js';
import { adminCookie } from '../end_user_lifecycle/fixtures.ts';
import {
	connect,
	provider,
	reload,
	scim,
	scimBucket,
	scimUser,
	slugOf
} from '../scim/helpers.ts';
import { admin } from './helpers.ts';

/**
 * @proves An administrator sets up a provisioning connection on a bucket and controls it: the connection
 * tells them what to give the directory, binds its provider, can be disabled, cannot be created where it
 * must not be, and cannot be deleted from under its users (spec 070, User Story 2, scenarios 1, 5–7, 9;
 * FR-003, FR-005, FR-006, FR-007).
 */
describe('administering provisioning connections', () => {
	let cookie: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		cookie = await adminCookie();
	});

	it('shows the base URL, token endpoint and scope, and closes its provider to just-in-time creation', async () => {
		const bucket = await scimBucket([provider('corp')]);

		const created = await admin(
			'POST',
			`/admin/api/buckets/${bucket._id}/provisioning-connections`,
			cookie,
			{ displayName: 'Contoso', providerId: 'corp' }
		);

		expect(created.status).toBe(201);
		expect(created.json).toMatchObject({
			scimBaseUrl: `http://e.ly/${slugOf(bucket)}/scim/v2`,
			tokenEndpoint: `http://e.ly/${slugOf(bucket)}/token`,
			metadataUrl: `http://e.ly/.well-known/oauth-protected-resource/${slugOf(bucket)}/scim/v2`,
			scope: 'scim',
			clientId: `scim-${String(created.json.id)}`
		});
		const after = await reload(bucket);
		expect(after.federation[0]?.provisioning).toBe('existing_only');
	});

	it('defaults a Microsoft provider’s rule to oid against externalId', async () => {
		const bucket = await scimBucket([
			provider('entra', {
				issuer:
					'https://login.microsoftonline.com/1d6e9c2a-0000-4000-8000-000000000001/v2.0'
			})
		]);

		const created = await admin(
			'POST',
			`/admin/api/buckets/${bucket._id}/provisioning-connections`,
			cookie,
			{ displayName: 'Entra', providerId: 'entra' }
		);

		expect(created.status).toBe(201);
		expect(created.json.correlation).toEqual({
			claim: 'oid',
			attribute: 'externalId'
		});
	});

	it('refuses every SCIM request through a disabled connection and leaves its users as they are', async () => {
		const c = await connect(await scimBucket());
		const made = await scim('POST', `${c.base}/Users`, {
			token: c.token,
			body: scimUser('mia@contoso.com')
		});

		const disabled = await admin(
			'PATCH',
			`/admin/api/buckets/${c.bucket._id}/provisioning-connections/${c.connection._id}`,
			cookie,
			{ enabled: false }
		);
		const refused = await scim('GET', `${c.base}/Users`, { token: c.token });

		expect(disabled.status).toBe(200);
		expect(refused.status).toBe(401);
		const user = await getUserStore(c.bucket._id).find(made.json.id as string);
		expect(user?.active).toBe(true);
	});

	it('refuses a connection on the administrators’ bucket', async () => {
		const res = await admin(
			'POST',
			`/admin/api/buckets/${ADMIN_BUCKET_ID}/provisioning-connections`,
			cookie,
			{ displayName: 'Nope', providerId: 'corp' }
		);

		expect(res.status).toBe(403);
	});

	it('refuses to delete a bound provider or switch it to just-in-time creation', async () => {
		const c = await connect(await scimBucket([provider('corp')]));
		const path = `/admin/api/buckets/${c.bucket._id}/federation/corp`;

		const switched = await admin('PATCH', path, cookie, {
			provisioning: 'jit'
		});
		const deleted = await admin('DELETE', path, cookie);

		expect(switched.status).toBe(409);
		expect(deleted.status).toBe(409);
		expect((await reload(c.bucket)).federation[0]).toMatchObject({
			id: 'corp',
			provisioning: 'existing_only'
		});
	});

	it('refuses to delete a connection that manages users, stating how many', async () => {
		const c = await connect(await scimBucket());
		await scim('POST', `${c.base}/Users`, {
			token: c.token,
			body: scimUser('noah@contoso.com')
		});

		const res = await admin(
			'DELETE',
			`/admin/api/buckets/${c.bucket._id}/provisioning-connections/${c.connection._id}`,
			cookie
		);

		expect(res.status).toBe(409);
		expect(res.json.blockers).toEqual([{ kind: 'enduser', count: 1 }]);
	});
});
