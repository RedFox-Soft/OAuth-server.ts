import { describe, it, beforeAll, afterEach, expect } from 'bun:test';
import { Type } from '@sinclair/typebox';

import { getUserStore } from 'lib/adapters/index.js';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { SCIM_GROUP_SCHEMA } from 'lib/consts/scim.js';
import bootstrap from '../test_helper.js';
import { shaped } from '../shape.ts';
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
 * FR-003, FR-005, FR-006, FR-007); its read states the users and groups it manages and the credential kinds
 * the instance would issue it (spec 084 R4).
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

	describe('reading a connection before deciding what to do with it', () => {
		afterEach(() => {
			ApplicationConfig['scim.secretCredentials'] = true;
			ApplicationConfig['scim.staticTokens'] = true;
		});

		it('states how many users and groups it manages, in the list and the single read alike', async () => {
			const c = await connect(await scimBucket());
			await scim('POST', `${c.base}/Users`, {
				token: c.token,
				body: scimUser('ava@contoso.com')
			});
			await scim('POST', `${c.base}/Groups`, {
				token: c.token,
				body: { schemas: [SCIM_GROUP_SCHEMA], displayName: 'Payroll' }
			});
			const base = `/admin/api/buckets/${c.bucket._id}/provisioning-connections`;

			const one = await admin('GET', `${base}/${c.connection._id}`, cookie);
			const list = shaped(
				Type.Array(Type.Record(Type.String(), Type.Unknown())),
				(await admin('GET', base, cookie)).body
			);

			expect(one.json).toMatchObject({ managedUsers: 1, managedGroups: 1 });
			expect(list[0]).toMatchObject({ managedUsers: 1, managedGroups: 1 });
		});

		it('offers every credential kind while the instance issues them all', async () => {
			const c = await connect(await scimBucket());

			const res = await admin(
				'GET',
				`/admin/api/buckets/${c.bucket._id}/provisioning-connections/${c.connection._id}`,
				cookie
			);

			expect(res.json.availableCredentialKinds).toEqual([
				'key',
				'secret',
				'static_token'
			]);
		});

		it('offers only a key once secrets and static tokens are switched off', async () => {
			const c = await connect(await scimBucket());
			ApplicationConfig['scim.secretCredentials'] = false;
			ApplicationConfig['scim.staticTokens'] = false;

			const res = await admin(
				'GET',
				`/admin/api/buckets/${c.bucket._id}/provisioning-connections/${c.connection._id}`,
				cookie
			);

			expect(res.json.availableCredentialKinds).toEqual(['key']);
		});
	});
});
