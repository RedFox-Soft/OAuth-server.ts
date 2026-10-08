import { describe, it, beforeAll, expect } from 'bun:test';

import { ClientCredentials } from 'lib/models/client_credentials.js';
import bootstrap from '../test_helper.js';
import { adminCookie } from '../end_user_lifecycle/fixtures.ts';
import { connect, scimBucket, slugOf } from '../scim/helpers.ts';
import { admin, basic, token } from './helpers.ts';

/**
 * @proves What happens to a bucket's provisioning connections when the bucket moves or goes: an address
 * change names them before it is made, and a deletion takes their tokens with it (spec 070, Edge Cases;
 * research R19).
 */
describe('a bucket with provisioning connections', () => {
	let cookie: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		cookie = await adminCookie();
	});

	it('names its connections in the preview of an address change', async () => {
		const c = await connect(await scimBucket());

		const preview = await admin(
			'POST',
			`/admin/api/buckets/${c.bucket._id}/address`,
			cookie,
			{ slug: `moved-${Math.random().toString(36).slice(2, 8)}` }
		);

		expect(preview.status).toBe(409);
		expect(preview.json.provisioningConnectionsNeedingReconfiguration).toEqual([
			{ id: c.connection._id, displayName: 'Directory' }
		]);
	});

	it('revokes its connections’ tokens when it is deleted', async () => {
		const c = await connect(await scimBucket());
		const path = `/admin/api/buckets/${c.bucket._id}/provisioning-connections/${c.connection._id}`;
		const issued = await admin('POST', `${path}/credentials`, cookie, {
			kind: 'secret'
		});
		const granted = await token(
			`/${slugOf(c.bucket)}/token`,
			{ grant_type: 'client_credentials' },
			basic(`scim-${c.connection._id}`, issued.json.secret as string)
		);
		expect(granted.status).toBe(200);

		const deleted = await admin(
			'DELETE',
			`/admin/api/buckets/${c.bucket._id}`,
			cookie
		);

		expect(deleted.status).toBe(200);
		expect(
			await ClientCredentials.tryFind(granted.json.access_token as string)
		).toBeUndefined();
	});
});
