import { describe, it, beforeAll, expect } from 'bun:test';

import {
	getContainerOwnershipStore,
	getGroupStore
} from 'lib/adapters/index.js';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import bootstrap from '../test_helper.js';
import {
	connect,
	scim,
	scimBucket,
	scimUser,
	type Connected
} from './helpers.ts';

/**
 * @proves An enterprise identity system keeps provisioning a bucket's users with the credential it already
 * holds after the bucket moves to another administrator group: the connection belongs to the bucket, not to
 * the group that administers it (spec 075, SC-005).
 */
describe('provisioning after the bucket moved to another group', () => {
	let c: Connected;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'scim' });
		c = await connect(await scimBucket());
		const team = await getGroupStore().create({
			name: 'Team',
			kind: 'regular',
			members: [{ userId: 'team-owner', role: 'owner' }]
		});
		const moved = await getContainerOwnershipStore().moveBucket(
			c.bucket._id,
			UNASSIGNED_GROUP_ID,
			team._id
		);
		expect(moved.status).toBe('moved');
	});

	it('creates a user with a token issued before the move', async () => {
		const created = await scim('POST', `${c.base}/Users`, {
			token: c.token,
			body: scimUser(`moved-${Math.random().toString(36).slice(2)}@contoso.com`)
		});

		expect(created.status).toBe(201);
	});
});
