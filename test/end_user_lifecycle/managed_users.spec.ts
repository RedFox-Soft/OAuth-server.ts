import { describe, it, beforeAll, expect } from 'bun:test';

import { adminAuditStore } from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { createEndUser } from 'lib/end_users/service.ts';
import nanoid from 'lib/helpers/nanoid.js';
import bootstrap from '../test_helper.js';
import { admin, adminCookie, defaultBucket } from './fixtures.ts';

/* A user provisioned by connection `conn-a`, as part 2's provisioning surface will create one. */
async function provisionedUser() {
	return createEndUser(
		await defaultBucket(),
		{ kind: 'connection', connectionId: 'conn-a' },
		{ id: nanoid(), email: `managed-${nanoid()}@x.io` },
		async () => {}
	);
}

/**
 * @proves A user a provisioning connection manages cannot be changed by an administrator of this
 * server — the connection is its source of truth (spec 069, FR-006).
 */
describe('an administrator acting on a user managed by a provisioning connection', () => {
	let cookie: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		cookie = await adminCookie();
	});

	it('is refused with 409 naming the connection when updating the user', async () => {
		const user = await provisionedUser();

		const res = await admin.admin.api
			.buckets({ id: DEFAULT_BUCKET_ID })
			.users({ uid: user._id })
			.patch({ roles: [] }, { headers: { cookie } });

		expect(res.status).toBe(409);
		expect(res.error?.value).toHaveProperty(
			'message',
			'user is managed by connection conn-a'
		);
		const { entries } = await adminAuditStore.list({ targetId: user._id });
		expect(entries).toEqual([]);
	});

	it('is refused with 409 when deleting the user', async () => {
		const user = await provisionedUser();

		const res = await admin.admin.api
			.buckets({ id: DEFAULT_BUCKET_ID })
			.users({ uid: user._id })
			.delete(undefined, { headers: { cookie } });

		expect(res.status).toBe(409);
		const { entries } = await adminAuditStore.list({ targetId: user._id });
		expect(entries).toEqual([]);
	});
});
