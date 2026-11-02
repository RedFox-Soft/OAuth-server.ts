import { afterEach, beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { assertNoPendingInterceptors } from '../fetch_mock.js';
import {
	adminAuditStore,
	getUserStore,
	rawConnectedAccountStoreForTests
} from 'lib/adapters/index.ts';
import type { UserBucket } from 'lib/adapters/types.ts';
import { revocationsSettled } from 'lib/connected_services/accounts.ts';
import {
	addService,
	admin,
	projectAdministrator,
	seededAccount
} from './harness.ts';
import { unique } from './stubs.ts';

async function personIn(bucket: UserBucket) {
	const user = await getUserStore(bucket._id).create(
		`${unique('p')}@acme.test`,
		'hash',
		true
	);
	return { accountId: user._id, bucket };
}

/**
 * @proves An administrator of the project sees which services a person connected and can disconnect one, never
 * seeing a token, and the trail records the disconnection before it happens.
 */
describe('a project administrator and a person’s connected accounts', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});
	afterEach(async () => {
		await revocationsSettled();
		assertNoPendingInterceptors();
	});

	it('lists a person’s accounts without any token value', async () => {
		const { cookie, bucket } = await projectAdministrator();
		const service = await addService(
			{
				kind: 'catalogue',
				catalogueId: 'microsoft',
				tenant: 'common',
				scopes: ['User.Read']
			},
			bucket._id
		);
		const who = await personIn(bucket);
		const account = await seededAccount(who, service);

		const listed = await admin(
			cookie,
			'GET',
			`/admin/api/projects/${bucket._id}/users/${who.accountId}/connected-accounts`
		);

		expect(listed.status).toBe(200);
		const [view] = listed.json.accounts as Record<string, unknown>[];
		expect(view).toMatchObject({
			id: account._id,
			label: account.label,
			status: 'connected'
		});
		const body = JSON.stringify(listed.json);
		expect(body).not.toContain(String(account.accessToken));
		expect(body).not.toContain(String(account.refreshToken));
	});

	it('records an administrator’s disconnection before the account is gone', async () => {
		const { cookie, bucket } = await projectAdministrator();
		const service = await addService(
			{ kind: 'catalogue', catalogueId: 'microsoft', tenant: 'common' },
			bucket._id
		);
		const who = await personIn(bucket);
		const kept = await seededAccount(who, service);
		const removed = await seededAccount(who, service);

		const response = await admin(
			cookie,
			'DELETE',
			`/admin/api/projects/${bucket._id}/users/${who.accountId}/connected-accounts/${removed._id}`
		);

		expect(response.status).toBe(200);
		const { entries } = await adminAuditStore.list({ targetId: who.accountId });
		expect(
			entries.find((e) => e.action === 'connected.account.delete')
		).toMatchObject({
			targetScope: bucket._id,
			connectedAccountId: removed._id
		});
		const left = await rawConnectedAccountStoreForTests().listByAccount(
			bucket._id,
			who.accountId
		);
		expect(left.map((a) => a._id)).toEqual([kept._id]);
	});

	it('refuses an administrator of another project', async () => {
		const owner = await projectAdministrator();
		const stranger = await projectAdministrator();
		const who = await personIn(owner.bucket);

		const refused = await admin(
			stranger.cookie,
			'GET',
			`/admin/api/projects/${owner.bucket._id}/users/${who.accountId}/connected-accounts`
		);

		expect([403, 404]).toContain(refused.status);
	});
});
