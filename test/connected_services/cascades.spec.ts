import { afterEach, beforeAll, describe, expect, it, spyOn } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { assertNoPendingInterceptors, fetchAnswering } from '../fetch_mock.js';
import {
	getBucketStore,
	getUserStore,
	rawConnectedAccountStoreForTests
} from 'lib/adapters/index.ts';
import type { UserBucket } from 'lib/adapters/types.ts';
import { destroyBucket } from 'lib/admin/buckets/destroy.ts';
import { revocationsSettled } from 'lib/connected_services/accounts.ts';
import { present } from '../shape.ts';
import {
	addService,
	admin,
	projectAdministrator,
	seededAccount
} from './harness.ts';
import { githubStub, unique } from './stubs.ts';

async function personIn(bucket: UserBucket) {
	const user = await getUserStore(bucket._id).create(
		`${unique('p')}@acme.test`,
		'hash',
		true
	);
	return { accountId: user._id, bucket };
}

async function remaining(bucketId: string, accountId: string) {
	return rawConnectedAccountStoreForTests().listByAccount(bucketId, accountId);
}

/**
 * @proves A person's connected accounts end when the person, the service or the project does, each provider being
 * asked to revoke, and survive a lock, which can be lifted.
 */
describe('deleting what connected accounts belong to', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});
	afterEach(async () => {
		await revocationsSettled();
		assertNoPendingInterceptors();
	});

	it('deletes a deleted person’s connected accounts and asks the provider to revoke each', async () => {
		const { cookie, bucket } = await projectAdministrator();
		const service = await addService(
			{ kind: 'catalogue', catalogueId: 'github' },
			bucket._id
		);
		const who = await personIn(bucket);
		await seededAccount(who, service);
		await seededAccount(who, service);
		const stub = githubStub();
		stub.expectRevoke(service.clientId);
		stub.expectRevoke(service.clientId);

		const deleted = await admin(
			cookie,
			'DELETE',
			`/admin/api/projects/${bucket._id}/users/${who.accountId}`
		);
		await revocationsSettled();

		expect(deleted.status).toBe(200);
		expect(await remaining(bucket._id, who.accountId)).toEqual([]);
	});

	it('deletes the connected accounts of people deleted in bulk', async () => {
		const { cookie, bucket } = await projectAdministrator();
		const service = await addService(
			{ kind: 'catalogue', catalogueId: 'microsoft', tenant: 'common' },
			bucket._id
		);
		const who = await personIn(bucket);
		await seededAccount(who, service);

		await admin(
			cookie,
			'POST',
			`/admin/api/projects/${bucket._id}/users/bulk/delete`,
			{
				userIds: [who.accountId]
			}
		);

		expect(await remaining(bucket._id, who.accountId)).toEqual([]);
	});

	it('keeps a locked person’s connected accounts through the lock and the unlock', async () => {
		const { cookie, bucket } = await projectAdministrator();
		const service = await addService(
			{ kind: 'catalogue', catalogueId: 'github' },
			bucket._id
		);
		const who = await personIn(bucket);
		const account = await seededAccount(who, service);

		await admin(
			cookie,
			'POST',
			`/admin/api/projects/${bucket._id}/users/${who.accountId}/lock`,
			{
				reason: 'suspicious sign-in'
			}
		);
		const whileLocked = await remaining(bucket._id, who.accountId);
		await admin(
			cookie,
			'POST',
			`/admin/api/projects/${bucket._id}/users/${who.accountId}/unlock`,
			{}
		);

		expect(whileLocked.map((a) => a._id)).toEqual([account._id]);
		expect(
			(await remaining(bucket._id, who.accountId)).map((a) => a._id)
		).toEqual([account._id]);
	});

	it('deletes a deleted service’s accounts and says how many were disconnected', async () => {
		const { cookie, bucket } = await projectAdministrator();
		const service = await addService(
			{ kind: 'catalogue', catalogueId: 'microsoft', tenant: 'common' },
			bucket._id
		);
		const first = await personIn(bucket);
		const second = await personIn(bucket);
		await seededAccount(first, service);
		await seededAccount(second, service);

		const deleted = await admin(
			cookie,
			'DELETE',
			`/admin/api/projects/${bucket._id}/connected-services/${service.id}`
		);

		expect(deleted.json).toEqual({ deleted: true, disconnected: 2 });
		expect(await remaining(bucket._id, first.accountId)).toEqual([]);
		expect(await remaining(bucket._id, second.accountId)).toEqual([]);
		expect(
			(await getBucketStore().find(bucket._id))?.connectedServices
		).toEqual([]);
	});

	it('deletes a destroyed project’s connected accounts with its services', async () => {
		const { bucket } = await projectAdministrator();
		const service = await addService(
			{ kind: 'catalogue', catalogueId: 'microsoft', tenant: 'common' },
			bucket._id
		);
		const who = await personIn(bucket);
		await seededAccount(who, service);
		const scheduled = present(
			await getBucketStore().scheduleDeletion(bucket._id, {
				scheduledAt: new Date(),
				purgeAt: new Date(),
				scheduledBy: { userId: 'test' }
			}),
			'a scheduled project'
		);

		const outcome = await destroyBucket(
			scheduled,
			{ kind: 'server' },
			{ due: false }
		);

		expect(outcome.claimed).toBe(true);
		expect(await remaining(bucket._id, who.accountId)).toEqual([]);
	});

	it('finishes a service deletion without waiting for a provider that does not answer', async () => {
		const { cookie, bucket } = await projectAdministrator();
		const service = await addService(
			{ kind: 'catalogue', catalogueId: 'github' },
			bucket._id
		);
		const who = await personIn(bucket);
		await seededAccount(who, service);
		let reached = false;
		let answerLate: (() => void) | undefined;
		spyOn(globalThis, 'fetch').mockImplementation(
			fetchAnswering(
				() =>
					new Promise<Response>((resolve) => {
						reached = true;
						answerLate = () => resolve(new Response(null, { status: 204 }));
					})
			)
		);

		const started = Date.now();
		const deleted = await admin(
			cookie,
			'DELETE',
			`/admin/api/projects/${bucket._id}/connected-services/${service.id}`
		);

		expect(deleted.status).toBe(200);
		expect(Date.now() - started).toBeLessThan(1000);
		expect(await remaining(bucket._id, who.accountId)).toEqual([]);
		expect(reached).toBe(true);
		// The provider answers at last, after the deletion was already complete.
		answerLate?.();
	});
});
