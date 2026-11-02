import { randomBytes } from 'node:crypto';

import type { SealTarget } from '../lib/consts/sealed_fields.js';
import type {
	ConnectedAccountStoreInstance,
	SealingStoreInstance,
	UserBucketStoreInstance
} from '../lib/adapters/types.js';
import type {
	ConnectedAccount,
	ConnectedService
} from '../lib/connected_services/types.js';

type Check = (name: string, ok: boolean, detail?: string) => void;

/*
 * Connected services and accounts (specs/117) against a real datastore, through the undecorated stores, so what is
 * written is what is stored. What an in-memory double cannot show: that a reconnect lands on the same row by its
 * derived id, that every read and deletion stays inside its project, and that the encryption pass's compare-and-set
 * reaches exactly the service secret and the token it names. Shared by verify_mongodb.ts and verify_postgres.ts.
 */
export interface ConnectedAccountsFixture {
	sealing: SealingStoreInstance;
	buckets: UserBucketStoreInstance;
	accounts: ConnectedAccountStoreInstance;
}

function record(
	bucketId: string,
	serviceId: string,
	accountId: string,
	upstreamId: string,
	accessToken: string
): ConnectedAccount {
	const now = new Date().toISOString();
	return {
		_id: `${bucketId}:${serviceId}:${accountId}:${upstreamId}`,
		bucketId,
		serviceId,
		accountId,
		upstreamId,
		label: upstreamId,
		accessToken,
		refreshToken: `refresh-${upstreamId}`,
		tokenType: 'Bearer',
		scopes: ['read'],
		scopesInferred: false,
		connectedAt: now,
		updatedAt: now
	};
}

export async function verifyConnectedAccounts(
	fixture: ConnectedAccountsFixture,
	check: Check
): Promise<void> {
	const { accounts, buckets, sealing } = fixture;
	const stamp = `${Date.now()}-${randomBytes(3).toString('hex')}`;
	const bucketId = `connected-${stamp}`;
	const otherBucketId = `connected-other-${stamp}`;

	/* ---- the store ---- */

	const first = await accounts.put(
		record(bucketId, 'svc-a', 'person-1', 'u1', 'access-1')
	);
	const again = await accounts.put(
		record(bucketId, 'svc-a', 'person-1', 'u1', 'access-1b')
	);
	const found = await accounts.find(bucketId, `${bucketId}:svc-a:person-1:u1`);
	check(
		'connected accounts: a reconnect of the same upstream account replaces the row by its id',
		first.created && !again.created && found?.accessToken === 'access-1b',
		`${String(first.created)} ${String(again.created)} ${String(found?.accessToken)}`
	);
	check(
		'connected accounts: a row is read only within its own project',
		(await accounts.find(otherBucketId, `${bucketId}:svc-a:person-1:u1`)) ===
			null
	);

	await accounts.put(record(bucketId, 'svc-a', 'person-1', 'u2', 'access-2'));
	await accounts.put(record(bucketId, 'svc-b', 'person-1', 'u3', 'access-3'));
	await accounts.put(record(bucketId, 'svc-a', 'person-2', 'u4', 'access-4'));
	await accounts.put(
		record(otherBucketId, 'svc-a', 'person-1', 'u5', 'access-5')
	);
	check(
		'connected accounts: one person’s accounts at one service are counted alone',
		(await accounts.countByAccountAndService(bucketId, 'person-1', 'svc-a')) ===
			2
	);
	check(
		'connected accounts: a service’s accounts are counted within its project',
		(await accounts.countByService(bucketId, 'svc-a')) === 3
	);

	const byService = await accounts.destroyByService(bucketId, 'svc-b');
	check(
		'connected accounts: deleting a service removes exactly its accounts and returns them',
		byService.length === 1 && byService[0].upstreamId === 'u3',
		byService.map((row) => row.upstreamId).join(',')
	);
	const byAccount = await accounts.destroyByAccount(bucketId, 'person-2');
	check(
		'connected accounts: deleting a person removes exactly their accounts',
		byAccount.length === 1 && byAccount[0].upstreamId === 'u4'
	);
	const one = await accounts.destroy(bucketId, `${bucketId}:svc-a:person-1:u2`);
	const notHere = await accounts.destroy(
		otherBucketId,
		`${bucketId}:svc-a:person-1:u1`
	);
	check(
		'connected accounts: one account is deleted only within its own project',
		one?.upstreamId === 'u2' && notHere === null
	);

	/* ---- the encryption pass: a token, and the second of three services sharing one secret ---- */

	const tokenTarget = (await sealing.scan('connectedAccountToken')).find(
		(leaf) =>
			leaf.target.kind === 'connectedAccountToken' &&
			leaf.target.id === `${bucketId}:svc-a:person-1:u1` &&
			leaf.target.field === 'refreshToken'
	);
	check(
		'connected accounts: the scan finds a token as it is stored, with its person',
		tokenTarget !== undefined &&
			tokenTarget.value === 'refresh-u1' &&
			tokenTarget.target.kind === 'connectedAccountToken' &&
			tokenTarget.target.accountId === 'person-1'
	);
	if (tokenTarget) {
		const wrote = await sealing.sealAt(
			tokenTarget.target,
			'refresh-u1',
			'sealed-refresh-u1'
		);
		const stale = await sealing.sealAt(
			tokenTarget.target,
			'refresh-u1',
			'late'
		);
		const afterwards = await accounts.find(
			bucketId,
			`${bucketId}:svc-a:person-1:u1`
		);
		check(
			'connected accounts: a token compare-and-set writes once and never from a stale value',
			wrote &&
				!stale &&
				afterwards?.refreshToken === 'sealed-refresh-u1' &&
				afterwards.accessToken === 'access-1b',
			`${String(wrote)} ${String(stale)} ${String(afterwards?.refreshToken)}`
		);
	}

	const now = new Date().toISOString();
	const service = (id: string): ConnectedService => ({
		id,
		kind: 'catalogue',
		catalogueId: 'github',
		clientId: `${id}-client`,
		clientSecret: `shared-${stamp}`,
		scopes: ['read:user'],
		displayName: id,
		createdAt: now,
		updatedAt: now
	});
	const bucket = await buckets.create({
		name: `connected-${stamp}`,
		ownerGroupId: 'unassigned'
	});
	await buckets.update(bucket._id, {
		connectedServices: [service('first'), service('middle'), service('last')]
	});
	const middle = (await sealing.scan('connectedServiceSecret')).find(
		(leaf) =>
			leaf.target.kind === 'connectedServiceSecret' &&
			leaf.target.bucketId === bucket._id &&
			leaf.target.serviceId === 'middle'
	);
	check(
		'connected services: the scan finds the secret of each service as it is stored',
		middle?.value === `shared-${stamp}`
	);
	if (middle) {
		const target: SealTarget = middle.target;
		const wrote = await sealing.sealAt(
			target,
			`shared-${stamp}`,
			`sealed-${stamp}`
		);
		const stale = await sealing.sealAt(target, `shared-${stamp}`, 'late');
		const stored = (await buckets.find(bucket._id))?.connectedServices ?? [];
		check(
			'connected services: the compare-and-set reaches the middle service alone, once',
			wrote &&
				!stale &&
				stored.map((item) => item.clientSecret).join(',') ===
					[`shared-${stamp}`, `sealed-${stamp}`, `shared-${stamp}`].join(','),
			stored.map((item) => item.clientSecret).join(',')
		);
	}

	/* ---- tidy up ---- */

	const left = await accounts.destroyByBucket(bucketId);
	const leftOther = await accounts.destroyByBucket(otherBucketId);
	check(
		'connected accounts: deleting a project removes exactly its accounts',
		left.length === 1 && leftOther.length === 1 && left[0].upstreamId === 'u1'
	);
	await buckets.destroy(bucket._id);
}
