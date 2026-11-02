import { randomBytes } from 'node:crypto';

import { selectBackend } from '../lib/adapters/selectBackend.js';
import type { SealTarget } from '../lib/consts/sealed_fields.js';
import { STORE_AREAS, areaNamed } from '../lib/consts/storage_inventory.js';
import type {
	ConnectedAccountStoreInstance,
	ProtectedResourceStoreInstance,
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
	resources: ProtectedResourceStoreInstance;
}

/*
 * An API's exchanging application (specs/118 R3): set, kept through an unrelated edit, and removed by `null`. The
 * removal drops a key from the stored document, which on PostgreSQL binds a text array; a bare JS array there is
 * refused at runtime, which only a real server shows.
 */
async function verifyExchangingApplication(
	resources: ProtectedResourceStoreInstance,
	check: Check,
	stamp: string
): Promise<void> {
	const namespace = `verify-${stamp}`;
	const identifier = `https://mcp-${stamp}.example/`;
	await resources.create({
		namespace,
		identifier,
		bucketId: `connected-${stamp}`,
		name: 'An MCP server',
		scopes: ['repos'],
		tokenFormat: 'jwt'
	});
	const set = await resources.update(namespace, identifier, {
		exchangedBy: 'mcp-server'
	});
	const kept = await resources.update(namespace, identifier, {
		name: 'Renamed'
	});
	const cleared = await resources.update(namespace, identifier, {
		exchangedBy: null
	});
	check(
		'resources: an exchanging application is set, kept through another edit, and removed by null',
		set?.exchangedBy === 'mcp-server' &&
			kept?.exchangedBy === 'mcp-server' &&
			cleared !== null &&
			!('exchangedBy' in cleared) &&
			cleared.name === 'Renamed',
		`${String(set?.exchangedBy)} ${String(kept?.exchangedBy)} ${JSON.stringify(cleared)}`
	);
	await resources.destroy(namespace, identifier);
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

	await verifyRefreshes(accounts, check, stamp);
	await verifyKeepAliveIndex(check);
	await verifyExchangingApplication(fixture.resources, check, stamp);

	/* ---- tidy up ---- */

	const left = await accounts.destroyByBucket(bucketId);
	const leftOther = await accounts.destroyByBucket(otherBucketId);
	check(
		'connected accounts: deleting a project removes exactly its accounts',
		left.length === 1 && leftOther.length === 1 && left[0].upstreamId === 'u1'
	);
	await buckets.destroy(bucket._id);
}

/*
 * The refresh lease, the broken mark, the per-agent use list and the keep-alive scan (specs/118), in projects of
 * their own so the counts above stay this file's. What a double cannot show: that the lease is one atomic
 * compare-and-set under real concurrency, that a use landing beside a refresh is not overwritten by it, and that the
 * keep-alive filter reads the same rows on both backends.
 */
async function verifyRefreshes(
	accounts: ConnectedAccountStoreInstance,
	check: Check,
	stamp: string
): Promise<void> {
	const bucketId = `refresh-${stamp}`;
	const otherBucketId = `refresh-other-${stamp}`;
	const now = Math.floor(Date.now() / 1000);
	const idOf = (bucket: string, upstreamId: string): string =>
		`${bucket}:svc-r:person-r:${upstreamId}`;
	const put = async (
		upstreamId: string,
		extra: Partial<ConnectedAccount> = {},
		bucket = bucketId,
		withRefreshToken = true
	): Promise<string> => {
		const { refreshToken, ...base } = record(
			bucket,
			'svc-r',
			'person-r',
			upstreamId,
			`access-${upstreamId}`
		);
		await accounts.put({
			...base,
			...(withRefreshToken ? { refreshToken } : {}),
			...extra
		});
		return idOf(bucket, upstreamId);
	};

	/* ---- the lease ---- */

	const raced = await put('race');
	const claims = await Promise.all([
		accounts.claimRefresh(bucketId, raced, 'holder-a', now, now + 60),
		accounts.claimRefresh(bucketId, raced, 'holder-b', now, now + 60)
	]);
	const winners = claims.filter((claim) => claim !== null);
	const stored = await accounts.find(bucketId, raced);
	check(
		'refresh lease: of two concurrent claims exactly one wins, and the record names it',
		winners.length === 1 &&
			winners[0]?.refreshLease?.holder === stored?.refreshLease?.holder &&
			stored?.refreshLease?.until === now + 60,
		claims.map((claim) => claim?.refreshLease?.holder ?? 'null').join(',')
	);

	const expiring = await put('expiring');
	const firstClaim = await accounts.claimRefresh(
		bucketId,
		expiring,
		'holder-a',
		now,
		now + 30
	);
	const whileHeld = await accounts.claimRefresh(
		bucketId,
		expiring,
		'holder-b',
		now + 10,
		now + 70
	);
	const atExpiry = await accounts.claimRefresh(
		bucketId,
		expiring,
		'holder-b',
		now + 30,
		now + 90
	);
	check(
		'refresh lease: a held lease is refused, and one whose until has come is taken over',
		firstClaim !== null &&
			whileHeld === null &&
			atExpiry?.refreshLease?.holder === 'holder-b' &&
			atExpiry.refreshLease.until === now + 90,
		`${String(firstClaim?.refreshLease?.holder)} ${String(whileHeld?.refreshLease?.holder ?? null)} ${String(atExpiry?.refreshLease?.holder)}`
	);
	check(
		'refresh lease: a claim is refused in another project',
		(await accounts.claimRefresh(
			otherBucketId,
			expiring,
			'holder-c',
			now + 1000,
			now + 1060
		)) === null
	);

	/* ---- writing a refresh ---- */

	const lateWrite = await accounts.finishRefresh(
		bucketId,
		expiring,
		'holder-a',
		{
			accessToken: 'late',
			tokenType: 'Bearer',
			scopes: ['read'],
			refreshedAt: now
		}
	);
	const untouched = await accounts.find(bucketId, expiring);
	check(
		'finish refresh: a holder whose lease was taken over writes nothing',
		!lateWrite &&
			untouched?.accessToken === 'access-expiring' &&
			untouched.refreshLease?.holder === 'holder-b' &&
			untouched.refreshedAt === undefined,
		`${String(lateWrite)} ${String(untouched?.accessToken)}`
	);

	const kept = await put('kept', {
		accessTokenExpiresAt: now + 3600,
		refreshTokenExpiresAt: now + 86400
	});
	await accounts.claimRefresh(bucketId, kept, 'holder-a', now, now + 60);
	const wrote = await accounts.finishRefresh(bucketId, kept, 'holder-a', {
		accessToken: 'access-kept-2',
		tokenType: 'bearer',
		scopes: ['read', 'write'],
		refreshedAt: now + 5
	});
	const refreshed = await accounts.find(bucketId, kept);
	check(
		'finish refresh: the holder writes the tokens and frees the lease',
		wrote &&
			refreshed?.accessToken === 'access-kept-2' &&
			refreshed.tokenType === 'bearer' &&
			refreshed.scopes.join(',') === 'read,write' &&
			refreshed.refreshedAt === now + 5 &&
			refreshed.refreshLease === undefined,
		JSON.stringify(refreshed)
	);
	check(
		'finish refresh: a refresh token the provider did not replace is kept',
		refreshed?.refreshToken === 'refresh-kept' &&
			refreshed.refreshTokenExpiresAt === now + 86400,
		`${String(refreshed?.refreshToken)} ${String(refreshed?.refreshTokenExpiresAt)}`
	);
	check(
		'finish refresh: an access token now given no expiry loses the old one',
		refreshed !== null && !('accessTokenExpiresAt' in refreshed),
		String(refreshed?.accessTokenExpiresAt)
	);

	await accounts.claimRefresh(bucketId, kept, 'holder-b', now, now + 60);
	const rotated = await accounts.finishRefresh(bucketId, kept, 'holder-b', {
		accessToken: 'access-kept-3',
		refreshToken: 'refresh-kept-rotated',
		tokenType: 'Bearer',
		accessTokenExpiresAt: now + 7200,
		refreshTokenExpiresAt: now + 172800,
		scopes: ['read'],
		refreshedAt: now + 10
	});
	const afterRotation = await accounts.find(bucketId, kept);
	check(
		'finish refresh: a rotated refresh token and new expiries replace the old ones',
		rotated &&
			afterRotation?.refreshToken === 'refresh-kept-rotated' &&
			afterRotation.accessTokenExpiresAt === now + 7200 &&
			afterRotation.refreshTokenExpiresAt === now + 172800 &&
			afterRotation.refreshLease === undefined,
		JSON.stringify(afterRotation)
	);

	/* ---- releasing ---- */

	const released = await put('released');
	await accounts.claimRefresh(bucketId, released, 'holder-a', now, now + 60);
	await accounts.releaseRefresh(bucketId, released, 'holder-b');
	const notReleased = await accounts.find(bucketId, released);
	await accounts.releaseRefresh(bucketId, released, 'holder-a');
	const isReleased = await accounts.find(bucketId, released);
	check(
		'release refresh: only the holder frees the lease',
		notReleased?.refreshLease?.holder === 'holder-a' &&
			isReleased !== null &&
			isReleased.refreshLease === undefined,
		`${String(notReleased?.refreshLease?.holder)} ${JSON.stringify(isReleased?.refreshLease)}`
	);

	/* ---- breaking ---- */

	const broken = await put('broken');
	await accounts.claimRefresh(bucketId, broken, 'holder-a', now, now + 60);
	const firstBreak = await accounts.markBroken(
		bucketId,
		broken,
		'refresh_rejected',
		now
	);
	const secondBreak = await accounts.markBroken(
		bucketId,
		broken,
		'identity_changed',
		now + 1
	);
	const brokenRecord = await accounts.find(bucketId, broken);
	check(
		'mark broken: the first call breaks the account and says so, the second does not',
		firstBreak.first && !secondBreak.first,
		`${String(firstBreak.first)} ${String(secondBreak.first)}`
	);
	check(
		'mark broken: the record keeps the first reason and holds no lease',
		brokenRecord?.broken?.reason === 'refresh_rejected' &&
			brokenRecord.broken.at === now &&
			brokenRecord.broken.notified &&
			brokenRecord.refreshLease === undefined,
		JSON.stringify(brokenRecord?.broken)
	);
	const unbroken = await put('unbroken');
	const elsewhere = await accounts.markBroken(
		otherBucketId,
		unbroken,
		'refresh_rejected',
		now
	);
	const stillWhole = await accounts.find(bucketId, unbroken);
	check(
		'mark broken: never reaches another project',
		!elsewhere.first && stillWhole !== null && stillWhole.broken === undefined
	);

	/* ---- who used it ---- */

	const urlClient = 'https://agent.example/client.json';
	const used = await put('used');
	await accounts.noteUse(bucketId, used, 'agent-1', now + 1);
	await accounts.noteUse(bucketId, used, urlClient, now + 2);
	await accounts.noteUse(bucketId, used, 'agent-1', now + 3);
	const usedRecord = await accounts.find(bucketId, used);
	const uses = new Map(
		(usedRecord?.usedBy ?? []).map((entry) => [entry.clientId, entry.at])
	);
	check(
		'note use: one entry per agent, the newer use replacing the older, a URL client id included',
		usedRecord?.usedBy?.length === 2 &&
			uses.get('agent-1') === now + 3 &&
			uses.get(urlClient) === now + 2,
		JSON.stringify(usedRecord?.usedBy)
	);

	await Promise.all([
		accounts.noteUse(bucketId, used, 'agent-twice', now + 4),
		accounts.noteUse(bucketId, used, 'agent-twice', now + 4)
	]);
	const twice = (await accounts.find(bucketId, used))?.usedBy ?? [];
	check(
		'note use: two concurrent first uses by one agent leave one entry',
		twice.filter((entry) => entry.clientId === 'agent-twice').length === 1 &&
			twice.length === 3,
		JSON.stringify(twice)
	);

	const lostUpdates: string[] = [];
	for (let round = 0; round < 10; round += 1) {
		const holder = `holder-${round}`;
		const agent = `agent-race-${round}`;
		await accounts.claimRefresh(bucketId, used, holder, now, now + 60);
		const [, finished] = await Promise.all([
			accounts.noteUse(bucketId, used, agent, now + 10 + round),
			accounts.finishRefresh(bucketId, used, holder, {
				accessToken: `access-race-${round}`,
				tokenType: 'Bearer',
				scopes: ['read'],
				refreshedAt: now + round
			})
		]);
		const after = await accounts.find(bucketId, used);
		if (
			!finished ||
			after?.accessToken !== `access-race-${round}` ||
			!after.usedBy?.some(
				(entry) => entry.clientId === agent && entry.at === now + 10 + round
			)
		) {
			lostUpdates.push(`${round}: ${JSON.stringify(after)}`);
		}
	}
	check(
		'note use: a use landing beside a refresh loses neither, ten times over',
		lostUpdates.length === 0,
		lostUpdates.join(' | ')
	);

	/* ---- the keep-alive scan, across projects ---- */

	const usedRecently = [{ clientId: 'agent-1', at: now - 100 }];
	const due = {
		staleBefore: now - 1000,
		expiringBefore: now + 1000,
		usedSince: now - 5000
	};
	const expected = [
		await put('due-never-refreshed', { usedBy: usedRecently }),
		await put(
			'due-stale',
			{ refreshedAt: now - 2000, usedBy: usedRecently },
			otherBucketId
		),
		await put('due-expiring', {
			refreshedAt: now,
			refreshTokenExpiresAt: now + 500,
			usedBy: usedRecently
		}),
		await put('due-one-of-two-recent', {
			refreshedAt: now - 2000,
			usedBy: [
				{ clientId: 'agent-old', at: now - 10000 },
				{ clientId: urlClient, at: now - 10 }
			]
		})
	];
	const notDue = [
		await put('fresh', {
			refreshedAt: now,
			refreshTokenExpiresAt: now + 100000,
			usedBy: usedRecently
		}),
		await put('fresh-no-expiry', { refreshedAt: now, usedBy: usedRecently }),
		await put(
			'broken-stale',
			{
				refreshedAt: now - 2000,
				usedBy: usedRecently,
				broken: { reason: 'refresh_rejected', at: now, notified: true }
			},
			otherBucketId
		),
		await put('never-used', { refreshedAt: now - 2000 }),
		await put('used-long-ago', {
			refreshedAt: now - 2000,
			usedBy: [{ clientId: 'agent-1', at: now - 10000 }]
		}),
		await put(
			'no-refresh-token',
			{ refreshedAt: now - 2000, usedBy: usedRecently },
			otherBucketId,
			false
		)
	];
	const ours = new Set([...expected, ...notDue]);
	const listed = (await accounts.listKeepAliveDue({ ...due, limit: 100000 }))
		.map((row) => row._id)
		.filter((id) => ours.has(id))
		.sort();
	check(
		'keep-alive: exactly the stale or expiring, unbroken, recently used accounts holding a refresh token, across projects',
		listed.join(',') === [...expected].sort().join(','),
		listed.map((id) => id.split(':').at(-1)).join(',')
	);

	/* ---- tidy up ---- */

	await accounts.destroyByBucket(bucketId);
	await accounts.destroyByBucket(otherBucketId);
}

/*
 * The keep-alive scan's index on `refreshedAt` (specs/118 R11), as provisioning made it from the inventory. Which
 * backend this run is on is read the way the adapters chose it; both modules are already loaded by the caller, so
 * importing one here opens nothing new.
 */
async function verifyKeepAliveIndex(check: Check): Promise<void> {
	const backend = selectBackend(process.env);
	if (backend === 'mongodb') {
		const { db } = await import('../lib/adapters/mongodb/db.js');
		const indexes = await db
			.collection(STORE_AREAS.connectedAccounts)
			.indexes();
		check(
			'connected accounts: the keep-alive index on refreshedAt is provisioned',
			indexes.some(
				(index) =>
					Object.keys(index.key).join(',') === 'refreshedAt' &&
					index.key.refreshedAt === 1
			),
			indexes.map((index) => JSON.stringify(index.key)).join(' ')
		);
	} else if (backend === 'postgres') {
		const { indexStatements, sql } =
			await import('../lib/adapters/postgres/index.js');
		const area = areaNamed(STORE_AREAS.connectedAccounts);
		const planned = indexStatements(area).filter((index) =>
			index.statement.includes("'refreshedAt'")
		);
		const handle = sql();
		const present = await handle<{ indexname: string; indexdef: string }[]>`
			SELECT indexname, indexdef FROM pg_indexes WHERE tablename = ${area.name}
		`;
		const found = present.find((row) => row.indexname === planned[0]?.name);
		check(
			'connected accounts: the keep-alive index on refreshedAt is provisioned',
			planned.length === 1 &&
				found !== undefined &&
				found.indexdef.includes("'refreshedAt'"),
			found?.indexdef ?? present.map((row) => row.indexname).join(', ')
		);
	}
}
