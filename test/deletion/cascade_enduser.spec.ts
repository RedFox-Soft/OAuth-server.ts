import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';

import bootstrap, { agent, type Setup } from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { AccessToken } from 'lib/models/access_token.js';
import { RefreshToken } from 'lib/models/refresh_token.js';
import { Session } from 'lib/models/session.js';
import { Grant } from 'lib/models/grant.js';
import { Client } from 'lib/models/client.js';
import {
	adapter,
	adminSessionStore,
	getBucketStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import epochTime from 'lib/helpers/epoch_time.js';

// User Story 2 — deleting an end-user ends their access everywhere.
//
// The subtle one is the last: VerificationResend is addressed by `${bucketId}:${email}`, so the cascade
// has to read the account's email *before* destroying the row. Get the order wrong and that record is
// silently left behind with no error anywhere — which is why it has its own test rather than being
// folded into a "sweeps everything" assertion.

describe('deletion cascade: end-user', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		await ensureAdminSeed();
	});

	async function superAdminCookie(): Promise<string> {
		const admin = await getUserStore(ADMIN_BUCKET_ID).create(
			`sa-${Math.random()}@x.io`,
			'hash',
			['super_admin']
		);
		const session = await adminSessionStore.create({
			userId: admin._id,
			bucketId: ADMIN_BUCKET_ID,
			tokens: {},
			ttlSeconds: 60,
			absoluteTtlSeconds: 3600
		});
		return `${ADMIN_SESSION_COOKIE}=${session._id}`;
	}

	/* A bucket holding one end-user, returned with everything a cascade could be asked to reach. */
	async function endUser(email = `u-${Math.random()}@example.com`) {
		const bucket = await getBucketStore().create({
			name: `b-${Math.random()}`,
			roles: [],
			managedBy: []
		});
		const user = await getUserStore(bucket._id).create(email, 'hash');
		return { bucketId: bucket._id, uid: user._id, email };
	}

	async function deleteUser(bucketId: string, uid: string) {
		const cookie = await superAdminCookie();
		return agent.admin.api
			.buckets({ id: bucketId })
			.users({ uid })
			.delete(undefined, { headers: { cookie } });
	}

	async function consentFor(accountId: string) {
		const grant = new Grant({ clientId: 'doomed', accountId });
		grant.addOIDCScope('openid offline_access');
		return grant.save();
	}

	it('stops the account session from authorizing (scenario 1)', async () => {
		const { bucketId, uid } = await endUser();
		const session = new Session({ accountId: uid, loginTs: epochTime() });
		const sessionId = await session.save();
		expect(await adapter('Session').find(sessionId)).toBeDefined();

		const res = await deleteUser(bucketId, uid);
		expect(res.status).toBe(200);

		expect(await adapter('Session').find(sessionId)).toBeUndefined();
		expect(
			await adapter('Session').findByUid(session.payload.uid)
		).toBeUndefined();
	});

	it('refuses the account refresh token (scenario 2)', async () => {
		const { bucketId, uid } = await endUser();
		const grantId = await consentFor(uid);
		const rt = new RefreshToken({
			client: await client('doomed'),
			accountId: uid,
			grantId,
			scope: 'openid offline_access',
			gty: 'authorization_code'
		});
		const token = await rt.save();
		expect(await introspect(token)).toHaveProperty('active', true);

		await deleteUser(bucketId, uid);

		expect(await introspect(token)).toHaveProperty('active', false);
		const exchange = await agent.token.post(
			{ grant_type: 'refresh_token', refresh_token: token },
			{ headers: AuthorizationRequest.basicAuthHeader('doomed', 'secret') }
		);
		expect(errorOf(exchange)).toMatch(/invalid_grant/);
	});

	it('refuses the account access token and reports it inactive (scenario 3)', async () => {
		const { bucketId, uid } = await endUser();
		const grantId = await consentFor(uid);
		const at = new AccessToken({
			client: await client('doomed'),
			accountId: uid,
			grantId,
			scope: 'openid'
		});
		const bearer = await at.save();

		await deleteUser(bucketId, uid);

		const userinfo = await agent.userinfo.get({
			headers: { authorization: `Bearer ${bearer}` }
		});
		expect(userinfo.status).toBe(401);
		expect(await introspect(bearer)).toHaveProperty('active', false);
	});

	it('destroys the account consent records (scenario 4)', async () => {
		const { bucketId, uid } = await endUser();
		const mine = await consentFor(uid);
		const { uid: otherUid } = await endUser();
		const theirs = await consentFor(otherUid);

		await deleteUser(bucketId, uid);

		expect(await adapter('Grant').find(mine)).toBeUndefined();
		expect(await adapter('Grant').find(theirs)).toBeDefined();
	});

	it('destroys a pending interaction and verification challenge (scenario 5)', async () => {
		const { bucketId, uid } = await endUser();
		const ttl = 300;
		await adapter('Interaction').upsert(
			`int-${uid}`,
			{ accountId: uid, exp: epochTime() + ttl } as never,
			ttl
		);
		await adapter('VerificationChallenge').upsert(
			`vc-${uid}`,
			{
				accountId: uid,
				bucketId,
				email: 'x@example.com',
				method: 'code',
				attempts: 0,
				exp: epochTime() + ttl
			} as never,
			ttl
		);

		await deleteUser(bucketId, uid);

		expect(await adapter('Interaction').find(`int-${uid}`)).toBeUndefined();
		expect(
			await adapter('VerificationChallenge').find(`vc-${uid}`)
		).toBeUndefined();
	});

	// The record nothing else can find once the account row is gone.
	it('destroys the resend record keyed by the account email (scenario 6)', async () => {
		const { bucketId, uid, email } = await endUser();
		const resendId = `${bucketId}:${email}`;
		const ttl = 300;
		await adapter('VerificationResend').upsert(
			resendId,
			{
				lastSentAt: epochTime(),
				dayCount: 1,
				windowStart: epochTime(),
				exp: epochTime() + ttl
			} as never,
			ttl
		);

		const res = await deleteUser(bucketId, uid);
		expect(res.status).toBe(200);

		expect(await adapter('VerificationResend').find(resendId)).toBeUndefined();
	});

	/*
	 * The reset secret is owner-swept like any other account-owned area; its throttle counters are the
	 * second record addressed by `${bucketId}:${email}` rather than found, so it fails the same silent way
	 * scenario 6 does if the id is computed after the account row is gone. Asserted separately for that
	 * reason (specs/020-enduser-password-reset, contracts/storage-and-cascade.md S2).
	 */
	it('destroys an outstanding password reset secret and its counters', async () => {
		const { bucketId, uid, email } = await endUser();
		const ttl = 300;
		await adapter('PasswordResetChallenge').upsert(
			`prc-${uid}`,
			{ accountId: uid, bucketId, email, exp: epochTime() + ttl } as never,
			ttl
		);
		const throttleId = `${bucketId}:${email}`;
		await adapter('PasswordResetThrottle').upsert(
			throttleId,
			{
				lastSentAt: epochTime(),
				dayCount: 1,
				windowStart: epochTime(),
				exp: epochTime() + ttl
			} as never,
			ttl
		);

		const res = await deleteUser(bucketId, uid);
		expect(res.status).toBe(200);

		expect(
			await adapter('PasswordResetChallenge').find(`prc-${uid}`)
		).toBeUndefined();
		expect(
			await adapter('PasswordResetThrottle').find(throttleId)
		).toBeUndefined();
	});

	it('leaves an account in another bucket untouched (scenario 7)', async () => {
		const mine = await endUser();
		const theirs = await endUser();
		const theirSession = new Session({
			accountId: theirs.uid,
			loginTs: epochTime()
		});
		const theirSessionId = await theirSession.save();

		await deleteUser(mine.bucketId, mine.uid);

		expect(await getUserStore(theirs.bucketId).find(theirs.uid)).not.toBeNull();
		expect(await adapter('Session').find(theirSessionId)).toBeDefined();
	});
});

async function client(clientId: string) {
	const found = await Client.tryFind(clientId);
	if (!found) throw new Error(`client ${clientId} is not seeded`);
	return found;
}

/* Introspected by a client that is not part of the story, so the answer is about the token. */
async function introspect(token: string): Promise<unknown> {
	const res = await agent.token.introspect.post(
		{ token },
		{ headers: AuthorizationRequest.basicAuthHeader('bystander', 'secret') }
	);
	return res.data;
}

/* Eden's response type varies per route, so this narrows from `unknown` rather than naming a shape that
 * only fits one of them. */
function errorOf(response: unknown): string {
	return bodyOf<{ error?: string }>(response)?.error ?? '';
}

/* The body of a response, whether the route answered with it as data or as an error. */
function bodyOf<T>(response: unknown): T | undefined {
	if (typeof response !== 'object' || response === null) return undefined;
	const { data, error } = response as {
		data?: unknown;
		error?: { value?: unknown } | null;
	};
	return (data ?? error?.value) as T | undefined;
}
