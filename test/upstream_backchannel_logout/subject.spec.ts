import { describe, it, beforeAll, afterEach, expect, mock } from 'bun:test';

import { getUserStore } from 'lib/adapters/index.js';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import bootstrap from '../test_helper.js';
import { assertNoPendingInterceptors } from '../fetch_mock.js';
import { idpStub } from '../federation/idp_stub.js';
import { defaultBucketWith } from '../global_token_revocation/helpers.js';
import {
	CLIENT_AT_IDP,
	keysServedForLogout,
	logoutEndpointOf,
	logoutProvider,
	passwordAccount,
	relyingPartyListening,
	sendLogout,
	sessionRecord,
	signInThroughProvider,
	signInWithPassword,
	uniqueOrigin,
	upstreamOfDefaultBucket,
	type Upstream
} from './helpers.ts';

/*
 * One person reachable three ways: through provider A, through provider B, and with a password — each sign-in
 * a session of its own.
 */
async function personWithThreeSessions() {
	const a = await upstreamOfDefaultBucket('kc-a');
	const bOrigin = uniqueOrigin('kc-b');
	const bStub = await idpStub(bOrigin);
	bStub.expectDiscovery();
	const bProvider = logoutProvider('kc-b', bOrigin);
	const bucket = await defaultBucketWith([a.provider, bProvider]);
	const b: Upstream = { stub: bStub, provider: bProvider, bucket };

	const email = `three-${crypto.randomUUID()}@example.com`;
	const account = await passwordAccount(email);
	await getUserStore(DEFAULT_BUCKET_ID).update(account._id, {
		federated: [
			{ providerId: a.provider.id, sub: 'person-at-a', linkedAt: new Date() },
			{ providerId: b.provider.id, sub: 'person-at-b', linkedAt: new Date() }
		]
	});
	const viaA = await signInThroughProvider(a, {
		sub: 'person-at-a',
		sid: 'a-session'
	});
	const viaB = await signInThroughProvider(b, {
		sub: 'person-at-b',
		sid: 'b-session'
	});
	const withPassword = await signInWithPassword(email);
	return { a, viaA, viaB, withPassword };
}

/**
 * @proves A provider reporting that a person signed out without naming a session ends every session of
 * theirs that came through that provider and none that came another way; and a token pairing one person with
 * another's session ends nothing (spec 073 User Story 2; FR-009, FR-010, FR-013; SC-004).
 */
describe('an upstream provider signing a person out of every session', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	afterEach(() => {
		try {
			mock.restore();
		} finally {
			assertNoPendingInterceptors();
		}
	});

	it('ends the person’s session that came through that provider', async () => {
		const { a, viaA } = await personWithThreeSessions();
		await keysServedForLogout(a.stub);
		relyingPartyListening('https://client.example.com');

		await sendLogout(
			logoutEndpointOf(a.bucket),
			await a.stub.logoutToken({ aud: CLIENT_AT_IDP, sub: 'person-at-a' })
		);

		expect(sessionRecord(viaA.sessionId)).toBeUndefined();
	});

	it('leaves the person’s sessions from a password and from another provider', async () => {
		const { a, viaB, withPassword } = await personWithThreeSessions();
		await keysServedForLogout(a.stub);
		relyingPartyListening('https://client.example.com');

		await sendLogout(
			logoutEndpointOf(a.bucket),
			await a.stub.logoutToken({ aud: CLIENT_AT_IDP, sub: 'person-at-a' })
		);

		expect(sessionRecord(viaB.sessionId)).toBeDefined();
		expect(sessionRecord(withPassword)).toBeDefined();
	});

	it('ends nothing when the token pairs one person with another person’s session', async () => {
		const upstream = await upstreamOfDefaultBucket('kc');
		const victim = await signInThroughProvider(upstream, {
			sub: 'victim',
			sid: 'victim-session'
		});
		await signInThroughProvider(upstream, {
			sub: 'other',
			sid: 'other-session'
		});
		await keysServedForLogout(upstream.stub);

		const res = await sendLogout(
			logoutEndpointOf(upstream.bucket),
			await upstream.stub.logoutToken({
				aud: CLIENT_AT_IDP,
				sub: 'other',
				sid: 'victim-session'
			})
		);

		expect(res.status).toBe(200);
		expect(sessionRecord(victim.sessionId)).toBeDefined();
	});

	it('answers success and changes nothing for a subject nobody here is linked to', async () => {
		const upstream = await upstreamOfDefaultBucket('kc');
		const person = await signInThroughProvider(upstream, {
			sub: 'someone',
			sid: 'someone-session'
		});
		await keysServedForLogout(upstream.stub);

		const res = await sendLogout(
			logoutEndpointOf(upstream.bucket),
			await upstream.stub.logoutToken({
				aud: CLIENT_AT_IDP,
				sub: 'nobody-here'
			})
		);

		expect(res.status).toBe(200);
		expect(sessionRecord(person.sessionId)).toBeDefined();
	});
});
