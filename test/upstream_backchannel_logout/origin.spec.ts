import { describe, it, beforeAll, afterEach, expect, mock } from 'bun:test';
import { decodeJwt } from 'jose';

import { getUserStore } from 'lib/adapters/index.js';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { present } from 'test/shape.js';
import bootstrap, { agent } from '../test_helper.js';
import { assertNoPendingInterceptors } from '../fetch_mock.js';
import { walk } from '../federation/harness.js';
import {
	CLIENT_AT_IDP,
	cookiesOf,
	keysServedForLogout,
	logoutEndpointOf,
	passwordAccount,
	passwordSignIn,
	sendLogout,
	sessionRecord,
	signInThroughProvider,
	upstreamOfDefaultBucket
} from './helpers.ts';

/**
 * @proves A session answers to the upstream session of its latest sign-in only — a password re-authentication
 * detaches it, a sign-in that completed a pending link attaches it — and the provider's session identifier is
 * never handed to a relying party or a browser (spec 073 FR-001–FR-003).
 */
describe('where a session came from', () => {
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

	it('no longer ends a session the person re-authenticated with their password', async () => {
		const upstream = await upstreamOfDefaultBucket('kc');
		const email = `both-${crypto.randomUUID()}@example.com`;
		const account = await passwordAccount(email);
		await getUserStore(DEFAULT_BUCKET_ID).update(account._id, {
			federated: [
				{
					providerId: upstream.provider.id,
					sub: 'kc-both',
					linkedAt: new Date()
				}
			]
		});
		const person = await signInThroughProvider(upstream, {
			sub: 'kc-both',
			sid: 'kc-session-before'
		});
		const reauth = new AuthorizationRequest({
			client_id: 'client',
			scope: 'openid',
			prompt: 'login'
		});
		const { response } = await agent.auth.get({
			query: reauth.params,
			headers: { cookie: person.cookie }
		});
		const uid = present(
			response.headers.get('location')?.split('/')[2],
			'the interaction'
		);
		const sessionId = await passwordSignIn(
			uid,
			[person.cookie, ...cookiesOf(response)],
			email,
			person.sessionId
		);
		await keysServedForLogout(upstream.stub);

		const res = await sendLogout(
			logoutEndpointOf(upstream.bucket),
			await upstream.stub.logoutToken({
				aud: CLIENT_AT_IDP,
				sub: 'kc-both',
				sid: 'kc-session-before'
			})
		);

		expect(res.status).toBe(200);
		expect(sessionRecord(sessionId)).toBeDefined();
	});

	it('ends a session whose sign-in completed a link proven at the provider', async () => {
		const upstream = await upstreamOfDefaultBucket('kc', {
			emailTrusted: true
		});
		const email = `linking-${crypto.randomUUID()}@example.com`;
		await passwordAccount(email);
		const auth = new AuthorizationRequest({
			client_id: 'client',
			scope: 'openid'
		});
		const { response } = await agent.auth.get({ query: auth.params });
		const uid = present(
			response.headers.get('location')?.split('/')[2],
			'the interaction'
		);
		const interactionCookies = cookiesOf(response);
		await walk(
			uid,
			interactionCookies.join('; '),
			{
				idp: upstream.stub,
				claims: {
					sub: 'kc-linking',
					email,
					email_verified: true,
					sid: 'kc-session-link'
				},
				opts: { audience: CLIENT_AT_IDP }
			},
			{ providerId: upstream.provider.id }
		);
		const sessionId = await passwordSignIn(uid, interactionCookies, email);
		await keysServedForLogout(upstream.stub);

		await sendLogout(
			logoutEndpointOf(upstream.bucket),
			await upstream.stub.logoutToken({
				aud: CLIENT_AT_IDP,
				sub: 'kc-linking',
				sid: 'kc-session-link'
			})
		);

		expect(sessionRecord(sessionId)).toBeUndefined();
	});

	describe('the provider’s session identifier', () => {
		const UPSTREAM_SID = 'upstream-sid-that-must-stay-here-7f3a';

		it('is not in the ID token a relying party receives', async () => {
			const upstream = await upstreamOfDefaultBucket('kc');
			const person = await signInThroughProvider(upstream, {
				sub: 'kc-leak-1',
				sid: UPSTREAM_SID
			});

			expect(JSON.stringify(decodeJwt(person.idToken))).not.toContain(
				UPSTREAM_SID
			);
		});

		it('is not in the userinfo response', async () => {
			const upstream = await upstreamOfDefaultBucket('kc');
			const person = await signInThroughProvider(upstream, {
				sub: 'kc-leak-2',
				sid: UPSTREAM_SID
			});

			const { data } = await agent.userinfo.get({
				headers: { authorization: `Bearer ${person.accessToken}` }
			});

			expect(JSON.stringify(present(data, 'userinfo'))).not.toContain(
				UPSTREAM_SID
			);
		});

		it('is not in any cookie set during the sign-in', async () => {
			const upstream = await upstreamOfDefaultBucket('kc');
			const person = await signInThroughProvider(upstream, {
				sub: 'kc-leak-3',
				sid: UPSTREAM_SID
			});

			expect(person.setCookies.join('\n')).not.toContain(UPSTREAM_SID);
		});
	});
});
