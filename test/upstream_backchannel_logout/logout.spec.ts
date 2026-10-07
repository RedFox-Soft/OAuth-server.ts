import { describe, it, beforeAll, afterEach, expect, mock } from 'bun:test';

import bootstrap from '../test_helper.js';
import { assertNoPendingInterceptors } from '../fetch_mock.js';
import { BACKCHANNEL_LOGOUT_EVENT } from '../federation/idp_stub.js';
import {
	CLIENT_AT_IDP,
	authorizeInSession,
	introspect,
	keysServedForLogout,
	logoutEndpointOf,
	nextAuthorization,
	refresh,
	relyingPartyListening,
	sendLogout,
	sessionRecord,
	signInThroughProvider,
	upstreamOfDefaultBucket
} from './helpers.ts';

const RP = 'https://client.example.com';
const RP_2 = 'https://client-2.example.com';

/**
 * @proves When a bucket's upstream provider reports that a person signed out of an upstream session, every
 * session here that came from it ends as a sign-out here ends — relying parties told, session-bound access
 * ended, offline access kept, the account untouched — and nothing else does (spec 073 User Story 1; FR-009,
 * FR-011–FR-014, FR-022; SC-001, SC-003, SC-004).
 */
describe('an upstream provider signing a person out', () => {
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

	it('ends the session that came from the upstream session it names', async () => {
		const upstream = await upstreamOfDefaultBucket('kc');
		const person = await signInThroughProvider(upstream, {
			sub: 'kc-user-1',
			sid: 'kc-session-1'
		});
		await keysServedForLogout(upstream.stub);
		relyingPartyListening(RP);

		const res = await sendLogout(
			logoutEndpointOf(upstream.bucket),
			await upstream.stub.logoutToken({
				aud: CLIENT_AT_IDP,
				sub: 'kc-user-1',
				sid: 'kc-session-1'
			})
		);

		expect(res.status).toBe(200);
		expect(sessionRecord(person.sessionId)).toBeUndefined();
	});

	it('answers with an empty body that no cache may keep', async () => {
		const upstream = await upstreamOfDefaultBucket('kc');
		await signInThroughProvider(upstream, {
			sub: 'kc-user-2',
			sid: 'kc-session-2'
		});
		await keysServedForLogout(upstream.stub);
		relyingPartyListening(RP);

		const res = await sendLogout(
			logoutEndpointOf(upstream.bucket),
			await upstream.stub.logoutToken({
				aud: CLIENT_AT_IDP,
				sub: 'kc-user-2',
				sid: 'kc-session-2'
			})
		);

		expect(res.text).toBe('');
		expect(res.headers.get('cache-control')).toContain('no-store');
	});

	it('sends a logout notice to every relying party the session signed the person in to', async () => {
		const upstream = await upstreamOfDefaultBucket('kc');
		const person = await signInThroughProvider(upstream, {
			sub: 'kc-user-3',
			sid: 'kc-session-3'
		});
		await authorizeInSession(person, 'client-2');
		await keysServedForLogout(upstream.stub);
		const first = relyingPartyListening(RP);
		const second = relyingPartyListening(RP_2);

		await sendLogout(
			logoutEndpointOf(upstream.bucket),
			await upstream.stub.logoutToken({
				aud: CLIENT_AT_IDP,
				sub: 'kc-user-3',
				sid: 'kc-session-3'
			})
		);

		expect(first.delivered).toHaveLength(1);
		expect(second.delivered).toHaveLength(1);
		expect(first.delivered[0]).toStartWith('logout_token=');
	});

	it('leaves an access token issued without offline access inactive', async () => {
		const upstream = await upstreamOfDefaultBucket('kc');
		const person = await signInThroughProvider(upstream, {
			sub: 'kc-user-4',
			sid: 'kc-session-4'
		});
		const sessionBound = await authorizeInSession(person, 'client-2');
		await keysServedForLogout(upstream.stub);
		relyingPartyListening(RP);
		relyingPartyListening(RP_2);

		await sendLogout(
			logoutEndpointOf(upstream.bucket),
			await upstream.stub.logoutToken({
				aud: CLIENT_AT_IDP,
				sub: 'kc-user-4',
				sid: 'kc-session-4'
			})
		);

		expect(await introspect('client-2', sessionBound.accessToken)).toEqual({
			active: false
		});
	});

	it('keeps an offline refresh token working', async () => {
		const upstream = await upstreamOfDefaultBucket('kc');
		const person = await signInThroughProvider(upstream, {
			sub: 'kc-user-5',
			sid: 'kc-session-5'
		});
		await keysServedForLogout(upstream.stub);
		relyingPartyListening(RP);

		await sendLogout(
			logoutEndpointOf(upstream.bucket),
			await upstream.stub.logoutToken({
				aud: CLIENT_AT_IDP,
				sub: 'kc-user-5',
				sid: 'kc-session-5'
			})
		);

		const { response } = await refresh(person.refreshToken);
		expect(response.status).toBe(200);
	});

	it('asks the person to sign in on their next authorization', async () => {
		const upstream = await upstreamOfDefaultBucket('kc');
		const person = await signInThroughProvider(upstream, {
			sub: 'kc-user-6',
			sid: 'kc-session-6'
		});
		await keysServedForLogout(upstream.stub);
		relyingPartyListening(RP);

		await sendLogout(
			logoutEndpointOf(upstream.bucket),
			await upstream.stub.logoutToken({
				aud: CLIENT_AT_IDP,
				sub: 'kc-user-6',
				sid: 'kc-session-6'
			})
		);

		expect(await nextAuthorization(person.cookie)).toMatch(/^\/ui\/[^/]+\//);
	});

	it('ends every session that came from the same upstream session', async () => {
		const upstream = await upstreamOfDefaultBucket('kc');
		const first = await signInThroughProvider(upstream, {
			sub: 'kc-user-7',
			sid: 'kc-session-7'
		});
		const second = await signInThroughProvider(upstream, {
			sub: 'kc-user-7',
			sid: 'kc-session-7'
		});
		await keysServedForLogout(upstream.stub);
		relyingPartyListening(RP, 2);

		await sendLogout(
			logoutEndpointOf(upstream.bucket),
			await upstream.stub.logoutToken({
				aud: CLIENT_AT_IDP,
				sub: 'kc-user-7',
				sid: 'kc-session-7'
			})
		);

		expect(sessionRecord(first.sessionId)).toBeUndefined();
		expect(sessionRecord(second.sessionId)).toBeUndefined();
	});

	it('leaves a session that came from another upstream session of the same provider', async () => {
		const upstream = await upstreamOfDefaultBucket('kc');
		await signInThroughProvider(upstream, {
			sub: 'kc-user-8',
			sid: 'kc-session-8a'
		});
		const other = await signInThroughProvider(upstream, {
			sub: 'kc-user-8',
			sid: 'kc-session-8b'
		});
		await keysServedForLogout(upstream.stub);
		relyingPartyListening(RP);

		await sendLogout(
			logoutEndpointOf(upstream.bucket),
			await upstream.stub.logoutToken({
				aud: CLIENT_AT_IDP,
				sub: 'kc-user-8',
				sid: 'kc-session-8a'
			})
		);

		expect(sessionRecord(other.sessionId)).toBeDefined();
	});

	it('answers success and changes nothing for an upstream session that signed in nobody here', async () => {
		const upstream = await upstreamOfDefaultBucket('kc');
		const person = await signInThroughProvider(upstream, {
			sub: 'kc-user-9',
			sid: 'kc-session-9'
		});
		await keysServedForLogout(upstream.stub);

		const res = await sendLogout(
			logoutEndpointOf(upstream.bucket),
			await upstream.stub.logoutToken({
				aud: CLIENT_AT_IDP,
				sub: 'kc-user-9',
				sid: 'kc-session-never-seen'
			})
		);

		expect(res.status).toBe(200);
		expect(sessionRecord(person.sessionId)).toBeDefined();
	});

	it('lets a person signed out this way sign in again through the provider', async () => {
		const upstream = await upstreamOfDefaultBucket('kc');
		const person = await signInThroughProvider(upstream, {
			sub: 'kc-user-10',
			sid: 'kc-session-10'
		});
		await keysServedForLogout(upstream.stub);
		relyingPartyListening(RP);
		await sendLogout(
			logoutEndpointOf(upstream.bucket),
			await upstream.stub.logoutToken({
				aud: CLIENT_AT_IDP,
				sub: 'kc-user-10',
				sid: 'kc-session-10'
			})
		);

		const again = await signInThroughProvider(upstream, {
			sub: 'kc-user-10',
			sid: 'kc-session-10b'
		});

		expect(again.accountId).toBe(person.accountId);
	});

	it('keeps offline access when Keycloak asks for offline sessions to be revoked too', async () => {
		const upstream = await upstreamOfDefaultBucket('kc');
		const person = await signInThroughProvider(upstream, {
			sub: 'kc-user-11',
			sid: 'kc-session-11'
		});
		await keysServedForLogout(upstream.stub);
		relyingPartyListening(RP);

		await sendLogout(
			logoutEndpointOf(upstream.bucket),
			await upstream.stub.logoutToken({
				aud: CLIENT_AT_IDP,
				sub: 'kc-user-11',
				sid: 'kc-session-11',
				events: {
					[BACKCHANNEL_LOGOUT_EVENT]: {},
					revoke_offline_access: true
				}
			})
		);

		const { response } = await refresh(person.refreshToken);
		expect(response.status).toBe(200);
	});

	describe('in the shapes the providers send', () => {
		it('accepts Keycloak’s: a generic header type, its own body type, a two-minute life', async () => {
			const upstream = await upstreamOfDefaultBucket('keycloak');
			const person = await signInThroughProvider(upstream, {
				sub: 'kc-user-12',
				sid: 'kc-session-12'
			});
			await keysServedForLogout(upstream.stub);
			relyingPartyListening(RP);

			await sendLogout(
				logoutEndpointOf(upstream.bucket),
				await upstream.stub.logoutToken(
					{
						aud: CLIENT_AT_IDP,
						sub: 'kc-user-12',
						sid: 'kc-session-12',
						typ: 'Logout'
					},
					{ typ: 'JWT', expiresIn: 120 }
				)
			);

			expect(sessionRecord(person.sessionId)).toBeUndefined();
		});

		it('accepts Auth0’s: a generic header type', async () => {
			const upstream = await upstreamOfDefaultBucket('auth0');
			const person = await signInThroughProvider(upstream, {
				sub: 'auth0|user-13',
				sid: 'auth0-session-13'
			});
			await keysServedForLogout(upstream.stub);
			relyingPartyListening(RP);

			await sendLogout(
				logoutEndpointOf(upstream.bucket),
				await upstream.stub.logoutToken(
					{ aud: CLIENT_AT_IDP, sub: 'auth0|user-13', sid: 'auth0-session-13' },
					{ typ: 'JWT' }
				)
			);

			expect(sessionRecord(person.sessionId)).toBeUndefined();
		});

		it('accepts Ping’s: the logout token type', async () => {
			const upstream = await upstreamOfDefaultBucket('ping');
			const person = await signInThroughProvider(upstream, {
				sub: 'ping-user-14',
				sid: 'ping-session-14'
			});
			await keysServedForLogout(upstream.stub);
			relyingPartyListening(RP);

			await sendLogout(
				logoutEndpointOf(upstream.bucket),
				await upstream.stub.logoutToken(
					{ aud: CLIENT_AT_IDP, sub: 'ping-user-14', sid: 'ping-session-14' },
					{ typ: 'logout+jwt' }
				)
			);

			expect(sessionRecord(person.sessionId)).toBeUndefined();
		});

		it('accepts one with no header type at all', async () => {
			const upstream = await upstreamOfDefaultBucket('untyped');
			const person = await signInThroughProvider(upstream, {
				sub: 'user-15',
				sid: 'session-15'
			});
			await keysServedForLogout(upstream.stub);
			relyingPartyListening(RP);

			await sendLogout(
				logoutEndpointOf(upstream.bucket),
				await upstream.stub.logoutToken(
					{ aud: CLIENT_AT_IDP, sub: 'user-15', sid: 'session-15' },
					{ typ: null }
				)
			);

			expect(sessionRecord(person.sessionId)).toBeUndefined();
		});
	});
});
