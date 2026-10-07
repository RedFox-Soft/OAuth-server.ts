import {
	describe,
	it,
	beforeAll,
	afterEach,
	expect,
	mock,
	setSystemTime
} from 'bun:test';

import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { getBucketStore } from 'lib/adapters/index.js';
import { ApplicationConfig } from 'lib/configs/application.ts';
import type { FederationProvider } from 'lib/federation/types.js';
import { resetUnauthenticatedCharge } from 'lib/helpers/unauthenticated_charge.ts';
import bootstrap from '../test_helper.js';
import { assertNoPendingInterceptors } from '../fetch_mock.js';
import {
	BACKCHANNEL_LOGOUT_EVENT,
	type AssertionOptions
} from '../federation/idp_stub.js';
import { pathBucketWith } from '../global_token_revocation/helpers.js';
import {
	CLIENT_AT_IDP,
	keysServedForLogout,
	logoutEndpointOf,
	sendLogout,
	sessionRecord,
	signInThroughProvider,
	upstreamOfDefaultBucket,
	type SignedIn,
	type Upstream
} from './helpers.ts';

/* A person signed in through a fresh provider of the default bucket, holding a session it could end. */
async function target(
	overrides: Partial<FederationProvider> = {}
): Promise<{ upstream: Upstream; person: SignedIn; endpoint: string }> {
	const upstream = await upstreamOfDefaultBucket('kc', overrides);
	const person = await signInThroughProvider(upstream, {
		sub: 'kc-target',
		sid: 'kc-target-session'
	});
	return { upstream, person, endpoint: logoutEndpointOf(upstream.bucket) };
}

const VALID = {
	aud: CLIENT_AT_IDP,
	sub: 'kc-target',
	sid: 'kc-target-session'
};

type Variant = [
	string,
	Record<string, unknown>,
	AssertionOptions,
	/* Whether the receiver gets as far as reading the provider's keys before refusing. */
	'reads keys' | 'refused first'
];

const VARIANTS: Variant[] = [
	['that is unsigned', {}, { unsecured: true }, 'refused first'],
	[
		'signed with a shared secret',
		{},
		{ hmacSecret: 'shared' },
		'refused first'
	],
	[
		'from an issuer the bucket has no provider for',
		{ iss: 'https://elsewhere.idp.test' },
		{},
		'refused first'
	],
	[
		'audienced to another client of the provider',
		{ aud: 'somebody-else' },
		{},
		'refused first'
	],
	[
		'audienced to several parties',
		{ aud: [CLIENT_AT_IDP, 'somebody-else'] },
		{},
		'refused first'
	],
	['with no audience', { aud: undefined }, {}, 'refused first'],
	[
		'typed as a global token revocation assertion',
		{},
		{ typ: 'global-token-revocation+jwt' },
		'refused first'
	],
	[
		'signed by a key the provider does not publish',
		{},
		{ foreignKey: true },
		'reads keys'
	],
	['that has expired', {}, { expiresIn: -600 }, 'reads keys'],
	['issued in the future', {}, { issuedIn: 600, expiresIn: 700 }, 'reads keys'],
	['living longer than five minutes', {}, { expiresIn: 900 }, 'reads keys'],
	['with no expiry', {}, { noExp: true }, 'reads keys'],
	['with no issue time', {}, { noIssuedAt: true }, 'reads keys'],
	['with no identifier', {}, { noJti: true }, 'reads keys'],
	['carrying a nonce', { nonce: 'n-0S6_WzA2Mj' }, {}, 'reads keys'],
	['without the logout event', { events: undefined }, {}, 'reads keys'],
	[
		'whose logout event is not an object',
		{ events: { [BACKCHANNEL_LOGOUT_EVENT]: true } },
		{},
		'reads keys'
	],
	[
		'naming neither a person nor a session',
		{ sub: undefined, sid: undefined },
		{},
		'reads keys'
	]
];

/**
 * @proves Only an opted-in upstream provider of the addressed bucket, presenting a fresh, single-use logout
 * token signed with its own published keys and shaped as Back-Channel Logout 1.0 requires, can end a session;
 * every other request is answered 400 with one indistinguishable body and ends nothing, whatever any setting
 * says (spec 073 User Story 3; FR-005–FR-008, FR-015, FR-016; SC-002, SC-006; Keycloak CVE-2026-18569).
 */
describe('refusing a back-channel logout', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	afterEach(() => {
		setSystemTime();
		resetUnauthenticatedCharge();
		try {
			mock.restore();
		} finally {
			assertNoPendingInterceptors();
		}
	});

	describe('a token differing from a valid one in one respect', () => {
		for (const [name, claims, opts, reach] of VARIANTS) {
			it(`refuses one ${name}, ending nothing`, async () => {
				const { upstream, person, endpoint } = await target();
				if (reach === 'reads keys') await keysServedForLogout(upstream.stub);

				const res = await sendLogout(
					endpoint,
					await upstream.stub.logoutToken({ ...VALID, ...claims }, opts)
				);

				expect(res.status).toBe(400);
				expect(res.json).toEqual({ error: 'invalid_request' });
				expect(sessionRecord(person.sessionId)).toBeDefined();
			});
		}
	});

	it('refuses a request carrying no logout token', async () => {
		const { endpoint } = await target();

		const res = await sendLogout(endpoint, undefined);

		expect(res.status).toBe(400);
		expect(res.json).toEqual({ error: 'invalid_request' });
	});

	it('refuses a logout token that is not form-encoded', async () => {
		const { upstream, person, endpoint } = await target();

		const res = await sendLogout(endpoint, undefined, {
			contentType: 'application/json',
			rawBody: JSON.stringify({
				logout_token: await upstream.stub.logoutToken(VALID)
			})
		});

		expect(res.status).toBe(400);
		expect(sessionRecord(person.sessionId)).toBeDefined();
	});

	it('refuses a value that is not a token at all', async () => {
		const { endpoint } = await target();

		const res = await sendLogout(endpoint, 'not-a-jwt');

		expect(res.status).toBe(400);
		expect(res.json).toEqual({ error: 'invalid_request' });
	});

	it('refuses a token sent a second time', async () => {
		const { upstream, endpoint } = await target();
		await keysServedForLogout(upstream.stub);
		/* Names a session nobody signed in through, so the first delivery ends nothing either. */
		const token = await upstream.stub.logoutToken({
			...VALID,
			sid: 'kc-nobody'
		});
		await sendLogout(endpoint, token);

		const res = await sendLogout(endpoint, token);

		expect(res.status).toBe(400);
	});

	it('refuses a valid token from a provider not opted in, ending nothing', async () => {
		const { upstream, person, endpoint } = await target({
			acceptsBackChannelLogout: false
		});
		await keysServedForLogout(upstream.stub);

		const res = await sendLogout(
			endpoint,
			await upstream.stub.logoutToken(VALID)
		);

		expect(res.status).toBe(400);
		expect(sessionRecord(person.sessionId)).toBeDefined();
	});

	it('refuses a valid token from a provider an administrator disabled, ending nothing', async () => {
		const { upstream, person, endpoint } = await target();
		await getBucketStore().update(DEFAULT_BUCKET_ID, {
			federation: [{ ...upstream.provider, enabled: false }]
		});
		await keysServedForLogout(upstream.stub);

		const res = await sendLogout(
			endpoint,
			await upstream.stub.logoutToken(VALID)
		);

		expect(res.status).toBe(400);
		expect(sessionRecord(person.sessionId)).toBeDefined();
	});

	it('refuses a valid token sent to a bucket that does not hold its provider', async () => {
		const { upstream, person } = await target();
		const elsewhere = await pathBucketWith([]);

		const res = await sendLogout(
			logoutEndpointOf(elsewhere),
			await upstream.stub.logoutToken(VALID)
		);

		expect(res.status).toBe(400);
		expect(sessionRecord(person.sessionId)).toBeDefined();
	});

	it('refuses the provider’s own ID token presented as a logout token', async () => {
		const { upstream, person, endpoint } = await target();
		await keysServedForLogout(upstream.stub);

		const res = await sendLogout(
			endpoint,
			await upstream.stub.idToken(
				{ sub: 'kc-target', sid: 'kc-target-session', nonce: 'n' },
				{ audience: CLIENT_AT_IDP }
			)
		);

		expect(res.status).toBe(400);
		expect(sessionRecord(person.sessionId)).toBeDefined();
	});

	it('refuses the provider’s global token revocation assertion presented as a logout token', async () => {
		const { upstream, person, endpoint } = await target();

		const res = await sendLogout(
			endpoint,
			await upstream.stub.revocationAssertion({
				sub: CLIENT_AT_IDP,
				aud: endpoint
			})
		);

		expect(res.status).toBe(400);
		expect(sessionRecord(person.sessionId)).toBeDefined();
	});

	it('refuses an unsigned token with every option this server has switched on', async () => {
		const { upstream, person, endpoint } = await target({
			acceptsGlobalTokenRevocation: true,
			emailTrusted: true
		});
		const before = ApplicationConfig['globalTokenRevocation.enabled'];
		ApplicationConfig['globalTokenRevocation.enabled'] = true;
		try {
			const res = await sendLogout(
				endpoint,
				await upstream.stub.logoutToken(VALID, { unsecured: true })
			);

			expect(res.status).toBe(400);
			expect(sessionRecord(person.sessionId)).toBeDefined();
		} finally {
			ApplicationConfig['globalTokenRevocation.enabled'] = before;
		}
	});

	it('answers every refused credential with the same body', async () => {
		const { upstream, endpoint } = await target();

		const bodies = [
			(await sendLogout(endpoint, 'not-a-jwt')).text,
			(
				await sendLogout(
					endpoint,
					await upstream.stub.logoutToken(VALID, { unsecured: true })
				)
			).text,
			(
				await sendLogout(
					endpoint,
					await upstream.stub.logoutToken({ ...VALID, aud: 'somebody-else' })
				)
			).text
		];

		expect(new Set(bodies).size).toBe(1);
	});

	it('limits failed credentials at the strict per-origin rate', async () => {
		const { endpoint } = await target();
		const max = ApplicationConfig['rateLimit.strict.max'] as number;
		const enabled = ApplicationConfig['rateLimit.enabled'];
		ApplicationConfig['rateLimit.enabled'] = true;
		try {
			let last: Awaited<ReturnType<typeof sendLogout>> | undefined;
			for (let i = 0; i <= max; i += 1) {
				last = await sendLogout(endpoint, 'not-a-jwt');
			}

			expect(last?.status).toBe(429);
			expect(last?.headers.get('retry-after')).toBeTruthy();
		} finally {
			ApplicationConfig['rateLimit.enabled'] = enabled;
		}
	});
});
