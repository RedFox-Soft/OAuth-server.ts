import {
	describe,
	it,
	beforeAll,
	afterEach,
	expect,
	mock,
	setSystemTime,
	spyOn
} from 'bun:test';

import bootstrap, { agent, getHeader } from '../test_helper.js';
import epochTime from 'lib/helpers/epoch_time.js';
import { decode as decodeJWT } from 'lib/helpers/jwt.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { present } from 'test/shape.js';
import { walk } from '../federation/harness.js';
import {
	CLIENT_AT_IDP,
	nextAuthorization,
	signInThroughProvider,
	upstreamOfDefaultBucket
} from '../upstream_backchannel_logout/helpers.ts';

const RP = 'https://client.example.com';
const DAY = 24 * 60 * 60;

function idTokenClaims(idToken: string) {
	const { iat, session_expiry } = decodeJWT(idToken).payload;
	if (typeof iat !== 'number') throw new Error('expected an iat');
	return { iat, sessionExpiry: session_expiry };
}

/* A federated sign-in whose callback answer is all a case looks at: it is refused before a session exists. */
async function callbackFor(claims: Record<string, unknown>, label: string) {
	const upstream = await upstreamOfDefaultBucket(label);
	const prompts = spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(
		false
	);
	try {
		const auth = new AuthorizationRequest({
			client_id: 'client',
			scope: 'openid'
		});
		const { response } = await agent.auth.get({ query: auth.params });
		const uid = present(
			getHeader(response, 'location').split('/')[2],
			'the interaction uid'
		);
		const { callback } = await walk(
			uid,
			present(response.headers.get('set-cookie'), 'the interaction cookie'),
			{
				idp: upstream.stub,
				claims: {
					sub: `${label}-user`,
					email: `${label}@example.com`,
					...claims
				},
				opts: { audience: CLIENT_AT_IDP }
			},
			{ providerId: upstream.provider.id }
		);
		return callback;
	} finally {
		prompts.mockRestore();
	}
}

/**
 * @proves A session created through an upstream provider never outlives the moment that provider said its
 * own session ends, and neither does what this server tells its applications — while a provider that says
 * nothing changes nothing, and one that says something unusable is refused (IPSIE SL1 §3.2.2).
 */
describe('a sign-in through a provider that says when its session ends', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'upstream' });
	});

	afterEach(() => {
		setSystemTime();
		mock.restore();
	});

	it("reuses the session without a prompt before the provider's session_expiry", async () => {
		const upstream = await upstreamOfDefaultBucket('se-before');
		const person = await signInThroughProvider(upstream, {
			sub: 'se-before-user',
			claims: { session_expiry: epochTime() + 3600 }
		});

		expect(await nextAuthorization(person.cookie)).toStartWith(RP);
	});

	it("asks the person to sign in again after the provider's session_expiry", async () => {
		const upstream = await upstreamOfDefaultBucket('se-after');
		const end = epochTime() + 3600;
		const person = await signInThroughProvider(upstream, {
			sub: 'se-after-user',
			claims: { session_expiry: end }
		});

		setSystemTime(new Date((end + 60) * 1000));

		expect(await nextAuthorization(person.cookie)).toMatch(/^\/ui\/[^/]+\//);
	});

	it("the ID token's session_expiry is no later than the provider's", async () => {
		const upstream = await upstreamOfDefaultBucket('se-token');
		const end = epochTime() + 3600;
		const person = await signInThroughProvider(upstream, {
			sub: 'se-token-user',
			claims: { session_expiry: end }
		});

		expect(idTokenClaims(person.idToken).sessionExpiry).toBe(end);
	});

	it('session_expiry is iat plus five minutes when the provider’s session ends sooner', async () => {
		const upstream = await upstreamOfDefaultBucket('se-floor');
		const person = await signInThroughProvider(upstream, {
			sub: 'se-floor-user',
			claims: { session_expiry: epochTime() + 100 }
		});

		const { iat, sessionExpiry } = idTokenClaims(person.idToken);
		expect(sessionExpiry).toBe(iat + 300);
	});

	it('a provider that sends no session_expiry leaves the session as before', async () => {
		const upstream = await upstreamOfDefaultBucket('se-none');
		const person = await signInThroughProvider(upstream, {
			sub: 'se-none-user'
		});

		const { iat, sessionExpiry } = idTokenClaims(person.idToken);
		expect(sessionExpiry).toBe(iat + DAY);
		expect(await nextAuthorization(person.cookie)).toStartWith(RP);
	});

	it('refuses a sign-in whose upstream session_expiry has already passed', async () => {
		const callback = await callbackFor(
			{ session_expiry: epochTime() - 60 },
			'se-past'
		);

		expect(callback.status).toBe(400);
	});

	it('refuses a sign-in whose upstream session_expiry is not an integer', async () => {
		const callback = await callbackFor(
			{ session_expiry: 'tomorrow' },
			'se-malformed'
		);

		expect(callback.status).toBe(400);
	});
});
