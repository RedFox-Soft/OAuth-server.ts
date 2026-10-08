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
import { ApplicationConfig } from 'lib/configs/application.ts';
import { ISSUER } from 'lib/configs/env.ts';
import nanoid from 'lib/helpers/nanoid.js';
import { resetUnauthenticatedCharge } from 'lib/helpers/unauthenticated_charge.ts';
import bootstrap, { type Setup } from '../test_helper.js';
import {
	assertNoPendingInterceptors,
	mock as mockHttp
} from '../fetch_mock.js';
import { idpStub } from '../federation/idp_stub.js';
import { refresh, signIn } from '../end_user_lifecycle/fixtures.ts';
import {
	CLIENT_AT_IDP,
	defaultBucketWith,
	endpointOf,
	issSub,
	linkTo,
	pathBucketWith,
	revoke,
	servesKeys,
	uniqueOrigin,
	upstreamOfDefaultBucket,
	upstreamProvider
} from './helpers.ts';

/**
 * @proves Only an opted-in upstream provider of the addressed bucket, presenting a fresh assertion signed with
 * its own published keys, can end a user's access; every other request is refused and ends nobody's session
 * (spec 072, User Story 2; FR-006–FR-009, FR-016; SC-003; Keycloak CVE-2026-18569).
 */
describe('refusing a global token revocation', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url);
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

	/* A signed-in user linked to a fresh opted-in provider of the default bucket. */
	async function target(
		overrides: Parameters<typeof upstreamOfDefaultBucket>[1] = {}
	) {
		const upstream = await upstreamOfDefaultBucket('okta', overrides);
		const user = await signIn(setup);
		const sub = `okta-${nanoid()}`;
		await linkTo(DEFAULT_BUCKET_ID, user.accountId, upstream.provider.id, sub);
		return { ...upstream, user, sub };
	}

	async function stillSignedIn(refreshToken: string): Promise<void> {
		const { error } = await refresh(refreshToken);
		expect(error).toBeNull();
	}

	it('refuses a request without a credential, with a Bearer challenge', async () => {
		const { provider, bucket, user, sub } = await target();

		const res = await revoke(endpointOf(bucket), {
			body: issSub(provider.issuer, sub)
		});

		expect(res.status).toBe(401);
		expect(res.json).toHaveProperty('error', 'invalid_token');
		expect(res.headers.get('www-authenticate')).toStartWith('Bearer');
		await stillSignedIn(user.refreshToken);
	});

	it('refuses an unsigned assertion', async () => {
		const { stub, provider, bucket, user, sub } = await target();
		stub.expectDiscovery();

		const res = await revoke(endpointOf(bucket), {
			assertion: await stub.revocationAssertion(
				{ sub: CLIENT_AT_IDP, aud: endpointOf(bucket) },
				{ unsecured: true }
			),
			body: issSub(provider.issuer, sub)
		});

		expect(res.status).toBe(401);
		await stillSignedIn(user.refreshToken);
	});

	it('refuses an assertion signed with a shared secret', async () => {
		const { stub, provider, bucket, user, sub } = await target();
		stub.expectDiscovery();

		const res = await revoke(endpointOf(bucket), {
			assertion: await stub.revocationAssertion(
				{ sub: CLIENT_AT_IDP, aud: endpointOf(bucket) },
				{ hmacSecret: 'stub-secret' }
			),
			body: issSub(provider.issuer, sub)
		});

		expect(res.status).toBe(401);
		await stillSignedIn(user.refreshToken);
	});

	it('refuses a shared-secret assertion whatever the provider advertises and the instance allows', async () => {
		const origin = uniqueOrigin('hs');
		const stub = await idpStub(origin, {
			id_token_signing_alg_values_supported: ['HS256', 'RS256']
		});
		const provider = upstreamProvider('hs', origin, {
			clientSecret: 'stub-secret'
		});
		const bucket = await defaultBucketWith([provider]);
		const user = await signIn(setup);
		await linkTo(DEFAULT_BUCKET_ID, user.accountId, 'hs', 'hs-user');
		stub.expectDiscovery();

		const res = await revoke(endpointOf(bucket), {
			assertion: await stub.revocationAssertion(
				{ sub: CLIENT_AT_IDP, aud: endpointOf(bucket) },
				{ hmacSecret: 'stub-secret' }
			),
			body: issSub(origin, 'hs-user')
		});

		expect(res.status).toBe(401);
		await stillSignedIn(user.refreshToken);
	});

	it('refuses an assertion signed by a key the provider does not publish', async () => {
		const { stub, provider, bucket, user, sub } = await target();
		await servesKeys(stub);

		const res = await revoke(endpointOf(bucket), {
			assertion: await stub.revocationAssertion(
				{ sub: CLIENT_AT_IDP, aud: endpointOf(bucket) },
				{ foreignKey: true }
			),
			body: issSub(provider.issuer, sub)
		});

		expect(res.status).toBe(401);
		await stillSignedIn(user.refreshToken);
	});

	it('refuses an assertion addressed to another bucket’s endpoint', async () => {
		const { stub, provider, bucket, user, sub } = await target();
		await servesKeys(stub);

		const res = await revoke(endpointOf(bucket), {
			assertion: await stub.revocationAssertion({
				sub: CLIENT_AT_IDP,
				aud: `${ISSUER}/someone-else/global-token-revocation`
			}),
			body: issSub(provider.issuer, sub)
		});

		expect(res.status).toBe(401);
		await stillSignedIn(user.refreshToken);
	});

	it('refuses an assertion whose audience carries a query string', async () => {
		const { stub, provider, bucket, user, sub } = await target();
		await servesKeys(stub);

		const res = await revoke(endpointOf(bucket), {
			assertion: await stub.revocationAssertion({
				sub: CLIENT_AT_IDP,
				aud: `${endpointOf(bucket)}?tenant=x`
			}),
			body: issSub(provider.issuer, sub)
		});

		expect(res.status).toBe(401);
		await stillSignedIn(user.refreshToken);
	});

	it('refuses an expired assertion', async () => {
		const { stub, provider, bucket, user, sub } = await target();
		await servesKeys(stub);

		const res = await revoke(endpointOf(bucket), {
			assertion: await stub.revocationAssertion(
				{ sub: CLIENT_AT_IDP, aud: endpointOf(bucket) },
				{ issuedIn: -400, expiresIn: -100 }
			),
			body: issSub(provider.issuer, sub)
		});

		expect(res.status).toBe(401);
		await stillSignedIn(user.refreshToken);
	});

	it('refuses an assertion not yet valid', async () => {
		const { stub, provider, bucket, user, sub } = await target();
		await servesKeys(stub);

		const res = await revoke(endpointOf(bucket), {
			assertion: await stub.revocationAssertion(
				{ sub: CLIENT_AT_IDP, aud: endpointOf(bucket) },
				{ notBefore: 120 }
			),
			body: issSub(provider.issuer, sub)
		});

		expect(res.status).toBe(401);
		await stillSignedIn(user.refreshToken);
	});

	it('refuses an assertion valid for longer than five minutes', async () => {
		const { stub, provider, bucket, user, sub } = await target();
		await servesKeys(stub);

		const res = await revoke(endpointOf(bucket), {
			assertion: await stub.revocationAssertion(
				{ sub: CLIENT_AT_IDP, aud: endpointOf(bucket) },
				{ expiresIn: 3600 }
			),
			body: issSub(provider.issuer, sub)
		});

		expect(res.status).toBe(401);
		await stillSignedIn(user.refreshToken);
	});

	it('refuses an assertion without an identifier', async () => {
		const { stub, provider, bucket, user, sub } = await target();
		await servesKeys(stub);

		const res = await revoke(endpointOf(bucket), {
			assertion: await stub.revocationAssertion(
				{ sub: CLIENT_AT_IDP, aud: endpointOf(bucket) },
				{ noJti: true }
			),
			body: issSub(provider.issuer, sub)
		});

		expect(res.status).toBe(401);
		await stillSignedIn(user.refreshToken);
	});

	it('refuses an assertion presented a second time', async () => {
		const { stub, provider, bucket, sub } = await target();
		await servesKeys(stub);
		mockHttp('https://client.example.com')
			.intercept({ path: '/backchannel_logout', method: 'POST' })
			.reply(200);
		const assertion = await stub.revocationAssertion({
			sub: CLIENT_AT_IDP,
			aud: endpointOf(bucket)
		});
		await revoke(endpointOf(bucket), {
			assertion,
			body: issSub(provider.issuer, sub)
		});

		const replayed = await revoke(endpointOf(bucket), {
			assertion,
			body: issSub(provider.issuer, sub)
		});

		expect(replayed.status).toBe(401);
	});

	for (const typ of ['at+jwt', 'logout+jwt', 'secevent+jwt']) {
		it(`refuses an assertion declared as ${typ}`, async () => {
			const { stub, provider, bucket, user, sub } = await target();

			const res = await revoke(endpointOf(bucket), {
				assertion: await stub.revocationAssertion(
					{ sub: CLIENT_AT_IDP, aud: endpointOf(bucket) },
					{ typ }
				),
				body: issSub(provider.issuer, sub)
			});

			expect(res.status).toBe(401);
			await stillSignedIn(user.refreshToken);
		});
	}

	it('refuses another bucket’s provider signing out this bucket’s users', async () => {
		const { provider, bucket, user, sub } = await target();
		const otherOrigin = uniqueOrigin('other');
		const otherStub = await idpStub(otherOrigin);
		await pathBucketWith([upstreamProvider('other', otherOrigin)]);

		const res = await revoke(endpointOf(bucket), {
			assertion: await otherStub.revocationAssertion({
				sub: CLIENT_AT_IDP,
				aud: endpointOf(bucket)
			}),
			body: issSub(provider.issuer, sub)
		});

		expect(res.status).toBe(401);
		await stillSignedIn(user.refreshToken);
	});

	it('refuses a disabled provider as not authorized', async () => {
		const { stub, provider, bucket, user, sub } = await target({
			enabled: false
		});
		await servesKeys(stub);

		const res = await revoke(endpointOf(bucket), {
			assertion: await stub.revocationAssertion({
				sub: CLIENT_AT_IDP,
				aud: endpointOf(bucket)
			}),
			body: issSub(provider.issuer, sub)
		});

		expect(res.status).toBe(403);
		expect(res.json).toHaveProperty('error', 'access_denied');
		await stillSignedIn(user.refreshToken);
	});

	it('refuses a provider not opted in to revocation as not authorized', async () => {
		const { stub, provider, bucket, user, sub } = await target({
			acceptsGlobalTokenRevocation: false
		});
		await servesKeys(stub);

		const res = await revoke(endpointOf(bucket), {
			assertion: await stub.revocationAssertion({
				sub: CLIENT_AT_IDP,
				aud: endpointOf(bucket)
			}),
			body: issSub(provider.issuer, sub)
		});

		expect(res.status).toBe(403);
		await stillSignedIn(user.refreshToken);
	});

	it('lets each of two providers sharing an issuer sign out only its own users', async () => {
		const origin = uniqueOrigin('shared');
		const stub = await idpStub(origin);
		const first = upstreamProvider('first', origin, { clientId: 'app-one' });
		const second = upstreamProvider('second', origin, {
			clientId: 'app-two'
		});
		const bucket = await defaultBucketWith([first, second]);
		const user = await signIn(setup);
		await linkTo(DEFAULT_BUCKET_ID, user.accountId, 'second', 'shared-user');
		await servesKeys(stub);

		const res = await revoke(endpointOf(bucket), {
			assertion: await stub.revocationAssertion({
				sub: 'app-one',
				aud: endpointOf(bucket)
			}),
			body: issSub(origin, 'shared-user')
		});

		expect(res.status).toBe(404);
		await stillSignedIn(user.refreshToken);
	});

	it('accepts an assertion signed with a rotated key once the provider publishes it', async () => {
		const { stub, provider, bucket, sub } = await target();
		const accountId = `rotated-${nanoid()}`;
		await linkTo(DEFAULT_BUCKET_ID, accountId, provider.id, sub);
		await servesKeys(stub);
		mockHttp('https://client.example.com')
			.intercept({ path: '/backchannel_logout', method: 'POST' })
			.reply(200);
		await revoke(endpointOf(bucket), {
			assertion: await stub.revocationAssertion({
				sub: CLIENT_AT_IDP,
				aud: endpointOf(bucket)
			}),
			body: issSub(provider.issuer, sub)
		});
		await stub.rotateKey('stub-key-2');
		await stub.expectJwks();
		/* Past the cooldown that keeps a stream of unknown key ids from refetching the provider's keys. */
		setSystemTime(new Date(Date.now() + 31_000));

		const res = await revoke(endpointOf(bucket), {
			assertion: await stub.revocationAssertion({
				sub: CLIENT_AT_IDP,
				aud: endpointOf(bucket)
			}),
			body: issSub(provider.issuer, sub)
		});

		expect(res.status).toBe(204);
	});

	it('answers a provider whose keys cannot be fetched as unable to process', async () => {
		const { stub, provider, bucket, user, sub } = await target();
		stub.expectDiscoveryFailure(503);

		const res = await revoke(endpointOf(bucket), {
			assertion: await stub.revocationAssertion({
				sub: CLIENT_AT_IDP,
				aud: endpointOf(bucket)
			}),
			body: issSub(provider.issuer, sub)
		});

		expect(res.status).toBe(422);
		await stillSignedIn(user.refreshToken);
	});

	it('does not serve the administrators’ bucket', async () => {
		const res = await revoke(`${ISSUER}/admin/global-token-revocation`, {
			body: issSub('https://any.example', 'anyone')
		});

		expect(res.status).toBe(404);
	});

	it('limits failed credentials at the strict per-origin rate', async () => {
		const { provider, bucket, sub } = await target();
		const max = ApplicationConfig['rateLimit.strict.max'];
		const enabled = ApplicationConfig['rateLimit.enabled'];
		ApplicationConfig['rateLimit.enabled'] = true;
		try {
			let last = 0;
			for (let i = 0; i <= max; i += 1) {
				last = (
					await revoke(endpointOf(bucket), {
						authorization: 'Bearer not-a-jwt',
						body: issSub(provider.issuer, sub)
					})
				).status;
			}

			expect(last).toBe(429);
		} finally {
			ApplicationConfig['rateLimit.enabled'] = enabled;
		}
	});
});
