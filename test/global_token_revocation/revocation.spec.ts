import {
	describe,
	it,
	beforeAll,
	afterEach,
	expect,
	mock,
	spyOn
} from 'bun:test';

import { adapter, getBucketStore, getUserStore } from 'lib/adapters/index.ts';
import { findAccount } from 'lib/addon/index.ts';
import { DEFAULT_BUCKET_ID, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import nanoid from 'lib/helpers/nanoid.js';
import { TestAdapter } from '../models.js';
import bootstrap, { seedAccount, type Setup } from '../test_helper.js';
import {
	mock as mockHttp,
	assertNoPendingInterceptors
} from '../fetch_mock.js';
import { idpStub } from '../federation/idp_stub.js';
import { introspect, refresh, signIn } from '../end_user_lifecycle/fixtures.ts';
import {
	CLIENT_AT_IDP,
	email,
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

function acceptLogout(times = 1): void {
	for (let i = 0; i < times; i += 1) {
		mockHttp('https://client.example.com')
			.intercept({ path: '/backchannel_logout', method: 'POST' })
			.reply(200);
	}
}

/**
 * @proves A bucket's upstream identity provider, opted in, ends everything a user it names holds here — their
 * sessions, refresh tokens and opaque access tokens, with relying parties told — while the account stays able
 * to sign in again (spec 072, User Story 1; FR-001, FR-007, FR-011–FR-013; SC-001, SC-002, SC-006).
 */
describe('an upstream provider revoking a user', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url);
	});

	afterEach(() => {
		try {
			mock.restore();
		} finally {
			assertNoPendingInterceptors();
		}
	});

	it('ends the user’s refresh token when named by issuer and subject', async () => {
		const { stub, provider, bucket } = await upstreamOfDefaultBucket('okta');
		const user = await signIn(setup);
		await linkTo(DEFAULT_BUCKET_ID, user.accountId, provider.id, 'okta-user-1');
		await servesKeys(stub);
		acceptLogout();

		const res = await revoke(endpointOf(bucket), {
			assertion: await stub.revocationAssertion({
				sub: CLIENT_AT_IDP,
				aud: endpointOf(bucket)
			}),
			body: issSub(provider.issuer, 'okta-user-1')
		});

		expect(res.status).toBe(204);
		const { error } = await refresh(user.refreshToken);
		expect(error?.value).toHaveProperty('error', 'invalid_grant');
	});

	it('leaves the user’s opaque access token inactive at introspection', async () => {
		const { stub, provider, bucket } = await upstreamOfDefaultBucket('okta');
		const user = await signIn(setup);
		await linkTo(DEFAULT_BUCKET_ID, user.accountId, provider.id, 'okta-user-2');
		await servesKeys(stub);
		acceptLogout();

		await revoke(endpointOf(bucket), {
			assertion: await stub.revocationAssertion({
				sub: CLIENT_AT_IDP,
				aud: endpointOf(bucket)
			}),
			body: issSub(provider.issuer, 'okta-user-2')
		});

		expect(await introspect(user.accessToken)).toEqual({ active: false });
	});

	it('ends the user’s session, so their next authorization asks them to sign in', async () => {
		const { stub, provider, bucket } = await upstreamOfDefaultBucket('okta');
		const user = await signIn(setup);
		const sessionId = setup.getLastSession().id;
		await linkTo(DEFAULT_BUCKET_ID, user.accountId, provider.id, 'okta-user-3');
		await servesKeys(stub);
		acceptLogout();

		await revoke(endpointOf(bucket), {
			assertion: await stub.revocationAssertion({
				sub: CLIENT_AT_IDP,
				aud: endpointOf(bucket)
			}),
			body: issSub(provider.issuer, 'okta-user-3')
		});

		expect(TestAdapter.for('Session').syncFind(sessionId)).toBeUndefined();
	});

	it('sends a logout notice to a relying party holding a session for the user', async () => {
		const { stub, provider, bucket } = await upstreamOfDefaultBucket('okta');
		const user = await signIn(setup);
		await linkTo(DEFAULT_BUCKET_ID, user.accountId, provider.id, 'okta-user-4');
		await servesKeys(stub);
		let delivered = false;
		mockHttp('https://client.example.com')
			.intercept({
				path: '/backchannel_logout',
				method: 'POST',
				body(value) {
					delivered = value.startsWith('logout_token=');
					return true;
				}
			})
			.reply(200);

		await revoke(endpointOf(bucket), {
			assertion: await stub.revocationAssertion({
				sub: CLIENT_AT_IDP,
				aud: endpointOf(bucket)
			}),
			body: issSub(provider.issuer, 'okta-user-4')
		});

		expect(delivered).toBe(true);
	});

	it('leaves the revoked user able to sign in again', async () => {
		const { stub, provider, bucket } = await upstreamOfDefaultBucket('okta');
		const user = await signIn(setup);
		await linkTo(DEFAULT_BUCKET_ID, user.accountId, provider.id, 'okta-user-5');
		await servesKeys(stub);
		acceptLogout();

		await revoke(endpointOf(bucket), {
			assertion: await stub.revocationAssertion({
				sub: CLIENT_AT_IDP,
				aud: endpointOf(bucket)
			}),
			body: issSub(provider.issuer, 'okta-user-5')
		});

		expect(await findAccount(undefined, user.accountId)).toHaveProperty(
			'accountId',
			user.accountId
		);
	});

	it('ends the access of a user named by email in any letter case', async () => {
		const { stub, provider, bucket } = await upstreamOfDefaultBucket('okta');
		const user = await signIn(setup);
		const address = `mixed-${nanoid().toLowerCase()}@example.com`;
		await getUserStore(DEFAULT_BUCKET_ID).update(user.accountId, {
			email: address
		});
		await linkTo(DEFAULT_BUCKET_ID, user.accountId, provider.id, 'okta-user-6');
		await servesKeys(stub);
		acceptLogout();

		const res = await revoke(endpointOf(bucket), {
			assertion: await stub.revocationAssertion({
				sub: CLIENT_AT_IDP,
				aud: endpointOf(bucket)
			}),
			body: email(address.toUpperCase())
		});

		expect(res.status).toBe(204);
		const { error } = await refresh(user.refreshToken);
		expect(error?.value).toHaveProperty('error', 'invalid_grant');
	});

	it('accepts an assertion shaped exactly as Okta sends it, not-before five minutes in the past', async () => {
		const { stub, provider, bucket } = await upstreamOfDefaultBucket('okta');
		const accountId = `holding-nothing-${nanoid()}`;
		seedAccount(accountId, {
			federated: [
				{ providerId: provider.id, sub: 'okta-user-7', linkedAt: new Date() }
			]
		});
		await servesKeys(stub);

		const res = await revoke(endpointOf(bucket), {
			assertion: await stub.revocationAssertion(
				{ sub: CLIENT_AT_IDP, aud: endpointOf(bucket) },
				{ notBefore: -300, expiresIn: 300 }
			),
			body: issSub(provider.issuer, 'okta-user-7')
		});

		expect(res.status).toBe(204);
	});

	it('answers 204 for a reachable user who holds nothing', async () => {
		const { stub, provider, bucket } = await upstreamOfDefaultBucket('okta');
		const accountId = `holding-nothing-${nanoid()}`;
		seedAccount(accountId, {
			federated: [
				{ providerId: provider.id, sub: 'okta-user-8', linkedAt: new Date() }
			]
		});
		await servesKeys(stub);

		const res = await revoke(endpointOf(bucket), {
			assertion: await stub.revocationAssertion({
				sub: CLIENT_AT_IDP,
				aud: endpointOf(bucket)
			}),
			body: issSub(provider.issuer, 'okta-user-8')
		});

		expect(res.status).toBe(204);
	});

	it('answers beneath a path-addressed bucket’s issuer', async () => {
		const origin = uniqueOrigin('path');
		const stub = await idpStub(origin);
		const provider = upstreamProvider('corp', origin);
		const bucket = await pathBucketWith([provider]);
		seedAccount(
			`path-user-${nanoid()}`,
			{
				federated: [{ providerId: 'corp', sub: 'corp-1', linkedAt: new Date() }]
			},
			bucket._id
		);
		await servesKeys(stub);

		const res = await revoke(endpointOf(bucket), {
			assertion: await stub.revocationAssertion({
				sub: CLIENT_AT_IDP,
				aud: endpointOf(bucket)
			}),
			body: issSub(origin, 'corp-1')
		});

		expect(endpointOf(bucket)).toContain(`/${bucket.slug}/`);
		expect(res.status).toBe(204);
	});

	it('answers at a hostname-addressed bucket’s issuer', async () => {
		const origin = uniqueOrigin('host');
		const stub = await idpStub(origin);
		const provider = upstreamProvider('corp', origin);
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: `gtr-host-${nanoid()}`,
			host: `gtr-${nanoid()
				.toLowerCase()
				.replace(/[^a-z0-9]/g, '')}.example.org`,
			federation: [provider]
		});
		seedAccount(
			`host-user-${nanoid()}`,
			{
				federated: [{ providerId: 'corp', sub: 'corp-2', linkedAt: new Date() }]
			},
			bucket._id
		);
		await servesKeys(stub);

		const res = await revoke(endpointOf(bucket), {
			assertion: await stub.revocationAssertion({
				sub: CLIENT_AT_IDP,
				aud: endpointOf(bucket)
			}),
			body: issSub(origin, 'corp-2')
		});

		expect(res.status).toBe(204);
	});

	it('answers 500 when an area could not be swept, and a retry completes it', async () => {
		const { stub, provider, bucket } = await upstreamOfDefaultBucket('okta');
		const user = await signIn(setup);
		await linkTo(DEFAULT_BUCKET_ID, user.accountId, provider.id, 'okta-user-9');
		await servesKeys(stub);
		acceptLogout();
		spyOn(adapter('RefreshToken'), 'destroyByOwner').mockRejectedValueOnce(
			new Error('the datastore is unavailable')
		);
		const send = async () =>
			revoke(endpointOf(bucket), {
				assertion: await stub.revocationAssertion({
					sub: CLIENT_AT_IDP,
					aud: endpointOf(bucket)
				}),
				body: issSub(provider.issuer, 'okta-user-9')
			});

		const first = await send();
		const retried = await send();

		expect(first.status).toBe(500);
		expect(retried.status).toBe(204);
		const { error } = await refresh(user.refreshToken);
		expect(error?.value).toHaveProperty('error', 'invalid_grant');
	});

	it('revokes a user holding fifty sessions within two seconds when relying parties answer at once', async () => {
		const { stub, provider, bucket } = await upstreamOfDefaultBucket('okta');
		const accountId = `busy-${nanoid()}`;
		for (let i = 0; i < 50; i += 1) {
			await setup.login({ accountId });
		}
		await linkTo(DEFAULT_BUCKET_ID, accountId, provider.id, 'okta-user-10');
		await servesKeys(stub);
		acceptLogout(50);
		const assertion = await stub.revocationAssertion({
			sub: CLIENT_AT_IDP,
			aud: endpointOf(bucket)
		});

		const started = performance.now();
		const res = await revoke(endpointOf(bucket), {
			assertion,
			body: issSub(provider.issuer, 'okta-user-10')
		});
		const elapsed = performance.now() - started;

		expect(res.status).toBe(204);
		expect(elapsed).toBeLessThan(2000);
	});
});
