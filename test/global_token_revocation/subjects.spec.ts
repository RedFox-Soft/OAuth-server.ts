import { describe, it, beforeAll, afterEach, expect, mock } from 'bun:test';

import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { getProvisioningConnectionStore } from 'lib/adapters/index.ts';
import nanoid from 'lib/helpers/nanoid.js';
import bootstrap, { seedAccount } from '../test_helper.js';
import { assertNoPendingInterceptors } from '../fetch_mock.js';
import {
	CLIENT_AT_IDP,
	email,
	endpointOf,
	issSub,
	revoke,
	servesKeys,
	upstreamOfDefaultBucket,
	type Upstream
} from './helpers.ts';

/**
 * @proves A provider names only the people it speaks for — those it signs in and those its connection
 * provisioned — and every other user, or a user who does not exist, is answered identically, so the endpoint
 * cannot be used to learn who a bucket holds (spec 072, FR-010, FR-011; User Story 2 scenarios 8–9).
 */
describe('the users an upstream provider may name', () => {
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

	async function named(upstream: Upstream, body: unknown) {
		return revoke(endpointOf(upstream.bucket), {
			assertion: await upstream.stub.revocationAssertion({
				sub: CLIENT_AT_IDP,
				aud: endpointOf(upstream.bucket)
			}),
			body
		});
	}

	it('answers a user linked only to another provider as not found', async () => {
		const upstream = await upstreamOfDefaultBucket('okta');
		const address = `other-${nanoid()}@example.com`;
		seedAccount(`other-${nanoid()}`, {
			email: address,
			federated: [{ providerId: 'elsewhere', sub: 'x', linkedAt: new Date() }]
		});
		await servesKeys(upstream.stub);

		const res = await named(upstream, email(address));

		expect(res.status).toBe(404);
	});

	it('answers a local user the provider never signed in as not found', async () => {
		const upstream = await upstreamOfDefaultBucket('okta');
		const address = `local-${nanoid()}@example.com`;
		seedAccount(`local-${nanoid()}`, { email: address });
		await servesKeys(upstream.stub);

		const res = await named(upstream, email(address));

		expect(res.status).toBe(404);
	});

	it('answers an absent user exactly as it answers one it may not name', async () => {
		const upstream = await upstreamOfDefaultBucket('okta');
		const address = `local-${nanoid()}@example.com`;
		seedAccount(`local-${nanoid()}`, { email: address });
		await servesKeys(upstream.stub);

		const unreachable = await named(upstream, email(address));
		const absent = await named(
			upstream,
			email(`nobody-${nanoid()}@example.com`)
		);

		expect(absent.status).toBe(unreachable.status);
		expect(absent.json).toEqual(unreachable.json);
	});

	it('reaches by email a user its provisioning connection provisioned', async () => {
		const upstream = await upstreamOfDefaultBucket('okta');
		const connection = await getProvisioningConnectionStore().create({
			_id: `conn-${nanoid()}`,
			bucketId: DEFAULT_BUCKET_ID,
			displayName: 'Directory',
			enabled: true,
			providerId: upstream.provider.id,
			correlation: { claim: 'preferred_username', attribute: 'userName' },
			emailTrust: 'trusted',
			oauthCredential: null
		});
		const address = `provisioned-${nanoid()}@example.com`;
		seedAccount(`provisioned-${nanoid()}`, {
			email: address,
			provisionedBy: connection._id
		});
		await servesKeys(upstream.stub);

		const res = await named(upstream, email(address));

		expect(res.status).toBe(204);
	});

	it('refuses an unsupported subject format as a malformed request', async () => {
		const upstream = await upstreamOfDefaultBucket('okta');

		const res = await named(upstream, {
			sub_id: { format: 'opaque', id: 'someone' }
		});

		expect(res.status).toBe(400);
		expect(res.json).toHaveProperty('error', 'invalid_request');
	});

	it('refuses an issuer-and-subject naming another issuer as a malformed request', async () => {
		const upstream = await upstreamOfDefaultBucket('okta');
		await servesKeys(upstream.stub);

		const res = await named(
			upstream,
			issSub('https://someone-else.example', 'someone')
		);

		expect(res.status).toBe(400);
	});

	it('refuses a body that is not JSON as a malformed request', async () => {
		const upstream = await upstreamOfDefaultBucket('okta');

		const res = await revoke(endpointOf(upstream.bucket), {
			assertion: await upstream.stub.revocationAssertion({
				sub: CLIENT_AT_IDP,
				aud: endpointOf(upstream.bucket)
			}),
			rawBody: 'sub_id=someone',
			contentType: 'application/x-www-form-urlencoded'
		});

		expect(res.status).toBe(400);
	});
});
