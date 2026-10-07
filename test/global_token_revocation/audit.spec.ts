import { describe, it, beforeAll, afterEach, expect, mock } from 'bun:test';

import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { eventBus } from 'lib/index.ts';
import nanoid from 'lib/helpers/nanoid.js';
import bootstrap, { seedAccount } from '../test_helper.js';
import { assertNoPendingInterceptors } from '../fetch_mock.js';
import { groupIdFor, sessionFor } from '../admin_session.ts';
import { admin } from '../provisioning/helpers.ts';
import { createAdministrator } from '../administrators.ts';
import { idpStub, type IdpStub } from '../federation/idp_stub.js';
import {
	CLIENT_AT_IDP,
	endpointOf,
	issSub,
	pathBucketWith,
	revoke,
	servesKeys,
	uniqueOrigin,
	upstreamProvider
} from './helpers.ts';
import type { UserBucket } from 'lib/adapters/types.ts';

interface Entry {
	actorId: string;
	action: string;
	targetId: string;
	viaSurface?: string | null;
}

/**
 * @proves The administrators of a bucket see every revocation its upstream provider made — which provider,
 * which user, never the identifier the provider named them by — and nothing for a request that was refused
 * (spec 072, FR-014, FR-015).
 */
describe('the audit trail of upstream revocations', () => {
	let cookie: string;
	let bucket: UserBucket;
	let stub: IdpStub;
	let origin: string;

	async function upstreamEntries(): Promise<Entry[]> {
		const res = await admin(
			'GET',
			'/admin/api/audit?viaSurface=upstream&pageSize=100',
			cookie
		);
		expect(res.status).toBe(200);
		return res.json.entries as Entry[];
	}

	function linkedUser(sub: string, address: string): string {
		const accountId = `audited-${nanoid()}`;
		seedAccount(
			accountId,
			{
				email: address,
				federated: [{ providerId: 'corp', sub, linkedAt: new Date() }]
			},
			bucket._id
		);
		return accountId;
	}

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		/* An administrator of the bucket's group, not a super administrator: what they see is scoped. */
		const user = await createAdministrator(
			'plain',
			`owner-${Math.random()}@x.io`
		);
		const session = await sessionFor(user);
		cookie = `${ADMIN_SESSION_COOKIE}=${session._id}`;
		origin = uniqueOrigin('audit');
		stub = await idpStub(origin);
		bucket = await pathBucketWith([upstreamProvider('corp', origin)]);
		const { getBucketStore } = await import('lib/adapters/index.ts');
		const owned = await getBucketStore().update(bucket._id, {
			ownerGroupId: await groupIdFor(user)
		});
		if (owned) bucket = owned;
		await servesKeys(stub);
	});

	afterEach(() => {
		try {
			mock.restore();
		} finally {
			assertNoPendingInterceptors();
		}
	});

	it('records a revocation under the provider, visible to the bucket’s own administrators', async () => {
		const accountId = linkedUser('corp-a', `a-${nanoid()}@contoso.com`);

		await revoke(endpointOf(bucket), {
			assertion: await stub.revocationAssertion({
				sub: CLIENT_AT_IDP,
				aud: endpointOf(bucket)
			}),
			body: issSub(origin, 'corp-a')
		});

		const entry = (await upstreamEntries()).find(
			(e) => e.targetId === accountId
		);
		expect(entry).toMatchObject({
			actorId: `upstream:${bucket._id}:corp`,
			action: 'enduser.signout',
			viaSurface: 'upstream'
		});
	});

	it('records neither the subject identifier nor the email the provider named the user by', async () => {
		const address = `secret-${nanoid()}@contoso.com`;
		const accountId = linkedUser('corp-secret-subject', address);

		await revoke(endpointOf(bucket), {
			assertion: await stub.revocationAssertion({
				sub: CLIENT_AT_IDP,
				aud: endpointOf(bucket)
			}),
			body: issSub(origin, 'corp-secret-subject')
		});

		const entry = (await upstreamEntries()).find(
			(e) => e.targetId === accountId
		);
		expect(entry).toBeDefined();
		expect(JSON.stringify(entry)).not.toContain('corp-secret-subject');
		expect(JSON.stringify(entry)).not.toContain(address);
	});

	it('records nothing for a refused revocation', async () => {
		linkedUser('corp-refused', `r-${nanoid()}@contoso.com`);
		const before = (await upstreamEntries()).length;

		const refused = await revoke(endpointOf(bucket), {
			assertion: await stub.revocationAssertion(
				{ sub: CLIENT_AT_IDP, aud: endpointOf(bucket) },
				{ foreignKey: true }
			),
			body: issSub(origin, 'corp-refused')
		});

		expect(refused.status).toBe(401);
		expect((await upstreamEntries()).length).toBe(before);
	});

	it('makes a refused revocation observable as an event naming the reason', async () => {
		const reasons: unknown[] = [];
		const listener = (event: { reason?: unknown }) => {
			reasons.push(event.reason);
		};
		eventBus.on('upstream.revocation.refused', listener);

		try {
			await revoke(endpointOf(bucket), {
				assertion: await stub.revocationAssertion({
					sub: CLIENT_AT_IDP,
					aud: endpointOf(bucket)
				}),
				body: issSub(origin, `nobody-${nanoid()}`)
			});
		} finally {
			eventBus.off('upstream.revocation.refused', listener);
		}

		expect(reasons).toEqual(['unknown_subject']);
	});
});
