import { describe, it, expect, beforeAll } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adapter,
	getBucketGroupStore,
	getBucketStore,
	getProtectedResourceStore,
	getProvisioningConnectionStore,
	getUserStore
} from 'lib/adapters/index.ts';
import type { User, UserBucket } from 'lib/adapters/types.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { shaped } from 'test/shape.ts';
import { provider } from '../scim/helpers.ts';
import { createAdministrator } from '../administrators.ts';
import { cookieFor, regularGroup } from './ownership_fixtures.ts';

async function request(
	method: string,
	path: string,
	cookie: string,
	body?: Readonly<Record<string, unknown>>
): Promise<{ status: number; body: unknown }> {
	const response = await elysia.handle(
		new Request(`http://e.ly${path}`, {
			method,
			headers: { 'content-type': 'application/json', cookie },
			...(body === undefined ? {} : { body: JSON.stringify(body) })
		})
	);
	const text = await response.text();
	return {
		status: response.status,
		body: text ? (JSON.parse(text) as unknown) : null
	};
}

const Summary = Type.Object({
	users: Type.Number(),
	unverified: Type.Number(),
	withoutAuthenticator: Type.Number(),
	withoutLinkedIdentity: Type.Number(),
	userGroups: Type.Number(),
	connections: Type.Number(),
	held: Type.Number(),
	applications: Type.Number(),
	apis: Type.Number(),
	providers: Type.Object({ enabled: Type.Number(), creating: Type.Number() }),
	activeThisMonth: Type.Optional(Type.Number()),
	mailDeliveryConfigured: Type.Boolean()
});

const BucketRead = Type.Object({
	addressForm: Type.String(),
	issuer: Type.Union([Type.String(), Type.Null()]),
	discoveryUrl: Type.Union([Type.String(), Type.Null()]),
	applications: Type.Number(),
	apis: Type.Number()
});

const ListRow = Type.Object({
	_id: Type.String(),
	addressForm: Type.String(),
	issuer: Type.Union([Type.String(), Type.Null()]),
	hostReached: Type.Boolean(),
	held: Type.Boolean()
});

const Discovery = Type.Object({ issuer: Type.String() });

const unique = () =>
	nanoid()
		.toLowerCase()
		.replace(/[^a-z0-9]/g, '');

const ENROLMENT = {
	secret: 'JBSWY3DPEHPK3PXP',
	enrolledAt: new Date(),
	lastStep: 0
};

async function connection(bucketId: string, providerId: string) {
	return getProvisioningConnectionStore().create({
		_id: nanoid(),
		bucketId,
		displayName: `Directory ${providerId}`,
		enabled: true,
		providerId,
		correlation: { claim: 'oid', attribute: 'externalId' },
		emailTrust: 'untrusted',
		oauthCredential: null
	});
}

/**
 * @proves Opening a bucket tells its administrators what it holds and what needs attention — counts that
 * match its accounts, groups, connections and providers, active users only to those who may read its
 * activity, and the issuer and discovery addresses its clients are configured with — and the bucket list
 * marks a held bucket and a hostname no request has reached.
 */
describe("a bucket's overview", () => {
	let owner: User;
	let ownerCookie: string;
	let superCookie: string;
	let bucket: UserBucket;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await ensureAdminSeed();
		owner = await createAdministrator();
		const owning = await regularGroup([owner]);
		ownerCookie = await cookieFor(owner);
		superCookie = await cookieFor(await createAdministrator('super'));

		const id = unique();
		bucket = await getBucketStore().create({
			name: `overview ${id}`,
			slug: `ov-${id}`,
			ownerGroupId: owning._id,
			federation: [
				provider('creating'),
				provider('existing', { provisioning: 'existing_only' }),
				provider('disabled', { enabled: false })
			]
		});
		for (const clientId of [`overview-app-a-${id}`, `overview-app-b-${id}`]) {
			await adapter('Client').upsert(clientId, {
				clientId,
				bucketId: bucket._id,
				grantTypes: ['authorization_code'],
				responseTypes: ['code'],
				redirectUris: [`https://${clientId}.example.com/cb`],
				token_endpoint_auth_method: 'none'
			});
		}
		await getProtectedResourceStore().create({
			namespace: bucket._id,
			identifier: `https://api-${id}.example.com/`,
			bucketId: bucket._id,
			name: 'Overview API',
			scopes: ['read']
		});

		const users = getUserStore(bucket._id);
		const complete = await users.create(`complete-${id}@x.io`, 'h', true);
		await users.update(complete._id, {
			totp: ENROLMENT,
			federated: [{ providerId: 'creating', sub: id, linkedAt: new Date() }]
		});
		await users.create(`unverified-${id}@x.io`, 'h', false);
		const unlinked = await users.create(`unlinked-${id}@x.io`, 'h', true);
		await users.update(unlinked._id, { federated: [] });

		await getBucketGroupStore().create({
			_id: nanoid(),
			bucketId: bucket._id,
			displayName: 'Staff'
		});
		const held = await connection(bucket._id, 'creating');
		await connection(bucket._id, 'existing');
		await getProvisioningConnectionStore().holdIfFree(held._id, {
			since: new Date(),
			count: 5
		});
	});

	async function summaryAs(cookie: string) {
		const answer = await request(
			'GET',
			`/admin/api/buckets/${bucket._id}/summary`,
			cookie
		);
		expect(answer.status).toBe(200);
		return shaped(Summary, answer.body);
	}

	it('counts users, unverified, without an authenticator, without a linked identity, user groups, connections, held connections, applications, APIs and providers', async () => {
		const summary = await summaryAs(ownerCookie);

		expect(summary).toMatchObject({
			users: 3,
			unverified: 1,
			withoutAuthenticator: 2,
			withoutLinkedIdentity: 2,
			userGroups: 1,
			connections: 2,
			held: 1,
			applications: 2,
			apis: 1,
			providers: { enabled: 2, creating: 1 }
		});
	});

	it('gives active users this month to a caller who may read the bucket’s activity', async () => {
		const summary = await summaryAs(ownerCookie);

		expect(typeof summary.activeThisMonth).toBe('number');
	});

	it('refuses the summary to an administrator outside the bucket', async () => {
		const outsider = await cookieFor(await createAdministrator());

		const answer = await request(
			'GET',
			`/admin/api/buckets/${bucket._id}/summary`,
			outsider
		);

		expect(answer.status).toBe(403);
	});

	it('gives the issuer and discovery address discovery itself serves, the address form and how many applications and APIs it holds', async () => {
		const read = shaped(
			BucketRead,
			(await request('GET', `/admin/api/buckets/${bucket._id}`, ownerCookie))
				.body
		);
		const discovered = await elysia.handle(
			new Request(String(read.discoveryUrl))
		);

		expect(discovered.status).toBe(200);
		expect(shaped(Discovery, await discovered.json()).issuer).toBe(
			String(read.issuer)
		);
		expect(read.addressForm).toBe('path');
		expect(read.applications).toBe(2);
		expect(read.apis).toBe(1);
	});

	it('gives no issuer for a bucket with no address of its own', async () => {
		const legacy = await getBucketStore().create({
			name: `legacy ${unique()}`,
			ownerGroupId: bucket.ownerGroupId
		});

		const read = shaped(
			BucketRead,
			(await request('GET', `/admin/api/buckets/${legacy._id}`, ownerCookie))
				.body
		);

		expect([read.addressForm, read.issuer, read.discoveryUrl]).toEqual([
			'unaddressed',
			null,
			null
		]);
	});

	describe('in the bucket list', () => {
		async function rowOf(id: string) {
			const rows = shaped(
				Type.Array(ListRow),
				(await request('GET', '/admin/api/buckets', superCookie)).body
			);
			const row = rows.find((r) => r._id === id);
			expect(row).toBeDefined();
			return shaped(ListRow, row);
		}

		it('marks a bucket one of whose connections is holding a deprovisioning', async () => {
			const row = await rowOf(bucket._id);

			expect(row.held).toBe(true);
		});

		it('marks a hostname no request has reached, and one a request has', async () => {
			const id = unique();
			const quiet = await getBucketStore().create({
				name: `quiet ${id}`,
				host: `quiet-${id}.e.ly`,
				ownerGroupId: bucket.ownerGroupId
			});
			const reached = await getBucketStore().create({
				name: `reached ${id}`,
				host: `reached-${id}.e.ly`,
				ownerGroupId: bucket.ownerGroupId
			});
			await getBucketStore().update(reached._id, {
				hostFirstSeenAt: new Date(),
				hostLastSeenAt: new Date()
			});

			const rows = [await rowOf(quiet._id), await rowOf(reached._id)];

			expect(rows.map((r) => [r.hostReached, r.held])).toEqual([
				[false, false],
				[true, false]
			]);
			expect(rows.map((r) => r.issuer)).toEqual([
				`http://quiet-${id}.e.ly`,
				`http://reached-${id}.e.ly`
			]);
		});

		it('marks a new hostname not reached after an address change, whatever reached the old one', async () => {
			const id = unique();
			const moving = await getBucketStore().create({
				name: `moving ${id}`,
				host: `before-${id}.e.ly`,
				ownerGroupId: bucket.ownerGroupId
			});
			await getBucketStore().update(moving._id, {
				hostFirstSeenAt: new Date(),
				hostLastSeenAt: new Date()
			});

			const changed = await request(
				'POST',
				`/admin/api/buckets/${moving._id}/address`,
				superCookie,
				{
					host: `after-${id}.e.ly`,
					confirm: true,
					expect: {
						applications: 0,
						connections: 0,
						providers: 0,
						resources: 0
					}
				}
			);
			forgetBucketAddresses();

			expect(changed.status).toBe(200);
			expect((await rowOf(moving._id)).hostReached).toBe(false);
		});
	});
});
