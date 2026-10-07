import { describe, it, beforeAll, afterEach, expect, mock } from 'bun:test';

import { getBucketStore } from 'lib/adapters/index.ts';
import { ADMIN_SESSION_COOKIE, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import nanoid from 'lib/helpers/nanoid.js';
import bootstrap from '../test_helper.js';
import { assertNoPendingInterceptors } from '../fetch_mock.js';
import { sessionFor } from '../admin_session.ts';
import { admin } from '../provisioning/helpers.ts';
import { createAdministrator } from '../administrators.ts';
import { idpStub } from '../federation/idp_stub.js';
import {
	endpointOf,
	pathBucketWith,
	uniqueOrigin,
	upstreamProvider
} from './helpers.ts';

interface Entry {
	action: string;
	targetId: string;
	attributes?: string[];
}

/**
 * @proves An administrator connects an identity provider's logout: the option is off until switched on, the
 * switch is audited with the provider change, the console is given the exact address to paste into the
 * provider, and a provider that publishes no keys cannot be switched on (spec 072, User Story 3; FR-004, FR-005).
 */
describe('opting a provider in to global token revocation', () => {
	let cookie: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		const user = await createAdministrator(
			'super',
			`super-${Math.random()}@x.io`
		);
		cookie = `${ADMIN_SESSION_COOKIE}=${(await sessionFor(user))._id}`;
	});

	afterEach(() => {
		try {
			mock.restore();
		} finally {
			assertNoPendingInterceptors();
		}
	});

	it('creates a provider that does not accept revocation unless told to', async () => {
		const origin = uniqueOrigin('create');
		const stub = await idpStub(origin);
		stub.expectDiscovery();
		const bucket = await pathBucketWith([]);

		const res = await admin(
			'POST',
			`/admin/api/buckets/${bucket._id}/federation`,
			cookie,
			{
				id: 'corp',
				displayName: 'Corp',
				issuer: origin,
				clientId: 'our-client',
				clientSecret: 'secret'
			}
		);

		expect(res.status).toBe(201);
		expect(res.json.acceptsGlobalTokenRevocation).toBe(false);
		expect(res.json).not.toHaveProperty('globalTokenRevocationEndpoint');
	});

	it('records switching revocation on under the provider update', async () => {
		const bucket = await pathBucketWith([
			upstreamProvider('corp', uniqueOrigin('audit'), {
				acceptsGlobalTokenRevocation: false
			})
		]);

		await admin(
			'PATCH',
			`/admin/api/buckets/${bucket._id}/federation/corp`,
			cookie,
			{ acceptsGlobalTokenRevocation: true }
		);

		const trail = await admin(
			'GET',
			`/admin/api/audit?action=federation.provider.update&targetId=${bucket._id}`,
			cookie
		);
		const entries = trail.json.entries as Entry[];
		expect(entries[0]?.attributes).toEqual(['acceptsGlobalTokenRevocation']);
	});

	it('shows the address to give the identity provider once revocation is on', async () => {
		const bucket = await pathBucketWith([
			upstreamProvider('corp', uniqueOrigin('address'), {
				acceptsGlobalTokenRevocation: false
			})
		]);

		const res = await admin(
			'PATCH',
			`/admin/api/buckets/${bucket._id}/federation/corp`,
			cookie,
			{ acceptsGlobalTokenRevocation: true }
		);

		expect(res.status).toBe(200);
		expect(res.json.globalTokenRevocationEndpoint).toBe(endpointOf(bucket));
	});

	it('refuses revocation for a provider that publishes no signing keys', async () => {
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: `gh-${nanoid()}`,
			slug: `gh${nanoid()
				.toLowerCase()
				.replace(/[^a-z0-9]/g, '')
				.slice(0, 8)}`,
			federation: [
				upstreamProvider('github', 'https://github.com', {
					scopes: ['read:user', 'user:email'],
					acceptsGlobalTokenRevocation: false
				})
			]
		});

		const res = await admin(
			'PATCH',
			`/admin/api/buckets/${bucket._id}/federation/github`,
			cookie,
			{ acceptsGlobalTokenRevocation: true }
		);

		expect(res.status).toBe(422);
	});
});
