import { describe, it, beforeAll, afterEach, expect, mock } from 'bun:test';

import { getBucketStore } from 'lib/adapters/index.ts';
import {
	ADMIN_SESSION_COOKIE,
	DEFAULT_BUCKET_ID,
	UNASSIGNED_GROUP_ID
} from 'lib/admin/consts.ts';
import nanoid from 'lib/helpers/nanoid.js';
import { Type } from '@sinclair/typebox';
import { shaped } from 'test/shape.js';
import bootstrap from '../test_helper.js';
import { assertNoPendingInterceptors } from '../fetch_mock.js';
import { sessionFor } from '../admin_session.ts';
import { admin } from '../provisioning/helpers.ts';
import { createAdministrator } from '../administrators.ts';
import { idpStub } from '../federation/idp_stub.js';
import { pathBucketWith } from '../global_token_revocation/helpers.js';
import {
	CLIENT_AT_IDP,
	keysServedForLogout,
	logoutEndpointOf,
	logoutProvider,
	relyingPartyListening,
	sendLogout,
	sessionRecord,
	signInThroughProvider,
	uniqueOrigin,
	upstreamOfDefaultBucket
} from './helpers.ts';

interface Entry {
	attributes?: string[];
}

/**
 * @proves An administrator connects an identity provider's back-channel logout: off until switched on, the
 * switch audited as the provider change it is, the console given the address to register at the provider,
 * the provider's logout tokens accepted only while it is on, and a provider that publishes no keys unable to
 * turn it on (spec 073 User Story 4; FR-019, FR-020).
 */
describe('connecting a provider’s back-channel logout', () => {
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

	it('creates a provider that does not accept back-channel logout unless told to', async () => {
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
		expect(res.json.acceptsBackChannelLogout).toBe(false);
		expect(res.json).not.toHaveProperty('backChannelLogoutEndpoint');
	});

	it('shows the address to register at the provider once it is switched on', async () => {
		const bucket = await pathBucketWith([
			logoutProvider('corp', uniqueOrigin('address'), {
				acceptsBackChannelLogout: false
			})
		]);

		const res = await admin(
			'PATCH',
			`/admin/api/buckets/${bucket._id}/federation/corp`,
			cookie,
			{ acceptsBackChannelLogout: true }
		);

		expect(res.status).toBe(200);
		expect(res.json.backChannelLogoutEndpoint).toBe(logoutEndpointOf(bucket));
	});

	it('records switching it on under the provider update', async () => {
		const bucket = await pathBucketWith([
			logoutProvider('corp', uniqueOrigin('audit'), {
				acceptsBackChannelLogout: false
			})
		]);
		await admin(
			'PATCH',
			`/admin/api/buckets/${bucket._id}/federation/corp`,
			cookie,
			{ acceptsBackChannelLogout: true }
		);

		const trail = await admin(
			'GET',
			`/admin/api/audit?action=federation.provider.update&targetId=${bucket._id}`,
			cookie
		);

		const entries = trail.json.entries as Entry[];
		expect(entries[0]?.attributes).toEqual(['acceptsBackChannelLogout']);
	});

	it('reads a provider stored before the option existed as not accepting, with no address', async () => {
		const { acceptsBackChannelLogout: _absent, ...stored } = logoutProvider(
			'corp',
			uniqueOrigin('legacy')
		);
		const bucket = await pathBucketWith([stored]);

		const res = await admin(
			'GET',
			`/admin/api/buckets/${bucket._id}/federation`,
			cookie
		);

		const [provider] = shaped(
			Type.Array(Type.Record(Type.String(), Type.Unknown())),
			res.json
		);
		expect(provider?.acceptsBackChannelLogout).not.toBe(true);
		expect(provider).not.toHaveProperty('backChannelLogoutEndpoint');
	});

	it('refuses it for a provider that publishes no signing keys', async () => {
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: `gh-${nanoid()}`,
			slug: `gh${nanoid()
				.toLowerCase()
				.replace(/[^a-z0-9]/g, '')
				.slice(0, 8)}`,
			federation: [
				logoutProvider('github', 'https://github.com', {
					scopes: ['read:user', 'user:email'],
					acceptsBackChannelLogout: false
				})
			]
		});

		const res = await admin(
			'PATCH',
			`/admin/api/buckets/${bucket._id}/federation/github`,
			cookie,
			{ acceptsBackChannelLogout: true }
		);

		expect(res.status).toBe(422);
	});

	it('lets the provider sign people out once an administrator switches it on', async () => {
		const upstream = await upstreamOfDefaultBucket('kc', {
			acceptsBackChannelLogout: false
		});
		const person = await signInThroughProvider(upstream, {
			sub: 'kc-switched-on',
			sid: 'kc-switched-on-session'
		});
		await admin(
			'PATCH',
			`/admin/api/buckets/${DEFAULT_BUCKET_ID}/federation/${upstream.provider.id}`,
			cookie,
			{ acceptsBackChannelLogout: true }
		);
		await keysServedForLogout(upstream.stub);
		relyingPartyListening('https://client.example.com');

		await sendLogout(
			logoutEndpointOf(upstream.bucket),
			await upstream.stub.logoutToken({
				aud: CLIENT_AT_IDP,
				sub: 'kc-switched-on',
				sid: 'kc-switched-on-session'
			})
		);

		expect(sessionRecord(person.sessionId)).toBeUndefined();
	});

	it('stops the provider signing people out once an administrator switches it off', async () => {
		const upstream = await upstreamOfDefaultBucket('kc');
		const person = await signInThroughProvider(upstream, {
			sub: 'kc-switched-off',
			sid: 'kc-switched-off-session'
		});
		await admin(
			'PATCH',
			`/admin/api/buckets/${DEFAULT_BUCKET_ID}/federation/${upstream.provider.id}`,
			cookie,
			{ acceptsBackChannelLogout: false }
		);
		await keysServedForLogout(upstream.stub);

		const res = await sendLogout(
			logoutEndpointOf(upstream.bucket),
			await upstream.stub.logoutToken({
				aud: CLIENT_AT_IDP,
				sub: 'kc-switched-off',
				sid: 'kc-switched-off-session'
			})
		);

		expect(res.status).toBe(400);
		expect(sessionRecord(person.sessionId)).toBeDefined();
	});
});
