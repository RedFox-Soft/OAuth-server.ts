import {
	afterAll,
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	mock
} from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap, { seedAccount } from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { ISSUER } from 'lib/configs/env.js';
import { getBucketStore, getUserStore } from 'lib/adapters/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { purgeAtOf } from 'lib/consts/bucket_deletion.ts';
import { AccessToken } from 'lib/models/access_token.js';
import { RefreshToken } from 'lib/models/refresh_token.js';
import { Grant } from 'lib/models/grant.js';
import { Session } from 'lib/models/session.js';
import { Interaction } from 'lib/models/interaction.js';
import { Client } from 'lib/models/client.js';
import { request as requestPasswordReset } from 'lib/password_reset/challenge.ts';
import epochTime from 'lib/helpers/epoch_time.js';
import nanoid from 'lib/helpers/nanoid.ts';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { TestAdapter } from 'test/models.js';
import { present, shaped } from 'test/shape.js';
import {
	extractResetUrl,
	lastEmail,
	resetSentEmails
} from '../mail_capture.ts';
import { assertNoPendingInterceptors } from '../fetch_mock.js';
import { idpStub } from '../federation/idp_stub.js';
import {
	CLIENT_AT_IDP,
	logoutProvider,
	sendLogout,
	uniqueOrigin
} from '../upstream_backchannel_logout/helpers.ts';

const BUCKET_ID = 'doors-bucket';
const SLUG = 'doors';
const HOST = 'doors.e.ly';
const ACCOUNT = 'doors-person';
const EMAIL = 'doors-person@example.com';
const BASE = `${ISSUER}/${SLUG}`;

const Introspected = Type.Object({ active: Type.Boolean() });
const ErrorBody = Type.Object({ error: Type.String() });

async function schedule(id = BUCKET_ID): Promise<void> {
	const scheduledAt = new Date();
	await getBucketStore().scheduleDeletion(id, {
		scheduledAt,
		purgeAt: purgeAtOf(scheduledAt),
		scheduledBy: { userId: 'an-administrator' }
	});
	forgetBucketAddresses();
}

async function restore(id = BUCKET_ID): Promise<void> {
	await getBucketStore().cancelDeletion(id, new Date());
	forgetBucketAddresses();
}

/* A consent, a refresh token and an access token of the bucket, as a sign-in there would have left them. */
async function tokens(): Promise<{ refresh: string; access: string }> {
	const client = present(await Client.tryFind('tenant-app'), 'tenant-app');
	const grant = new Grant({ clientId: 'tenant-app', accountId: ACCOUNT });
	grant.addOIDCScope('openid offline_access');
	const grantId = await grant.save();
	const shared = {
		client,
		accountId: ACCOUNT,
		grantId,
		bucketId: BUCKET_ID
	};
	const refresh = await new RefreshToken({
		...shared,
		scope: 'openid offline_access',
		gty: 'authorization_code'
	}).save();
	const access = await new AccessToken({ ...shared, scope: 'openid' }).save();
	return { refresh, access };
}

function post(
	url: string,
	form: Record<string, string>,
	clientId = 'tenant-app'
): Promise<Response> {
	return elysia.handle(
		new Request(url, {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
				...AuthorizationRequest.basicAuthHeader(clientId, 'secret')
			},
			body: new URLSearchParams(form).toString()
		})
	);
}

function get(url: string, headers: Record<string, string> = {}) {
	return elysia.handle(new Request(url, { headers, redirect: 'manual' }));
}

/* Every door at the bucket's own address, each asked the way a client or a directory asks it. */
const DOORS: [string, () => Promise<Response>][] = [
	['discovery', () => get(`${BASE}/.well-known/openid-configuration`)],
	['the key set', () => get(`${BASE}/jwks`)],
	[
		'the authorization endpoint',
		() =>
			get(
				`${BASE}/auth?${new URLSearchParams({
					client_id: 'tenant-app',
					response_type: 'code',
					scope: 'openid',
					redirect_uri: 'https://tenant.example.com/cb',
					code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
					code_challenge_method: 'S256'
				}).toString()}`
			)
	],
	[
		'the token endpoint',
		async () =>
			post(`${BASE}/token`, {
				grant_type: 'refresh_token',
				refresh_token: (await tokens()).refresh
			})
	],
	[
		'userinfo',
		async () =>
			get(`${BASE}/userinfo`, {
				authorization: `Bearer ${(await tokens()).access}`
			})
	],
	[
		'introspection',
		async () =>
			post(`${BASE}/token/introspect`, { token: (await tokens()).access })
	],
	['the SCIM base', () => get(`${BASE}/scim/v2/ServiceProviderConfig`)]
];

/**
 * @proves While a bucket is scheduled for deletion every door at its address answers as an address where no
 * bucket exists, none of its tokens is honoured anywhere else on the server, its in-flight sign-ins and
 * emailed links stop working, an upstream provider can still end its sessions — and a restore brings back
 * the same tokens, unchanged.
 */
describe('a bucket scheduled for deletion', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'scheduled_doors' });
		await getBucketStore().create({
			_id: BUCKET_ID,
			name: 'Doors',
			slug: SLUG,
			ownerGroupId: UNASSIGNED_GROUP_ID
		});
		seedAccount(ACCOUNT, { email: EMAIL }, BUCKET_ID);
		forgetBucketAddresses();
	});

	afterAll(async () => {
		await getBucketStore().destroy(BUCKET_ID);
		forgetBucketAddresses();
	});

	beforeEach(async () => {
		await schedule();
	});

	afterEach(async () => {
		await restore();
		mock.restore();
	});

	it.each(DOORS)('answers 404 from %s at its address', async (_, ask) => {
		expect((await ask()).status).toBe(404);
	});

	it('answers 404 at its own hostname', async () => {
		const hosted = await getBucketStore().create({
			name: 'Hosted doors',
			host: HOST,
			ownerGroupId: UNASSIGNED_GROUP_ID
		});
		await schedule(hosted._id);
		try {
			const response = await elysia.handle(
				new Request(`http://${HOST}/.well-known/openid-configuration`)
			);

			expect(response.status).toBe(404);
		} finally {
			await getBucketStore().destroy(hosted._id);
			forgetBucketAddresses();
		}
	});

	it('refuses its refresh token at the root token endpoint with invalid_grant', async () => {
		const { refresh } = await tokens();

		const response = await post(`${ISSUER}/token`, {
			grant_type: 'refresh_token',
			refresh_token: refresh
		});

		expect(response.status).toBe(400);
		expect(shaped(ErrorBody, await response.json()).error).toBe(
			'invalid_grant'
		);
	});

	it('refuses its access token at the root userinfo endpoint', async () => {
		const { access } = await tokens();

		const response = await get(`${ISSUER}/userinfo`, {
			authorization: `Bearer ${access}`
		});

		expect(response.status).toBe(401);
	});

	it('reports its access token inactive to introspection at the root', async () => {
		const { access } = await tokens();

		const response = await post(
			`${ISSUER}/token/introspect`,
			{ token: access },
			'bystander'
		);

		expect(shaped(Introspected, await response.json()).active).toBe(false);
	});

	it('refuses a sign-in that was in flight when it was scheduled, as an interaction that does not exist', async () => {
		const uid = nanoid();
		const cookieID = nanoid();
		await new Interaction(uid, {
			params: { client_id: 'tenant-app', scope: 'openid' },
			bucketId: BUCKET_ID,
			cookieID
		}).save(60);

		const inFlight = await get(`${ISSUER}/ui/${uid}/login`, {
			cookie: `_interaction=${cookieID}`
		});
		const unknown = await get(`${ISSUER}/ui/${nanoid()}/login`, {
			cookie: `_interaction=${cookieID}`
		});

		expect(inFlight.status).not.toBe(200);
		expect(inFlight.status).toBe(unknown.status);
	});

	it('refuses a password-reset link mailed before it was scheduled', async () => {
		await restore();
		resetSentEmails();
		await requestPasswordReset(EMAIL, BUCKET_ID);
		const link = present(
			extractResetUrl(present(lastEmail(), 'the reset email')),
			'the reset link'
		);
		await schedule();

		const response = await get(link.replace(/^https?:\/\/[^/]+/, ISSUER));

		expect(response.status).toBe(400);
	});

	it('still lets its upstream provider end a session through back-channel logout', async () => {
		const origin = uniqueOrigin('doors');
		const stub = await idpStub(origin);
		stub.expectDiscovery();
		await stub.expectJwks();
		const provider = logoutProvider('doors-idp', origin);
		await restore();
		await getBucketStore().update(BUCKET_ID, { federation: [provider] });
		await getUserStore(BUCKET_ID).update(ACCOUNT, {
			federated: [
				{ providerId: provider.id, sub: 'upstream-sub', linkedAt: new Date() }
			]
		});
		const sessionId = await new Session({
			accountId: ACCOUNT,
			loginTs: epochTime(),
			bucketId: BUCKET_ID,
			upstream: { providerId: provider.id }
		}).save();
		await schedule();

		try {
			const response = await sendLogout(
				`${BASE}/federation/backchannel-logout`,
				await stub.logoutToken({ aud: CLIENT_AT_IDP, sub: 'upstream-sub' })
			);

			expect(response.status).toBe(200);
			expect(TestAdapter.for('Session').syncFind(sessionId)).toBeUndefined();
			assertNoPendingInterceptors();
		} finally {
			await getBucketStore().update(BUCKET_ID, { federation: [] });
		}
	});

	describe('once restored', () => {
		it('accepts the same refresh token at its address', async () => {
			const { refresh } = await tokens();
			await restore();

			const response = await post(`${BASE}/token`, {
				grant_type: 'refresh_token',
				refresh_token: refresh
			});

			expect(response.status).toBe(200);
		});

		it('answers discovery at its address again', async () => {
			await restore();

			expect(
				(await get(`${BASE}/.well-known/openid-configuration`)).status
			).toBe(200);
		});

		it('answers userinfo for an access token issued before it was scheduled', async () => {
			const { access } = await tokens();
			await restore();

			const response = await get(`${BASE}/userinfo`, {
				authorization: `Bearer ${access}`
			});

			expect(response.status).toBe(200);
		});
	});
});
