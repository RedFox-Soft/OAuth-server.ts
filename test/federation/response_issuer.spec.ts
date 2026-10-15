import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.ts';
import {
	adminSessionStore,
	getBucketStore,
	getUserStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import type { UserBucket } from 'lib/adapters/types.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ensurePersonalGroup } from 'lib/admin/groups/personal.ts';
import { shaped } from 'test/shape.js';
import { createAdministrator } from '../administrators.ts';
import { admin } from '../provisioning/helpers.ts';
import { idpStub } from './idp_stub.ts';
import { microsoftStub } from './recognised_stubs.ts';
import {
	CLIENT,
	get,
	provider,
	seedBucket,
	signedInAccountIds,
	startInteraction,
	walk
} from './harness.ts';

const TryRead = Type.Object({
	status: Type.Literal('done'),
	result: Type.Object({
		error: Type.Optional(
			Type.Object({ stage: Type.String(), reason: Type.String() })
		)
	})
});

/*
 * A sign-in whose authorization response carries `returned` beside the code. `answers` says whether the
 * provider's token endpoint is reached at all: a response refused for its issuer is refused before the code is
 * exchanged, and an interceptor nobody consumes would fail a later case.
 */
async function signIn(
	origin: string,
	metadata: Record<string, unknown>,
	returned: Record<string, string>,
	answers: boolean
) {
	const bucketId = await seedBucket(CLIENT, {
		federation: [provider(origin, { emailTrusted: true })]
	});
	const idp = await idpStub(origin, metadata);
	idp.expectDiscovery();
	const { uid, cookie } = await startInteraction();
	const walked = await walk(uid, cookie, undefined, {
		onAuthorize: async (url) => {
			if (answers) {
				await idp.answerToken(url, {
					email: 'iss@acme.test',
					email_verified: true
				});
			}
		},
		extraReturnParams: returned
	});
	return { ...walked, uid, bucketId };
}

/**
 * @proves A federated sign-in whose authorization response names an issuer other than the provider's own, or
 * names none when the provider declares it always does, is refused with nothing written, while every other
 * response proceeds as before — including one from a provider whose published issuer is a template — and a
 * try of a provider reports the refusal (RFC 9207; spec 088, User Story 4).
 */
describe('the issuer an authorization response names', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'signin' });
	});

	beforeEach(() => {
		resetAdminMemoryStores();
	});

	it('refuses a response naming another issuer, and writes nothing', async () => {
		const { callback, bucketId } = await signIn(
			'https://idp-iss-mismatch.test',
			{},
			{ iss: 'https://idp-iss-other.test' },
			false
		);

		expect(callback.status).toBe(400);
		expect(callback.location).toBe('');
		expect(await getUserStore(bucketId).list()).toEqual([]);
	});

	it('proceeds with a response naming the provider’s own issuer', async () => {
		const { callback, uid, complete } = await signIn(
			'https://idp-iss-match.test',
			{},
			{ iss: 'https://idp-iss-match.test' },
			true
		);

		expect(callback.location).toStartWith(`/ui/${uid}/federation/complete`);
		expect(complete?.status).toBe(303);
	});

	it('refuses a response without one from a provider that declares it always sends one', async () => {
		const { callback, bucketId } = await signIn(
			'https://idp-iss-missing.test',
			{ authorization_response_iss_parameter_supported: true },
			{},
			false
		);

		expect(callback.status).toBe(400);
		expect(await getUserStore(bucketId).list()).toEqual([]);
	});

	it('proceeds when the provider neither declares nor sends one', async () => {
		const { callback, uid } = await signIn(
			'https://idp-iss-silent.test',
			{},
			{},
			true
		);

		expect(callback.location).toStartWith(`/ui/${uid}/federation/complete`);
	});

	it('leaves a provider whose published issuer is a template to the ID token’s issuer check', async () => {
		const idp = await microsoftStub('common');
		const bucketId = await seedBucket(CLIENT, {
			federation: [
				provider(idp.issuer, {
					id: 'microsoft',
					clientId: idp.clientId,
					tenant: 'common',
					emailTrusted: true
				})
			]
		});
		idp.expectTemplatedDiscovery();
		const { uid, cookie } = await startInteraction();

		const { complete } = await walk(uid, cookie, undefined, {
			providerId: 'microsoft',
			onAuthorize: (url) =>
				idp.answerToken(url, { email: 'tpl@acme.test', email_verified: true }),
			extraReturnParams: {
				iss: 'https://login.microsoftonline.com/a-real-tenant/v2.0'
			}
		});

		expect(complete?.status).toBe(303);
		expect(signedInAccountIds().length).toBeGreaterThan(0);
		expect(await getUserStore(bucketId).list()).toHaveLength(1);
	});

	it('reports the refusal of a response from another issuer in a try', async () => {
		await ensureAdminSeed();
		const user = await createAdministrator('super');
		const personal = await ensurePersonalGroup(user._id, user.email);
		const session = await adminSessionStore.create({
			userId: user._id,
			bucketId: ADMIN_BUCKET_ID,
			activeGroupId: personal._id,
			tokens: {},
			ttlSeconds: 600,
			absoluteTtlSeconds: 3600
		});
		const cookie = `${ADMIN_SESSION_COOKIE}=${session._id}`;
		const origin = 'https://idp-iss-try.test';
		const bucketId = await seedBucket(CLIENT, {
			federation: [provider(origin)]
		});
		const bucket = (await getBucketStore().find(bucketId)) as UserBucket;
		const idp = await idpStub(origin);
		idp.expectDiscovery();
		const path = `/admin/api/projects/${bucket._id}/federation/acme-sso/try`;
		const started = await admin('POST', path, cookie);
		const authorizationUrl = new URL(String(started.json.authorizationUrl));
		const state = authorizationUrl.searchParams.get('state') ?? '';

		await get(
			`/federation/callback?${new URLSearchParams({ code: 'c', state, iss: 'https://elsewhere.test' }).toString()}`
		);
		const read = await admin(
			'GET',
			`${path}/${String(started.json.tryRef)}`,
			cookie
		);

		expect(shaped(TryRead, read.body).result.error).toEqual({
			stage: 'rejected',
			reason: 'issuer_mismatch'
		});
	});
});
