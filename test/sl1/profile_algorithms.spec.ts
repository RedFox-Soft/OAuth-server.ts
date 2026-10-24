import {
	describe,
	it,
	expect,
	beforeAll,
	beforeEach,
	afterEach,
	spyOn,
	mock
} from 'bun:test';
import { Type } from '@sinclair/typebox';
import { decodeProtectedHeader, generateKeyPair, SignJWT } from 'jose';

import bootstrap, { type Setup } from '../test_helper.ts';
import { adapter, getBucketStore } from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ISSUER } from 'lib/configs/env.ts';
import { OIDCContext } from 'lib/helpers/oidc_context.ts';
import { shaped } from 'test/shape.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { send } from '../feature_gate/helpers.ts';
import {
	discoveryDocument,
	superAdminCookie
} from '../settings_apply/helpers.ts';
import { publishedKeys } from '../bucket_keys/tenants.ts';
import { assertionKey, INITIAL_ACCESS_TOKEN } from './profile.config.ts';
import {
	answer,
	proof,
	signedIn,
	tokenRequest,
	type KeyPair
} from './profile_flow.ts';

const SL1 = ['PS256', 'ES256', 'EdDSA', 'Ed25519'];
const ErrorBody = Type.Object({
	error: Type.String(),
	error_description: Type.Optional(Type.String())
});

function register(body: Record<string, unknown>) {
	return send('/reg', {
		method: 'POST',
		headers: {
			'content-type': 'application/json',
			authorization: `Bearer ${INITIAL_ACCESS_TOKEN}`
		},
		body: JSON.stringify({
			redirect_uris: ['https://alg.example.com/cb'],
			...body
		})
	});
}

function assertion(clientId: string, alg: string, key: CryptoKey | Uint8Array) {
	return new SignJWT({})
		.setProtectedHeader({ alg })
		.setIssuer(clientId)
		.setSubject(clientId)
		.setAudience(ISSUER)
		.setJti(crypto.randomUUID())
		.setIssuedAt()
		.setExpirationTime('1m')
		.sign(key);
}

/**
 * @proves Under the IPSIE SL1 profile everything the server signs, and every JWT it takes from an application, uses
 * PS256, ES256 or EdDSA, and an application that registered no algorithm is signed for PS256 and has PS256 written
 * when it is next saved.
 */
describe('signing algorithms under the IPSIE SL1 profile', () => {
	let setup: Setup;
	let keypair: KeyPair;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'profile' });
		await ensureAdminSeed();
		keypair = await generateKeyPair('ES256');
	});

	beforeEach(() => {
		spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(false);
	});

	afterEach(() => {
		mock.restore();
	});

	describe('registering an algorithm outside the profile', () => {
		for (const alg of ['RS256', 'HS256']) {
			it(`is refused for ${alg}, naming the attribute and the requirement`, async () => {
				const res = await register({ id_token_signed_response_alg: alg });

				expect(res.status).toBe(400);
				const body = shaped(ErrorBody, await res.json());
				expect(body.error).toBe('invalid_client_metadata');
				expect(body.error_description).toContain(
					'id_token_signed_response_alg'
				);
				expect(body.error_description).toContain('CR §3.3');
			});
		}
	});

	it('signs an ID token for PS256 for an application stored with no algorithm', async () => {
		const issued = await signedIn(setup, keypair, {
			client: 'sl1-web',
			secret: 'sl1-web-secret'
		});

		expect(decodeProtectedHeader(issued.id_token ?? '').alg).toBe('PS256');
	});

	it('writes PS256 into an application with no algorithm when an administrator saves it', async () => {
		const res = await send(
			`/admin/api/projects/${DEFAULT_BUCKET_ID}/clients/sl1-web`,
			{
				method: 'PATCH',
				headers: {
					cookie: await superAdminCookie(),
					'content-type': 'application/json'
				},
				body: JSON.stringify({ clientName: 'Saved under SL1' })
			}
		);

		expect(res.status).toBe(200);
		expect(
			(await adapter('Client').find('sl1-web'))?.id_token_signed_response_alg
		).toBe('PS256');
	});

	/*
	 * Every save writes the validated record, defaults included, so a stored RS256 is the default an earlier save wrote
	 * — the state of almost every application created before the profile.
	 */
	it('signs an ID token for PS256 for an application whose record holds the RS256 default', async () => {
		const issued = await signedIn(setup, keypair, {
			client: 'sl1-rs256',
			secret: 'sl1-rs256-secret'
		});

		expect(decodeProtectedHeader(issued.id_token ?? '').alg).toBe('PS256');
	});

	it('lets an administrator save an application holding the RS256 default, writing PS256', async () => {
		const res = await send(
			`/admin/api/projects/${DEFAULT_BUCKET_ID}/clients/sl1-rs256`,
			{
				method: 'PATCH',
				headers: {
					cookie: await superAdminCookie(),
					'content-type': 'application/json'
				},
				body: JSON.stringify({ clientName: 'Saved under SL1' })
			}
		);

		expect(res.status).toBe(200);
		expect(
			(await adapter('Client').find('sl1-rs256'))?.id_token_signed_response_alg
		).toBe('PS256');
	});

	it('refuses a stored application registered for HS256 as an unknown client', async () => {
		const res = await new AuthorizationRequest({
			client_id: 'sl1-hs256',
			scope: 'openid'
		}).authorize();

		expect(res.status).toBe(400);
		expect(await res.text()).toContain('invalid_client');
	});

	it('refuses an application that authenticates with client_secret_jwt', async () => {
		const res = await tokenRequest(
			{
				grant_type: 'client_credentials',
				client_assertion_type:
					'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
				client_assertion: await assertion(
					'sl1-hmac',
					'HS256',
					new TextEncoder().encode(
						'a-shared-secret-long-enough-for-hs256-signing'
					)
				)
			},
			{ client: 'sl1-hmac', dpop: await proof(keypair) }
		);

		expect((await answer(res)).error).toBe('invalid_client');
	});

	it('accepts a private_key_jwt assertion signed with PS256', async () => {
		const res = await tokenRequest(
			{
				grant_type: 'client_credentials',
				client_assertion_type:
					'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
				client_assertion: await assertion(
					'sl1-pkjwt',
					'PS256',
					assertionKey.privateKey
				)
			},
			{ client: 'sl1-pkjwt', dpop: await proof(keypair) }
		);

		expect((await answer(res)).token_type).toBe('DPoP');
	});

	it('refuses a request object signed with HS256', async () => {
		const plain = new AuthorizationRequest({
			client_id: 'sl1-web',
			scope: 'openid'
		});
		const request = await new SignJWT({ ...plain.params })
			.setProtectedHeader({ alg: 'HS256' })
			.setIssuer('sl1-web')
			.setAudience(ISSUER)
			.setIssuedAt()
			.setExpirationTime('1m')
			.sign(new TextEncoder().encode('sl1-web-secret'));

		const res = await new AuthorizationRequest({
			client_id: 'sl1-web',
			scope: 'openid',
			code_challenge: plain.params.code_challenge,
			request
		}).authorize();

		const where = `${res.headers.get('location') ?? ''} ${await res.text()}`;
		expect(where).toContain('invalid_request_object');
	});

	it('advertises only the profile’s algorithms, the code flow, and no shared-secret JWTs', async () => {
		const discovery = shaped(
			Type.Object({
				id_token_signing_alg_values_supported: Type.Array(Type.String()),
				request_object_signing_alg_values_supported: Type.Array(Type.String()),
				token_endpoint_auth_signing_alg_values_supported: Type.Array(
					Type.String()
				),
				token_endpoint_auth_methods_supported: Type.Array(Type.String()),
				response_types_supported: Type.Array(Type.String()),
				client_id_metadata_document_supported: Type.Optional(Type.Boolean())
			}),
			await discoveryDocument()
		);

		for (const list of [
			discovery.id_token_signing_alg_values_supported,
			discovery.request_object_signing_alg_values_supported,
			discovery.token_endpoint_auth_signing_alg_values_supported
		]) {
			expect(list.length).toBeGreaterThan(0);
			for (const alg of list) expect(SL1).toContain(alg);
		}
		expect(discovery.response_types_supported).toEqual(['code']);
		expect(discovery.token_endpoint_auth_methods_supported).not.toContain(
			'client_secret_jwt'
		);
		expect(discovery.client_id_metadata_document_supported).toBeUndefined();
	});

	it('gives a project created while the profile is on a PS256 signing key at once', async () => {
		await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Born under SL1',
			slug: 'bornsl1'
		});

		const { keys } = await publishedKeys(`${ISSUER}/bornsl1/jwks`);

		expect(keys.map((key) => key.alg)).toContain('PS256');
	});
});
