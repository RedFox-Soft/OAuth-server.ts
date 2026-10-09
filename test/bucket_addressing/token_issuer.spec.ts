import { afterAll, beforeAll, describe, expect, it } from 'bun:test';

import bootstrap, {
	jsonToFormUrlEncoded,
	clearSeededBuckets,
	seedBucket,
	type Setup
} from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { ISSUER } from 'lib/configs/env.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { Type } from '@sinclair/typebox';
import { present, shaped } from 'test/shape.js';

const SLUG = 'acme';

async function post(path: string, form: Record<string, string>) {
	return elysia.handle(
		new Request(`http://localhost${path}`, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams(form).toString()
		})
	);
}

/**
 * @proves A token carries the issuer of the bucket that minted it, and an authorization server
 * reports a token it did not issue as inactive.
 */
describe('a token minted by a named bucket', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url);
		await seedBucket({
			bucketId: 'acme-bucket',
			slug: SLUG,
			clientId: 'acme-app',
			accountId: 'bob'
		});
	});

	afterAll(async () => {
		await clearSeededBuckets();
	});

	/*
	 * Minted through the real flow rather than constructed by hand: what is being proved is that the
	 * issuing bucket survives from the authorization request through the code to the token, and a
	 * hand-built token would skip every step that could lose it.
	 */
	async function accessTokenFrom(bucket: 'acme' | 'default') {
		const acme = bucket === 'acme';
		const prefix = acme ? `/${SLUG}` : '';
		const clientId = acme ? 'acme-app' : 'default-app';
		const redirect = acme
			? 'https://acme.example.com/cb'
			: 'https://default.example.com/cb';

		const cookie = await setup.login({
			accountId: acme ? 'bob' : 'ana',
			...(acme ? { bucketId: 'acme-bucket' } : {})
		});
		const auth = new AuthorizationRequest({
			client_id: clientId,
			scope: 'openid',
			redirect_uri: redirect
		});
		const query = jsonToFormUrlEncoded(auth.params);

		const authorized = await elysia.handle(
			new Request(`http://localhost${prefix}/auth?${query}`, {
				headers: { cookie }
			})
		);
		const code = new URL(
			authorized.headers.get('location') ?? ''
		).searchParams.get('code');
		expect(code).toBeTruthy();

		/* Through the suite's own exchange helper, which carries the PKCE verifier and whatever client
		 * authentication this client is configured for. */
		const { data } = await auth.getToken(
			present(code, 'an authorization code')
		);
		expect(data?.access_token).toBeTruthy();
		return { token: present(data?.access_token, 'an access token'), clientId };
	}

	async function introspect(at: string, clientId: string) {
		const response = await post('/token/introspect', {
			token: at,
			client_id: clientId
		});
		return shaped(
			Type.Object({
				active: Type.Boolean(),
				iss: Type.Optional(Type.String())
			}),
			await response.json()
		);
	}

	/*
	 * RFC 7662 §2.2: `active: true` asserts that *this* authorization server issued the token. Two
	 * buckets are two authorization servers, so a token of one presented to the other has to be
	 * inactive — otherwise a resource server is told a token from a different population is good, which
	 * is the realm-confusion defect reported against a Keycloak integration from the other end.
	 */
	it('is reported inactive by a bucket that did not issue it', async () => {
		const { token } = await accessTokenFrom('acme');

		expect(await introspect(token, 'default-app')).toMatchObject({
			active: false
		});
	});

	it('is reported active, with that address own issuer, by the bucket that issued it', async () => {
		const { token, clientId } = await accessTokenFrom('default');

		expect(await introspect(token, clientId)).toMatchObject({
			active: true,
			iss: ISSUER
		});
	});

	/*
	 * Introspected at the bucket's *own* endpoint, which is the address its metadata advertises and the
	 * one a client following discovery will use.
	 *
	 * The cases above introspect at the bare address, and they would keep passing even if every
	 * client-authenticated endpoint beneath a bucket resolved the wrong population — which is what
	 * happened: the shared client-authentication step built its context without reading the address, so
	 * `/acme/token/introspect` compared against the default bucket and reported acme's own tokens
	 * inactive. A token's issuer survives that, because it is inherited from the artifact rather than
	 * the address; the `active` answer does not.
	 */
	it('is reported active at the bucket own introspection endpoint', async () => {
		const cookie = await setup.login({
			accountId: 'bob',
			bucketId: 'acme-bucket'
		});
		const auth = new AuthorizationRequest({
			client_id: 'acme-app',
			scope: 'openid',
			redirect_uri: 'https://acme.example.com/cb'
		});
		const query = jsonToFormUrlEncoded(auth.params);
		const authorized = await elysia.handle(
			new Request(`http://localhost/${SLUG}/auth?${query}`, {
				headers: { cookie }
			})
		);
		const code = present(
			new URL(authorized.headers.get('location') ?? '').searchParams.get(
				'code'
			),
			'an authorization code'
		);

		const tokens = await post(`/${SLUG}/token`, {
			grant_type: 'authorization_code',
			code,
			redirect_uri: 'https://acme.example.com/cb',
			client_id: 'acme-app',
			code_verifier: auth.code_verifier
		});
		const body = shaped(
			Type.Object({
				access_token: Type.Optional(Type.String()),
				id_token: Type.Optional(Type.String())
			}),
			await tokens.json()
		);
		expect(body.access_token).toBeTruthy();

		const claims = shaped(
			Type.Object({ iss: Type.String() }),
			JSON.parse(
				Buffer.from(
					present(body.id_token, 'an ID token').split('.')[1],
					'base64url'
				).toString()
			)
		);
		expect(claims.iss).toBe(`${ISSUER}/${SLUG}`);

		const introspected = await post(`/${SLUG}/token/introspect`, {
			token: present(body.access_token, 'an access token'),
			client_id: 'acme-app'
		});
		expect(await introspected.json()).toMatchObject({
			active: true,
			iss: `${ISSUER}/${SLUG}`
		});
	});
});
