import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap, { jsonToFormUrlEncoded, type Setup } from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { ISSUER } from 'lib/configs/env.js';
import { AccessToken } from 'lib/models/access_token.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { Type } from '@sinclair/typebox';
import { present, shaped } from 'test/shape.js';

async function get(path: string) {
	return elysia.handle(new Request(`http://localhost${path}`));
}

/**
 * @proves A deployment that had no tenants keeps the issuer, the endpoints and the tokens it had, so
 * nothing integrated before buckets became tenants has to be reconfigured.
 */
describe('a deployment upgraded to per-bucket issuers', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url);
	});

	/*
	 * The compatibility promise, asserted as the property it actually is rather than against a recorded
	 * copy of the document: an issuer identifier is a promise already made, and every endpoint hanging
	 * off it unprefixed is what "nothing moved" means. A snapshot would also pass if the whole document
	 * moved together.
	 */
	it('declares the instance issuer and unprefixed endpoints at the bare well-known location', async () => {
		const doc = shaped(
			Type.Record(Type.String(), Type.Unknown()),
			await (await get('/.well-known/openid-configuration')).json()
		);

		expect(doc.issuer).toBe(ISSUER);
		for (const [member, value] of Object.entries(doc)) {
			if (!member.endsWith('_endpoint') && member !== 'jwks_uri') continue;
			if (typeof value !== 'string') continue;
			expect(new URL(value).origin).toBe(new URL(ISSUER).origin);
			expect(value.startsWith(`${ISSUER}/`)).toBe(true);
		}
	});

	it('serves the OAuth metadata document at the bare well-known location too', async () => {
		const response = await get('/.well-known/oauth-authorization-server');

		expect(response.status).toBe(200);
		expect(
			shaped(Type.Object({ issuer: Type.String() }), await response.json())
				.issuer
		).toBe(ISSUER);
	});

	/*
	 * A token minted before this feature carries no record of an issuing bucket, because the field did
	 * not exist. Reading that absence as the default bucket is not a fallback — the default bucket's
	 * issuer *is* the bare one those tokens were minted with — and it is what keeps every token in
	 * circulation valid across the upgrade rather than turning a deployment into a flag day.
	 */
	it('accepts a token that records no issuing bucket, as the instance own', async () => {
		const cookie = await setup.login({ accountId: 'ana' });
		const auth = new AuthorizationRequest({
			client_id: 'default-app',
			scope: 'openid',
			redirect_uri: 'https://default.example.com/cb'
		});
		const query = jsonToFormUrlEncoded(auth.params);
		const authorized = await elysia.handle(
			new Request(`http://localhost/auth?${query}`, { headers: { cookie } })
		);
		const code = present(
			new URL(authorized.headers.get('location') ?? '').searchParams.get(
				'code'
			),
			'an authorization code'
		);
		const { data } = await auth.getToken(code);
		const token = present(data?.access_token, 'an access token');

		/* Aged back to what a pre-upgrade record looks like: the field simply absent. */
		const stored = await AccessToken.find(token);
		delete stored.payload.bucketId;
		await stored.save();

		const response = await elysia.handle(
			new Request('http://localhost/token/introspect', {
				method: 'POST',
				headers: { 'content-type': 'application/x-www-form-urlencoded' },
				body: new URLSearchParams({
					token,
					client_id: 'default-app'
				}).toString()
			})
		);

		expect(await response.json()).toMatchObject({
			active: true,
			iss: ISSUER
		});
	});
});
