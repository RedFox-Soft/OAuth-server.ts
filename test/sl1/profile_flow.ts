import { Type } from '@sinclair/typebox';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';

import { agent, getHeader, type Setup } from '../test_helper.ts';
import { ISSUER } from 'lib/configs/env.ts';
import { shaped } from 'test/shape.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { send } from '../feature_gate/helpers.ts';

/*
 * The browser and token-endpoint steps the IPSIE SL1 specs share. Under the profile every token request carries a
 * DPoP proof, so the shared harness steps that exchange a code without one cannot be used here.
 */

export type KeyPair = Awaited<ReturnType<typeof generateKeyPair>>;

export const TokenBody = Type.Object({
	error: Type.Optional(Type.String()),
	error_description: Type.Optional(Type.String()),
	token_type: Type.Optional(Type.String()),
	access_token: Type.Optional(Type.String()),
	refresh_token: Type.Optional(Type.String()),
	id_token: Type.Optional(Type.String())
});

export function tokenRequest(
	body: Record<string, string>,
	{ client, secret, dpop }: { client: string; secret?: string; dpop?: string }
) {
	return send('/token', {
		method: 'POST',
		headers: {
			'content-type': 'application/x-www-form-urlencoded',
			...(secret
				? { authorization: `Basic ${btoa(`${client}:${secret}`)}` }
				: {}),
			...(dpop ? { dpop } : {})
		},
		body: new URLSearchParams(
			secret ? body : { client_id: client, ...body }
		).toString()
	});
}

export async function answer(res: Response) {
	return shaped(TokenBody, await res.json());
}

/*
 * A code for `client` from a signed-in session, as the browser hands it back. The caller takes the consent a
 * refresh token needs as given (`promptPending`), as test/refresh does.
 */
export async function codeFor(
	setup: Setup,
	client: string,
	{
		scope = 'openid offline_access',
		accountId
	}: { scope?: string; accountId?: string } = {}
) {
	const cookie = await setup.login({
		scope,
		...(accountId ? { accountId } : {})
	});
	const auth = new AuthorizationRequest({
		client_id: client,
		scope,
		prompt: 'consent'
	});
	const res = await agent.auth.get({ query: auth.params, headers: { cookie } });
	const location = new URL(getHeader(res.response, 'location'), ISSUER);
	const code = location.searchParams.get('code');
	if (!code) throw new Error(`no code in ${location.href}`);
	return { auth, code };
}

/* A code exchanged with a proof, for a client whose first registered redirect URI the request used. */
export async function signedIn(
	setup: Setup,
	keypair: KeyPair,
	{
		client,
		secret,
		accountId
	}: { client: string; secret?: string; accountId?: string }
) {
	const { auth, code } = await codeFor(setup, client, { accountId });
	return answer(
		await tokenRequest(
			{
				grant_type: 'authorization_code',
				code,
				code_verifier: auth.code_verifier,
				redirect_uri: auth.params.redirect_uri ?? ''
			},
			{ client, secret, dpop: await proof(keypair) }
		)
	);
}

/* A DPoP proof (RFC 9449 §4.2); `accessToken` adds the `ath` a resource request carries. */
export async function proof(
	keypair: KeyPair,
	{
		htu = `${ISSUER}/token`,
		htm = 'POST',
		accessToken
	}: { htu?: string; htm?: string; accessToken?: string } = {}
) {
	return new SignJWT({
		htu,
		htm,
		...(accessToken
			? {
					ath: new Bun.CryptoHasher('sha256')
						.update(accessToken)
						.digest('base64url')
				}
			: {})
	})
		.setProtectedHeader({
			alg: 'ES256',
			typ: 'dpop+jwt',
			jwk: await exportJWK(keypair.publicKey)
		})
		.setJti(crypto.randomUUID())
		.setIssuedAt()
		.sign(keypair.privateKey);
}
