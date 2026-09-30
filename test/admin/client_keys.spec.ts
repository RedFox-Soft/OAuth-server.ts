import { createPrivateKey } from 'node:crypto';

import { describe, it, expect, beforeAll } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.js';
import clientKey from '../client.sig.key.js';
import { send } from '../feature_gate/helpers.js';
import { superAdminCookie } from '../settings_apply/helpers.js';
import { shaped } from '../shape.js';
import * as JWT from 'lib/helpers/jwt.ts';
import nanoid from 'lib/helpers/nanoid.js';
import { ISSUER } from 'lib/configs/env.js';
import { getProjectStore } from 'lib/adapters/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';

const {
	d: _d,
	p: _p,
	q: _q,
	dp: _dp,
	dq: _dq,
	qi: _qi,
	...publicKey
} = clientKey as Record<string, string>;
const privateKey = createPrivateKey({ format: 'jwk', key: clientKey });

const ClientView = Type.Object({
	clientId: Type.String(),
	tokenEndpointAuthMethod: Type.String(),
	jwks: Type.Optional(Type.Unknown()),
	jwksUri: Type.Optional(Type.String()),
	requirePushedAuthorizationRequests: Type.Optional(Type.Boolean()),
	dpopBoundAccessTokens: Type.Optional(Type.Boolean()),
	requireSignedRequestObject: Type.Optional(Type.Boolean()),
	requestObjectSigningAlg: Type.Optional(Type.String()),
	idTokenSignedResponseAlg: Type.Optional(Type.String()),
	authorizationSignedResponseAlg: Type.Optional(Type.String()),
	backchannelLogoutUri: Type.Optional(Type.String()),
	backchannelLogoutSessionRequired: Type.Optional(Type.Boolean())
});

let cookie: string;
let projectId: string;

function json(method: string, path: string, body?: unknown) {
	return send(path, {
		method,
		headers: { cookie, 'content-type': 'application/json' },
		body: body === undefined ? undefined : JSON.stringify(body)
	});
}

async function createClient(body: Record<string, unknown>) {
	return json('POST', `/admin/api/projects/${projectId}/clients`, body);
}

async function created(body: Record<string, unknown>) {
	const res = await createClient(body);
	expect(res.status).toBe(201);
	return shaped(ClientView, await res.json());
}

/**
 * @proves An operator registers from the management API a client that authenticates with its own
 * key and demands the request protections FAPI asks of it, the server enforces what was registered,
 * and a key set carrying private key material is refused.
 */
describe('a key-authenticated client registered by an operator', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'client_keys' });
		cookie = await superAdminCookie();
		projectId = (
			await getProjectStore().create({
				name: 'Keys',
				slug: `keys-${nanoid()}`,
				ownerGroupId: UNASSIGNED_GROUP_ID
			})
		)._id;
	});

	it('is issued a token for an assertion signed with the key it was registered with', async () => {
		const client = await created({
			grantTypes: ['client_credentials'],
			tokenEndpointAuthMethod: 'private_key_jwt',
			jwks: { keys: [publicKey] }
		});

		const assertion = await JWT.sign(
			{
				jti: nanoid(),
				aud: ISSUER,
				sub: client.clientId,
				iss: client.clientId
			},
			privateKey,
			'RS256',
			{ expiresIn: 60 }
		);
		const res = await send('/token', {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({
				grant_type: 'client_credentials',
				client_assertion_type:
					'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
				client_assertion: assertion
			}).toString()
		});

		expect(res.status).toBe(200);
	});

	it('refuses a key set carrying private key material', async () => {
		const res = await createClient({
			grantTypes: ['client_credentials'],
			tokenEndpointAuthMethod: 'private_key_jwt',
			jwks: { keys: [clientKey] }
		});

		expect(res.status).toBe(422);
	});

	/*
	 * Through the composed server, not the admin routes mounted alone: a metadata refusal is a protocol
	 * error class, and on its way out it reached the OAuth error handler first — the console received
	 * 400 in the protocol's shape, with no `message` to show. wiki/concepts/admin-plane-error-shape.md
	 * records the same fault for the admin plane's own errors.
	 */
	it('answers a refused registration in the admin plane’s shape', async () => {
		const res = await createClient({
			grantTypes: ['authorization_code'],
			tokenEndpointAuthMethod: 'none',
			redirectUris: ['not a url']
		});

		expect(res.status).toBe(422);
		expect(
			shaped(
				Type.Object({ error: Type.String(), message: Type.String() }),
				await res.json()
			)
		).toMatchObject({ error: 'admin_error' });
	});

	it('reports the request protections it was registered with', async () => {
		const client = await created({
			grantTypes: ['authorization_code'],
			redirectUris: ['https://rp.example.test/cb'],
			tokenEndpointAuthMethod: 'private_key_jwt',
			jwks: { keys: [publicKey] },
			requirePushedAuthorizationRequests: true,
			dpopBoundAccessTokens: true,
			requireSignedRequestObject: true,
			requestObjectSigningAlg: 'RS256',
			idTokenSignedResponseAlg: 'RS256',
			authorizationSignedResponseAlg: 'RS256',
			backchannelLogoutUri: 'https://rp.example.test/logout',
			backchannelLogoutSessionRequired: true
		});

		expect(client).toMatchObject({
			requirePushedAuthorizationRequests: true,
			dpopBoundAccessTokens: true,
			requireSignedRequestObject: true,
			requestObjectSigningAlg: 'RS256',
			idTokenSignedResponseAlg: 'RS256',
			authorizationSignedResponseAlg: 'RS256',
			backchannelLogoutUri: 'https://rp.example.test/logout',
			backchannelLogoutSessionRequired: true
		});
	});

	it('is refused an authorization request it did not push when pushing was required of it', async () => {
		const client = await created({
			grantTypes: ['authorization_code'],
			redirectUris: ['https://rp.example.test/cb'],
			tokenEndpointAuthMethod: 'private_key_jwt',
			jwks: { keys: [publicKey] },
			requirePushedAuthorizationRequests: true
		});

		const query = new URLSearchParams({
			client_id: client.clientId,
			response_type: 'code',
			scope: 'openid',
			redirect_uri: 'https://rp.example.test/cb',
			code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
			code_challenge_method: 'S256'
		});
		const res = await send(`/auth?${query}`, { method: 'GET' });

		const location = res.headers.get('location');
		expect(location).not.toBeNull();
		expect(new URL(location ?? '').searchParams.get('error')).toBe(
			'invalid_request'
		);
	});

	it('replaces a key set location with an inline key set on an edit', async () => {
		const client = await created({
			grantTypes: ['client_credentials'],
			tokenEndpointAuthMethod: 'private_key_jwt',
			jwksUri: 'https://rp.example.test/jwks'
		});

		const res = await json(
			'PATCH',
			`/admin/api/projects/${projectId}/clients/${client.clientId}`,
			{ jwksUri: null, jwks: { keys: [publicKey] } }
		);

		expect(res.status).toBe(200);
		const edited = shaped(ClientView, await res.json());
		expect(edited.jwksUri).toBeUndefined();
		expect(edited.jwks).toEqual({ keys: [publicKey] });
	});
});
