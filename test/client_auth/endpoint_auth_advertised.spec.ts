import { createPrivateKey, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { importJWK } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'bun:test';

import nanoid from '../../lib/helpers/nanoid.ts';
import * as JWT from '../../lib/helpers/jwt.ts';
import bootstrap, { agent } from '../test_helper.js';
import clientKey from '../client.sig.key.js';
import { ApplicationConfig } from 'lib/configs/application.js';
import { ISSUER } from 'lib/configs/env.js';
import { elysia } from 'lib/index.js';
import { Client, clientKeys } from 'lib/models/client.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { present } from 'test/shape.js';

const rsacrt = new X509Certificate(
	readFileSync('test/jwks/rsa.crt', { encoding: 'ascii' })
);

type Credential = {
	body: Record<string, string>;
	headers: Record<string, string>;
};

const JWT_BEARER = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

async function assertion(
	clientId: string,
	key: Parameters<typeof JWT.sign>[1],
	alg: string
) {
	return JWT.sign(
		{ jti: nanoid(), aud: ISSUER, sub: clientId, iss: clientId },
		key,
		alg,
		{ expiresIn: 60 }
	);
}

/*
 * One credential per authentication method, for a client of client_auth.config.ts registered for it.
 * A method the document advertises that is missing here fails the test rather than being skipped:
 * the claim is "every advertised method works", and an unexercised method would pass it vacuously.
 */
const credentials: Partial<Record<string, () => Promise<Credential>>> = {
	none: async () => ({ body: { client_id: 'client-none' }, headers: {} }),
	client_secret_basic: async () => ({
		body: {},
		headers: AuthorizationRequest.basicAuthHeader('client-basic', 'secret')
	}),
	client_secret_post: async () => ({
		body: { client_id: 'client-post', client_secret: 'secret' },
		headers: {}
	}),
	client_secret_jwt: async () => {
		const key = await importJWK(
			clientKeys(
				await Client.find('client-jwt-secret')
			).symmetric.selectForSign({
				alg: 'HS256'
			})[0]
		);
		return {
			body: {
				client_assertion: await assertion('client-jwt-secret', key, 'HS256'),
				client_assertion_type: JWT_BEARER
			},
			headers: {}
		};
	},
	private_key_jwt: async () => ({
		body: {
			client_assertion: await assertion(
				'client-jwt-key',
				createPrivateKey({ format: 'jwk', key: clientKey }),
				'RS256'
			),
			client_assertion_type: JWT_BEARER
		},
		headers: {}
	}),
	tls_client_auth: async () => ({
		body: { client_id: 'client-pki-mtls' },
		headers: {
			'x-ssl-client-cert': rsacrt.raw.toString('base64'),
			'x-ssl-client-verify': 'SUCCESS',
			'x-ssl-client-san-dns': 'rp.example.com'
		}
	}),
	self_signed_tls_client_auth: async () => ({
		body: { client_id: 'client-self-signed-mtls' },
		headers: { 'x-ssl-client-cert': rsacrt.raw.toString('base64') }
	})
};

async function authenticateAt(path: string, method: string) {
	const credential = credentials[method];
	if (!credential) {
		throw new Error(`no client in client_auth.config.ts exercises ${method}`);
	}
	const { body, headers } = await credential();
	return elysia.handle(
		new Request(`${ISSUER}${path}`, {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
				...headers
			},
			body: new URLSearchParams({ token: 'foo', ...body })
		})
	);
}

/**
 * @proves A client that authenticates to introspection or revocation with any method the metadata
 * advertises for that endpoint is accepted — the document names no method the endpoint refuses.
 */
describe('the authentication methods advertised for introspection and revocation', () => {
	let document: Record<string, unknown>;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'client_auth' });
		ApplicationConfig['revocation.enabled'] = true;
		const { data } = await agent['.well-known']['openid-configuration'].get();
		document = present(data, 'the discovery document');
	});

	afterAll(() => {
		ApplicationConfig['revocation.enabled'] = false;
	});

	for (const [member, path] of [
		['introspection_endpoint_auth_methods_supported', '/token/introspect'],
		['revocation_endpoint_auth_methods_supported', '/token/revocation']
	] as const) {
		it(`each authenticate a client at ${path}`, async () => {
			const advertised = document[member];
			expect(Array.isArray(advertised) && advertised.length > 0).toBe(true);

			for (const method of advertised as string[]) {
				const res = await authenticateAt(path, method);
				expect({ method, status: res.status }).toEqual({ method, status: 200 });
			}
		});
	}
});
