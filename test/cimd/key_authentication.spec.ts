import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	spyOn
} from 'bun:test';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';

import bootstrap, { type Setup } from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { ISSUER } from 'lib/configs/env.js';
import { clearDocumentCache } from 'lib/client_metadata_document/cache.ts';
import { resolver } from 'lib/client_metadata_document/fetch.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { decide, openConsent } from '../consent_page/flow.ts';
import { codeOf } from '../consent_choices/rows.ts';
import { assertNoPendingInterceptors } from '../fetch_mock.js';
import { present } from 'test/shape.js';
import { mock, serveDocument } from './document_host.js';

/*
 * Draft -02 §8.2: "When a client declares token_endpoint_auth_method as private_key_jwt, the authorization
 * server MUST require client authentication … using the corresponding key discovered from the client's
 * metadata document." The key comes from the document and nowhere else, and fetching it is held to the same
 * address rules as fetching the document (§8.6).
 */

const publicAddress = '93.184.216.34';
const REDIRECT = 'https://app.example.com/callback';
const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

/**
 * @proves A document client that declares a key authenticates at the token endpoint only with an assertion
 * signed by the key its document publishes, and a key set address on a reserved range is never fetched.
 */
describe('a document client that authenticates with a private key', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'cimd' });
	});

	beforeEach(() => {
		clearDocumentCache();
		resolver.lookup = async () => [publicAddress];
	});

	afterEach(() => {
		mock.restore();
		resolver.lookup = resolver.realLookup;
	});

	/* A fresh sign-in each time: a consent decision rotates the session it was made in. */
	async function codeFor(identifier: string) {
		const cookie = await setup.login({ scope: 'openid' });
		const page = await openConsent(
			{ client_id: identifier, scope: 'openid', redirect_uri: REDIRECT },
			cookie
		);
		const decided = await decide(page, 'allow');
		return { code: codeOf(decided), auth: page.auth };
	}

	function redeem(form: Record<string, string>) {
		return elysia.handle(
			new Request(`${ISSUER}/token`, {
				method: 'POST',
				headers: { 'content-type': 'application/x-www-form-urlencoded' },
				body: new URLSearchParams(form).toString()
			})
		);
	}

	async function keyedDocument() {
		const { publicKey, privateKey } = await generateKeyPair('ES256');
		const jwk = { ...(await exportJWK(publicKey)), alg: 'ES256', use: 'sig' };
		const { identifier } = serveDocument({
			overrides: {
				redirect_uris: [REDIRECT],
				token_endpoint_auth_method: 'private_key_jwt',
				token_endpoint_auth_signing_alg: 'ES256',
				jwks: { keys: [jwk] }
			}
		});
		return { identifier, privateKey };
	}

	it('refuses a client that declares a key and presents no assertion', async () => {
		const { identifier } = await keyedDocument();
		const { code, auth } = await codeFor(identifier);

		const response = await redeem({
			grant_type: 'authorization_code',
			client_id: identifier,
			code,
			code_verifier: present(auth.code_verifier, 'a PKCE verifier'),
			redirect_uri: REDIRECT
		});

		expect(response.status).toBe(401);
		expect(await response.json()).toMatchObject({ error: 'invalid_client' });
	});

	it('serves a client that presents an assertion signed with its published key', async () => {
		const { identifier, privateKey } = await keyedDocument();
		const { code, auth } = await codeFor(identifier);
		const assertion = await new SignJWT({ jti: nanoid() })
			.setProtectedHeader({ alg: 'ES256' })
			.setIssuer(identifier)
			.setSubject(identifier)
			.setAudience(`${ISSUER}/token`)
			.setIssuedAt()
			.setExpirationTime('1m')
			.sign(privateKey);

		const response = await redeem({
			grant_type: 'authorization_code',
			code,
			code_verifier: present(auth.code_verifier, 'a PKCE verifier'),
			redirect_uri: REDIRECT,
			client_assertion_type: ASSERTION_TYPE,
			client_assertion: assertion
		});

		expect(response.status).toBe(200);
	});

	it('refuses a client whose key set address resolves to a reserved range, without fetching it', async () => {
		spyOn(resolver, 'lookup').mockImplementation(async (host: string) =>
			host === 'keys.internal.example' ? ['10.0.0.1'] : [publicAddress]
		);
		const { privateKey } = await generateKeyPair('ES256');
		const { identifier } = serveDocument({
			overrides: {
				redirect_uris: [REDIRECT],
				token_endpoint_auth_method: 'private_key_jwt',
				token_endpoint_auth_signing_alg: 'ES256',
				jwks_uri: 'https://keys.internal.example/jwks.json'
			}
		});
		mock('https://keys.internal.example')
			.intercept({ path: '/jwks.json' })
			.reply(200, '{"keys":[]}', {
				headers: { 'content-type': 'application/json' }
			});
		const { code, auth } = await codeFor(identifier);
		const assertion = await new SignJWT({ jti: nanoid() })
			.setProtectedHeader({ alg: 'ES256' })
			.setIssuer(identifier)
			.setSubject(identifier)
			.setAudience(`${ISSUER}/token`)
			.setIssuedAt()
			.setExpirationTime('1m')
			.sign(privateKey);

		const response = await redeem({
			grant_type: 'authorization_code',
			code,
			code_verifier: present(auth.code_verifier, 'a PKCE verifier'),
			redirect_uri: REDIRECT,
			client_assertion_type: ASSERTION_TYPE,
			client_assertion: assertion
		});

		expect(response.status).toBe(401);
		expect(await response.json()).toMatchObject({ error: 'invalid_client' });
		expect(() => assertNoPendingInterceptors()).toThrow(
			'https://keys.internal.example/jwks.json'
		);
	});
});
