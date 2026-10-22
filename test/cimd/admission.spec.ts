import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it
} from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import { clearDocumentCache } from 'lib/client_metadata_document/cache.ts';
import { resolver } from 'lib/client_metadata_document/fetch.ts';
import { serveDocument, mock } from './document_host.js';

/*
 * What the authorization endpoint answers for a document a client hosts, as draft -02 shapes it: a document
 * that describes a public client is admitted whether or not it names an authentication method, and every
 * document the server will not honour is refused as an unknown client — never with a registration error code,
 * which means nothing to a browser arriving at `/auth`.
 */

const publicAddress = '93.184.216.34';
const REDIRECT = 'https://app.example.com/callback';

function authorize(clientId: string, redirectUri = REDIRECT) {
	return agent.auth.get({
		query: {
			client_id: clientId,
			response_type: 'code',
			redirect_uri: redirectUri,
			scope: 'openid',
			code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
			code_challenge_method: 'S256'
		}
	});
}

/* An unknown client is answered on the page, never redirected: its redirect targets are unverified. */
function refusalOf(response: Response): string | undefined {
	return (
		new URL(response.headers.get('location') ?? 'http://x/').searchParams.get(
			'error'
		) ?? undefined
	);
}

/**
 * @proves A document describing a public client is admitted at the authorization endpoint even when it names
 * no authentication method, and a document the server will not honour is refused as an unknown client.
 */
describe('a document presented at the authorization endpoint', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'cimd' });
	});

	beforeEach(() => {
		clearDocumentCache();
		resolver.lookup = async () => [publicAddress];
	});

	afterEach(() => {
		mock.restore();
		resolver.lookup = resolver.realLookup;
	});

	it('admits a document naming no authentication method, sending the end user on to sign in', async () => {
		const { identifier } = serveDocument({
			overrides: { token_endpoint_auth_method: undefined }
		});

		const { response } = await authorize(identifier);

		expect(response.status).toBe(303);
		expect(response.headers.get('location')).toStartWith('/ui/');
	});

	it('refuses as an unknown client a document that fails the general client rules', async () => {
		const { identifier } = serveDocument({
			overrides: { id_token_signed_response_alg: 'HS256' }
		});

		const { response, error } = await authorize(identifier);

		expect(response.status).toBe(400);
		expect(refusalOf(response) ?? error?.value).toMatchObject({
			error: 'invalid_client'
		});
	});

	/* RFC 8252 §7.3: a desktop or command-line client binds its port when the sign-in starts, not before. */
	it('lets a native document client come back on any loopback port', async () => {
		const { identifier } = serveDocument({
			overrides: {
				application_type: 'native',
				redirect_uris: ['http://127.0.0.1:3000/callback']
			}
		});

		const { response } = await authorize(
			identifier,
			'http://127.0.0.1:51234/callback'
		);

		expect(response.status).toBe(303);
		expect(response.headers.get('location')).toStartWith('/ui/');
	});

	it('refuses as an unknown client a document whose redirect is plain http on a host that is not loopback', async () => {
		const { identifier } = serveDocument({
			overrides: { redirect_uris: ['http://intranet.example/callback'] }
		});

		const { response, error } = await authorize(
			identifier,
			'http://intranet.example/callback'
		);

		expect(response.status).toBe(400);
		expect(refusalOf(response) ?? error?.value).toMatchObject({
			error: 'invalid_client'
		});
	});

	it('refuses as an unknown client a document whose key set address is plain http', async () => {
		const { identifier } = serveDocument({
			overrides: {
				token_endpoint_auth_method: 'private_key_jwt',
				jwks_uri: 'http://app.example.com/jwks.json'
			}
		});

		const { response, error } = await authorize(identifier);

		expect(response.status).toBe(400);
		expect(refusalOf(response) ?? error?.value).toMatchObject({
			error: 'invalid_client'
		});
	});
});
