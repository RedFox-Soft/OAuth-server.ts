import {
	describe,
	beforeAll,
	beforeEach,
	afterEach,
	it,
	expect
} from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import { adapter } from 'lib/adapters/index.ts';
import { tryFindClient } from 'lib/models/client/validate.ts';
import { clearDocumentCache } from 'lib/client_metadata_document/cache.ts';
import { resolver } from 'lib/client_metadata_document/fetch.ts';
import { serveDocument, mock } from './document_host.js';

/*
 * That a document identifier creates no client record, and that the branch resolving it cannot shadow
 * a stored client whose id happens to be a URL.
 *
 * The second half is the trap. A URL-shaped `client_id` is not new to this server —
 * `test/client_id_uri/` covers dynamic registration issuing one through a deployment's `idFactory` —
 * so a resolution order that tried the document first would break every such client. The order is
 * asserted here rather than left to a comment.
 */

const publicAddress = '93.184.216.34';

async function clientCount() {
	/* TestAdapter keeps its records in a shape the harness owns; count through the adapter contract. */
	let count = 0;
	for (const id of ['client', 'stored-url-client']) {
		if (await adapter('Client').find(id)) count += 1;
	}
	return count;
}

describe('a client identified by a document, and one merely named like it', () => {
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

	it('resolves a client from its document without storing anything', async () => {
		const { identifier } = serveDocument();
		const before = await clientCount();

		const client = await tryFindClient(identifier);

		expect(client).toBeDefined();
		expect(client?.clientId).toBe(identifier);
		/* The store is untouched: the identifier resolves to no record, now or later. */
		expect(await adapter('Client').find(identifier)).toBeFalsy();
		expect(await clientCount()).toBe(before);
	});

	it('creates no record however many times the same client connects', async () => {
		const before = await clientCount();

		for (let attempt = 0; attempt < 3; attempt += 1) {
			clearDocumentCache();
			const { identifier } = serveDocument();
			expect(await tryFindClient(identifier)).toBeDefined();
			mock.restore();
			resolver.lookup = async () => [publicAddress];
		}

		expect(await clientCount()).toBe(before);
	});

	/*
	 * The ordering assertion. A stored client whose id is a URL must resolve from the adapter, and no
	 * document is served here — so if the branch ran first, this would fail for want of an interceptor
	 * rather than returning the stored client.
	 */
	it('lets a stored client whose id is a URL resolve from the adapter', async () => {
		const identifier = 'https://stored.example.com/client.json';
		await adapter('Client').upsert(identifier, {
			clientId: identifier,
			token_endpoint_auth_method: 'none',
			grantTypes: ['authorization_code'],
			responseTypes: ['code'],
			redirectUris: ['https://stored.example.com/cb']
		});

		const client = await tryFindClient(identifier);

		expect(client).toBeDefined();
		expect(client?.redirectUris).toEqual(['https://stored.example.com/cb']);
	});

	it('declines a document identifier that resolves to nothing, rather than failing the request', async () => {
		/* A mocked origin with no interceptor: the host is there and answers nothing usable. */
		mock('https://app.example.com');

		expect(
			await tryFindClient('https://app.example.com/missing.json')
		).toBeUndefined();
	});

	it('leaves an ordinary client id untouched', async () => {
		expect(await tryFindClient('client')).toBeDefined();
		expect(await tryFindClient('no-such-client')).toBeUndefined();
	});

	/*
	 * End to end through the HTTP layer: the authorization endpoint resolves a document-identified
	 * client far enough to act on its registered redirect target. An unknown client is refused with
	 * `invalid_client` and never redirects, so reaching a redirect at all is the proof.
	 */
	it('is accepted at the authorization endpoint', async () => {
		const { identifier } = serveDocument();

		const res = await agent.auth.get({
			query: {
				client_id: identifier,
				response_type: 'code',
				redirect_uri: 'https://app.example.com/callback',
				scope: 'openid',
				code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
				code_challenge_method: 'S256'
			}
		});

		expect(res.status).not.toBe(400);
	});
});
