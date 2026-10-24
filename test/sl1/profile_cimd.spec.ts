import { describe, it, expect, beforeAll, afterEach } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { clearDocumentCache } from 'lib/client_metadata_document/cache.ts';
import { resolver } from 'lib/client_metadata_document/fetch.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { documentFor, mock } from '../cimd/document_host.ts';
import { PRE_REGISTERED } from './profile_cimd.config.ts';

const DOCUMENT = 'https://app.example.com/oauth/client-metadata.json';

/**
 * @proves Under the IPSIE SL1 profile a client id that is a URL is served only from a record an administrator stored
 * under it: an unknown one is refused without this server fetching anything.
 */
describe('a URL client id under the IPSIE SL1 profile', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'profile_cimd' });
	});

	afterEach(() => {
		mock.restore();
		resolver.lookup = resolver.realLookup;
		clearDocumentCache();
	});

	it('refuses an unknown one as an unknown client, fetching no document', async () => {
		resolver.lookup = async () => ['93.184.216.34'];
		const served = mock('https://app.example.com')
			.intercept({ path: '/oauth/client-metadata.json' })
			.reply(200, JSON.stringify(documentFor(DOCUMENT)), {
				headers: { 'content-type': 'application/json' }
			});

		const res = await new AuthorizationRequest({
			client_id: DOCUMENT,
			redirect_uri: 'https://app.example.com/callback',
			scope: 'openid'
		}).authorize();

		expect(res.status).toBe(400);
		expect(await res.text()).toContain('invalid_client');
		expect(served.consumed).toBe(false);
	});

	it('accepts one an administrator stored under the URL', async () => {
		const res = await new AuthorizationRequest({
			client_id: PRE_REGISTERED,
			scope: 'openid'
		}).authorize();

		expect(res.status).toBe(303);
		expect(res.headers.get('location')).toContain('/ui/');
	});
});
