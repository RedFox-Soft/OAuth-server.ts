import {
	describe,
	beforeAll,
	beforeEach,
	afterEach,
	it,
	expect
} from 'bun:test';

import bootstrap from '../test_helper.js';
import { tryFindClient } from 'lib/models/client/validate.ts';
import { clearDocumentCache } from 'lib/client_metadata_document/cache.ts';
import { resolver } from 'lib/client_metadata_document/fetch.ts';
import { serveDocument, mock } from './document_host.js';

const publicAddress = '93.184.216.34';
const SECTOR = 'https://sector.example.com';

/**
 * @proves A client described by a document is held to its sector identifier document when it is
 * resolved, because a document client is never stored and its resolution is its registration.
 */
describe('a pairwise client identified by a document', () => {
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

	it('is refused when its sector identifier document does not list its redirect URIs', async () => {
		const { identifier } = serveDocument({
			overrides: {
				subject_type: 'pairwise',
				sector_identifier_uri: `${SECTOR}/sector.json`
			}
		});
		mock(SECTOR)
			.intercept({ path: '/sector.json' })
			.reply(200, JSON.stringify(['https://elsewhere.example.com/cb']), {
				headers: { 'content-type': 'application/json' }
			});

		await expect(tryFindClient(identifier)).rejects.toMatchObject({
			error_description:
				'all registered redirectUris must be included in the sector_identifier_uri response'
		});
	});
});
