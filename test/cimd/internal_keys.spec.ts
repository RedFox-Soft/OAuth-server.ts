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
import { present } from 'test/shape.js';
import { serveDocument, mock } from './document_host.js';

/*
 * A client description document is written by whoever hosts it, so everything in it is the
 * attacker's choice. Only the snake_case wire metadata may speak for the client: a document that also
 * carried the model's canonical attribute names could otherwise claim a stored client's id, keep a
 * shared secret the draft forbids, or switch off the consent screen that is the only defence a
 * document-identified client leaves the End-User.
 */

const publicAddress = '93.184.216.34';

async function resolveServed(overrides: Record<string, unknown>) {
	const { identifier } = serveDocument({ overrides });
	return {
		identifier,
		client: present(await tryFindClient(identifier), 'a resolved client')
	};
}

/**
 * @proves A document-identified client is always the client its URL names, never holds a shared
 * secret and never skips consent, whatever internal attribute names its document carries.
 */
describe('a client document naming internal client attributes', () => {
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

	it('resolves to the identifier it was fetched from when it claims a stored client id', async () => {
		const { identifier, client } = await resolveServed({ clientId: 'client' });

		expect(client.clientId).toBe(identifier);
	});

	it('carries no secret when it supplies one under the internal key', async () => {
		const { client } = await resolveServed({ clientSecret: 'chosen-by-host' });

		expect(client.clientSecret).toBeUndefined();
	});

	it('keeps the consent screen when it asks to skip it', async () => {
		const { client } = await resolveServed({ 'consent.require': false });

		expect(client['consent.require']).not.toBe(false);
	});
});
