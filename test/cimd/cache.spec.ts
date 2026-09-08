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
import {
	clearDocumentCache,
	reuseSecondsFor,
	MIN_CACHE_SECONDS,
	MAX_CACHE_SECONDS,
	DEFAULT_CACHE_SECONDS
} from 'lib/client_metadata_document/cache.ts';
import { resolver } from 'lib/client_metadata_document/fetch.ts';
import { serveDocument, mock } from './document_host.js';

/*
 * How long a retrieved document may be reused, and the two things that must never be remembered.
 *
 * Reuse is proved by exhaustion rather than by counting calls: the fetch mock consumes an interceptor
 * on first match, so registering exactly one document and resolving twice succeeds only if the second
 * resolution never reached the network.
 */

const publicAddress = '93.184.216.34';

describe('reuse window taken from the document host', () => {
	it('honours max-age within our own bounds', () => {
		expect(reuseSecondsFor('max-age=300', null)).toBe(300);
	});

	it('clamps a window shorter than the floor', () => {
		expect(reuseSecondsFor('max-age=1', null)).toBe(MIN_CACHE_SECONDS);
	});

	/*
	 * A host asking for a year must not be able to make a stale copy authoritative: the document is
	 * how a client's redirect targets are known, and those change.
	 */
	it('clamps a window longer than the ceiling', () => {
		expect(reuseSecondsFor('max-age=31536000', null)).toBe(MAX_CACHE_SECONDS);
	});

	/*
	 * Treated as "the shortest reuse we allow" rather than as zero. A document is not a private
	 * response, and honouring it literally would turn one sign-in into a chain of outbound requests.
	 */
	it('treats no-store and no-cache as the floor, not as zero', () => {
		expect(reuseSecondsFor('no-store', null)).toBe(MIN_CACHE_SECONDS);
		expect(reuseSecondsFor('private, no-cache', null)).toBe(MIN_CACHE_SECONDS);
	});

	it('falls back to Expires when there is no cache-control', () => {
		const now = Date.now();
		const at = new Date(now + 600_000).toUTCString();

		expect(reuseSecondsFor(null, at, now)).toBeGreaterThanOrEqual(
			MIN_CACHE_SECONDS
		);
		expect(reuseSecondsFor(null, at, now)).toBeLessThanOrEqual(600);
	});

	it('applies a default when the host says nothing', () => {
		expect(reuseSecondsFor(null, null)).toBe(DEFAULT_CACHE_SECONDS);
	});

	it('ignores an unparseable Expires rather than trusting it', () => {
		expect(reuseSecondsFor(null, 'whenever')).toBe(DEFAULT_CACHE_SECONDS);
	});
});

describe('reusing a retrieved document', () => {
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

	it('resolves a second time without going back to the host', async () => {
		const { identifier } = serveDocument({
			headers: { 'cache-control': 'max-age=300' }
		});

		expect(await tryFindClient(identifier)).toBeDefined();
		/* One interceptor was registered and consumed; a second retrieval would throw. */
		expect(await tryFindClient(identifier)).toBeDefined();
	});

	/*
	 * The draft forbids caching an error response, and this is why it matters: a transient outage must
	 * not be pinned in front of a document that works.
	 */
	it('never remembers a failure, so a recovered host is reachable at once', async () => {
		mock('https://app.example.com')
			.intercept({ path: '/oauth/client-metadata.json' })
			.reply(503, 'unavailable');

		expect(
			await tryFindClient('https://app.example.com/oauth/client-metadata.json')
		).toBeUndefined();

		mock.restore();
		resolver.lookup = async () => [publicAddress];
		const { identifier } = serveDocument();

		expect(await tryFindClient(identifier)).toBeDefined();
	});

	/*
	 * The same rule for a document that arrived intact and proved invalid. One malformed document,
	 * served once, must not be able to keep a client out for the life of a cache entry.
	 */
	it('never remembers an invalid document', async () => {
		serveDocument({ rawBody: '{ not json' });

		expect(
			await tryFindClient('https://app.example.com/oauth/client-metadata.json')
		).toBeUndefined();

		mock.restore();
		resolver.lookup = async () => [publicAddress];
		const { identifier } = serveDocument();

		expect(await tryFindClient(identifier)).toBeDefined();
	});
});
