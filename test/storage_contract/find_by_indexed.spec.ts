import { describe, it, beforeAll, expect } from 'bun:test';

import bootstrap from '../test_helper.js';
import { adapter } from 'lib/adapters/index.ts';

/**
 * @proves A bucket's applications are listed by the field they are stored with (specs/099), and a listing
 * by a field the area declares no index on is refused before any query — a caller-chosen name never
 * reaches the datastore, and a listing is never a scan.
 */
describe('storage contract: listing a model area by an indexed field', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('lists exactly the clients that belong to a bucket', async () => {
		await adapter('Client').upsert('fbi-a', {
			clientId: 'fbi-a',
			bucketId: 'fbi-one'
		});
		await adapter('Client').upsert('fbi-b', {
			clientId: 'fbi-b',
			bucketId: 'fbi-two'
		});

		const listed = await adapter('Client').findByIndexed('bucketId', 'fbi-one');

		expect(listed.map((record) => record.clientId)).toEqual(['fbi-a']);
	});

	it('refuses a listing by a field with no declared index', async () => {
		await expect(
			adapter('Client').findByIndexed('clientName', 'anything')
		).rejects.toThrow(/declares no index on payload\.clientName/);
	});
});
