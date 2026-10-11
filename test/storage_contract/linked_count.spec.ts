import { describe, it, expect, beforeAll } from 'bun:test';

import bootstrap from '../test_helper.js';
import { getBucketStore, getUserStore } from 'lib/adapters/index.js';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';

/**
 * @proves The number of people a provider's page says are linked to it counts exactly the accounts holding a
 * link to that provider — each once, however many links it holds — and nobody linked only elsewhere.
 */
describe('counting the accounts linked to a provider', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('counts the accounts linked to the provider and no other', async () => {
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'linked-count'
		});
		const store = getUserStore(bucket._id);
		const link = (providerId: string, sub: string) => ({
			providerId,
			sub,
			linkedAt: new Date()
		});
		const both = await store.create('both@acme.test', 'hash', true);
		await store.update(both._id, {
			federated: [link('acme', 'a-1'), link('other', 'o-1')]
		});
		const twice = await store.create('twice@acme.test', 'hash', true);
		await store.update(twice._id, {
			federated: [link('acme', 'a-2'), link('acme', 'a-3')]
		});
		const elsewhere = await store.create('elsewhere@acme.test', 'hash', true);
		await store.update(elsewhere._id, { federated: [link('other', 'o-2')] });
		await store.create('password@acme.test', 'hash', true);

		expect(await store.countLinkedTo('acme')).toBe(2);
		expect(await store.countLinkedTo('nobody')).toBe(0);
	});
});
