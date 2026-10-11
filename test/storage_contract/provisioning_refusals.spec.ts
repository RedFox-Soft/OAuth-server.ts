import { describe, it, expect, beforeAll } from 'bun:test';

import bootstrap from '../test_helper.js';
import { ProvisioningRefusalStore } from 'lib/adapters/memory/index.js';
import type { ProvisioningRefusalInput } from 'lib/adapters/types.js';

/*
 * The store's half of the hold panel (specs/084 R2), against the in-memory adapter the suite runs on. The same
 * contract is exercised on MongoDB and PostgreSQL by database/verify_084_refusals.ts, which is what proves the
 * upsert is one atomic write there.
 */

const at = (second: number) => new Date(Date.UTC(2026, 9, 11, 12, 0, second));

function refusal(
	overrides: Partial<ProvisioningRefusalInput> = {}
): ProvisioningRefusalInput {
	return {
		connectionId: 'conn-a',
		bucketId: 'bucket-a',
		epoch: 0,
		userId: 'user-1',
		operation: 'deactivate',
		at: at(0),
		...overrides
	};
}

/**
 * @proves A held directory's refused removals are kept one per person per hold, counting every retry and
 * remembering the latest request, listed newest first with their total, and leave with their connection or
 * their bucket.
 */
describe('the record of refused removals', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('keeps one record per person per hold, counting every attempt', async () => {
		const store = new ProvisioningRefusalStore();

		await store.note(refusal({ at: at(1) }));
		await store.note(refusal({ at: at(2) }));
		await store.note(refusal({ at: at(3), operation: 'delete' }));

		const { refusals, total } = await store.list('conn-a', 0, 10);
		expect(total).toBe(1);
		expect(refusals[0]).toMatchObject({
			userId: 'user-1',
			attempts: 3,
			operation: 'delete',
			firstAt: at(1),
			lastAt: at(3)
		});
	});

	it('counts no attempt lost when refusals of one person arrive together', async () => {
		const store = new ProvisioningRefusalStore();

		await Promise.all(
			Array.from({ length: 25 }, (_, i) => store.note(refusal({ at: at(i) })))
		);

		const { refusals } = await store.list('conn-a', 0, 10);
		expect(refusals[0]?.attempts).toBe(25);
	});

	it('starts a person afresh in the next hold', async () => {
		const store = new ProvisioningRefusalStore();
		await store.note(refusal({ epoch: 0 }));

		await store.note(refusal({ epoch: 1 }));

		expect((await store.list('conn-a', 1, 10)).refusals[0]?.attempts).toBe(1);
	});

	it('lists the most recently refused first, with the total beyond the page', async () => {
		const store = new ProvisioningRefusalStore();
		await store.note(refusal({ userId: 'early', at: at(1) }));
		await store.note(refusal({ userId: 'late', at: at(9) }));
		await store.note(refusal({ userId: 'middle', at: at(5) }));

		const { refusals, total } = await store.list('conn-a', 0, 2);

		expect(refusals.map((r) => r.userId)).toEqual(['late', 'middle']);
		expect(total).toBe(3);
	});

	it('lists nothing of another connection', async () => {
		const store = new ProvisioningRefusalStore();
		await store.note(refusal({ connectionId: 'conn-b' }));

		expect(await store.list('conn-a', 0, 10)).toEqual({
			refusals: [],
			total: 0
		});
	});

	it('forgets every hold of a connection when that connection’s records are destroyed', async () => {
		const store = new ProvisioningRefusalStore();
		await store.note(refusal({ epoch: 0 }));
		await store.note(refusal({ epoch: 1, userId: 'user-2' }));
		await store.note(refusal({ connectionId: 'conn-b' }));

		expect(await store.destroyByConnection('conn-a')).toBe(2);

		expect((await store.list('conn-a', 1, 10)).total).toBe(0);
		expect((await store.list('conn-b', 0, 10)).total).toBe(1);
	});

	it('forgets every connection of a bucket when the bucket’s records are destroyed', async () => {
		const store = new ProvisioningRefusalStore();
		await store.note(refusal());
		await store.note(refusal({ connectionId: 'conn-b' }));
		await store.note(
			refusal({ connectionId: 'conn-c', bucketId: 'bucket-other' })
		);

		expect(await store.destroyByBucket('bucket-a')).toBe(2);

		expect((await store.list('conn-c', 0, 10)).total).toBe(1);
	});
});
