import { describe, it, expect } from 'bun:test';

import { UserBucketStore } from 'lib/adapters/memory/userBucketStore.ts';

/*
 * The in-memory half of the contract; database/verify_090_bucket_deletion.ts holds MongoDB and PostgreSQL
 * to the same cases. A store of its own per case, so no case sees another's buckets.
 */

const at = (minute: number) => new Date(Date.UTC(2026, 9, 12, 12, minute));

function schedule(scheduledAt: Date, purgeAt: Date) {
	return {
		scheduledAt,
		purgeAt,
		scheduledBy: { userId: 'admin-1', email: 'admin@example.com' }
	};
}

async function scheduled(purgeAt = at(30)) {
	const store = new UserBucketStore();
	const bucket = await store.create({
		name: 'Doomed',
		slug: 'doomed',
		ownerGroupId: 'group-1'
	});
	await store.scheduleDeletion(bucket._id, schedule(at(0), purgeAt));
	return { store, id: bucket._id };
}

/**
 * @proves A bucket's scheduled destruction changes state only through one transition at a time: it is
 * scheduled once, restored only while no destruction is under way, destroyed by one claimant, never early
 * by the background pass, recorded once however often it is retried, and gone without trace when restored.
 */
describe('a bucket’s scheduled destruction, as stored', () => {
	it('refuses a second schedule and keeps the first date', async () => {
		const { store, id } = await scheduled();

		const again = await store.scheduleDeletion(id, schedule(at(5), at(60)));

		expect(again).toBeNull();
		expect((await store.find(id))?.deletion?.purgeAt).toEqual(at(30));
	});

	it('refuses a restore while a destruction holds a live claim', async () => {
		const { store, id } = await scheduled();
		await store.claimPurge(id, at(1), at(16), { due: false });

		expect(await store.cancelDeletion(id, at(10))).toBeNull();
		expect((await store.find(id))?.deletion).toBeDefined();
	});

	it('allows a restore once the claim has lapsed', async () => {
		const { store, id } = await scheduled();
		await store.claimPurge(id, at(1), at(16), { due: false });

		expect(await store.cancelDeletion(id, at(17))).not.toBeNull();
	});

	it('gives one winner to claims made at the same moment', async () => {
		const { store, id } = await scheduled();

		const answers = await Promise.all([
			store.claimPurge(id, at(31), at(46), { due: true }),
			store.claimPurge(id, at(31), at(46), { due: true })
		]);

		expect(answers.filter((answer) => answer !== null)).toHaveLength(1);
	});

	it('refuses the background pass a claim before the date', async () => {
		const { store, id } = await scheduled();

		expect(
			await store.claimPurge(id, at(29), at(44), { due: true })
		).toBeNull();
	});

	it('keeps the record of the audit entry when a lapsed claim is taken again', async () => {
		const { store, id } = await scheduled();
		await store.claimPurge(id, at(31), at(46), { due: true });
		await store.markPurgeRecorded(id, at(32));

		const again = await store.claimPurge(id, at(47), at(62), { due: true });

		expect(again?.deletion?.purge?.recordedAt).toEqual(at(32));
	});

	it('lets the next claim in at once when its holder releases it, keeping the audit record', async () => {
		const { store, id } = await scheduled();
		await store.claimPurge(id, at(31), at(46), { due: true });
		await store.markPurgeRecorded(id, at(32));
		await store.releasePurge(id, at(46));

		const again = await store.claimPurge(id, at(33), at(48), { due: true });

		expect(again?.deletion?.purge?.recordedAt).toEqual(at(32));
	});

	it('leaves a claim alone that its releaser no longer holds', async () => {
		const { store, id } = await scheduled();
		await store.claimPurge(id, at(31), at(46), { due: true });
		await store.claimPurge(id, at(47), at(62), { due: true });

		await store.releasePurge(id, at(46));

		expect(
			await store.claimPurge(id, at(48), at(63), { due: true })
		).toBeNull();
	});

	it('leaves no deletion on a restored bucket', async () => {
		const { store, id } = await scheduled();

		await store.cancelDeletion(id, at(1));

		expect(await store.find(id)).not.toHaveProperty('deletion');
	});
});
