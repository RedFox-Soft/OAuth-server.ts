import { describe, it, expect, beforeAll } from 'bun:test';

import bootstrap from '../test_helper.js';
import { TestAdapter } from 'test/models.js';
import epochTime from 'lib/helpers/epoch_time.js';
import { getBucketStore, getUserStore } from 'lib/adapters/index.js';
import { cascadeForAccount } from 'lib/helpers/cascade.js';
import { openHandoff } from 'lib/federation/state.js';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';

/*
 * What each deletion reaches.
 *
 * The claim being tested is that embedding a link on the user row makes deletion integrity **structural**:
 * no cascade arm knows the `federated` field exists, and none needs to. Asserted rather than assumed,
 * because "nothing was left behind" is the kind of property that is true until an area is added.
 */

const LINK = {
	providerId: 'acme-sso',
	sub: 'upstream-subject-1',
	linkedAt: new Date()
};

describe('federated links and deletion', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('takes an account’s links with the account, leaving nothing a sign-in could resolve', async () => {
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'deletion'
		});
		const store = getUserStore(bucket._id);
		const user = await store.create('linked@acme.test', 'hash', [], true);
		await store.update(user._id, { federated: [LINK] });

		expect(
			await store.findByFederatedIdentity(LINK.providerId, LINK.sub)
		).not.toBeNull();

		await cascadeForAccount(user._id, bucket._id);
		await store.destroy(user._id);

		// No orphan: the lookup a federated sign-in performs finds nobody.
		expect(
			await store.findByFederatedIdentity(LINK.providerId, LINK.sub)
		).toBeNull();
		expect(await store.find(user._id)).toBeNull();
	});

	it('sweeps an outstanding handoff naming a deleted account', async () => {
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'handoff-sweep'
		});
		const store = getUserStore(bucket._id);
		const user = await store.create('inflight@acme.test', 'hash', [], true);

		// A sign-in mid-flight: the account has been resolved and the handoff written, and then the operator
		// deletes the account.
		await openHandoff({ interactionUid: 'int-sweep', accountId: user._id });
		const before = handoffsFor(user._id);
		expect(before).toBe(1);

		await cascadeForAccount(user._id, bucket._id);

		/*
		 * Swept by the ownership declaration alone — no cascade arm mentions FederationState. This is the
		 * property the area's `byAccount` declaration buys, and the reason declaring it `unowned` would have
		 * been wrong as well as unimplementable.
		 */
		expect(handoffsFor(user._id)).toBe(0);
	});

	it('leaves the per-bucket area empty once its accounts are gone', async () => {
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'area'
		});
		const store = getUserStore(bucket._id);
		const user = await store.create('last@acme.test', 'hash', [], true);
		await store.update(user._id, { federated: [LINK] });

		/*
		 * Bucket deletion is **guarded**, not cascading: the admin route refuses with 409 while any account
		 * remains, so a live link is never destroyed by deleting its bucket — the accounts holding them must go
		 * first. This is that ordering, and the area is empty at the end of it.
		 */
		expect(await store.list()).toHaveLength(1);
		await store.destroy(user._id);
		expect(await store.list()).toEqual([]);

		await store.destroyArea();
		// Re-created under the same id, a bucket inherits nothing.
		expect(await getUserStore(bucket._id).list()).toEqual([]);
	});
});

/* How many live handoffs name this account. Read from the adapter, since nothing queries them by owner. */
function handoffsFor(accountId: string): number {
	const store = TestAdapter.for('FederationState').store as Map<
		string,
		{ accountId?: string; exp?: number }
	>;
	let found = 0;
	for (const [key, value] of store) {
		if (typeof key !== 'string' || !key.startsWith('FederationState:'))
			continue;
		if (value?.accountId === accountId && (value.exp ?? 0) > epochTime()) {
			found += 1;
		}
	}
	return found;
}
