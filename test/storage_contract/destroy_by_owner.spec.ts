import { describe, it, beforeAll, expect } from 'bun:test';

import bootstrap from '../test_helper.js';
import epochTime from 'lib/helpers/epoch_time.js';
import { adapter } from 'lib/adapters/index.ts';

// Storage contract for owner-derived destruction and per-collection revocation —
// specs/019-deletion-integrity/contracts/storage-adapter.md, clauses C1..C10.
//
// Asserted at the adapter boundary rather than through model classes: these are adapter clauses, and
// the MongoDB half is verified by reading plus the manual procedure in that feature's quickstart § 4
// (the suite runs with no MONGODB_URI on purpose — Constitution III).
//
// Ids are prefixed per test because the in-memory store is one module-level map shared by the whole
// suite.

const TTL = 60;

async function seed(
	area: string,
	id: string,
	payload: Record<string, unknown>
): Promise<void> {
	await adapter(area).upsert(
		id,
		{ ...payload, exp: epochTime() + TTL } as never,
		TTL
	);
}

describe('storage contract: destroyByOwner', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('destroys only records in its own area (C1)', async () => {
		await seed('AccessToken', 'c1-at', { clientId: 'c1-client' });
		await seed('RefreshToken', 'c1-rt', { clientId: 'c1-client' });

		const destroyed = await adapter('AccessToken').destroyByOwner(
			'clientId',
			'c1-client'
		);

		expect(destroyed).toBe(1);
		expect(await adapter('AccessToken').find('c1-at')).toBeUndefined();
		expect(await adapter('RefreshToken').find('c1-rt')).toBeDefined();
	});

	it('returns the exact number destroyed, and zero is not an error (C2)', async () => {
		await seed('AccessToken', 'c2-at-1', { accountId: 'c2-account' });
		await seed('AccessToken', 'c2-at-2', { accountId: 'c2-account' });
		await seed('AccessToken', 'c2-at-3', { accountId: 'c2-other' });

		expect(
			await adapter('AccessToken').destroyByOwner('accountId', 'c2-account')
		).toBe(2);
		expect(
			await adapter('AccessToken').destroyByOwner('accountId', 'c2-nobody')
		).toBe(0);
		expect(await adapter('AccessToken').find('c2-at-3')).toBeDefined();
	});

	it('is idempotent (C3)', async () => {
		await seed('RefreshToken', 'c3-rt', { clientId: 'c3-client' });

		expect(
			await adapter('RefreshToken').destroyByOwner('clientId', 'c3-client')
		).toBe(1);
		expect(
			await adapter('RefreshToken').destroyByOwner('clientId', 'c3-client')
		).toBe(0);
	});

	it('matches on strict equality and never matches a record missing the field (C4)', async () => {
		await seed('AccessToken', 'c4-with', { clientId: 'c4-client' });
		await seed('AccessToken', 'c4-without', { accountId: 'c4-account' });

		expect(
			await adapter('AccessToken').destroyByOwner('clientId', 'c4-client')
		).toBe(1);
		// The record that never carried `clientId` is untouched, not swept by a loose comparison.
		expect(await adapter('AccessToken').find('c4-without')).toBeDefined();
	});

	it('sweeps each declared owner field of the same area independently (C1, C2)', async () => {
		await seed('AccessToken', 'c5-at', {
			clientId: 'c5-client',
			accountId: 'c5-account'
		});

		expect(
			await adapter('AccessToken').destroyByOwner('accountId', 'c5-account')
		).toBe(1);
		expect(
			await adapter('AccessToken').destroyByOwner('clientId', 'c5-client')
		).toBe(0);
	});

	// The dangling-index decision, pinned so a later "cleanup" cannot quietly change the contract into
	// one that must walk indexes.
	it('leaves grant and session-uid index entries dangling, harmlessly (C6)', async () => {
		await seed('AccessToken', 'c6-at', {
			clientId: 'c6-client',
			grantId: 'c6-grant'
		});
		await adapter('Session').upsert(
			'c6-session',
			{
				uid: 'c6-uid',
				accountId: 'c6-account',
				exp: epochTime() + TTL
			} as never,
			TTL
		);

		await adapter('AccessToken').destroyByOwner('clientId', 'c6-client');
		await adapter('Session').destroyByOwner('accountId', 'c6-account');

		// Deleting through a stale index entry is a no-op, not a throw.
		await adapter('AccessToken').revokeByGrantId('c6-grant');
		// Resolving a uid whose payload is gone yields nothing, rather than a partial record.
		expect(await adapter('Session').findByUid('c6-uid')).toBeUndefined();
	});
});

describe('storage contract: revokeByGrantId is per-collection', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('revokes only the calling area, leaving other areas of the same grant intact (C7, C8)', async () => {
		await seed('AccessToken', 'c7-at', {
			clientId: 'c7-client',
			grantId: 'c7-grant'
		});
		await seed('RefreshToken', 'c7-rt', {
			clientId: 'c7-client',
			grantId: 'c7-grant'
		});
		await seed('AuthorizationCode', 'c7-ac', {
			clientId: 'c7-client',
			grantId: 'c7-grant'
		});

		await adapter('AccessToken').revokeByGrantId('c7-grant');

		expect(await adapter('AccessToken').find('c7-at')).toBeUndefined();
		expect(await adapter('RefreshToken').find('c7-rt')).toBeDefined();
		expect(await adapter('AuthorizationCode').find('c7-ac')).toBeDefined();
	});

	it('still reaches every area when each is asked in turn (C9)', async () => {
		await seed('AccessToken', 'c9-at', {
			clientId: 'c9-client',
			grantId: 'c9-grant'
		});
		await seed('RefreshToken', 'c9-rt', {
			clientId: 'c9-client',
			grantId: 'c9-grant'
		});

		await adapter('AccessToken').revokeByGrantId('c9-grant');
		await adapter('RefreshToken').revokeByGrantId('c9-grant');

		expect(await adapter('AccessToken').find('c9-at')).toBeUndefined();
		expect(await adapter('RefreshToken').find('c9-rt')).toBeUndefined();
	});

	it('never destroys the Grant record itself (C10)', async () => {
		await adapter('Grant').upsert(
			'c10-grant',
			{
				clientId: 'c10-client',
				accountId: 'c10-account',
				createdAt: epochTime(),
				lastModifiedAt: epochTime(),
				trusted: false
			} as never,
			TTL
		);
		await seed('AccessToken', 'c10-at', {
			clientId: 'c10-client',
			grantId: 'c10-grant'
		});

		await adapter('AccessToken').revokeByGrantId('c10-grant');

		// Revoking tokens is not withdrawing consent; only a principal cascade destroys grant rows.
		expect(await adapter('Grant').find('c10-grant')).toBeDefined();
	});
});
