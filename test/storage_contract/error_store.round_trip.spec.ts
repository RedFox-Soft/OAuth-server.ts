import {
	describe,
	it,
	expect,
	beforeEach,
	afterEach,
	setSystemTime
} from 'bun:test';

import { ErrorStore } from 'lib/adapters/memory/errorStore.ts';
import type { ErrorOccurrence, ErrorRecord } from 'lib/adapters/types.ts';

// The error store contract — specs/025-server-error-store/contracts/storage.md.
//
// Memory implementation only, for the reason every store spec here gives: lib/adapters/mongodb/db.ts
// connects at module scope and throws without MONGODB_URI, which this suite deliberately lacks. The
// MongoDB class is held by the inventory drift guards and by sharing every filter, paging and
// admission rule with this one through lib/helpers/error_store_query.ts.
//
// Two properties here are load-bearing rather than incidental:
//
//  - the (lastSeenAt desc, _id desc) order is TOTAL, so paging cannot drop or repeat a group when two
//    faults share a millisecond — which a storm makes ordinary rather than hypothetical;
//  - the occurrence count is exact however many samples the cap discards. A store that under-reports
//    how often something is failing is worse than one that keeps no samples at all.

let seq = 0;
/* Narrows an optional the test has already established is present, so no assertion is needed. */
function must<T>(value: T | undefined | null, what: string): T {
	if (value === null || value === undefined) {
		throw new Error(`expected ${what} to be present`);
	}
	return value;
}

function record(over: Partial<ErrorRecord> = {}): ErrorRecord {
	seq += 1;
	return {
		reference: `ref-${seq}`,
		at: new Date(),
		clientId: null,
		actor: null,
		scope: null,
		requestId: null,
		origin: null,
		userAgent: null,
		submittedFields: [],
		...over
	};
}

function occurrence(over: Partial<ErrorOccurrence> = {}): ErrorOccurrence {
	return {
		fingerprint: 'fp-token-500',
		errorCode: 'server_error',
		status: 500,
		surface: 'oauth',
		route: '/token',
		method: 'POST',
		origin: { file: 'lib/actions/token.ts', line: 42, frame: 'grant()' },
		message: 'boom',
		record: record(),
		...over
	};
}

describe('ErrorStore (memory)', () => {
	let store: ErrorStore;
	let bounds = { retentionDays: 30, maxGroups: 100, samplesPerGroup: 10 };

	beforeEach(() => {
		store = new ErrorStore();
		bounds = { retentionDays: 30, maxGroups: 100, samplesPerGroup: 10 };
	});

	afterEach(() => {
		setSystemTime();
	});

	describe('record', () => {
		it('creates one group for a fault, stamped and identified', async () => {
			const group = must(await store.record(occurrence(), bounds), 'the group');

			expect(group).toBeDefined();
			expect(group?._id).toBeTruthy();
			expect(group?.occurrences).toBe(1);
			expect(group?.samples).toHaveLength(1);
			expect(group?.firstSeenAt).toBeInstanceOf(Date);
			expect(group?.expiresAt.getTime()).toBeGreaterThan(
				group.lastSeenAt.getTime()
			);
		});

		it('groups repeat occurrences of one fingerprint', async () => {
			await store.record(occurrence(), bounds);
			await store.record(occurrence(), bounds);
			const group = must(await store.record(occurrence(), bounds), 'the group');

			expect(group?.occurrences).toBe(3);
			const page = await store.list();
			expect(page.total).toBe(1);
		});

		it('separates distinct fingerprints', async () => {
			await store.record(occurrence({ fingerprint: 'a' }), bounds);
			await store.record(occurrence({ fingerprint: 'b' }), bounds);

			expect((await store.list()).total).toBe(2);
		});

		// The tally is exact however many samples go. This is the property the sample cap must not cost.
		it('keeps the count exact past the sample cap', async () => {
			bounds = {
				retentionDays: 30,
				maxGroups: 100,
				samplesPerGroup: 2
			};
			for (let i = 0; i < 50; i += 1) {
				await store.record(occurrence(), bounds);
			}

			const group = (await store.list()).groups[0];
			expect(group.occurrences).toBe(50);
			expect(group.samples).toHaveLength(2);
		});

		// Earliest kept, remainder most-recent-first: where it started, and what it is doing now.
		it('retains the earliest sample and the most recent ones', async () => {
			bounds = {
				retentionDays: 30,
				maxGroups: 100,
				samplesPerGroup: 3
			};
			for (const ref of ['first', 'second', 'third', 'fourth', 'fifth']) {
				await store.record(
					occurrence({ record: record({ reference: ref }) }),
					bounds
				);
			}

			const group = (await store.list()).groups[0];
			expect(group.samples.map((s) => s.reference)).toEqual([
				'first',
				'fourth',
				'fifth'
			]);
		});

		it('advances the expiry on every occurrence', async () => {
			setSystemTime(new Date('2026-01-01T00:00:00Z'));
			const first = must(
				await store.record(occurrence(), bounds),
				'the first group'
			);
			setSystemTime(new Date('2026-01-10T00:00:00Z'));
			const later = must(
				await store.record(occurrence(), bounds),
				'the later group'
			);

			expect(later.expiresAt.getTime()).toBeGreaterThan(
				first.expiresAt.getTime()
			);
			// The window runs from last-seen, so the first occurrence's own time is not what expires it.
			expect(later.firstSeenAt).toEqual(first.firstSeenAt);
		});

		// A caller holding a live reference into the store could edit what the store says happened.
		it('hands out no reference a caller could mutate', async () => {
			const group = must(await store.record(occurrence(), bounds), 'the group');
			group.occurrences = 9999;
			group.samples.length = 0;

			const stored = (await store.list()).groups[0];
			expect(stored.occurrences).toBe(1);
			expect(stored.samples).toHaveLength(1);
		});
	});

	describe('bounding', () => {
		it('evicts the least recently seen group at the cap', async () => {
			bounds = {
				retentionDays: 30,
				maxGroups: 2,
				samplesPerGroup: 5
			};

			setSystemTime(new Date('2026-01-01T00:00:00Z'));
			await store.record(occurrence({ fingerprint: 'old-but-active' }), bounds);
			setSystemTime(new Date('2026-01-02T00:00:00Z'));
			await store.record(occurrence({ fingerprint: 'one-off' }), bounds);

			// The long-running fault is seen again, so the one-off becomes least-recently-seen.
			setSystemTime(new Date('2026-01-03T00:00:00Z'));
			await store.record(occurrence({ fingerprint: 'old-but-active' }), bounds);

			setSystemTime(new Date('2026-01-04T00:00:00Z'));
			await store.record(occurrence({ fingerprint: 'newcomer' }), bounds);

			const fingerprints = (await store.list()).groups.map(
				(g) => g.fingerprint
			);
			expect(fingerprints).not.toContain('one-off');
			expect(fingerprints).toContain('old-but-active');
			expect(fingerprints).toContain('newcomer');
		});

		it('never exceeds the group cap', async () => {
			bounds = {
				retentionDays: 30,
				maxGroups: 3,
				samplesPerGroup: 5
			};
			for (let i = 0; i < 30; i += 1) {
				await store.record(occurrence({ fingerprint: `fp-${i}` }), bounds);
			}

			expect((await store.list()).total).toBe(3);
		});

		// Invisible on read whether or not the sweep has run, so sweep timing cannot change an answer.
		it('hides an expired group', async () => {
			setSystemTime(new Date('2026-01-01T00:00:00Z'));
			await store.record(occurrence(), bounds);

			setSystemTime(new Date('2026-03-01T00:00:00Z'));
			expect((await store.list()).total).toBe(0);
		});
	});

	describe('list', () => {
		it('orders newest-first and reports the total independent of limit', async () => {
			setSystemTime(new Date('2026-01-01T00:00:00Z'));
			await store.record(occurrence({ fingerprint: 'a' }), bounds);
			setSystemTime(new Date('2026-01-02T00:00:00Z'));
			await store.record(occurrence({ fingerprint: 'b' }), bounds);
			setSystemTime(new Date('2026-01-03T00:00:00Z'));
			await store.record(occurrence({ fingerprint: 'c' }), bounds);

			const page = await store.list({ limit: 1 });
			expect(page.groups).toHaveLength(1);
			expect(page.groups[0].fingerprint).toBe('c');
			expect(page.total).toBe(3);
		});

		/*
		 * The total-order property, exercised where it actually breaks: every group sharing a timestamp,
		 * paged one at a time. Without the `_id` tiebreaker this drops or repeats a row.
		 */
		it('pages without dropping or repeating on colliding timestamps', async () => {
			setSystemTime(new Date('2026-01-01T00:00:00Z'));
			for (const fp of ['a', 'b', 'c', 'd', 'e']) {
				await store.record(occurrence({ fingerprint: fp }), bounds);
			}

			const seen: string[] = [];
			for (let offset = 0; offset < 5; offset += 1) {
				const page = await store.list({ limit: 1, offset });
				seen.push(page.groups[0].fingerprint);
			}

			expect(new Set(seen).size).toBe(5);
		});

		it('filters on group fields', async () => {
			await store.record(
				occurrence({ fingerprint: 'a', route: '/token', status: 500 }),
				bounds
			);
			await store.record(
				occurrence({ fingerprint: 'b', route: '/authorize', status: 502 }),
				bounds
			);

			expect((await store.list({ route: '/token' })).total).toBe(1);
			expect((await store.list({ status: 502 })).total).toBe(1);
			expect((await store.list({ surface: 'admin' })).total).toBe(0);
		});

		it('filters on sample fields', async () => {
			await store.record(
				occurrence({
					fingerprint: 'a',
					record: record({ clientId: 'client-1' })
				}),
				bounds
			);
			await store.record(
				occurrence({
					fingerprint: 'b',
					record: record({
						actor: { id: 'admin-1', email: 'ops@example.com' }
					})
				}),
				bounds
			);

			expect((await store.list({ clientId: 'client-1' })).total).toBe(1);
			// Actor matches on either arm, so a deleted admin stays findable by id.
			expect((await store.list({ actor: 'ops@example.com' })).total).toBe(1);
			expect((await store.list({ actor: 'admin-1' })).total).toBe(1);
		});

		it('applies an inclusive time window on last-seen', async () => {
			setSystemTime(new Date('2026-01-01T00:00:00Z'));
			await store.record(occurrence({ fingerprint: 'a' }), bounds);
			setSystemTime(new Date('2026-01-05T00:00:00Z'));
			await store.record(occurrence({ fingerprint: 'b' }), bounds);

			expect(
				(await store.list({ from: new Date('2026-01-05T00:00:00Z') })).total
			).toBe(1);
			expect(
				(await store.list({ to: new Date('2026-01-01T00:00:00Z') })).total
			).toBe(1);
		});
	});

	describe('lookup', () => {
		it('resolves a reference to its group and sample', async () => {
			await store.record(
				occurrence({ record: record({ reference: 'known-ref' }) }),
				bounds
			);

			const hit = await store.findByReference('known-ref');
			expect(hit?.sample.reference).toBe('known-ref');
			expect(hit?.group.fingerprint).toBe('fp-token-500');
		});

		// Undefined, not an empty page: the caller must be able to say "no such record".
		it('returns undefined for an unknown reference', async () => {
			expect(await store.findByReference('nope')).toBeUndefined();
		});

		it('gets a group by id', async () => {
			const created = must(
				await store.record(occurrence(), bounds),
				'the created group'
			);
			expect((await store.get(created._id))?._id).toBe(created._id);
			expect(await store.get('missing')).toBeUndefined();
		});
	});

	describe('summarize', () => {
		it('sums occurrences rather than counting rows', async () => {
			for (let i = 0; i < 9; i += 1) {
				await store.record(
					occurrence({ fingerprint: 'loud', route: '/token' }),
					bounds
				);
			}
			await store.record(
				occurrence({ fingerprint: 'quiet', route: '/authorize' }),
				bounds
			);

			const summary = await store.summarize();
			expect(summary.total).toBe(10);
			// Most frequent first: one fault seen nine times outranks one seen once.
			expect(summary.byRoute[0]).toEqual({ key: '/token', count: 9 });
			expect(summary.byErrorCode[0]).toEqual({
				key: 'server_error',
				count: 10
			});
		});
	});

	describe('purge', () => {
		it('previews and removes the same set', async () => {
			await store.record(
				occurrence({ fingerprint: 'a', route: '/token' }),
				bounds
			);
			await store.record(
				occurrence({ fingerprint: 'a', route: '/token' }),
				bounds
			);
			await store.record(
				occurrence({ fingerprint: 'b', route: '/authorize' }),
				bounds
			);

			const estimate = await store.previewPurge({ route: '/token' });
			expect(estimate).toEqual({ groups: 1, occurrences: 2 });

			expect(await store.purge({ route: '/token' })).toBe(1);
			expect((await store.list()).total).toBe(1);
		});

		it('reports zero when nothing matches', async () => {
			await store.record(occurrence(), bounds);
			expect(await store.purge({ route: '/nowhere' })).toBe(0);
		});
	});
});
