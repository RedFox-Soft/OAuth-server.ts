import {
	describe,
	it,
	expect,
	beforeEach,
	afterEach,
	setSystemTime
} from 'bun:test';

import { AdminAuditStore } from 'lib/adapters/memory/adminAuditStore.ts';
import type { AdminAuditEntry } from 'lib/adapters/types.ts';

// The admin audit store contract — specs/016-admin-audit-completeness/contracts/audit-store.md.
// Clause ids below (R-1.., L-1..) are that document's.
//
// Memory implementation only, for the reason every store spec here gives: lib/adapters/mongodb/db.ts
// connects at module scope and throws without MONGODB_URI, which this suite deliberately lacks. The
// MongoDB class is verified by hand per the feature's quickstart.
//
// The load-bearing property is L-2: the (timestamp desc, _id desc) order is TOTAL, so paging cannot
// drop or repeat an entry when timestamps collide. Colliding timestamps are not hypothetical — an
// admin action and its follow-up can land in the same millisecond, and an audit trail that loses a
// row at a page boundary is worse than one that is merely hard to read.

const base = {
	actorId: 'admin-1',
	actorEmail: 'ops@example.com',
	action: 'project.update',
	targetType: 'Project',
	targetId: 'p1'
};

describe('AdminAuditStore (memory)', () => {
	let store: AdminAuditStore;

	beforeEach(() => {
		store = new AdminAuditStore();
	});

	// The store stamps entries itself (R-1), and hands out no reference a caller could mutate (L-11),
	// so the clock is the only way to control when an entry claims to have happened.
	afterEach(() => {
		setSystemTime();
	});

	// Writes `count` entries that all share one timestamp, leaving ordering nothing but the `_id`
	// tiebreaker to work with.
	async function seedColliding(count: number, stamp: Date) {
		setSystemTime(stamp);
		const written: AdminAuditEntry[] = [];
		for (let i = 0; i < count; i += 1) {
			written.push(await store.record({ ...base, targetId: `p${i}` }));
		}
		setSystemTime();
		return written;
	}

	describe('record', () => {
		it('allocates the id and the timestamp itself, and returns the stored entry (R-1, R-2)', async () => {
			const saved = await store.record(base);

			expect(saved._id).toBeTruthy();
			expect(saved.timestamp).toBeInstanceOf(Date);
			expect(saved.actorEmail).toBe('ops@example.com');
			expect(saved.action).toBe('project.update');
		});

		it('stores attributes as given, and omits them when not supplied (R-3)', async () => {
			await store.record({ ...base, attributes: ['name', 'slug'] });
			await store.record({ ...base, targetId: 'p2' });

			const { entries } = await store.list({ targetId: 'p1' });
			expect(entries[0]?.attributes).toEqual(['name', 'slug']);

			// Read-side default, not a stored value: an entry written before the field existed and one
			// written with nothing to say are indistinguishable, which is what makes FR-008b free.
			const bare = await store.list({ targetId: 'p2' });
			expect(bare.entries[0]?.attributes).toEqual([]);
		});

		it('stores targetScope as given, and omits it when not supplied (R-3a)', async () => {
			await store.record({
				...base,
				action: 'enduser.update',
				targetType: 'EndUser',
				targetId: 'u1',
				targetScope: 'bucket-9'
			});

			const { entries } = await store.list({ targetId: 'u1' });
			expect(entries[0]?.targetScope).toBe('bucket-9');

			await store.record({ ...base, targetId: 'p3' });
			const bare = await store.list({ targetId: 'p3' });
			expect(bare.entries[0]?.targetScope).toBeNull();
		});

		it('does not normalize any field (R-5)', async () => {
			await store.record({ ...base, actorEmail: 'OPS@Example.COM' });

			const { entries } = await store.list();
			expect(entries[0]?.actorEmail).toBe('OPS@Example.COM');
		});
	});

	describe('list ordering', () => {
		it('returns newest first (L-1)', async () => {
			setSystemTime(new Date('2026-01-01T00:00:00Z'));
			await store.record({ ...base, targetId: 'old' });
			setSystemTime(new Date('2026-06-01T00:00:00Z'));
			await store.record({ ...base, targetId: 'new' });
			setSystemTime();

			const { entries } = await store.list();
			expect(entries.map((e) => e.targetId)).toEqual(['new', 'old']);
		});

		it('totally orders entries sharing a timestamp, so paging loses none (L-2, L-3)', async () => {
			const stamp = new Date('2026-03-03T03:03:03Z');
			const written = await seedColliding(7, stamp);

			const pageOne = await store.list({ limit: 3, offset: 0 });
			const pageTwo = await store.list({ limit: 3, offset: 3 });
			const pageThree = await store.list({ limit: 3, offset: 6 });

			const seen = [
				...pageOne.entries,
				...pageTwo.entries,
				...pageThree.entries
			];
			expect(seen).toHaveLength(7);
			expect(new Set(seen.map((e) => e._id)).size).toBe(7);
			expect(new Set(written.map((e) => e._id))).toEqual(
				new Set(seen.map((e) => e._id))
			);

			// Descending by id, since every timestamp is equal.
			const ids = seen.map((e) => e._id);
			expect([...ids].sort().reverse()).toEqual(ids);
		});
	});

	describe('list filters', () => {
		beforeEach(async () => {
			await store.record({
				...base,
				actorId: 'a1',
				actorEmail: 'one@x.io',
				action: 'project.create',
				targetId: 'p1'
			});
			await store.record({
				...base,
				actorId: 'a2',
				actorEmail: 'two@x.io',
				action: 'project.delete',
				targetId: 'p2'
			});
			await store.record({
				...base,
				actorId: 'a2',
				actorEmail: 'two@x.io',
				action: 'enduser.delete',
				targetType: 'EndUser',
				targetId: 'u1',
				targetScope: 'bucket-1'
			});
		});

		it('matches an actor by id or by email (L-4)', async () => {
			expect((await store.list({ actor: 'a2' })).total).toBe(2);
			expect((await store.list({ actor: 'two@x.io' })).total).toBe(2);
			expect((await store.list({ actor: 'one@x.io' })).total).toBe(1);
			expect((await store.list({ actor: 'nobody' })).total).toBe(0);
		});

		it('matches exactly, never partially (L-4)', async () => {
			expect((await store.list({ actor: 'a' })).total).toBe(0);
			expect((await store.list({ action: 'project' })).total).toBe(0);
		});

		it('matches action, targetType, targetId and targetScope (L-5)', async () => {
			expect((await store.list({ action: 'project.create' })).total).toBe(1);
			expect((await store.list({ targetType: 'EndUser' })).total).toBe(1);
			expect((await store.list({ targetId: 'p2' })).total).toBe(1);
			expect((await store.list({ targetScope: 'bucket-1' })).total).toBe(1);
			expect((await store.list({ targetScope: 'bucket-2' })).total).toBe(0);
		});

		it('combines filters with AND (L-5)', async () => {
			expect(
				(await store.list({ actor: 'a2', targetType: 'Project' })).total
			).toBe(1);
			expect(
				(await store.list({ actor: 'a1', targetType: 'EndUser' })).total
			).toBe(0);
		});

		it('imposes no constraint for an absent filter (L-6)', async () => {
			expect((await store.list()).total).toBe(3);
			expect((await store.list({})).total).toBe(3);
		});
	});

	describe('list time window', () => {
		beforeEach(async () => {
			setSystemTime(new Date('2026-01-15T12:00:00Z'));
			await store.record({ ...base, targetId: 'jan' });
			setSystemTime(new Date('2026-03-15T12:00:00Z'));
			await store.record({ ...base, targetId: 'mar' });
			setSystemTime(new Date('2026-06-15T12:00:00Z'));
			await store.record({ ...base, targetId: 'jun' });
			setSystemTime();
		});

		it('bounds the window inclusively, each bound valid alone (L-5a)', async () => {
			const since = await store.list({
				from: new Date('2026-03-15T12:00:00Z')
			});
			expect(since.entries.map((e) => e.targetId)).toEqual(['jun', 'mar']);

			const until = await store.list({ to: new Date('2026-03-15T12:00:00Z') });
			expect(until.entries.map((e) => e.targetId)).toEqual(['mar', 'jan']);

			const between = await store.list({
				from: new Date('2026-02-01T00:00:00Z'),
				to: new Date('2026-05-01T00:00:00Z')
			});
			expect(between.entries.map((e) => e.targetId)).toEqual(['mar']);
		});

		it('combines the window with the other filters (L-5, L-5a)', async () => {
			const { total } = await store.list({
				actor: 'admin-1',
				from: new Date('2026-06-01T00:00:00Z')
			});
			expect(total).toBe(1);
		});

		it('returns an empty page for a backwards window rather than throwing (L-5b)', async () => {
			// Refusing one is the route's job, where a caller can be told why; the store just applies
			// the bounds it was given.
			const { entries, total } = await store.list({
				from: new Date('2026-06-01T00:00:00Z'),
				to: new Date('2026-01-01T00:00:00Z')
			});
			expect(entries).toEqual([]);
			expect(total).toBe(0);
		});
	});

	describe('list paging', () => {
		beforeEach(async () => {
			for (let i = 0; i < 5; i += 1) {
				await store.record({ ...base, targetId: `p${i}` });
			}
		});

		it('counts every match regardless of paging (L-7)', async () => {
			const { entries, total } = await store.list({ limit: 2 });
			expect(entries).toHaveLength(2);
			expect(total).toBe(5);
		});

		it('defaults the limit to 50 and clamps it to 200 (L-8)', async () => {
			for (let i = 0; i < 250; i += 1) {
				await store.record({ ...base, targetId: `bulk${i}` });
			}

			expect((await store.list()).entries).toHaveLength(50);
			expect((await store.list({ limit: 999 })).entries).toHaveLength(200);
			expect((await store.list({ limit: 0 })).entries).toHaveLength(1);
		});

		it('treats a negative offset as zero (L-8)', async () => {
			const negative = await store.list({ offset: -5, limit: 2 });
			const zero = await store.list({ offset: 0, limit: 2 });
			expect(negative.entries.map((e) => e._id)).toEqual(
				zero.entries.map((e) => e._id)
			);
		});

		it('returns an empty page past the end, with the true total (L-9)', async () => {
			const { entries, total } = await store.list({ offset: 500 });
			expect(entries).toEqual([]);
			expect(total).toBe(5);
		});
	});

	it('hands out no reference a caller could mutate to alter the trail (L-11)', async () => {
		await store.record(base);

		const first = await store.list();
		first.entries[0]!.action = 'tampered';

		const second = await store.list();
		expect(second.entries[0]?.action).toBe('project.update');
	});
});
