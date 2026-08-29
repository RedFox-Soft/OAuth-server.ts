import { describe, it, expect, beforeEach, setSystemTime } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { auditRoutes } from 'lib/admin/audit/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminAuditStore,
	adminSessionStore,
	getUserStore
} from 'lib/adapters/index.ts';
import type { AdminAuditEntry } from 'lib/adapters/types.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { sessionFor } from '../admin_session.ts';

/*
 * The read surface — specs/016-admin-audit-completeness/contracts/admin-audit-api.md.
 *
 * Every assertion is scoped to entries this spec wrote, by a per-test `targetScope` marker: the
 * in-memory trail is a process-wide singleton, it never shrinks, and other admin specs in the same
 * `bun test` process write to it too.
 *
 * The load-bearing cases are the ones where an empty page would be a lie: a backwards window is
 * refused rather than answered with nothing, and an unknown query parameter is refused rather than
 * silently returning the unfiltered trail.
 */
const app = new Elysia().use(resolveAdmin).use(auditRoutes);
const client = treaty(app);

let seq = 0;
const unique = (prefix: string) => `${prefix}-${Date.now()}-${(seq += 1)}`;

interface AuditPage {
	entries: AdminAuditEntry[];
	total: number;
	page: number;
	pageSize: number;
}

async function cookieFor(roles: string[]) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`${unique('admin')}@x.io`,
		'hash',
		roles
	);
	const session = await sessionFor(user);
	return {
		cookie: `${ADMIN_SESSION_COOKIE}=${session._id}`,
		userId: user._id,
		email: user.email
	};
}

async function seed(
	scope: string,
	entry: Partial<Omit<AdminAuditEntry, '_id' | 'timestamp'>> = {},
	at?: Date
) {
	if (at) {
		setSystemTime(at);
	}
	const saved = await adminAuditStore.record({
		actorId: entry.actorId ?? 'actor-1',
		actorEmail: entry.actorEmail ?? 'one@x.io',
		action: entry.action ?? 'project.update',
		targetType: entry.targetType ?? 'Project',
		targetId: entry.targetId ?? unique('target'),
		targetScope: scope,
		...(entry.attributes === undefined ? {} : { attributes: entry.attributes })
	});
	if (at) {
		setSystemTime();
	}
	return saved;
}

describe('GET /admin/api/audit', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	describe('authorization', () => {
		it('refuses an unauthenticated caller without disclosing records', async () => {
			const scope = unique('scope');
			await seed(scope);

			const res = await client.admin.api.audit.get({ query: {} });

			expect(res.status).toBe(401);
			expect(JSON.stringify(res.error?.value ?? res.data)).not.toContain(scope);
		});

		/*
		 * Was 'refuses an administrator who is not a super administrator'. A project administrator now
		 * reads their own groups' history — but sees nothing belonging to anyone else, which is the
		 * property that actually mattered in the old test and is asserted directly here.
		 */
		it('serves a project administrator only their own groups’ entries', async () => {
			const scope = unique('scope');
			await seed(scope);
			const { cookie } = await cookieFor(['project_admin']);

			const res = await client.admin.api.audit.get({
				query: {},
				headers: { cookie }
			});

			expect(res.status).toBe(200);
			// The seeded entry belongs to no group of theirs, so it must not appear.
			expect(JSON.stringify(res.data)).not.toContain(scope);
		});

		it('serves a super administrator', async () => {
			const scope = unique('scope');
			await seed(scope);
			const { cookie } = await cookieFor(['super_admin']);

			const res = await client.admin.api.audit.get({
				query: { targetScope: scope },
				headers: { cookie }
			});

			expect(res.status).toBe(200);
			expect((res.data as AuditPage).total).toBe(1);
		});
	});

	describe('ordering and shape', () => {
		it('returns newest first', async () => {
			const scope = unique('scope');
			await seed(
				scope,
				{ targetId: 'oldest' },
				new Date('2026-01-01T00:00:00Z')
			);
			await seed(
				scope,
				{ targetId: 'middle' },
				new Date('2026-03-01T00:00:00Z')
			);
			await seed(
				scope,
				{ targetId: 'newest' },
				new Date('2026-06-01T00:00:00Z')
			);
			const { cookie } = await cookieFor(['super_admin']);

			const res = await client.admin.api.audit.get({
				query: { targetScope: scope },
				headers: { cookie }
			});

			expect((res.data as AuditPage).entries.map((e) => e.targetId)).toEqual([
				'newest',
				'middle',
				'oldest'
			]);
		});

		it('presents an absent scope as null and absent attributes as an empty list', async () => {
			const { cookie } = await cookieFor(['super_admin']);
			const targetId = unique('unscoped');
			await adminAuditStore.record({
				actorId: 'actor-1',
				actorEmail: 'one@x.io',
				action: 'settings.update',
				targetType: 'ApplicationConfig',
				targetId
			});

			const res = await client.admin.api.audit.get({
				query: { targetId },
				headers: { cookie }
			});

			const [entry] = (res.data as AuditPage).entries;
			expect(entry!.targetScope).toBeNull();
			expect(entry!.attributes).toEqual([]);
		});

		it('reports the page and page size it applied', async () => {
			const scope = unique('scope');
			await seed(scope);
			const { cookie } = await cookieFor(['super_admin']);

			const res = await client.admin.api.audit.get({
				query: { targetScope: scope },
				headers: { cookie }
			});

			const page = res.data as AuditPage;
			expect(page.page).toBe(1);
			expect(page.pageSize).toBe(50);
		});
	});

	describe('filters', () => {
		it('matches an actor by id or by email', async () => {
			const scope = unique('scope');
			await seed(scope, { actorId: 'a-one', actorEmail: 'one@x.io' });
			await seed(scope, { actorId: 'a-two', actorEmail: 'two@x.io' });
			const { cookie } = await cookieFor(['super_admin']);

			const byId = await client.admin.api.audit.get({
				query: { targetScope: scope, actor: 'a-one' },
				headers: { cookie }
			});
			const byEmail = await client.admin.api.audit.get({
				query: { targetScope: scope, actor: 'two@x.io' },
				headers: { cookie }
			});

			expect((byId.data as AuditPage).total).toBe(1);
			expect((byId.data as AuditPage).entries[0]!.actorId).toBe('a-one');
			expect((byEmail.data as AuditPage).total).toBe(1);
			expect((byEmail.data as AuditPage).entries[0]!.actorId).toBe('a-two');
		});

		it('matches action, target type, target id and scope, combining conjunctively', async () => {
			const scope = unique('scope');
			await seed(scope, { action: 'project.delete', targetId: 'p-gone' });
			await seed(scope, {
				action: 'enduser.delete',
				targetType: 'EndUser',
				targetId: 'u-gone'
			});
			const { cookie } = await cookieFor(['super_admin']);

			const byAction = await client.admin.api.audit.get({
				query: { targetScope: scope, action: 'project.delete' },
				headers: { cookie }
			});
			expect((byAction.data as AuditPage).total).toBe(1);

			const byType = await client.admin.api.audit.get({
				query: { targetScope: scope, targetType: 'EndUser' },
				headers: { cookie }
			});
			expect((byType.data as AuditPage).total).toBe(1);

			const byId = await client.admin.api.audit.get({
				query: { targetScope: scope, targetId: 'p-gone' },
				headers: { cookie }
			});
			expect((byId.data as AuditPage).total).toBe(1);

			// Conjunctive: both clauses match different entries, so together they match none.
			const both = await client.admin.api.audit.get({
				query: {
					targetScope: scope,
					action: 'project.delete',
					targetType: 'EndUser'
				},
				headers: { cookie }
			});
			expect((both.data as AuditPage).total).toBe(0);
		});

		it('still returns entries whose actor and target no longer exist', async () => {
			const scope = unique('scope');
			await seed(scope, {
				actorId: 'deleted-admin',
				actorEmail: 'gone@x.io',
				targetId: 'deleted-project'
			});
			const { cookie } = await cookieFor(['super_admin']);

			const res = await client.admin.api.audit.get({
				query: { targetScope: scope },
				headers: { cookie }
			});

			const [entry] = (res.data as AuditPage).entries;
			expect(entry!.actorEmail).toBe('gone@x.io');
			expect(entry!.targetId).toBe('deleted-project');
		});
	});

	describe('time window', () => {
		const january = new Date('2026-01-15T12:00:00Z');
		const march = new Date('2026-03-15T12:00:00Z');
		const june = new Date('2026-06-15T12:00:00Z');

		async function seedThree(scope: string) {
			await seed(scope, { targetId: 'jan' }, january);
			await seed(scope, { targetId: 'mar' }, march);
			await seed(scope, { targetId: 'jun' }, june);
		}

		it('bounds inclusively, with each bound usable alone', async () => {
			const scope = unique('scope');
			await seedThree(scope);
			const { cookie } = await cookieFor(['super_admin']);

			const since = await client.admin.api.audit.get({
				query: { targetScope: scope, from: march.toISOString() },
				headers: { cookie }
			});
			expect((since.data as AuditPage).entries.map((e) => e.targetId)).toEqual([
				'jun',
				'mar'
			]);

			const until = await client.admin.api.audit.get({
				query: { targetScope: scope, to: march.toISOString() },
				headers: { cookie }
			});
			expect((until.data as AuditPage).entries.map((e) => e.targetId)).toEqual([
				'mar',
				'jan'
			]);

			const between = await client.admin.api.audit.get({
				query: {
					targetScope: scope,
					from: '2026-02-01T00:00:00.000Z',
					to: '2026-05-01T00:00:00.000Z'
				},
				headers: { cookie }
			});
			expect(
				(between.data as AuditPage).entries.map((e) => e.targetId)
			).toEqual(['mar']);
		});

		// A window far from the newest end must be one request, not a walk back through the pages —
		// otherwise "what changed last March" is unanswerable on a long trail.
		it('reaches a window deep in the trail in a single request', async () => {
			const scope = unique('scope');
			await seed(scope, { targetId: 'deep' }, january);
			for (let i = 0; i < 60; i += 1) {
				await seed(scope, { targetId: `recent-${i}` }, june);
			}
			const { cookie } = await cookieFor(['super_admin']);

			const res = await client.admin.api.audit.get({
				query: {
					targetScope: scope,
					from: '2026-01-01T00:00:00.000Z',
					to: '2026-02-01T00:00:00.000Z'
				},
				headers: { cookie }
			});

			const page = res.data as AuditPage;
			expect(page.total).toBe(1);
			expect(page.entries[0]!.targetId).toBe('deep');
		});

		it('refuses a backwards window instead of returning an empty page', async () => {
			const { cookie } = await cookieFor(['super_admin']);

			const res = await client.admin.api.audit.get({
				query: {
					from: june.toISOString(),
					to: january.toISOString()
				},
				headers: { cookie }
			});

			expect(res.status).toBe(422);
			expect(
				JSON.stringify(res.error?.value ?? res.data).toLowerCase()
			).toContain('window');
		});

		it('refuses an unparseable bound', async () => {
			const { cookie } = await cookieFor(['super_admin']);

			const res = await client.admin.api.audit.get({
				query: { from: 'last-tuesday' },
				headers: { cookie }
			});

			expect(res.status).toBe(422);
		});
	});

	describe('paging', () => {
		it('yields every entry exactly once across pages when timestamps collide', async () => {
			const scope = unique('scope');
			const stamp = new Date('2026-04-04T04:04:04Z');
			const written: string[] = [];
			for (let i = 0; i < 7; i += 1) {
				written.push((await seed(scope, { targetId: `c-${i}` }, stamp))._id);
			}
			const { cookie } = await cookieFor(['super_admin']);

			const seen: string[] = [];
			for (const page of [1, 2, 3]) {
				const res = await client.admin.api.audit.get({
					query: { targetScope: scope, page: String(page), pageSize: '3' },
					headers: { cookie }
				});
				seen.push(...(res.data as AuditPage).entries.map((e) => e._id));
			}

			expect(seen).toHaveLength(7);
			expect(new Set(seen).size).toBe(7);
			expect(new Set(seen)).toEqual(new Set(written));
		});

		it('clamps an oversized page size rather than refusing it', async () => {
			const scope = unique('scope');
			await seed(scope);
			const { cookie } = await cookieFor(['super_admin']);

			const res = await client.admin.api.audit.get({
				query: { targetScope: scope, pageSize: '5000' },
				headers: { cookie }
			});

			expect(res.status).toBe(200);
			expect((res.data as AuditPage).pageSize).toBe(200);
		});

		it('treats a page below one as the first page', async () => {
			const scope = unique('scope');
			await seed(scope);
			const { cookie } = await cookieFor(['super_admin']);

			const res = await client.admin.api.audit.get({
				query: { targetScope: scope, page: '0' },
				headers: { cookie }
			});

			expect((res.data as AuditPage).page).toBe(1);
			expect((res.data as AuditPage).entries).toHaveLength(1);
		});

		it('returns an empty page past the end, with the real total', async () => {
			const scope = unique('scope');
			await seed(scope);
			const { cookie } = await cookieFor(['super_admin']);

			const res = await client.admin.api.audit.get({
				query: { targetScope: scope, page: '99' },
				headers: { cookie }
			});

			expect(res.status).toBe(200);
			expect((res.data as AuditPage).entries).toEqual([]);
			expect((res.data as AuditPage).total).toBe(1);
		});
	});

	describe('request validation and immutability', () => {
		// A mistyped filter must not silently answer with the unfiltered trail — the one failure mode
		// that turns an audit read into a wrong answer rather than an error.
		it('refuses an unknown query parameter', async () => {
			const { cookie } = await cookieFor(['super_admin']);

			const res = await client.admin.api.audit.get({
				query: { targetTyp: 'Project' } as unknown as Record<string, string>,
				headers: { cookie }
			});

			expect(res.status).toBe(422);
		});

		it('serves no mutating method on the trail', async () => {
			const { cookie } = await cookieFor(['super_admin']);
			const scope = unique('scope');
			const entry = await seed(scope);

			for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
				const res = await app.handle(
					new Request(`http://e.ly/admin/api/audit/${entry._id}`, {
						method,
						headers: { cookie }
					})
				);
				expect(res.status).toBe(404);
			}

			const bare = await app.handle(
				new Request('http://e.ly/admin/api/audit', {
					method: 'DELETE',
					headers: { cookie }
				})
			);
			expect(bare.status).toBe(404);

			// Still there.
			const after = await adminAuditStore.list({ targetScope: scope });
			expect(after.total).toBe(1);
		});
	});
});
