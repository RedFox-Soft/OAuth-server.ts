import { describe, it, expect, beforeEach, afterEach, spyOn } from 'bun:test';
import { Elysia } from 'elysia';

import { ApplicationConfig } from 'lib/configs/application.ts';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { errorRoutes } from 'lib/admin/errors/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminAuditStore,
	adminSessionStore,
	errorStore,
	getUserStore
} from 'lib/adapters/index.ts';
import type { ErrorOccurrence } from 'lib/adapters/types.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { sessionFor } from '../admin_session.ts';

/*
 * US4 — the purge, and what the trail says about it.
 *
 * Two properties carry the weight. The preview and the purge must describe the same set, which is why
 * they share one query schema rather than each parsing filters their own way. And the purge is
 * audit-first: the entry precedes the deletion, so a trail that refuses a write aborts the request and
 * nothing is destroyed. The alternative — delete, then record — means a trail failure loses the only
 * account of what happened.
 *
 * A consequence worth stating, because it is visible in the trail: the entry written *before* the purge
 * can only ever state an intention. What was actually removed is a second entry under the same action.
 */
const app = new Elysia().use(resolveAdmin).use(errorRoutes);
const enabled = ApplicationConfig['errorStore.enabled'];
const bounds = { retentionDays: 30, maxGroups: 1000, samplesPerGroup: 10 };

let seq = 0;
const unique = (prefix: string) => `${prefix}-${Date.now()}-${(seq += 1)}`;

async function superCookie() {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`${unique('super')}@x.io`,
		'hash',
		['super_admin']
	);
	const session = await sessionFor(user);
	return `${ADMIN_SESSION_COOKIE}=${session._id}`;
}

async function seed(route: string, over: Partial<ErrorOccurrence> = {}) {
	return errorStore.record(
		{
			fingerprint: over.fingerprint ?? unique('fp'),
			errorCode: 'server_error',
			status: 500,
			surface: 'oauth',
			route,
			method: 'POST',
			origin: { file: 'lib/x.ts', line: 1, frame: 'f()' },
			message: 'seeded',
			record: {
				reference: unique('err'),
				at: new Date(),
				clientId: null,
				actor: null,
				scope: null,
				requestId: null,
				origin: null,
				userAgent: null,
				submittedFields: []
			},
			...over
		},
		bounds
	);
}

async function call(method: string, path: string, cookie?: string) {
	return app.handle(
		new Request(`http://e.ly${path}`, {
			method,
			headers: cookie ? { cookie } : {}
		})
	);
}

async function purgeEntriesFor(targetId: string) {
	const page = await adminAuditStore.list({
		action: 'error.purge',
		targetId
	});
	return page.entries;
}

describe('error store purge', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
		ApplicationConfig['errorStore.enabled'] = true;
	});

	afterEach(() => {
		ApplicationConfig['errorStore.enabled'] = enabled;
	});

	describe('preview', () => {
		it('reports what a filter would remove without removing it', async () => {
			const cookie = await superCookie();
			const route = unique('/prev');
			const print = unique('fp');
			await seed(route, { fingerprint: print });
			await seed(route, { fingerprint: print });
			await seed(route);

			const response = await call(
				'GET',
				`/admin/api/errors/purge-preview?route=${route}`,
				cookie
			);
			const body = (await response.json()) as {
				groups: number;
				occurrences: number;
			};

			expect(response.status).toBe(200);
			expect(body.groups).toBe(2);
			expect(body.occurrences).toBe(3);
			// Nothing went.
			expect((await errorStore.list({ route })).total).toBe(2);
		});

		it('requires a super-admin', async () => {
			expect(
				(await call('GET', '/admin/api/errors/purge-preview')).status
			).toBe(401);
		});
	});

	describe('purge', () => {
		it('removes exactly what the preview described', async () => {
			const cookie = await superCookie();
			const keep = unique('/keep');
			const drop = unique('/drop');
			await seed(drop);
			await seed(drop);
			await seed(keep);

			const preview = (await call(
				'GET',
				`/admin/api/errors/purge-preview?route=${drop}`,
				cookie
			).then((r) => r.json())) as { groups: number };

			const response = await call(
				'DELETE',
				`/admin/api/errors?route=${drop}`,
				cookie
			);
			const body = (await response.json()) as { removed: number };

			expect(response.status).toBe(200);
			expect(body.removed).toBe(preview.groups);
			expect((await errorStore.list({ route: drop })).total).toBe(0);
			// Scoped: everything outside the filter survives.
			expect((await errorStore.list({ route: keep })).total).toBe(1);
		});

		/*
		 * Deleting everything must be an explicit act. An empty filter is far more often a caller bug than
		 * an intention, and the cost of guessing wrong is the whole store.
		 */
		it('refuses a purge with no filter at all', async () => {
			const cookie = await superCookie();
			const response = await call('DELETE', '/admin/api/errors', cookie);
			const body = (await response.json()) as { message: string };

			expect(response.status).toBe(422);
			expect(body.message).toContain('filter');
		});

		it('refuses a non-super-admin and an unauthenticated caller', async () => {
			expect((await call('DELETE', '/admin/api/errors?route=/x')).status).toBe(
				401
			);

			const user = await getUserStore(ADMIN_BUCKET_ID).create(
				`${unique('plain')}@x.io`,
				'hash',
				['project_admin']
			);
			const session = await sessionFor(user);
			const refused = await call(
				'DELETE',
				'/admin/api/errors?route=/x',
				`${ADMIN_SESSION_COOKIE}=${session._id}`
			);
			expect(refused.status).toBe(403);
		});

		it('refuses an unknown query parameter rather than purging more than asked', async () => {
			const cookie = await superCookie();
			const response = await call(
				'DELETE',
				'/admin/api/errors?rout=/typo',
				cookie
			);
			expect(response.status).toBe(422);
		});
	});

	describe('the audit trail', () => {
		it('records the authorized attempt and what it removed', async () => {
			const cookie = await superCookie();
			const route = unique('/audited');
			await seed(route);
			await seed(route);

			const response = await call(
				'DELETE',
				`/admin/api/errors?route=${route}`,
				cookie
			);
			const body = (await response.json()) as {
				removed: number;
				purgeId: string;
			};

			const entries = await purgeEntriesFor(body.purgeId);
			// Two: the intention, then the outcome. The trail has no update path, so an entry written
			// before the deletion cannot later be told how much went.
			expect(entries).toHaveLength(2);
			expect(entries.every((e) => e.action === 'error.purge')).toBe(true);

			const attributes = entries.flatMap((e) => e.attributes ?? []);
			// The filter is recorded by field NAME, never its value — same rule as every other entry.
			expect(attributes).toContain('route');
			expect(attributes).toContain(`removed=${body.removed}`);
		});

		/*
		 * Audit-first, asserted by its consequence rather than its ordering: with the trail refusing
		 * writes, the request fails AND the records are still there. Recording after deleting would pass
		 * a test that only checked the status.
		 */
		it('deletes nothing when the trail refuses the entry', async () => {
			const cookie = await superCookie();
			const route = unique('/trail-down');
			await seed(route);

			const spy = spyOn(adminAuditStore, 'record').mockImplementation(() => {
				throw new Error('trail is unavailable');
			});

			try {
				const response = await call(
					'DELETE',
					`/admin/api/errors?route=${route}`,
					cookie
				);
				expect(response.status).toBe(500);
				expect((await errorStore.list({ route })).total).toBe(1);
			} finally {
				spy.mockRestore();
			}
		});
	});

	/*
	 * FR-010: an error record is not an administrative action and must never be written into the trail.
	 * True by construction today — nothing calls recordAdminAudit for a fault — so this is what stops a
	 * later refactor from breaking it silently.
	 */
	it('never files a fault itself as an audit entry', async () => {
		const route = unique('/not-audited');
		await seed(route);

		const page = await adminAuditStore.list({ targetType: 'ErrorRecord' });
		// Only purges name this target type; recording a fault writes nothing here.
		expect(page.entries.every((e) => e.action === 'error.purge')).toBe(true);
	});
});
