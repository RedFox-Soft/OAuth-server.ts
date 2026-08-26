import { describe, it, expect, beforeEach, afterEach } from 'bun:test';
import { Elysia } from 'elysia';

import { ApplicationConfig } from 'lib/configs/application.ts';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { errorRoutes } from 'lib/admin/errors/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminSessionStore,
	errorStore,
	getUserStore
} from 'lib/adapters/index.ts';
import type { ErrorOccurrence } from 'lib/adapters/types.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';

/*
 * The analysis surface — US2. What makes a pile of records answer a question.
 *
 * The load-bearing property is that counts sum *occurrences*, not group rows: one fault seen nine times
 * must outrank nine faults seen once. A summary that counted rows would rank a quiet long tail above the
 * outage, which is the opposite of what an operator opens it for.
 *
 * Scoped per test by a unique route marker — the in-memory store is a process-wide singleton shared with
 * every other spec in the same `bun test` process.
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
	const session = await adminSessionStore.create({
		userId: user._id,
		bucketId: ADMIN_BUCKET_ID,
		tokens: {},
		ttlSeconds: 60,
		absoluteTtlSeconds: 3600
	});
	return `${ADMIN_SESSION_COOKIE}=${session._id}`;
}

async function seed(over: Partial<ErrorOccurrence> & { route: string }) {
	return errorStore.record(
		{
			fingerprint: over.fingerprint ?? unique('fp'),
			errorCode: 'server_error',
			status: 500,
			surface: 'oauth',
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

async function get(path: string, cookie?: string) {
	return app.handle(
		new Request(`http://e.ly${path}`, { headers: cookie ? { cookie } : {} })
	);
}

interface Summary {
	total: number;
	byErrorCode: { key: string; count: number }[];
	byRoute: { key: string; count: number }[];
	dropped: number;
	recording: boolean;
}

describe('error store analysis', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
		ApplicationConfig['errorStore.enabled'] = true;
	});

	afterEach(() => {
		ApplicationConfig['errorStore.enabled'] = enabled;
	});

	describe('GET /admin/api/errors/summary', () => {
		it('requires a super-admin', async () => {
			expect((await get('/admin/api/errors/summary')).status).toBe(401);

			const user = await getUserStore(ADMIN_BUCKET_ID).create(
				`${unique('plain')}@x.io`,
				'hash',
				['project_admin']
			);
			const session = await adminSessionStore.create({
				userId: user._id,
				bucketId: ADMIN_BUCKET_ID,
				tokens: {},
				ttlSeconds: 60,
				absoluteTtlSeconds: 3600
			});
			const response = await get(
				'/admin/api/errors/summary',
				`${ADMIN_SESSION_COOKIE}=${session._id}`
			);
			expect(response.status).toBe(403);
		});

		/*
		 * The ranking property, stated as the case that would break a row-counting implementation: one
		 * loud fault against several quiet ones.
		 */
		it('ranks by occurrences, not by number of distinct faults', async () => {
			const cookie = await superCookie();
			const loud = unique('/loud');
			const quiet = unique('/quiet');

			const loudPrint = unique('fp');
			for (let i = 0; i < 9; i += 1) {
				await seed({ route: loud, fingerprint: loudPrint });
			}
			for (let i = 0; i < 3; i += 1) {
				await seed({ route: quiet });
			}

			const response = await get('/admin/api/errors/summary', cookie);
			const body = (await response.json()) as Summary;

			expect(response.status).toBe(200);

			const loudAt = body.byRoute.findIndex((b) => b.key === loud);
			const quietAt = body.byRoute.findIndex((b) => b.key === quiet);
			expect(body.byRoute[loudAt]?.count).toBe(9);
			expect(body.byRoute[quietAt]?.count).toBe(3);
			// One fault nine times outranks three faults once each. Compared by position, so neither
			// bucket has to be asserted non-null to be ranked.
			expect(loudAt).toBeGreaterThanOrEqual(0);
			expect(loudAt).toBeLessThan(quietAt);
		});

		it('breaks down by error code as well as route', async () => {
			const cookie = await superCookie();
			const route = unique('/codes');
			await seed({ route, errorCode: 'server_error' });
			await seed({ route, errorCode: 'admin_error' });

			const body = (await get('/admin/api/errors/summary', cookie).then((r) =>
				r.json()
			)) as Summary;

			const codes = body.byErrorCode.map((b) => b.key);
			expect(codes).toContain('server_error');
			expect(codes).toContain('admin_error');
		});

		it('applies an inclusive window', async () => {
			const cookie = await superCookie();
			const route = unique('/window');
			await seed({ route });

			const future = new Date(Date.now() + 60_000).toISOString();
			const body = (await get(
				`/admin/api/errors/summary?from=${future}`,
				cookie
			).then((r) => r.json())) as Summary;

			expect(body.byRoute.find((b) => b.key === route)).toBeUndefined();
		});

		it('refuses a backwards window rather than reporting nothing failed', async () => {
			const cookie = await superCookie();
			const response = await get(
				'/admin/api/errors/summary?from=2026-02-01T00:00:00Z&to=2026-01-01T00:00:00Z',
				cookie
			);
			expect(response.status).toBe(422);
		});

		// The summary takes a window only, so a filter it cannot aggregate over must be refused rather
		// than silently ignored — an ignored filter answers about the whole store while looking scoped.
		it('refuses a filter it does not support', async () => {
			const cookie = await superCookie();
			const response = await get(
				'/admin/api/errors/summary?route=/somewhere',
				cookie
			);
			expect(response.status).toBe(422);
		});

		it('reports the dropped count and whether recording is on', async () => {
			const cookie = await superCookie();
			const body = (await get('/admin/api/errors/summary', cookie).then((r) =>
				r.json()
			)) as Summary;

			expect(body.dropped).toBe(0);
			expect(body.recording).toBe(true);
		});
	});

	describe('filters on the listing', () => {
		it('filters by every supported dimension', async () => {
			const cookie = await superCookie();
			const route = unique('/dims');
			await seed({ route, status: 500, surface: 'oauth' });
			await seed({ route, status: 502, surface: 'admin' });

			const byStatus = (await get(
				`/admin/api/errors?route=${route}&status=502`,
				cookie
			).then((r) => r.json())) as { total: number };
			expect(byStatus.total).toBe(1);

			const bySurface = (await get(
				`/admin/api/errors?route=${route}&surface=admin`,
				cookie
			).then((r) => r.json())) as { total: number };
			expect(bySurface.total).toBe(1);

			const byCode = (await get(
				`/admin/api/errors?route=${route}&errorCode=server_error`,
				cookie
			).then((r) => r.json())) as { total: number };
			expect(byCode.total).toBe(2);
		});

		it('filters by client and by actor on either arm', async () => {
			const cookie = await superCookie();
			const route = unique('/who');
			await seed({
				route,
				record: {
					reference: unique('err'),
					at: new Date(),
					clientId: 'client-alpha',
					actor: { id: 'admin-9', email: 'ops9@x.io' },
					scope: null,
					requestId: null,
					origin: null,
					userAgent: null,
					submittedFields: []
				}
			});
			await seed({ route });

			const byClient = (await get(
				`/admin/api/errors?route=${route}&clientId=client-alpha`,
				cookie
			).then((r) => r.json())) as { total: number };
			expect(byClient.total).toBe(1);

			for (const actor of ['admin-9', 'ops9@x.io']) {
				const byActor = (await get(
					`/admin/api/errors?route=${route}&actor=${encodeURIComponent(actor)}`,
					cookie
				).then((r) => r.json())) as { total: number };
				expect(byActor.total).toBe(1);
			}
		});

		/*
		 * The total-order property at the layer an operator actually meets it. Every group shares a
		 * timestamp here, so without the `_id` tiebreaker paging drops or repeats a row.
		 */
		it('pages without dropping or repeating a group', async () => {
			const cookie = await superCookie();
			const route = unique('/paging');
			for (let i = 0; i < 5; i += 1) {
				await seed({ route });
			}

			const seen: string[] = [];
			for (let offset = 0; offset < 5; offset += 1) {
				const page = (await get(
					`/admin/api/errors?route=${route}&limit=1&offset=${offset}`,
					cookie
				).then((r) => r.json())) as { groups: { _id: string }[] };
				seen.push(page.groups[0]._id);
			}

			expect(new Set(seen).size).toBe(5);
		});
	});
});
