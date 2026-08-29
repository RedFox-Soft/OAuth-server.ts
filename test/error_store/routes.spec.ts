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
import { sessionFor } from '../admin_session.ts';

/*
 * The read surface — specs/025-server-error-store/contracts/admin-api.md.
 *
 * Every assertion is scoped to faults this spec wrote, by a per-test route marker: the in-memory store
 * is a process-wide singleton and other specs in the same `bun test` process record into it too.
 *
 * The load-bearing cases are the ones where an empty page would be a lie — an unknown query parameter
 * is refused rather than silently answered with the unfiltered store, and a backwards window is refused
 * rather than answered with nothing.
 */
const app = new Elysia().use(resolveAdmin).use(errorRoutes);
const enabled = ApplicationConfig['errorStore.enabled'];

let seq = 0;
const unique = (prefix: string) => `${prefix}-${Date.now()}-${(seq += 1)}`;

async function cookieFor(roles: string[]) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`${unique('admin')}@x.io`,
		'hash',
		roles
	);
	const session = await sessionFor(user);
	return `${ADMIN_SESSION_COOKIE}=${session._id}`;
}

const bounds = { retentionDays: 30, maxGroups: 1000, samplesPerGroup: 10 };
/* Narrows an optional the test has already established is present, so no assertion is needed. */
function must<T>(value: T | undefined | null, what: string): T {
	if (value === null || value === undefined) {
		throw new Error(`expected ${what} to be present`);
	}
	return value;
}

async function seedFault(route: string, over: Partial<ErrorOccurrence> = {}) {
	return errorStore.record(
		{
			fingerprint: unique('fp'),
			errorCode: 'server_error',
			status: 500,
			surface: 'oauth',
			route,
			method: 'POST',
			origin: { file: 'lib/x.ts', line: 1, frame: 'f()' },
			message: 'seeded fault',
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
		new Request(`http://e.ly${path}`, {
			headers: cookie ? { cookie } : {}
		})
	);
}

describe('GET /admin/api/errors', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
		ApplicationConfig['errorStore.enabled'] = true;
	});

	afterEach(() => {
		ApplicationConfig['errorStore.enabled'] = enabled;
	});

	describe('authorization', () => {
		it('refuses an unauthenticated caller', async () => {
			const route = unique('/r');
			await seedFault(route);

			const response = await get(`/admin/api/errors?route=${route}`);
			expect(response.status).toBe(401);
		});

		/*
		 * The refusal must be identical whether or not matching records exist, or the status itself
		 * becomes an oracle: an administrator without the privilege could learn what is failing by
		 * watching which requests are refused differently.
		 */
		it('refuses a non-super-admin without disclosing whether records exist', async () => {
			const cookie = await cookieFor(['project_admin']);
			const withRecords = unique('/r');
			await seedFault(withRecords);
			const withoutRecords = unique('/r');

			const populated = await get(
				`/admin/api/errors?route=${withRecords}`,
				cookie
			);
			const empty = await get(
				`/admin/api/errors?route=${withoutRecords}`,
				cookie
			);

			expect(populated.status).toBe(403);
			expect(empty.status).toBe(403);
			expect(await populated.text()).toBe(await empty.text());
		});

		it('serves a super-admin', async () => {
			const cookie = await cookieFor(['super_admin']);
			const route = unique('/r');
			await seedFault(route);

			const response = await get(`/admin/api/errors?route=${route}`, cookie);
			expect(response.status).toBe(200);
		});
	});

	describe('listing', () => {
		it('returns matching groups with a total independent of the limit', async () => {
			const cookie = await cookieFor(['super_admin']);
			const route = unique('/r');
			await seedFault(route);
			await seedFault(route);
			await seedFault(route);

			const response = await get(
				`/admin/api/errors?route=${route}&limit=2`,
				cookie
			);
			const body = (await response.json()) as {
				groups: unknown[];
				total: number;
				dropped: number;
			};

			expect(body.groups).toHaveLength(2);
			expect(body.total).toBe(3);
			// Always present, so an operator is never left assuming completeness.
			expect(body.dropped).toBe(0);
		});

		it('refuses an unknown query parameter rather than answering unfiltered', async () => {
			const cookie = await cookieFor(['super_admin']);

			const response = await get(
				'/admin/api/errors?rout=/typo-in-the-name',
				cookie
			);
			const body = (await response.json()) as { message: string };

			expect(response.status).toBe(422);
			expect(body.message).toContain('rout');
		});

		it('refuses a backwards window rather than answering with nothing', async () => {
			const cookie = await cookieFor(['super_admin']);

			const response = await get(
				'/admin/api/errors?from=2026-02-01T00:00:00Z&to=2026-01-01T00:00:00Z',
				cookie
			);
			expect(response.status).toBe(422);
		});

		it('refuses an unparseable date', async () => {
			const cookie = await cookieFor(['super_admin']);
			const response = await get('/admin/api/errors?from=not-a-date', cookie);
			expect(response.status).toBe(422);
		});
	});

	describe('detail', () => {
		it('returns one group with its samples', async () => {
			const cookie = await cookieFor(['super_admin']);
			const route = unique('/r');
			const created = must(await seedFault(route), 'the seeded group');

			const response = await get(`/admin/api/errors/${created._id}`, cookie);
			const body = (await response.json()) as {
				_id: string;
				samples: unknown[];
			};

			expect(response.status).toBe(200);
			expect(body._id).toBe(created._id);
			expect(body.samples).toHaveLength(1);
		});

		it('answers 404 for an unknown id', async () => {
			const cookie = await cookieFor(['super_admin']);
			const response = await get('/admin/api/errors/no-such-group', cookie);
			expect(response.status).toBe(404);
		});

		/*
		 * The literal paths under /admin/api/errors must not be swallowed by the :id route. The failure
		 * mode is silent — a 404 that reads as a missing record rather than as a route the server never
		 * reached — so it is asserted positively: `summary` answers as itself.
		 */
		it('does not treat a reserved sub-path as a group id', async () => {
			const cookie = await cookieFor(['super_admin']);
			const response = await get('/admin/api/errors/summary', cookie);
			const body = (await response.json()) as { byRoute?: unknown[] };

			expect(response.status).toBe(200);
			expect(Array.isArray(body.byRoute)).toBe(true);
		});
	});
});
