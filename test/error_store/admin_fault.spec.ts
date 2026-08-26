import { describe, it, expect, beforeEach, afterEach, spyOn } from 'bun:test';
import { Elysia } from 'elysia';

import { ApplicationConfig } from 'lib/configs/application.ts';
import { errorStore } from 'lib/adapters/index.ts';
import { errorHandler } from 'lib/shared/authorization_error_handler.ts';
import { adminApp } from 'lib/admin/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminAuditStore,
	adminSessionStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { flushForTest, resetQueue } from 'lib/error_store/queue.ts';

/*
 * The second capture site.
 *
 * There are two, and the reason is easy to get backwards. The root error handler stands aside for
 * admin-plane errors — but it keys that on the `adminPlane` marker, which only a deliberate AdminError
 * carries. So:
 *
 *   - an unexpected fault inside an admin route carries no marker, reaches the root handler like any
 *     other, and is recorded there — but must be filed under the admin surface, not the OAuth one;
 *   - a 5xx AdminError never reaches the root handler at all, and is recorded by the admin plane's own
 *     handler instead.
 *
 * Without the second site the only faults the store would miss are the ones the admin plane took the
 * trouble to explain, which is precisely the wrong half to lose.
 *
 * The 5xx case is provoked the way it actually happens — the audit trail refusing a write, which
 * aborts the request with AuditUnavailableError — rather than by throwing from a route this spec
 * mounts. A route defined on an outer app is not inside adminApp's error scope, so it would never
 * reach the handler under test; the real trigger is the only faithful one.
 */
const app = new Elysia().onError(errorHandler).use(adminApp);

const enabled = ApplicationConfig['errorStore.enabled'];
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

describe('admin-plane fault capture', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
		ApplicationConfig['errorStore.enabled'] = true;
		resetQueue();
	});

	afterEach(() => {
		ApplicationConfig['errorStore.enabled'] = enabled;
	});

	it('records a 5xx AdminError under the admin surface, with a reference in its own body', async () => {
		// Spied in the test rather than beforeEach: only this case wants the trail broken.
		const spy = spyOn(adminAuditStore, 'record').mockImplementation(() => {
			throw new Error('trail is unavailable');
		});

		try {
			const response = await app.handle(
				new Request('http://e.ly/admin/api/projects', {
					method: 'POST',
					headers: {
						'content-type': 'application/json',
						cookie: await superCookie()
					},
					body: JSON.stringify({ name: unique('p'), slug: unique('s') })
				})
			);
			const body = (await response.json()) as Record<string, string>;
			await flushForTest();

			expect(response.status).toBe(500);
			// The admin plane's own shape is preserved; the reference is additive.
			expect(body.error).toBe('admin_error');
			expect(body.message).toContain('audit unavailable');
			expect(body.error_reference).toMatch(/^err_[A-Za-z0-9_-]{16}$/);

			const page = await errorStore.list({ route: '/admin/api/projects' });
			expect(page.total).toBe(1);
			expect(page.groups[0].surface).toBe('admin');
			expect(page.groups[0].errorCode).toBe('admin_error');
			// The record resolves from the reference the caller was handed.
			const hit = await errorStore.findByReference(body.error_reference);
			expect(hit?.group.surface).toBe('admin');
		} finally {
			spy.mockRestore();
		}
	});

	// A deliberate refusal is not a fault, whatever plane it comes from.
	it('records nothing for a 4xx AdminError', async () => {
		const response = await app.handle(
			new Request('http://e.ly/admin/api/projects', {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify({ name: 'x', slug: 'y' })
			})
		);
		const body = (await response.json()) as Record<string, string>;
		await flushForTest();

		expect(response.status).toBe(401);
		expect(body.error).toBe('admin_error');
		expect(body.error_reference).toBeUndefined();
	});
});
