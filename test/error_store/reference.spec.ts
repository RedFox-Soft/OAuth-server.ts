import { describe, it, expect, beforeEach, afterEach } from 'bun:test';
import { Elysia } from 'elysia';

import { ApplicationConfig } from 'lib/configs/application.ts';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { errorRoutes } from 'lib/admin/errors/routes.ts';
import { errorHandler } from 'lib/shared/authorization_error_handler.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { adminSessionStore, getUserStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { flushForTest, resetQueue } from 'lib/error_store/queue.ts';
import { sessionFor } from '../admin_session.ts';

/*
 * US3 — matching a caller's complaint to a record.
 *
 * The end-to-end path is the point: take the reference out of the response a caller actually received,
 * hand it to the console, get that one record. A test that seeded a reference directly would prove the
 * lookup works while leaving the two halves free to disagree about the format.
 *
 * The negative cases carry equal weight. A reference must NOT appear where no record was made, and must
 * NOT appear in a redirect — a diagnostic handle in a URL ends up in browser history and at whatever
 * third party the redirect targets.
 */
const admin = new Elysia().use(resolveAdmin).use(errorRoutes);
const enabled = ApplicationConfig['errorStore.enabled'];

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

async function lookup(reference: string, cookie: string) {
	return admin.handle(
		new Request(
			`http://e.ly/admin/api/errors/reference/${encodeURIComponent(reference)}`,
			{ headers: { cookie } }
		)
	);
}

describe('error reference lookup', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
		ApplicationConfig['errorStore.enabled'] = true;
		resetQueue();
	});

	afterEach(() => {
		ApplicationConfig['errorStore.enabled'] = enabled;
	});

	it('resolves the reference a caller was handed to that one record', async () => {
		const route = unique('/ref');
		const faulting = new Elysia().onError(errorHandler).get(route, () => {
			throw new Error('the reported fault');
		});

		const response = await faulting.handle(new Request(`http://e.ly${route}`));
		const { error_reference: reference } = (await response.json()) as {
			error_reference: string;
		};
		await flushForTest();

		const found = await lookup(reference, await superCookie());
		const body = (await found.json()) as {
			group: { route: string; message: string };
			sample: { reference: string };
		};

		expect(found.status).toBe(200);
		expect(body.group.route).toBe(route);
		expect(body.sample.reference).toBe(reference);
		// The message the operator needs is on the group, and was never in the caller's response.
		expect(body.group.message).toContain('the reported fault');
	});

	/*
	 * "No such record" and not an empty page. An empty result would leave the operator unable to tell a
	 * mistyped reference from one whose record has aged out, and both from a store that is not recording.
	 */
	it('answers 404 for a reference that resolves to nothing', async () => {
		const cookie = await superCookie();
		const response = await lookup('err_AAAAAAAAAAAAAAAA', cookie);
		const body = (await response.json()) as { message?: string };

		expect(response.status).toBe(404);
		expect(body.message).toBe('no such error record');
	});

	// Refused before it reaches storage: an obviously malformed reference is not a query.
	it('refuses a malformed reference without searching', async () => {
		const cookie = await superCookie();
		const response = await lookup('not-a-reference', cookie);
		expect(response.status).toBe(404);
	});

	it('requires a super-admin', async () => {
		const response = await admin.handle(
			new Request('http://e.ly/admin/api/errors/reference/err_AAAAAAAAAAAAAAAA')
		);
		expect(response.status).toBe(401);

		const user = await getUserStore(ADMIN_BUCKET_ID).create(
			`${unique('plain')}@x.io`,
			'hash',
			['project_admin']
		);
		const session = await sessionFor(user);
		const refused = await lookup(
			'err_AAAAAAAAAAAAAAAA',
			`${ADMIN_SESSION_COOKIE}=${session._id}`
		);
		expect(refused.status).toBe(403);
	});

	describe('where a reference must not appear', () => {
		it('omits it from an unrecorded rejection', async () => {
			const app = new Elysia().onError(errorHandler);
			const response = await app.handle(
				new Request('http://e.ly/no-such-route-at-all')
			);
			const body = (await response.json()) as Record<string, string>;

			expect(response.status).toBe(404);
			expect(body.error_reference).toBeUndefined();
		});

		/*
		 * The redirect case. An authorization error that is handed back to the client by redirect must
		 * carry no reference in any part of the URL — not the query, not the fragment.
		 */
		it('omits it from a redirect back to a client', async () => {
			const route = unique('/redirecting');
			const app = new Elysia()
				.onError(errorHandler)
				.get(route, ({ redirect }) =>
					redirect('http://client.example/cb?error=server_error', 302)
				);

			const response = await app.handle(new Request(`http://e.ly${route}`));
			const location = response.headers.get('location') ?? '';

			expect(location).not.toContain('err_');
			expect(location).not.toContain('error_reference');
		});
	});
});
