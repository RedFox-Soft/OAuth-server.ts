import { describe, it, expect, beforeEach, afterEach } from 'bun:test';
import { Elysia } from 'elysia';

import { ApplicationConfig } from 'lib/configs/application.ts';
import { errorHandler } from 'lib/shared/authorization_error_handler.ts';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { errorRoutes } from 'lib/admin/errors/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminSessionStore,
	errorStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { flushForTest, resetQueue } from 'lib/error_store/queue.ts';

/*
 * What the capability switch does, and — as importantly — what it deliberately does NOT do.
 *
 * It does not hide the endpoint. Every other capability on this server gates its routes, and this one
 * looked like it should too, but the admin operation set is invariant under capability switches: `/admin`
 * is an alwaysAvailablePrefixes entry so that (for instance) a federation provider stays deletable by a
 * deployment that has just switched federation off, and test/mcp/capability_invariance.spec.ts holds that
 * property. Gating an admin path would also split this surface from the agent one, which re-dispatches
 * into these same routes without the gate plugin — the console would answer 404 where an agent answered
 * 403 for the identical call.
 *
 * So the switch is reported rather than enforced at the router: `recording: false` says the store is not
 * being written, which is what stops an empty page from being read as "nothing has failed".
 */
const app = new Elysia()
	.onError(errorHandler)
	.use(resolveAdmin)
	.use(errorRoutes);

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

async function list(cookie: string) {
	const response = await app.handle(
		new Request('http://e.ly/admin/api/errors', { headers: { cookie } })
	);
	return {
		status: response.status,
		body: (await response.json()) as {
			total: number;
			dropped: number;
			recording: boolean;
		}
	};
}

describe('error store capability switch', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
		resetQueue();
	});

	afterEach(() => {
		ApplicationConfig['errorStore.enabled'] = enabled;
	});

	it('keeps serving the surface while switched off, and says recording is off', async () => {
		ApplicationConfig['errorStore.enabled'] = false;
		const { status, body } = await list(await superCookie());

		expect(status).toBe(200);
		// The distinction the flag exists to preserve: not recording is not the same as nothing failing.
		expect(body.recording).toBe(false);
	});

	it('reports recording on once switched on', async () => {
		ApplicationConfig['errorStore.enabled'] = true;
		const { status, body } = await list(await superCookie());

		expect(status).toBe(200);
		expect(body.recording).toBe(true);
	});

	// The switch still governs writes: off means nothing is recorded, whatever the surface answers.
	it('writes nothing while switched off', async () => {
		ApplicationConfig['errorStore.enabled'] = false;

		const faulting = new Elysia().onError(errorHandler).get('/gate-off', () => {
			throw new Error('unrecorded while off');
		});
		const response = await faulting.handle(new Request('http://e.ly/gate-off'));
		const body = (await response.json()) as Record<string, string>;
		await flushForTest();

		expect(response.status).toBe(500);
		// No record was made, so there is no reference to hand out — the two go together by construction.
		expect(body.error_reference).toBeUndefined();
		expect((await errorStore.list({ route: '/gate-off' })).total).toBe(0);
	});

	it('records again once switched back on', async () => {
		ApplicationConfig['errorStore.enabled'] = true;
		const route = unique('/gate-on');

		const faulting = new Elysia().onError(errorHandler).get(route, () => {
			throw new Error('recorded while on');
		});
		await faulting.handle(new Request(`http://e.ly${route}`));
		await flushForTest();

		expect((await errorStore.list({ route })).total).toBe(1);
	});

	// Authorization is unaffected by the switch: the surface is super-admin only either way.
	it('still refuses an unauthenticated caller while switched off', async () => {
		ApplicationConfig['errorStore.enabled'] = false;

		const response = await app.handle(
			new Request('http://e.ly/admin/api/errors')
		);
		expect(response.status).toBe(401);
	});
});
