import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';

import { resolveAdmin, AdminError } from 'lib/admin/auth/rbac.ts';
import { projectRoutes } from 'lib/admin/projects/routes.ts';
import { clientRoutes } from 'lib/admin/clients/routes.ts';
import { adminUserRoutes } from 'lib/admin/users/routes.ts';
import { bucketRoutes } from 'lib/admin/buckets/routes.ts';
import { federationAdminRoutes } from 'lib/admin/federation/routes.ts';
import { endUserRoutes } from 'lib/admin/users-end/routes.ts';
import { settingsRoutes } from 'lib/admin/settings/routes.ts';
import { smtpSettingsRoutes } from 'lib/admin/settings/smtp/routes.ts';
import { jwksRoutes } from 'lib/admin/jwks/routes.ts';
import { auditRoutes } from 'lib/admin/audit/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminSessionStore,
	getUserStore,
	getProjectStore
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';

/*
 * The dispatch contract: what a composition of the admin route plugins does and does not carry.
 *
 * Written as the blocking spike for specs/024-admin-mcp-control-plane and kept, rather than deleted,
 * because it is the only place two facts are pinned directly. Neither is visible from the MCP tests,
 * which see the assembled surface and would not say *why* it is assembled this way:
 *
 * 1. Each route group owns the `AdminError` -> `{ error: 'admin_error', message }` arm, so a composition
 *    inherits it — structured `blockers` included.
 * 2. No group owns the `VALIDATION` -> 422 arm. A bare composition answers a validation failure in
 *    Elysia's own shape, which is why `lib/admin/routes.ts` carries that arm for both of its consumers.
 *    Delete this file and someone will eventually "simplify" that arm away.
 *
 * It also records the measurement behind mounting the plugins rather than `lib/admin/index.ts`: the
 * latter pulls `renderAdminShell`, and with it React and antd's CSS-in-JS, at ~86s to import against
 * ~350ms for the plugins.
 */

// Mirrors the root instance's options, which is part of what is under test.
const composed = new Elysia({ strictPath: true, normalize: false })
	.use(resolveAdmin)
	.use(projectRoutes)
	.use(clientRoutes)
	.use(adminUserRoutes)
	.use(bucketRoutes)
	.use(federationAdminRoutes)
	.use(endUserRoutes)
	.use(settingsRoutes)
	.use(smtpSettingsRoutes)
	.use(jwksRoutes)
	.use(auditRoutes);

// The same composition plus the one arm `adminApp` adds that no route group owns. Proving the
// difference is the point: if the arm is needed, the dispatcher must carry it.
const withValidationArm = new Elysia({ strictPath: true, normalize: false })
	.onError(({ code, error, set }) => {
		if (code === 'VALIDATION') {
			set.status = 422;
			return { error: 'invalid_request', message: error.message };
		}
	})
	.use(resolveAdmin)
	.use(projectRoutes)
	.use(bucketRoutes);

async function sessionCookieFor(roles: string[]) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`spike-${roles.join('-')}-${Math.random()}@x.io`,
		'hash',
		roles
	);
	const s = await adminSessionStore.create({
		userId: user._id,
		bucketId: ADMIN_BUCKET_ID,
		tokens: {},
		ttlSeconds: 60,
		absoluteTtlSeconds: 3600
	});
	return { cookie: `${ADMIN_SESSION_COOKIE}=${s._id}`, userId: user._id };
}

function get(app: Elysia, path: string, cookie?: string) {
	return app.handle(
		new Request(`http://e.ly${path}`, {
			headers: cookie ? { cookie } : {}
		})
	);
}

function post(app: Elysia, path: string, body: unknown, cookie?: string) {
	return app.handle(
		new Request(`http://e.ly${path}`, {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				...(cookie ? { cookie } : {})
			},
			body: JSON.stringify(body)
		})
	);
}

describe('in-process re-dispatch into the admin routes', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	// Q1. Does `.handle(new Request(...))` reach a route at all outside the root instance?
	it('routes a Request to a mounted admin handler', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const res = await get(composed, '/admin/api/projects', cookie);
		expect(res.status).toBe(200);
		expect(await res.json()).toBeArray();
	});

	// Q2. Does the `resolveAdmin` scoped derive run, and does authorization actually bite?
	it('runs the resolveAdmin derive: no cookie is 401, wrong role is 403', async () => {
		const anon = await get(composed, '/admin/api/projects');
		expect(anon.status).toBe(401);

		// `/admin/api/admins` is role-gated. `/admin/api/buckets` deliberately is NOT — it is
		// scope-filtered (a non-super-admin gets the buckets they manage), which is why it answers
		// 200 with a narrower list rather than 403.
		const { cookie } = await sessionCookieFor(['project_admin']);
		const forbidden = await get(composed, '/admin/api/admins', cookie);
		expect(forbidden.status).toBe(403);

		const scoped = await get(composed, '/admin/api/buckets', cookie);
		expect(scoped.status).toBe(200);
		expect(await scoped.json()).toEqual([]);
	});

	// Q3. Does the AdminError -> `{ error: 'admin_error', message }` mapping survive? Each route
	// group owns this arm itself, so the expectation is yes — and that is worth pinning, because it
	// means the dispatcher does not have to reproduce it.
	it('maps AdminError to the admin_error body with its status', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const res = await get(composed, '/admin/api/projects/nope', cookie);
		expect(res.status).toBe(404);
		expect(await res.json()).toEqual({
			error: 'admin_error',
			message: 'project not found'
		});
	});

	it('carries structured blockers through the admin_error body', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		expect(new AdminError(409, 'x', { blockers: [] }).adminPlane).toBe(true);

		const proj = await getProjectStore().create({
			name: 'Spike',
			slug: `spike-${Math.random()}`.replace(/[^a-z0-9-]/g, ''),
			managedBy: []
		});
		const created = await post(
			composed,
			`/admin/api/projects/${proj._id}/clients`,
			{
				clientName: 'SPA',
				grantTypes: ['authorization_code'],
				redirectUris: ['https://a.example.com/cb'],
				tokenEndpointAuthMethod: 'none'
			},
			cookie
		);
		expect(created.status).toBe(201);

		const refused = await composed.handle(
			new Request(`http://e.ly/admin/api/projects/${proj._id}`, {
				method: 'DELETE',
				headers: { cookie }
			})
		);
		expect(refused.status).toBe(409);
		const body = (await refused.json()) as {
			error: string;
			blockers?: { kind: string; count: number; ids?: string[] }[];
		};
		expect(body.error).toBe('admin_error');
		expect(body.blockers?.[0]?.kind).toBe('client');
		expect(body.blockers?.[0]?.count).toBe(1);
		expect(body.blockers?.[0]?.ids).toBeArray();
	});

	// Q4. The VALIDATION -> 422 arm. It lives only on `adminApp`, so a bare composition should NOT
	// produce 422 — and the composition that carries the arm should.
	it('needs the VALIDATION arm: bare composition does not 422, with the arm it does', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const bad = { slug: 'no-name-field' };

		const bare = await post(composed, '/admin/api/projects', bad, cookie);
		const armed = await post(
			withValidationArm,
			'/admin/api/projects',
			bad,
			cookie
		);

		expect(armed.status).toBe(422);
		expect(await armed.json()).toMatchObject({ error: 'invalid_request' });

		// The finding: the bare composition answers Elysia's own default for a validation error,
		// NOT the admin plane's 422 shape. So `lib/mcp/dispatch.ts` must carry this arm.
		expect(bare.status).toBe(422);
		const bareBody = await bare.json();
		expect(bareBody).not.toMatchObject({ error: 'invalid_request' });
	});

	// Q5. strictPath / normalize:false semantics, which the root instance sets and the dispatcher
	// must not silently relax.
	it('honours strictPath: a trailing slash is not the same route', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const exact = await get(composed, '/admin/api/projects', cookie);
		const slashed = await get(composed, '/admin/api/projects/', cookie);
		expect(exact.status).toBe(200);
		expect(slashed.status).not.toBe(200);
	});

	// Q6. The route inventory the drift guard (T006) will compare against.
	it('exposes the mounted route set for the drift guard', () => {
		const api = composed.routes.filter((r) => r.path.startsWith('/admin/api'));
		expect(api.length).toBe(43);

		// The three /admin/api routes NOT in any route plugin. Two are excluded from MCP anyway;
		// `GET /admin/api/me` is not, and the whoami tool needs it — so it must be extracted from
		// lib/admin/index.ts into a plugin both adminApp and the dispatcher can mount.
		const paths = new Set(api.map((r) => `${r.method} ${r.path}`));
		expect(paths.has('GET /admin/api/me')).toBe(false);
		expect(paths.has('POST /admin/api/setup')).toBe(false);
		expect(paths.has('POST /admin/api/logout')).toBe(false);
	});
});
