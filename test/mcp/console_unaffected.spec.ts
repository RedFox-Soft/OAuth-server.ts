import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	getUserStore,
	getProjectStore,
	getBucketStore,
	adminSessionStore,
	adminAuditStore
} from 'lib/adapters/index.ts';
import {
	ADMIN_BUCKET_ID,
	ADMIN_SESSION_COOKIE,
	UNASSIGNED_GROUP_ID
} from 'lib/admin/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { sessionFor } from '../admin_session.ts';

/*
 * FR-036: the console keeps both container deletions in full, and nothing about the agent surface
 * weakens what a human operator can do.
 *
 * This is a regression guard over shared code, not a feature test. Adding the MCP surface changed three
 * things the console depends on — `resolveAdmin` learned a second credential type, `recordAdminAudit`
 * learned two more fields, and the admin route set moved into its own module. Each was verified when it
 * landed; this file is what notices if a later change to any of them takes the console with it.
 *
 * It runs with `mcp.enabled` both on and off, because the console must be unaffected either way.
 */

async function cookieFor(roles: string[]) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`console-${roles.join('-')}-${Math.random()}@x.io`,
		'hash',
		roles
	);
	const s = await sessionFor(user);
	return { cookie: `${ADMIN_SESSION_COOKIE}=${s._id}`, user };
}

function admin(
	path: string,
	init: { method?: string; cookie?: string; body?: unknown } = {}
) {
	return elysia.handle(
		new Request(`http://e.ly${path}`, {
			method: init.method ?? 'GET',
			headers: {
				...(init.cookie ? { cookie: init.cookie } : {}),
				...(init.body !== undefined
					? { 'content-type': 'application/json' }
					: {})
			},
			...(init.body !== undefined ? { body: JSON.stringify(init.body) } : {})
		})
	);
}

function slug() {
	return `con-${Math.floor(Math.random() * 1e6)}`;
}

describe.each([
	['mcp.enabled on', true],
	['mcp.enabled off', false]
])('console is unaffected (%s)', (_label, mcpEnabled) => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		ApplicationConfig['mcp.enabled'] = mcpEnabled;
		await ensureAdminSeed();
	});

	it('still deletes an empty project', async () => {
		const { cookie } = await cookieFor(['super_admin']);
		const project = await getProjectStore().create({
			name: 'Deletable',
			slug: slug(),
			ownerGroupId: UNASSIGNED_GROUP_ID
		});

		const res = await admin(`/admin/api/projects/${project._id}`, {
			method: 'DELETE',
			cookie
		});
		expect(res.status).toBe(200);
		expect(await getProjectStore().find(project._id)).toBeNull();
	});

	it('still deletes an empty bucket', async () => {
		const { cookie } = await cookieFor(['super_admin']);
		const created = await admin('/admin/api/buckets', {
			method: 'POST',
			cookie,
			body: { name: 'Deletable bucket' }
		});
		expect(created.status).toBe(201);
		const bucket = (await created.json()) as { _id: string };

		const res = await admin(`/admin/api/buckets/${bucket._id}`, {
			method: 'DELETE',
			cookie
		});
		expect(res.status).toBe(200);
		expect(await getBucketStore().find(bucket._id)).toBeNull();
	});

	it('still refuses a populated project with its structured blockers', async () => {
		const { cookie } = await cookieFor(['super_admin']);
		const project = await getProjectStore().create({
			name: 'Populated',
			slug: slug(),
			ownerGroupId: UNASSIGNED_GROUP_ID
		});
		const created = await admin(`/admin/api/projects/${project._id}/clients`, {
			method: 'POST',
			cookie,
			body: {
				clientName: 'SPA',
				grantTypes: ['authorization_code'],
				redirectUris: ['https://a.example.com/cb'],
				tokenEndpointAuthMethod: 'none'
			}
		});
		expect(created.status).toBe(201);

		const refused = await admin(`/admin/api/projects/${project._id}`, {
			method: 'DELETE',
			cookie
		});
		expect(refused.status).toBe(409);
		const body = (await refused.json()) as {
			error: string;
			blockers?: { kind: string; count: number; ids?: string[] }[];
		};
		expect(body.error).toBe('admin_error');
		expect(body.blockers?.[0]?.kind).toBe('client');
		expect(body.blockers?.[0]?.ids).toBeArray();
	});

	it('resolves a cookie-authenticated administrator exactly as before', async () => {
		const { cookie, user } = await cookieFor(['super_admin']);

		const res = await admin('/admin/api/me', { cookie });
		expect(res.status).toBe(200);
		const me = (await res.json()) as Record<string, unknown>;

		expect(me.userId).toBe(user._id);
		expect(me.email).toBe(user.email);
		expect(me.roles).toEqual(['super_admin']);
		expect(me.bucketId).toBe(ADMIN_BUCKET_ID);
		// `managedProjectIds` was replaced by group memberships when ownership moved to groups.
		expect(me.memberships).toBeArray();
		expect(me.activeGroupId).toBeString();
		// The agent marker must be absent for a console session, or every audit entry it writes would
		// claim an agent was involved.
		expect(me.viaClientId).toBeUndefined();
	});

	it('writes console audit entries with no agent attribution', async () => {
		const { cookie, user } = await cookieFor(['super_admin']);

		const created = await admin('/admin/api/projects', {
			method: 'POST',
			cookie,
			body: { name: 'Audited by console', slug: slug() }
		});
		expect(created.status).toBe(201);

		const { entries } = await adminAuditStore.list({ actor: user._id });
		expect(entries.length).toBe(1);
		expect(entries[0].viaSurface ?? null).toBeNull();
		expect(entries[0].viaClientId ?? null).toBeNull();
	});

	it('still refuses an unauthenticated console request', async () => {
		const res = await admin('/admin/api/projects');
		expect(res.status).toBe(401);
	});

	it('refuses a bearer credential that is not an MCP-audience token', async () => {
		// The second credential arm must not become a way in for an arbitrary Authorization header.
		const res = await elysia.handle(
			new Request('http://e.ly/admin/api/projects', {
				headers: { authorization: 'Bearer not-a-real-token' }
			})
		);
		expect(res.status).toBe(401);
	});
});
