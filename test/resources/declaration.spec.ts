import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';

import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { resourceRoutes } from 'lib/admin/resources/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	getProjectStore,
	getProtectedResourceStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { sessionFor, personalGroupId } from '../admin_session.ts';

/*
 * Declaring a protected resource through the admin API.
 *
 * Mounted as `resolveAdmin` plus the one route group, the way every other admin route spec is: the
 * console's own HTML shell pulls React and antd and costs ~86s to import, against ~350ms for the
 * routes under test.
 */

/*
 * `normalize: false` mirrors the real app (`lib/index.ts` constructs it that way). It matters for one
 * case below: with normalization on — the framework default a bare `new Elysia()` gets — an unknown
 * body key is stripped before validation, so naming `identifier` in a PATCH would answer 200 having
 * silently ignored it. Production refuses. A spec that did not mirror the setting would be asserting
 * the wrong behaviour and would pass while the console did something else.
 */
const app = new Elysia({ normalize: false })
	.use(resolveAdmin)
	.use(resourceRoutes);
const api = treaty(app);

const AUDIENCE = 'https://mcp.example.com/mcp';
/* The identifier is a URL inside a path segment, and Eden treaty does not encode those for you. */
const encoded = encodeURIComponent(AUDIENCE);

async function admin(roles = ['project_admin']) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`${roles.join('-')}-${Math.random()}@x.io`,
		'hash',
		roles
	);
	const session = await sessionFor(user);
	return {
		cookie: `${ADMIN_SESSION_COOKIE}=${session._id}`,
		userId: user._id
	};
}

async function projectFor(userId: string) {
	return getProjectStore().create({
		name: 'Acme',
		slug: `acme-${Math.random().toString(36).slice(2)}`,
		ownerGroupId: await personalGroupId(userId)
	});
}

const body = {
	identifier: AUDIENCE,
	name: 'Acme MCP',
	scopes: ['mcp:tools-basic']
};

describe('protected resources API', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
		const store = getProtectedResourceStore();
		for (const resource of await store.list()) {
			await store.destroy(resource._id);
		}
	});

	it('refuses an anonymous caller', async () => {
		const project = await getProjectStore().create({
			name: 'Acme',
			slug: `anon-${Math.random().toString(36).slice(2)}`,
			ownerGroupId: 'unassigned'
		});

		const res = await api.admin.api
			.projects({ id: project._id })
			.resources.get();

		expect(res.status).toBe(401);
	});

	it('declares, lists, reads, amends and removes a resource', async () => {
		const { cookie, userId } = await admin();
		const project = await projectFor(userId);
		const headers = { cookie };
		const resources = api.admin.api.projects({ id: project._id }).resources;

		const created = await resources.post(body, { headers });
		expect(created.status).toBe(201);

		const listed = await resources.get({ headers });
		expect(listed.status).toBe(200);
		expect((listed.data as Array<{ _id: string }>).map((r) => r._id)).toEqual([
			AUDIENCE
		]);

		const read = await resources({ resourceId: encoded }).get({ headers });
		expect(read.status).toBe(200);
		expect((read.data as { name?: string }).name).toBe('Acme MCP');

		const amended = await resources({ resourceId: encoded }).patch(
			{ name: 'Acme MCP v2', scopes: ['mcp:tools-basic', 'mcp:files-read'] },
			{ headers }
		);
		expect(amended.status).toBe(200);
		expect((amended.data as { scopes?: string[] }).scopes).toEqual([
			'mcp:tools-basic',
			'mcp:files-read'
		]);

		const removed = await resources({ resourceId: encoded }).delete(undefined, {
			headers
		});
		expect(removed.status).toBe(204);
		expect((await resources.get({ headers })).data).toEqual([]);
	});

	it('canonicalizes on write, so two spellings cannot become two declarations', async () => {
		const { cookie, userId } = await admin();
		const project = await projectFor(userId);
		const headers = { cookie };
		const resources = api.admin.api.projects({ id: project._id }).resources;

		const created = await resources.post(
			{ ...body, identifier: 'HTTPS://MCP.Example.com/mcp/' },
			{ headers }
		);

		expect(created.status).toBe(201);
		expect((created.data as { _id?: string })._id).toBe(AUDIENCE);
	});

	it('refuses an identifier carrying a fragment', async () => {
		const { cookie, userId } = await admin();
		const project = await projectFor(userId);

		const res = await api.admin.api
			.projects({ id: project._id })
			.resources.post(
				{ ...body, identifier: `${AUDIENCE}#tools` },
				{ headers: { cookie } }
			);

		expect(res.status).toBe(400);
	});

	it('refuses an identifier that is not an absolute URI', async () => {
		const { cookie, userId } = await admin();
		const project = await projectFor(userId);

		const res = await api.admin.api
			.projects({ id: project._id })
			.resources.post(
				{ ...body, identifier: 'mcp.example.com' },
				{ headers: { cookie } }
			);

		expect(res.status).toBe(400);
	});

	/*
	 * Instance-wide uniqueness, across projects rather than within one. Two projects declaring the same
	 * audience would mean one token being valid at two owners' resources, which is the boundary an
	 * audience exists to draw.
	 */
	it('refuses an identifier already declared, including in another project', async () => {
		const first = await admin();
		const second = await admin();
		const projectA = await projectFor(first.userId);
		const projectB = await projectFor(second.userId);

		expect(
			(
				await api.admin.api
					.projects({ id: projectA._id })
					.resources.post(body, { headers: { cookie: first.cookie } })
			).status
		).toBe(201);

		const clash = await api.admin.api
			.projects({ id: projectB._id })
			.resources.post(body, { headers: { cookie: second.cookie } });

		expect(clash.status).toBe(409);
	});

	/*
	 * The administrative audience is claimed by the built-in descriptor before this store is ever
	 * consulted, so a declaration naming it could never take effect — refusing at declaration time is
	 * what makes that visible to the operator instead of silently inert.
	 */
	it('refuses an identifier this server serves itself', async () => {
		const { cookie, userId } = await admin();
		const project = await projectFor(userId);

		const res = await api.admin.api
			.projects({ id: project._id })
			.resources.post(
				{ ...body, identifier: 'http://e.ly/mcp' },
				{ headers: { cookie } }
			);

		expect(res.status).toBe(409);
	});

	/*
	 * A client given no scope guidance requests everything `scopes_supported` lists, so an omnibus
	 * scope is not a shorthand — it is a grant of everything to every client that arrives.
	 */
	it('refuses a wildcard or omnibus scope', async () => {
		const { cookie, userId } = await admin();
		const project = await projectFor(userId);
		const headers = { cookie };

		for (const scopes of [[], ['*'], ['all'], ['full-access'], ['a b']]) {
			const res = await api.admin.api
				.projects({ id: project._id })
				.resources.post({ ...body, scopes }, { headers });
			expect(res.status).toBe(400);
		}
	});

	it('refuses an administrator outside the project owning group', async () => {
		const owner = await admin();
		const outsider = await admin();
		const project = await projectFor(owner.userId);

		const res = await api.admin.api
			.projects({ id: project._id })
			.resources.get({ headers: { cookie: outsider.cookie } });

		expect(res.status).toBe(403);
	});

	it('refuses to amend the identifier, which is the audience of every token issued', async () => {
		const { cookie, userId } = await admin();
		const project = await projectFor(userId);
		const headers = { cookie };
		const resources = api.admin.api.projects({ id: project._id }).resources;
		await resources.post(body, { headers });

		const res = await resources({ resourceId: encoded }).patch(
			{ identifier: 'https://elsewhere.example.com/mcp' } as never,
			{ headers }
		);

		expect(res.status).toBe(422);
	});
});
