import { describe, it, expect, beforeEach, afterEach } from 'bun:test';
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
import { mock } from '../fetch_mock.js';
import { sessionFor, personalGroupId } from '../admin_session.ts';
import { serveResourceMetadata } from './resource_metadata.ts';

/*
 * A declared resource decides who may sign in to reach it and which bucket's issuer its tokens carry,
 * and identifiers are unique across the instance. So a declaration is a claim on somebody's server, and
 * any member of any group could make it first: the real owner was refused as a duplicate, and clients
 * naming the resource were routed into the claimant's bucket. The resource settles the claim itself —
 * its protected resource metadata (RFC 9728) has to name this server's issuer for the declaring project.
 */

const app = new Elysia({ normalize: false })
	.use(resolveAdmin)
	.use(resourceRoutes);
const api = treaty(app);

const AUDIENCE = 'https://mcp.owned.example/mcp';

async function adminWithProject(roles: string[]) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`${roles.join('-')}-${Math.random()}@x.io`,
		'hash',
		roles
	);
	const session = await sessionFor(user);
	const project = await getProjectStore().create({
		name: 'Acme',
		slug: `acme-${Math.random().toString(36).slice(2)}`,
		ownerGroupId: await personalGroupId(user._id)
	});
	return { cookie: `${ADMIN_SESSION_COOKIE}=${session._id}`, project };
}

async function declare(roles: string[] = ['project_admin']) {
	const { cookie, project } = await adminWithProject(roles);
	const res = await api.admin.api
		.projects({ id: project._id })
		.resources.post(
			{ identifier: AUDIENCE, name: 'Owned MCP', scopes: ['mcp:tools-basic'] },
			{ headers: { cookie } }
		);
	return res.status;
}

/**
 * @proves A resource is declared by a group administrator only when its own metadata names this
 * server's issuer for the declaring project.
 */
describe('declaring a resource somebody else might own', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
		const store = getProtectedResourceStore();
		for (const resource of await store.list()) {
			await store.destroy(resource._id);
		}
	});

	afterEach(() => {
		mock.restore();
	});

	it('is refused when the resource serves no metadata', async () => {
		expect(await declare()).toBe(422);
		expect(await getProtectedResourceStore().find(AUDIENCE)).toBeFalsy();
	});

	it('is refused when the metadata names another authorization server', async () => {
		serveResourceMetadata(AUDIENCE, {
			authorization_servers: ['https://other-as.example']
		});

		expect(await declare()).toBe(422);
	});

	it('is refused when the metadata describes a different resource', async () => {
		serveResourceMetadata(AUDIENCE, {
			resource: 'https://mcp.owned.example/other'
		});

		expect(await declare()).toBe(422);
	});

	it('is accepted when the metadata names this server', async () => {
		serveResourceMetadata(AUDIENCE);

		expect(await declare()).toBe(201);
	});

	it('is accepted when the metadata is published at the host root', async () => {
		serveResourceMetadata(AUDIENCE, {}, { atRoot: true });

		expect(await declare()).toBe(201);
	});

	it('is accepted from a super administrator without the metadata', async () => {
		expect(await declare(['super_admin'])).toBe(201);
	});
});
