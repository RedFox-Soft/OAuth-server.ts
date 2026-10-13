import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';

import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { resourceRoutes } from 'lib/admin/resources/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminAuditStore,
	getBucketStore,
	getProjectStore,
	getProtectedResourceStore
} from 'lib/adapters/index.ts';
import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { sessionFor, personalGroupId } from '../admin_session.ts';
import { createAdministrator } from '../administrators.ts';
import { answered } from './answered.ts';

const app = new Elysia({ normalize: false })
	.use(resolveAdmin)
	.use(resourceRoutes);
const api = treaty(app);

const AUDIENCE = 'https://mcp.example.com/mcp';
const encoded = encodeURIComponent(AUDIENCE);

async function declarer() {
	const user = await createAdministrator(
		'plain',
		`describer-${Math.random()}@x.io`
	);
	const session = await sessionFor(user);
	const ownerGroupId = await personalGroupId(user._id);
	const bucket = await getBucketStore().create({
		name: 'Described users',
		slug: `described-${Math.random().toString(36).slice(2)}`,
		ownerGroupId
	});
	const project = await getProjectStore().create({
		name: 'Described',
		slug: `described-${Math.random().toString(36).slice(2)}`,
		ownerGroupId,
		bucketId: bucket._id
	});
	return {
		headers: { cookie: `${ADMIN_SESSION_COOKIE}=${session._id}` },
		userId: user._id,
		resources: api.admin.api.projects({ id: project._id }).resources
	};
}

/**
 * @proves An administrator can say, for each scope of a service they declared, what it lets an app do and
 * whether it only sees or acts — and can only describe scopes the service actually has.
 */
describe('describing the scopes of a declared resource', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
		const store = getProtectedResourceStore();
		for (const resource of await store.list()) {
			await store.destroy(resource.namespace, resource.identifier);
		}
	});

	it('keeps the descriptions and kinds given when the resource is declared', async () => {
		const { headers, resources } = await declarer();

		const res = await resources.post(
			{
				identifier: AUDIENCE,
				name: 'Company MCP',
				scopes: ['tools:read', 'tools:call'],
				scopeDescriptions: {
					'tools:read': { description: '  see the tools  ', kind: 'see' },
					'tools:call': { description: 'run the tools as you' }
				}
			},
			{ headers }
		);

		expect(res.status).toBe(201);
		expect(answered(res.data).scopeDescriptions).toEqual({
			'tools:read': { description: 'see the tools', kind: 'see' },
			'tools:call': { description: 'run the tools as you' }
		});
	});

	it('refuses a description of a scope the resource does not declare', async () => {
		const { headers, resources } = await declarer();

		const res = await resources.post(
			{
				identifier: AUDIENCE,
				name: 'Company MCP',
				scopes: ['tools:read'],
				scopeDescriptions: { 'tools:delete': { description: 'delete tools' } }
			},
			{ headers }
		);

		expect(res.status).toBe(400);
		expect(JSON.stringify(res.error?.value)).toContain('scopeDescriptions');
	});

	it('refuses a description longer than two hundred characters', async () => {
		const { headers, resources } = await declarer();

		const res = await resources.post(
			{
				identifier: AUDIENCE,
				name: 'Company MCP',
				scopes: ['tools:read'],
				scopeDescriptions: { 'tools:read': { description: 'x'.repeat(201) } }
			},
			{ headers }
		);

		expect(res.status).toBe(422);
	});

	it('drops the description of a scope an edit removes, and records that it did', async () => {
		const { headers, userId, resources } = await declarer();
		await resources.post(
			{
				identifier: AUDIENCE,
				name: 'Company MCP',
				scopes: ['tools:read', 'tools:call'],
				scopeDescriptions: {
					'tools:read': { description: 'see the tools', kind: 'see' },
					'tools:call': { description: 'run the tools as you' }
				}
			},
			{ headers }
		);

		const res = await resources({ resourceId: encoded }).patch(
			{ scopes: ['tools:read'] },
			{ headers }
		);

		expect(res.status).toBe(200);
		expect(answered(res.data).scopeDescriptions).toEqual({
			'tools:read': { description: 'see the tools', kind: 'see' }
		});
		const { entries } = await adminAuditStore.list({
			action: 'resource.update',
			limit: 50
		});
		const mine = entries.find((e) => e.actorId === userId);
		expect(mine?.attributes).toContain('scopeDescriptions');
	});

	it('reads and works unchanged for a resource declared without descriptions', async () => {
		const { headers, resources } = await declarer();
		await resources.post(
			{ identifier: AUDIENCE, name: 'Company MCP', scopes: ['tools:read'] },
			{ headers }
		);

		const res = await resources({ resourceId: encoded }).patch(
			{ name: 'Company MCP v2', scopes: ['tools:read', 'tools:call'] },
			{ headers }
		);

		expect(res.status).toBe(200);
		expect(answered(res.data).scopeDescriptions).toBeUndefined();
		expect(answered(res.data).scopes).toEqual(['tools:read', 'tools:call']);
	});
});
