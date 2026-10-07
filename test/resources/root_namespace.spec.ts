import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';

import bootstrap from '../test_helper.ts';
import { elysia } from 'lib/index.ts';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { resourceRoutes } from 'lib/admin/resources/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ensurePersonalGroup } from 'lib/admin/groups/personal.ts';
import {
	getProjectStore,
	getProtectedResourceStore
} from 'lib/adapters/index.ts';
import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { AccessToken } from 'lib/models/access_token.ts';
import { Client } from 'lib/models/client.ts';
import {
	ADMIN_MCP_CLIENT_ID,
	MCP_RESOURCE,
	MCP_ROUTE
} from 'lib/mcp/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { ROOT_NAMESPACE } from 'lib/resources/namespace.ts';
import { sessionFor } from '../admin_session.ts';
import { createAdministrator, type AdminKind } from '../administrators.ts';

/*
 * A project with no bucket of its own is served at the root issuer, whose namespace every such tenant
 * shares. A resource's metadata can say it trusts the root issuer but not which of those tenants it
 * belongs to, so no proof closes squatting there — declaring at the root is a super administrator's.
 */

const app = new Elysia({ normalize: false })
	.use(resolveAdmin)
	.use(resourceRoutes);
const api = treaty(app);

const AUDIENCE = 'https://mcp.root.example/mcp';
const encoded = encodeURIComponent(AUDIENCE);
const body = {
	identifier: AUDIENCE,
	name: 'Root MCP',
	scopes: ['mcp:tools-basic']
};

async function administrator(kind: AdminKind) {
	const user = await createAdministrator(
		kind,
		`root-${kind}-${Math.random()}@x.io`
	);
	const group = await ensurePersonalGroup(user._id, user.email);
	const session = await sessionFor(user);
	return {
		user,
		groupId: group._id,
		cookie: `${ADMIN_SESSION_COOKIE}=${session._id}`
	};
}

async function rootProject(ownerGroupId: string) {
	return getProjectStore().create({
		name: 'Rootless',
		slug: `rootless-${Math.random().toString(36).slice(2)}`,
		ownerGroupId
	});
}

async function declaredAtRoot(projectId: string) {
	await getProtectedResourceStore().create({
		namespace: ROOT_NAMESPACE,
		identifier: AUDIENCE,
		projectId,
		name: 'Root MCP',
		scopes: ['mcp:tools-basic']
	});
}

let rpcId = 0;
async function rpc(payload: unknown, token: string) {
	const res = await elysia.handle(
		new Request(`http://e.ly${MCP_ROUTE}`, {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				accept: 'application/json, text/event-stream',
				authorization: `Bearer ${token}`
			},
			body: JSON.stringify(payload)
		})
	);
	const text = await res.text();
	const line = text.split('\n').find((l) => l.startsWith('data:'));
	return line
		? JSON.parse(line.slice('data:'.length).trim())
		: JSON.parse(text);
}

async function agentFor(userId: string) {
	const at = new AccessToken({
		client: await Client.find(ADMIN_MCP_CLIENT_ID),
		accountId: userId,
		scope: 'openid'
	});
	at.setAudience(MCP_RESOURCE);
	const token = await at.save();
	await rpc(
		{
			jsonrpc: '2.0',
			id: ++rpcId,
			method: 'initialize',
			params: {
				protocolVersion: '2026-07-28',
				capabilities: {},
				clientInfo: { name: 'test-agent', version: '1.0.0' }
			}
		},
		token
	);
	return token;
}

/**
 * @proves In the namespace every root-served tenant shares, only a super administrator declares,
 * amends or removes a protected resource, through the console and through an agent alike, and the
 * refusal says how a tenant can declare it instead.
 */
describe('a project without an addressable bucket', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'resources' });
	});

	beforeEach(async () => {
		ApplicationConfig['mcp.enabled'] = true;
		await ensureAdminSeed();
		const store = getProtectedResourceStore();
		for (const resource of await store.list()) {
			await store.destroy(resource.namespace, resource.identifier);
		}
	});

	it('refuses a group administrator declaring a resource, naming both ways out', async () => {
		const { cookie, groupId } = await administrator('plain');
		const project = await rootProject(groupId);

		const res = await api.admin.api
			.projects({ id: project._id })
			.resources.post(body, { headers: { cookie } });

		expect(res.status).toBe(403);
		const message = String((res.error?.value as { message?: string })?.message);
		expect(message).toContain('super administrator');
		expect(message).toContain('bucket');
		expect(await getProtectedResourceStore().list()).toEqual([]);
	});

	it('refuses a group administrator amending a resource declared there', async () => {
		const { cookie, groupId } = await administrator('plain');
		const project = await rootProject(groupId);
		await declaredAtRoot(project._id);

		const res = await api.admin.api
			.projects({ id: project._id })
			.resources({ resourceId: encoded })
			.patch({ name: 'Taken over' }, { headers: { cookie } });

		expect(res.status).toBe(403);
	});

	it('refuses a group administrator removing a resource declared there', async () => {
		const { cookie, groupId } = await administrator('plain');
		const project = await rootProject(groupId);
		await declaredAtRoot(project._id);

		const res = await api.admin.api
			.projects({ id: project._id })
			.resources({ resourceId: encoded })
			.delete(undefined, { headers: { cookie } });

		expect(res.status).toBe(403);
		expect(await getProtectedResourceStore().list()).toHaveLength(1);
	});

	it('lets a super administrator declare a resource with no outbound request', async () => {
		const { cookie, groupId } = await administrator('super');
		const project = await rootProject(groupId);

		const res = await api.admin.api
			.projects({ id: project._id })
			.resources.post(
				{ ...body, identifier: 'http://10.9.8.7/mcp' },
				{ headers: { cookie } }
			);

		expect(res.status).toBe(201);
	});

	it('refuses an agent acting for a group administrator declaring a resource', async () => {
		const { user, groupId } = await administrator('plain');
		const project = await rootProject(groupId);
		const token = await agentFor(user._id);

		const answer = await rpc(
			{
				jsonrpc: '2.0',
				id: ++rpcId,
				method: 'tools/call',
				params: {
					name: 'resource_declare',
					arguments: { id: project._id, ...body }
				}
			},
			token
		);

		expect(answer.result?.isError).toBe(true);
		expect(await getProtectedResourceStore().list()).toEqual([]);
	});
});
