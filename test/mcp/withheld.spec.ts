import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	getUserStore,
	getProjectStore,
	getBucketStore
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import {
	ADMIN_MCP_CLIENT_ID,
	MCP_RESOURCE,
	MCP_ROUTE
} from 'lib/mcp/consts.ts';
import { excludedConsoleOperations, mcpCatalogue } from 'lib/mcp/catalogue.ts';
import { ApplicationConfig } from 'lib/configs/application.js';

/*
 * The two withheld operations: deleting a project and deleting a user bucket.
 *
 * FR-031 says the surface must not *publish* them, which is stronger than refusing them when called —
 * so the assertions are about absence from `tools/list` and about no container ever disappearing, not
 * merely about an error being returned.
 *
 * FR-034 then says the refusal must read as "not available here" rather than as a permission problem,
 * because an operator told "forbidden" goes looking for a role that would unlock it, and there is none.
 */

let rpcId = 0;

async function rpc(body: unknown, token: string) {
	const res = await elysia.handle(
		new Request(`http://e.ly${MCP_ROUTE}`, {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				accept: 'application/json, text/event-stream',
				authorization: `Bearer ${token}`
			},
			body: JSON.stringify(body)
		})
	);
	const text = await res.text();
	const isEvent = (res.headers.get('content-type') ?? '').includes(
		'text/event-stream'
	);
	const line = isEvent
		? text.split('\n').find((l) => l.startsWith('data:'))
		: undefined;
	return isEvent
		? line
			? JSON.parse(line.slice('data:'.length).trim())
			: undefined
		: text
			? JSON.parse(text)
			: undefined;
}

function call(name: string, args: Record<string, unknown>) {
	return {
		jsonrpc: '2.0',
		id: ++rpcId,
		method: 'tools/call',
		params: { name, arguments: args }
	};
}

async function superAdmin() {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`wh-${Math.random()}@x.io`,
		'hash',
		['super_admin']
	);
	const at = new AccessToken({
		client: await Client.find(ADMIN_MCP_CLIENT_ID),
		accountId: user._id,
		scope: 'openid'
	});
	at.setAudience(MCP_RESOURCE);
	const token = (await at.save()) as unknown as string;
	const init = await rpc(
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
	return { user, token, init };
}

describe('withheld container deletions', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		ApplicationConfig['mcp.enabled'] = true;
		await ensureAdminSeed();
	});

	it('publishes neither deletion, and neither is in the catalogue', async () => {
		const { token } = await superAdmin();
		const listed = await rpc(
			{ jsonrpc: '2.0', id: ++rpcId, method: 'tools/list', params: {} },
			token
		);
		const names: string[] = (listed.result?.tools ?? []).map(
			(t: { name: string }) => t.name
		);

		expect(names).not.toContain('project_delete');
		expect(names).not.toContain('bucket_delete');
		// And nothing else that reaches the same routes by another name.
		const paths = new Set(mcpCatalogue.map((t) => `${t.method} ${t.path}`));
		expect(paths.has('DELETE /admin/api/projects/:id')).toBe(false);
		expect(paths.has('DELETE /admin/api/buckets/:id')).toBe(false);
	});

	it('announces what is withheld and where to do it, in the server instructions', async () => {
		const { init } = await superAdmin();
		const instructions = init.result?.instructions ?? '';

		// So an agent can answer correctly without a tool existing to discover the absence from.
		expect(instructions).toContain('admin console');
		expect(instructions.toLowerCase()).toContain('project');
		expect(instructions.toLowerCase()).toContain('bucket');
	});

	it('deletes no project however insistently it is asked, even as a super-administrator', async () => {
		const { token } = await superAdmin();
		const project = await getProjectStore().create({
			name: 'Survivor',
			slug: `wh-${Math.floor(Math.random() * 1e6)}`,
			ownerGroupId: UNASSIGNED_GROUP_ID
		});

		// Plainly, then again, then under a name an agent might invent.
		for (const name of [
			'project_delete',
			'project_delete',
			'delete_project',
			'project_remove'
		]) {
			const refused = await rpc(call(name, { id: project._id }), token);
			expect(refused.result?.isError ?? refused.error !== undefined).toBe(true);
		}

		expect(await getProjectStore().find(project._id)).not.toBeNull();
	});

	it('deletes no bucket however insistently it is asked', async () => {
		const { token } = await superAdmin();
		const created = await rpc(
			call('bucket_create', { name: 'Survivor' }),
			token
		);
		const bucketId = (
			created.result?.structuredContent?.result as { _id: string }
		)._id;

		for (const name of ['bucket_delete', 'bucket_delete', 'delete_bucket']) {
			const refused = await rpc(call(name, { id: bucketId }), token);
			expect(refused.result?.isError ?? refused.error !== undefined).toBe(true);
		}

		expect(await getBucketStore().find(bucketId)).not.toBeNull();
	});

	it('leaves the other steps of a multi-part instruction working', async () => {
		const { token } = await superAdmin();
		const project = await getProjectStore().create({
			name: 'Partly',
			slug: `wh-${Math.floor(Math.random() * 1e6)}`,
			ownerGroupId: UNASSIGNED_GROUP_ID
		});

		// A withheld step buried between two that should succeed.
		const before = await rpc(
			call('client_create', {
				id: project._id,
				clientName: 'Before',
				grantTypes: ['authorization_code'],
				redirectUris: ['https://a.example.com/cb'],
				tokenEndpointAuthMethod: 'none'
			}),
			token
		);
		const withheld = await rpc(
			call('project_delete', { id: project._id }),
			token
		);
		const after = await rpc(call('project_get', { id: project._id }), token);

		expect(before.result?.isError).not.toBe(true);
		expect(withheld.result?.isError ?? withheld.error !== undefined).toBe(true);
		expect(after.result?.isError).not.toBe(true);
		expect(await getProjectStore().find(project._id)).not.toBeNull();
	});

	it('still lets an operator learn what a deletion would involve', async () => {
		const { token } = await superAdmin();
		const project = await getProjectStore().create({
			name: 'Blocked',
			slug: `wh-${Math.floor(Math.random() * 1e6)}`,
			ownerGroupId: UNASSIGNED_GROUP_ID
		});
		const created = await rpc(
			call('client_create', {
				id: project._id,
				clientName: 'Blocker',
				grantTypes: ['authorization_code'],
				redirectUris: ['https://a.example.com/cb'],
				tokenEndpointAuthMethod: 'none'
			}),
			token
		);
		const clientId = (
			created.result?.structuredContent?.result as { clientId: string }
		).clientId;

		/*
		 * FR-035 asks for this through *ordinary* read operations, under those reads' own disclosure
		 * rules — which is exactly what the existing reads give, so no extra affordance was built. A
		 * project names the clients that block it; a bucket's end-users are countable.
		 */
		const detail = await rpc(call('project_get', { id: project._id }), token);
		const holds = (
			detail.result?.structuredContent?.result as { clientIds: string[] }
		).clientIds;
		expect(holds).toContain(clientId);

		const clients = await rpc(call('client_list', { id: project._id }), token);
		expect(JSON.stringify(clients)).toContain(clientId);
	});

	it('counts a bucket’s end-users without an operator needing the deletion', async () => {
		const { token } = await superAdmin();
		const created = await rpc(
			call('bucket_create', { name: 'Counted' }),
			token
		);
		const bucketId = (
			created.result?.structuredContent?.result as { _id: string }
		)._id;
		await rpc(
			call('bucket_user_create', {
				id: bucketId,
				email: `held-${Math.random()}@x.io`,
				password: 'correct horse battery staple'
			}),
			token
		);

		const users = await rpc(call('bucket_user_list', { id: bucketId }), token);
		const held = users.result?.structuredContent?.result as unknown[];
		expect(held.length).toBe(1);
	});

	it('emptying a container stays available, one confirmed deletion at a time', async () => {
		const { token } = await superAdmin();
		const project = await getProjectStore().create({
			name: 'Emptied',
			slug: `wh-${Math.floor(Math.random() * 1e6)}`,
			ownerGroupId: UNASSIGNED_GROUP_ID
		});
		const created = await rpc(
			call('client_create', {
				id: project._id,
				clientName: 'Only',
				grantTypes: ['authorization_code'],
				redirectUris: ['https://a.example.com/cb'],
				tokenEndpointAuthMethod: 'none'
			}),
			token
		);
		const clientId = (
			created.result?.structuredContent?.result as { clientId: string }
		).clientId;

		// Each item is its own confirmed deletion — the container cannot be cleared in one step.
		const described = await rpc(
			call('client_delete', { id: project._id, clientId }),
			token
		);
		const confirmationToken =
			described.result?.structuredContent?.confirmationToken;
		expect(confirmationToken).toBeString();

		const deleted = await rpc(
			call('client_delete', { id: project._id, clientId, confirmationToken }),
			token
		);
		expect(deleted.result?.isError).not.toBe(true);

		// The project is now empty — and still not deletable from here.
		const refused = await rpc(
			call('project_delete', { id: project._id }),
			token
		);
		expect(refused.result?.isError ?? refused.error !== undefined).toBe(true);
		expect(await getProjectStore().find(project._id)).not.toBeNull();
	});

	/*
	 * FR-034's actual delivery. The instructions announce the withheld operations, but an agent that
	 * guesses a tool name never reads them again — and the SDK's answer for a name it does not know is a
	 * bare `Tool <name> not found`, which reads as a typo rather than as a decision. These three cases
	 * pin the refusal that replaces it, and pin that it replaced nothing else.
	 */
	describe('naming an operation the surface does not publish', () => {
		it('answers a withheld operation with the reason the exclusion table holds', async () => {
			const { token } = await superAdmin();

			const refused = await rpc(
				call('project_delete', { id: 'anything' }),
				token
			);

			const expected = excludedConsoleOperations.find(
				(e) => e.path === '/admin/api/projects/:id' && e.method === 'DELETE'
			);
			expect(refused.result?.isError).toBe(true);
			expect(refused.result?.structuredContent?.reason).toBe(
				'not_available_here'
			);
			// The very string the table holds, not a paraphrase of it: that is the property FR-034 wants.
			expect(refused.result?.structuredContent?.message).toBe(expected!.reason);
			expect(refused.result?.content?.[0]?.text).toBe(expected!.reason);
		});

		it('answers an inapplicable operation the same way', async () => {
			const { token } = await superAdmin();

			// An agent has no console session to point at a group, so the operation is absent rather than
			// withheld — but an agent that guesses the name still deserves to be told which it is.
			const refused = await rpc(call('scope_switch', { groupId: 'g' }), token);

			expect(refused.result?.isError).toBe(true);
			expect(refused.result?.structuredContent?.message).toMatch(/console/i);
		});

		it('leaves a genuine unknown name to the SDK', async () => {
			const { token } = await superAdmin();

			// Not in the exclusion table, so nothing here should claim to explain it. The point of the
			// narrow match: a typo must not be dressed up as a policy decision.
			const typo = await rpc(call('projct_delete', { id: 'anything' }), token);

			expect(typo.result?.structuredContent?.reason).not.toBe(
				'not_available_here'
			);
			expect(typo.result?.isError ?? typo.error !== undefined).toBe(true);
		});
	});
});
