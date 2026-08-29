import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	getUserStore,
	getProjectStore,
	getBucketStore,
	adminSessionStore
} from 'lib/adapters/index.ts';
import {
	ADMIN_BUCKET_ID,
	ADMIN_SESSION_COOKIE,
	UNASSIGNED_GROUP_ID
} from 'lib/admin/consts.ts';
import {
	ADMIN_MCP_CLIENT_ID,
	MCP_RESOURCE,
	MCP_ROUTE
} from 'lib/mcp/consts.ts';
import { mcpCatalogue, pathArgName } from 'lib/mcp/catalogue.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { sessionFor, personalGroupId } from '../admin_session.ts';

/*
 * SC-006: no agent-initiated operation succeeds with permissions the same account would not have in the
 * console.
 *
 * The strongest form of that is a comparison, not a list of expected statuses — so most of this file
 * asks the *same question twice*, once over MCP and once over the console with a cookie, and asserts the
 * two answers agree. A rule that drifts in either direction fails, and the test needs no opinion about
 * which status is correct.
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

/* One administrator, reachable both ways: an MCP token and a console cookie. */
async function principal(roles: string[]) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`role-${roles.join('-')}-${Math.random()}@x.io`,
		'hash',
		roles
	);
	const at = new AccessToken({
		client: await Client.find(ADMIN_MCP_CLIENT_ID),
		accountId: user._id,
		scope: 'openid'
	});
	at.setAudience(MCP_RESOURCE);
	const token = (await at.save()) as unknown as string;
	const session = await sessionFor(user);
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
	return {
		user,
		token,
		cookie: `${ADMIN_SESSION_COOKIE}=${session._id}`
	};
}

/* Did the console allow this, and did the agent? Compared, never asserted individually. */
async function viaConsole(path: string, cookie: string) {
	const res = await elysia.handle(
		new Request(`http://e.ly${path}`, { headers: { cookie } })
	);
	return res.status;
}

async function viaAgent(
	tool: string,
	args: Record<string, unknown>,
	token: string
) {
	const response = await rpc(call(tool, args), token);
	return response.result?.isError === true
		? (response.result?.structuredContent?.reason as string)
		: 'ok';
}

/* The console status a tool's refusal reason corresponds to. */
const EQUIVALENT: Record<string, number> = {
	ok: 200,
	forbidden: 403,
	not_found: 404
};

const READS = mcpCatalogue.filter((t) => t.consequence === 'read');

describe('agent permissions match the console, per role', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		ApplicationConfig['mcp.enabled'] = true;
		await ensureAdminSeed();
	});

	it.each([['super_admin'], ['project_admin']])(
		'answers every parameterless read identically over both surfaces for %s',
		async (role) => {
			const { token, cookie } = await principal([role]);

			for (const tool of READS.filter((t) => t.pathParams.length === 0)) {
				const agent = await viaAgent(tool.tool, {}, token);
				const console_ = await viaConsole(tool.path, cookie);

				expect(
					EQUIVALENT[agent] ?? 500,
					`${tool.tool} disagreed for ${role}: agent said ${agent}, console said ${console_}`
				).toBe(console_);
			}
		}
	);

	it('scopes a project read to what the account manages, on both surfaces', async () => {
		const { token, cookie, user } = await principal(['project_admin']);

		const mine = await getProjectStore().create({
			name: 'Mine',
			slug: `mine-${Math.floor(Math.random() * 1e6)}`,
			ownerGroupId: await personalGroupId(user._id)
		});
		const theirs = await getProjectStore().create({
			name: 'Theirs',
			slug: `theirs-${Math.floor(Math.random() * 1e6)}`,
			ownerGroupId: UNASSIGNED_GROUP_ID
		});

		const listed = await rpc(call('project_list', {}), token);
		const ids = (
			(listed.result?.structuredContent?.result ?? []) as { _id: string }[]
		).map((p) => p._id);
		expect(ids).toContain(mine._id);
		expect(ids).not.toContain(theirs._id);

		// The console agrees, project by project.
		expect(await viaConsole(`/admin/api/projects/${mine._id}`, cookie)).toBe(
			200
		);
		expect(await viaConsole(`/admin/api/projects/${theirs._id}`, cookie)).toBe(
			403
		);
		expect(await viaAgent('project_get', { id: mine._id }, token)).toBe('ok');
		expect(await viaAgent('project_get', { id: theirs._id }, token)).toBe(
			'forbidden'
		);
	});

	it('grants bucket-user access to a project manager but not bucket-entity access', async () => {
		const { token, user } = await principal(['project_admin']);

		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Backing'
		});
		await getProjectStore().create({
			name: 'Backed',
			slug: `backed-${Math.floor(Math.random() * 1e6)}`,
			ownerGroupId: await personalGroupId(user._id),
			bucketId: bucket._id
		});

		// The broader access: managing the users of a bucket that backs a project they manage.
		expect(await viaAgent('bucket_user_list', { id: bucket._id }, token)).toBe(
			'ok'
		);
		expect(await viaAgent('bucket_get', { id: bucket._id }, token)).toBe('ok');

		// The stricter access: editing the bucket entity needs manager rights on the bucket itself.
		const renamed = await rpc(
			call('bucket_update', { id: bucket._id, name: 'Renamed' }),
			token
		);
		expect(renamed.result?.isError).toBe(true);
		expect(renamed.result?.structuredContent?.reason).toBe('forbidden');
	});

	it('refuses the reserved administrator bucket through the bucket tools', async () => {
		const { token, cookie } = await principal(['super_admin']);

		// Even to a super-administrator: administrators are managed through their own tools, and the
		// reserved bucket is not a place end-user operations may reach.
		expect(await viaAgent('bucket_get', { id: ADMIN_BUCKET_ID }, token)).toBe(
			'forbidden'
		);
		expect(
			await viaAgent('bucket_user_list', { id: ADMIN_BUCKET_ID }, token)
		).toBe('forbidden');
		expect(
			await viaConsole(`/admin/api/buckets/${ADMIN_BUCKET_ID}`, cookie)
		).toBe(403);

		// It is not listed either, so an agent cannot discover it and try.
		const listed = await rpc(call('bucket_list', {}), token);
		expect(JSON.stringify(listed)).not.toContain(`"${ADMIN_BUCKET_ID}"`);
	});

	it('refuses every super-admin-gated tool to a non-super-administrator', async () => {
		const { token } = await principal(['project_admin']);

		const gated = mcpCatalogue.filter((t) => t.requiredRole === 'super_admin');
		expect(gated.length).toBeGreaterThan(0);

		for (const tool of gated) {
			const args: Record<string, unknown> = {};
			for (const param of tool.pathParams) {
				args[pathArgName(tool, param)] = `no-such-${param}`;
			}
			// A body is not needed: the role check happens before anything reads one. Where a schema
			// requires fields the call is refused by validation, which is also not success.
			const reason = await viaAgent(tool.tool, args, token);
			expect(
				reason,
				`${tool.tool} was not refused to a project_admin`
			).not.toBe('ok');
		}
	});

	it('cannot escalate by asking a different tool for the same thing', async () => {
		const { token } = await principal(['project_admin']);

		/*
		 * The audit trail is no longer super-admin only: it is scope-filtered, so a project administrator
		 * reads it and sees only their own groups' entries. What must stay unreachable is the instance's
		 * own surfaces below — and the tenant isolation of the trail itself, which
		 * test/admin/audit_group_scope.spec.ts asserts directly rather than through a status code.
		 */
		expect(await viaAgent('audit_list', {}, token)).toBe('ok');
		expect(await viaAgent('admin_list', {}, token)).toBe('forbidden');
		expect(await viaAgent('settings_get', {}, token)).toBe('forbidden');
		expect(await viaAgent('jwks_list', {}, token)).toBe('forbidden');
		expect(await viaAgent('smtp_settings_get', {}, token)).toBe('forbidden');
	});
});
