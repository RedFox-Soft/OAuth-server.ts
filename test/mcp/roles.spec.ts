import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';

import bootstrap, { seedClient } from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { adminAuditStore, getBucketStore } from 'lib/adapters/index.ts';
import {
	ADMIN_BUCKET_ID,
	ADMIN_SESSION_COOKIE,
	UNASSIGNED_GROUP_ID
} from 'lib/admin/consts.ts';
import { ADMIN_MCP_CLIENT_ID, MCP_RESOURCE } from 'lib/mcp/consts.ts';
import { mcpCatalogue, pathArgName } from 'lib/mcp/catalogue.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { sessionFor, personalGroupId } from '../admin_session.ts';
import { shaped } from 'test/shape.js';
import { Type } from '@sinclair/typebox';
import { createAdministrator, type AdminKind } from '../administrators.ts';
import { call, rpc } from './rpc.ts';
import { SignInPreview } from '../admin/sign_in_consent.ts';

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

/* One administrator, reachable both ways: an MCP token and a console cookie. */
async function principal(kind: AdminKind) {
	const user = await createAdministrator(
		kind,
		`role-${kind}-${Math.random()}@x.io`
	);
	const at = new AccessToken({
		client: await Client.find(ADMIN_MCP_CLIENT_ID),
		accountId: user._id,
		scope: 'openid'
	});
	at.setAudience(MCP_RESOURCE);
	const token = await at.save();
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
	if (response.result?.isError !== true) return 'ok';
	const reason = response.result.structuredContent?.reason;
	// A call refused by the tool's own input schema never reaches a handler, so it carries no reason.
	return typeof reason === 'string' ? reason : 'refused without a reason';
}

/* The console status a tool's refusal reason corresponds to. */
const EQUIVALENT: Record<string, number> = {
	ok: 200,
	forbidden: 403,
	not_found: 404
};

const READS = mcpCatalogue.filter((t) => t.consequence === 'read');

/**
 * @proves An agent sees exactly what its authorizing administrator would see, cannot reach the
 * reserved bucket, and cannot escalate by asking a different tool for the same thing.
 */
describe('agent permissions match the console, per role', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		ApplicationConfig['mcp.enabled'] = true;
		await ensureAdminSeed();
	});

	it.each([['super'], ['plain']] as const)(
		'answers every parameterless read identically over both surfaces for a %s administrator',
		async (role) => {
			const { token, cookie } = await principal(role);

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

	it('scopes an application read to the buckets the account’s groups own, on both surfaces', async () => {
		const { token, cookie, user } = await principal('plain');
		const suffix = Math.floor(Math.random() * 1e6);

		const mine = await getBucketStore().create({
			name: 'Mine',
			ownerGroupId: await personalGroupId(user._id)
		});
		const theirs = await getBucketStore().create({
			name: 'Theirs',
			ownerGroupId: UNASSIGNED_GROUP_ID
		});
		for (const [bucket, clientId] of [
			[mine, `mine-app-${suffix}`],
			[theirs, `their-app-${suffix}`]
		] as const) {
			seedClient({
				clientId,
				bucketId: bucket._id,
				grantTypes: ['authorization_code'],
				responseTypes: ['code'],
				redirectUris: ['https://app.example.com/cb'],
				token_endpoint_auth_method: 'none'
			});
		}

		const listed = await rpc(call('client_list', { id: mine._id }), token);
		const ids = shaped(
			Type.Array(Type.Object({ clientId: Type.String() })),
			listed.result?.structuredContent?.result ?? []
		).map((c) => c.clientId);
		expect(ids).toEqual([`mine-app-${suffix}`]);

		// The console agrees, bucket by bucket.
		expect(
			await viaConsole(`/admin/api/buckets/${mine._id}/clients`, cookie)
		).toBe(200);
		expect(
			await viaConsole(`/admin/api/buckets/${theirs._id}/clients`, cookie)
		).toBe(403);
		expect(await viaAgent('client_list', { id: theirs._id }, token)).toBe(
			'forbidden'
		);
		expect(
			await viaAgent(
				'client_get',
				{ id: theirs._id, clientId: `their-app-${suffix}` },
				token
			)
		).toBe('forbidden');
	});

	it("gives a super administrator's agent the administrators' bucket settings, exactly as the console does", async () => {
		const { token, cookie } = await principal('super');

		expect(await viaAgent('bucket_get', { id: ADMIN_BUCKET_ID }, token)).toBe(
			'ok'
		);
		expect(
			await viaConsole(`/admin/api/buckets/${ADMIN_BUCKET_ID}`, cookie)
		).toBe(200);
		const listed = await rpc(call('bucket_list', {}), token);
		expect(JSON.stringify(listed)).toContain(`"${ADMIN_BUCKET_ID}"`);
	});

	it("lets a super administrator's agent change an administrators'-bucket setting, recorded against the agent and its principal", async () => {
		const { token, user } = await principal('super');
		try {
			const previewed = await rpc(
				call('bucket_update', { id: ADMIN_BUCKET_ID, totpRequired: true }),
				token
			);
			const preview = shaped(
				SignInPreview,
				previewed.result?.structuredContent?.preview
			);
			// The agent is shown what the console is shown, and nothing changed yet.
			expect(preview.changes).toEqual(['authenticatorOn']);
			expect((await getBucketStore().find(ADMIN_BUCKET_ID))?.totpRequired).toBe(
				false
			);
			expect(
				await viaAgent(
					'bucket_update',
					{
						id: ADMIN_BUCKET_ID,
						totpRequired: true,
						confirm: true,
						expect: preview.expect
					},
					token
				)
			).toBe('ok');

			const { entries } = await adminAuditStore.list({
				targetType: 'UserBucket',
				targetId: ADMIN_BUCKET_ID,
				actor: user._id
			});
			const entry = entries.find((e) => e.action === 'bucket.update');
			expect(entry?.viaClientId).toBe(ADMIN_MCP_CLIENT_ID);
		} finally {
			await getBucketStore().update(ADMIN_BUCKET_ID, { totpRequired: false });
		}
	});

	it("refuses an agent the guarded administrators'-bucket setting the console refuses, for the same reason", async () => {
		const { token, cookie } = await principal('super');

		const agentAnswer = await rpc(
			call('bucket_update', {
				id: ADMIN_BUCKET_ID,
				emailVerificationRequired: true
			}),
			token
		);
		const consoleAnswer = await elysia.handle(
			new Request(`http://e.ly/admin/api/buckets/${ADMIN_BUCKET_ID}`, {
				method: 'PATCH',
				headers: { cookie, 'content-type': 'application/json' },
				body: JSON.stringify({ emailVerificationRequired: true })
			})
		);
		const consoleBody = (await consoleAnswer.json()) as { message: string };

		expect(consoleAnswer.status).toBe(409);
		expect(agentAnswer.result?.isError).toBe(true);
		expect(JSON.stringify(agentAnswer.result)).toContain(consoleBody.message);
		expect(
			(await getBucketStore().find(ADMIN_BUCKET_ID))?.emailVerificationRequired
		).toBe(false);
	});

	it("refuses the administrators' bucket to the end-user tools, even for a super administrator", async () => {
		const { token } = await principal('super');

		// Administrators are managed through their own tools; the reserved bucket is not a place end-user
		// operations may reach.
		expect(
			await viaAgent('bucket_user_list', { id: ADMIN_BUCKET_ID }, token)
		).toBe('forbidden');
	});

	it("hides the administrators' bucket from an agent acting for an administrator who is not a super administrator", async () => {
		const { token, cookie } = await principal('plain');

		expect(await viaAgent('bucket_get', { id: ADMIN_BUCKET_ID }, token)).toBe(
			'forbidden'
		);
		expect(
			await viaConsole(`/admin/api/buckets/${ADMIN_BUCKET_ID}`, cookie)
		).toBe(403);
		const listed = await rpc(call('bucket_list', {}), token);
		expect(JSON.stringify(listed)).not.toContain(`"${ADMIN_BUCKET_ID}"`);
	});

	it('refuses every super-admin-gated tool to a non-super-administrator', async () => {
		const { token } = await principal('plain');

		const gated = mcpCatalogue.filter((t) => t.superAdminOnly);
		expect(gated.length).toBeGreaterThan(0);

		for (const tool of gated) {
			const args: Record<string, unknown> = {};
			for (const param of tool.pathParams) {
				args[pathArgName(tool, param)] = `no-such-${param}`;
			}
			// A body is not needed: the privilege check happens before anything reads one. Where a schema
			// requires fields the call is refused by validation, which is also not success.
			const reason = await viaAgent(tool.tool, args, token);
			expect(
				reason,
				`${tool.tool} was not refused to a non-super administrator`
			).not.toBe('ok');
		}
	});

	it("lets an agent correct the path of an unused bucket its administrator's group owns, as the console does", async () => {
		const { token, user } = await principal('plain');
		const suffix = Math.floor(Math.random() * 1e6);
		const bucket = await getBucketStore().create({
			name: 'Mistyped',
			slug: `mistpyed-${suffix}`,
			ownerGroupId: await personalGroupId(user._id)
		});
		const args = {
			id: bucket._id,
			slug: `mistyped-${suffix}`,
			confirm: true,
			expect: { applications: 0, connections: 0, providers: 0, resources: 0 }
		};

		const described = await rpc(call('bucket_address_change', args), token);
		const performed = await rpc(
			call('bucket_address_change', {
				...args,
				confirmationToken:
					described.result?.structuredContent?.confirmationToken
			}),
			token
		);

		expect(performed.result?.isError).not.toBe(true);
		expect((await getBucketStore().find(bucket._id))?.slug).toBe(
			`mistyped-${suffix}`
		);
	});

	it('refuses an agent a hostname for a bucket its administrator owns, as the console does', async () => {
		const { token, user } = await principal('plain');
		const suffix = Math.floor(Math.random() * 1e6);
		const bucket = await getBucketStore().create({
			name: 'Unhosted',
			slug: `unhosted-${suffix}`,
			ownerGroupId: await personalGroupId(user._id)
		});
		const args = {
			id: bucket._id,
			host: `unhosted-${suffix}.e.ly`,
			confirm: true,
			expect: { applications: 0, connections: 0, providers: 0, resources: 0 }
		};

		const described = await rpc(call('bucket_address_change', args), token);
		const performed = await rpc(
			call('bucket_address_change', {
				...args,
				confirmationToken:
					described.result?.structuredContent?.confirmationToken
			}),
			token
		);

		expect(performed.result?.structuredContent?.reason).toBe('forbidden');
		expect((await getBucketStore().find(bucket._id))?.host).toBeUndefined();
	});

	it('lets a non-super administrator create a bucket into their own scope', async () => {
		const { token } = await principal('plain');
		const suffix = Math.floor(Math.random() * 1e6);

		expect(
			await viaAgent(
				'bucket_create',
				{ name: 'Own bucket', slug: `own-bucket-${suffix}` },
				token
			)
		).toBe('ok');
		const bucket = (await getBucketStore().list()).find(
			(b) => b.slug === `own-bucket-${suffix}`
		);
		expect(await viaAgent('bucket_get', { id: bucket?._id }, token)).toBe('ok');
	});

	/*
	 * FR-010: a tenant's agent sets up an integration end to end in its own bucket — the application that
	 * signs people in and the API it calls — through the bucket-scoped tools alone, with no container
	 * between the bucket and either.
	 */
	it('adds an application and an API to a bucket of its own for a non-super administrator, and lists both there', async () => {
		const { token, user } = await principal('plain');
		const suffix = Math.floor(Math.random() * 1e6);
		const bucket = await getBucketStore().create({
			name: 'Tenant',
			slug: `tenant-${suffix}`,
			ownerGroupId: await personalGroupId(user._id)
		});
		const identifier = `https://api-${suffix}.example.com/mcp`;

		const created = await rpc(
			call('client_create', {
				id: bucket._id,
				clientName: 'Tenant app',
				grantTypes: ['authorization_code'],
				redirectUris: ['https://tenant.example.com/cb'],
				tokenEndpointAuthMethod: 'none'
			}),
			token
		);
		const declared = await rpc(
			call('resource_declare', {
				id: bucket._id,
				identifier,
				name: 'Tenant API',
				scopes: ['tools:call']
			}),
			token
		);

		expect(created.result?.isError).not.toBe(true);
		expect(declared.result?.isError).not.toBe(true);
		const { clientId } = shaped(
			Type.Object({ clientId: Type.String() }),
			created.result?.structuredContent?.result
		);
		const clients = shaped(
			Type.Array(Type.Object({ clientId: Type.String() })),
			(await rpc(call('client_list', { id: bucket._id }), token)).result
				?.structuredContent?.result
		);
		expect(clients.map((c) => c.clientId)).toEqual([clientId]);
		const apis = shaped(
			Type.Object({
				namespace: Type.String(),
				resources: Type.Array(Type.Object({ identifier: Type.String() }))
			}),
			(await rpc(call('resource_list', { id: bucket._id }), token)).result
				?.structuredContent?.result
		);
		expect(apis.namespace).toBe('bucket');
		expect(apis.resources.map((r) => r.identifier)).toEqual([identifier]);
	});

	it('cannot escalate by asking a different tool for the same thing', async () => {
		const { token } = await principal('plain');

		/*
		 * The audit trail is no longer super-admin only: it is scope-filtered, so a tenant administrator
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
