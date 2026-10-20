import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import bootstrap, { seedClient } from '../test_helper.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getBucketStore } from 'lib/adapters/index.ts';
import { ADMIN_SESSION_COOKIE, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { ADMIN_MCP_CLIENT_ID, MCP_RESOURCE } from 'lib/mcp/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { clientRoutes } from 'lib/admin/clients/routes.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { createAdministrator } from '../administrators.ts';
import { sessionFor } from '../admin_session.ts';
import { rpc } from './rpc.ts';

const console_ = treaty(new Elysia().use(resolveAdmin).use(clientRoutes));

let rpcId = 0;
function call(name: string, args: Record<string, unknown>) {
	return {
		jsonrpc: '2.0',
		id: ++rpcId,
		method: 'tools/call',
		params: { name, arguments: args }
	};
}

/* One super administrator, reaching the console with a session and the agent surface with a token. */
async function administrator() {
	const user = await createAdministrator('super', `conn-${nanoid()}@x.io`);
	const cookie = `${ADMIN_SESSION_COOKIE}=${(await sessionFor(user))._id}`;
	const at = new AccessToken({
		client: await Client.find(ADMIN_MCP_CLIENT_ID),
		accountId: user._id,
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
	return { cookie, token };
}

const ADDRESSES = {
	path: (id: string) => ({ slug: `conn-${id}` }),
	subdomain: (id: string) => ({ slug: `conn-${id}`, subdomain: true as const }),
	hostname: (id: string) => ({ host: `conn-${id}.example.org` })
};

/**
 * @proves An agent reading an application through the management surface gets exactly the connection values a person
 * reads in the console, whatever form the project's address takes.
 */
describe("an application's connection values, for an agent", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'tool_behaviours' });
	});

	beforeEach(async () => {
		ApplicationConfig['mcp.enabled'] = true;
		await ensureAdminSeed();
	});

	for (const [form, address] of Object.entries(ADDRESSES)) {
		it(`match the console's for a project at a ${form}`, async () => {
			const { cookie, token } = await administrator();
			const id = nanoid()
				.toLowerCase()
				.replace(/[^a-z0-9]/g, '');
			const bucket = await getBucketStore().create({
				name: `connection ${form}`,
				ownerGroupId: UNASSIGNED_GROUP_ID,
				...address(id)
			});
			forgetBucketAddresses();
			const clientId = `conn-app-${id}`;
			seedClient({
				clientId,
				bucketId: bucket._id,
				applicationType: 'web',
				redirectUris: ['https://rp.example.com/cb'],
				responseTypes: ['code'],
				grantTypes: ['authorization_code'],
				token_endpoint_auth_method: 'none'
			});

			const read = await console_.admin.api
				.projects({ id: bucket._id })
				.clients({ clientId })
				.get({ headers: { cookie } });
			const seen = (read.data as unknown as { connection: unknown }).connection;

			const answered = await rpc(
				call('client_get', { id: bucket._id, clientId }),
				token
			);
			const agent = (
				answered.result?.structuredContent?.result as { connection?: unknown }
			).connection;

			expect(seen).toBeDefined();
			expect(agent).toEqual(seen);
		});
	}
});
