import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';

import bootstrap from '../test_helper.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adapter,
	adminAuditStore,
	getProjectStore
} from 'lib/adapters/index.ts';
import { MCP_RESOURCE } from 'lib/mcp/consts.ts';
import { clearPermissions, permitIdentifier } from './permissions.ts';
import { createAdministrator } from '../administrators.ts';
import { rpc } from './rpc.ts';

/*
 * Who the audit trail names when an agent acts through a permitted client identity.
 *
 * The constitution requires an agent's action to be attributable to the agent *and* the authorizing
 * principal. The reserved client already satisfies that; this asserts a permitted document identifier
 * does too, because the attribution comes from the token's client rather than from a list of known
 * agents — which is what stops it drifting as new identities are permitted.
 *
 * Deliberately narrow. That a console action leaves the agent fields absent — the property that makes
 * their presence mean "an agent did this" — is covered in `audit_attribution.spec.ts`, through the
 * console route with a cookie. Asserting it again here from a direct store write would have looked
 * like coverage while testing nothing.
 */

const DOC = 'https://agent.example.com/oauth/client-metadata.json';

let rpcId = 0;

/**
 * @proves An action taken through a permitted client identity names both the administrator and
 * that identity.
 */
describe('attributing an action taken through a permitted identity', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'mcp' });
	});

	beforeEach(async () => {
		await ensureAdminSeed();
		await clearPermissions();
		await adapter('Client').upsert(DOC, {
			clientId: DOC,
			token_endpoint_auth_method: 'none',
			grantTypes: ['authorization_code', 'refresh_token'],
			responseTypes: ['code'],
			redirectUris: ['http://127.0.0.1:33418/callback']
		});
		await permitIdentifier(DOC);
	});

	it('names both the administrator and the client identity', async () => {
		const user = await createAdministrator(
			'super',
			`admin-${Math.random()}@x.io`
		);
		const at = new AccessToken({
			client: await Client.find(DOC),
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

		const slug = `attributed-${Math.random().toString(36).slice(2)}`;
		const response = await rpc(
			{
				jsonrpc: '2.0',
				id: ++rpcId,
				method: 'tools/call',
				params: {
					name: 'project_create',
					arguments: { name: 'Attributed', slug }
				}
			},
			token
		);
		expect(response.result?.isError).not.toBe(true);

		const created = await getProjectStore().findBySlug(slug);
		expect(created).toBeTruthy();

		const entries = await adminAuditStore.list({
			action: 'project.create',
			limit: 25
		});
		const mine = entries.entries.find((e) => e.targetId === created?._id);

		/* The administrator who authorized the agent... */
		expect(mine?.actorId).toBe(user._id);
		/* ...and the agent that acted, which is the client identity itself. */
		expect(mine?.viaClientId).toBe(DOC);
		expect(mine?.viaSurface).toBe('mcp');
	});
});
