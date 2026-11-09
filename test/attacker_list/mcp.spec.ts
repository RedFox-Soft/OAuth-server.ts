import { beforeAll, beforeEach, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import { ADMIN_MCP_CLIENT_ID, MCP_RESOURCE } from 'lib/mcp/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { createAdministrator } from '../administrators.ts';
import { postMcp } from '../mcp/rpc.ts';
import { present } from '../shape.ts';
import {
	clockAt,
	iso,
	listedAddress,
	pass,
	publication,
	resetAttackerList,
	seconds,
	signer
} from './helper.ts';
import { seedProject } from './door.ts';

let rpcId = 0;

async function rpc(body: unknown, token: string) {
	const { raw, message } = await postMcp(body, token);
	return { raw, payload: present(message, 'a JSON-RPC message') };
}

function call(name: string, args: Record<string, unknown>) {
	return {
		jsonrpc: '2.0',
		id: ++rpcId,
		method: 'tools/call',
		params: { name, arguments: args }
	};
}

async function agent(): Promise<string> {
	const user = await createAdministrator(
		'super',
		`list-agent-${Math.random()}@x.io`
	);
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
	return token;
}

let undoClock: () => void = () => {};

/**
 * @proves An agent reads the state of FoxTrust's attacker list and a project's numbers through the console's own
 * routes, never seeing an address from the list, and is refused making the administrators' project refuse
 * listed addresses, as the console is.
 */
describe('an agent and the attacker list', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		ApplicationConfig['mcp.enabled'] = true;
		await ensureAdminSeed();
		resetAttackerList();
		undoClock();
		undoClock = clockAt(0.1);
	});

	it("reads the list's state without any address", async () => {
		const foxtrust = await signer();
		const address = listedAddress();
		await publication().publish({
			version: `a${String(seconds(0))}`,
			builtAt: iso(0),
			validUntil: iso(3),
			lines: [{ network: address, lastSeen: seconds(-1) }],
			by: foxtrust
		});
		await pass(foxtrust);

		const { raw, payload } = await rpc(
			call('attacker_list_status_get', {}),
			await agent()
		);

		expect({
			error: payload.result?.isError === true,
			mentionsAddress: raw.includes(address),
			state: (payload.result?.structuredContent?.result as { state?: string })
				.state
		}).toEqual({ error: false, mentionsAddress: false, state: 'current' });
	});

	it("reads a project's choice and numbers", async () => {
		const bucketId = await seedProject();

		const { payload } = await rpc(
			call('project_password_guessing_get', { id: bucketId }),
			await agent()
		);

		expect(payload.result?.structuredContent?.result).toMatchObject({
			mode: 'count',
			days: 7,
			counts: { listedAttempts: 0, listedRightPassword: 0, refused: 0 }
		});
	});

	it("is refused making the administrators' project refuse listed addresses", async () => {
		const { payload } = await rpc(
			call('project_update', {
				id: ADMIN_BUCKET_ID,
				passwordGuessing: { mode: 'refuse', exempt: [] }
			}),
			await agent()
		);

		expect(payload.result?.isError).toBe(true);
	});
});
