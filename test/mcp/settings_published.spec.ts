import { describe, it, expect, beforeAll } from 'bun:test';

import bootstrap from '../test_helper.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ADMIN_MCP_CLIENT_ID, MCP_RESOURCE } from 'lib/mcp/consts.ts';
import { shaped } from 'test/shape.js';
import { Type, type Static } from '@sinclair/typebox';
import { createAdministrator } from '../administrators.ts';
import { rpc } from './rpc.ts';

/*
 * The schema an agent reads is the one `tools/list` returns, and that is two layers below where the
 * types are declared: the catalogue's body schema is spread into a tool schema, and that is handed to
 * the SDK's `fromJsonSchema` before anything is published. Proving the declaration exists proves
 * nothing about what comes back out — which is exactly the gap that let `settings_update` ship
 * describing no setting at all.
 */

let rpcId = 0;

async function session() {
	const user = await createAdministrator('super', `pub-${Math.random()}@x.io`);
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

// What an agent reads of one published setting; the values themselves are left to the assertions.
const Published = Type.Object({
	type: Type.Optional(Type.Unknown()),
	items: Type.Optional(Type.Object({ type: Type.Optional(Type.Unknown()) })),
	enum: Type.Optional(Type.Unknown())
});

const InputSchema = Type.Object({
	properties: Type.Optional(Type.Record(Type.String(), Published)),
	additionalProperties: Type.Optional(Type.Unknown())
});

/**
 * @proves An agent listing the tools is told what each server setting accepts, so it sends a typed
 * value rather than the text of one, and may still name a setting the catalogue does not declare.
 */
describe('the settings tool as an agent receives it', () => {
	let schema: Static<typeof InputSchema>;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'mcp' });
		await ensureAdminSeed();
		const token = await session();
		const listed = await rpc(
			{ jsonrpc: '2.0', id: ++rpcId, method: 'tools/list', params: {} },
			token
		);
		const tools = shaped(
			Type.Array(
				Type.Object({
					name: Type.String(),
					inputSchema: Type.Optional(Type.Unknown())
				})
			),
			listed.result?.tools ?? []
		);
		const tool = tools.find((t) => t.name === 'settings_update');
		if (!tool) throw new Error('settings_update is not published');
		schema = shaped(InputSchema, tool.inputSchema ?? {});
	});

	it('states the type of a switch, a list and a choice', () => {
		const properties: Partial<NonNullable<typeof schema.properties>> =
			schema.properties ?? {};

		expect(properties['par.enabled']?.type).toBe('boolean');
		expect(properties['scopes']?.type).toBe('array');
		expect(properties['scopes']?.items?.type).toBe('string');
		expect(properties['deviceFlow.charset']?.enum).toEqual([
			'base-20',
			'digits'
		]);
	});

	// The half that is easy to lose while adding the other: declaring the catalogue must not close the
	// object, or a setting retired between releases becomes a rejected argument with nothing naming it.
	it('still carries a setting it does not declare', () => {
		expect(schema.additionalProperties).not.toBe(false);
	});
});
