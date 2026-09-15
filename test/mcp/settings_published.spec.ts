import { describe, it, expect, beforeAll } from 'bun:test';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getUserStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import {
	ADMIN_MCP_CLIENT_ID,
	MCP_RESOURCE,
	MCP_ROUTE
} from 'lib/mcp/consts.ts';

/*
 * The schema an agent reads is the one `tools/list` returns, and that is two layers below where the
 * types are declared: the catalogue's body schema is spread into a tool schema, and that is handed to
 * the SDK's `fromJsonSchema` before anything is published. Proving the declaration exists proves
 * nothing about what comes back out — which is exactly the gap that let `settings_update` ship
 * describing no setting at all.
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

async function session() {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`pub-${Math.random()}@x.io`,
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

interface Published {
	type?: string;
	items?: { type?: string };
	enum?: string[];
}

/**
 * @proves An agent listing the tools is told what each server setting accepts, so it sends a typed
 * value rather than the text of one, and may still name a setting the catalogue does not declare.
 */
describe('the settings tool as an agent receives it', () => {
	let schema: {
		properties?: Record<string, Published>;
		additionalProperties?: boolean;
	};

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'mcp' });
		await ensureAdminSeed();
		const token = await session();
		const listed = await rpc(
			{ jsonrpc: '2.0', id: ++rpcId, method: 'tools/list', params: {} },
			token
		);
		const tools = (listed.result?.tools ?? []) as {
			name: string;
			inputSchema?: typeof schema;
		}[];
		const tool = tools.find((t) => t.name === 'settings_update');
		if (!tool) throw new Error('settings_update is not published');
		schema = tool.inputSchema ?? {};
	});

	it('states the type of a switch, a list and a choice', () => {
		const properties = schema.properties ?? {};

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
