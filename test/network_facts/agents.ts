import { elysia } from 'lib/index.ts';
import { ISSUER } from 'lib/configs/env.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { ADMIN_MCP_CLIENT_ID, MCP_RESOURCE } from 'lib/mcp/consts.ts';
import { sessionFor } from '../admin_session.ts';
import { createAdministrator, type AdminKind } from '../administrators.ts';
import { postMcp } from '../mcp/rpc.ts';
import { present } from '../shape.ts';

/* The console's routes and an agent's tools, as the network facts specs call them. */

export async function cookieOf(kind: AdminKind): Promise<string> {
	const user = await createAdministrator(kind, `${kind}-${Math.random()}@x.io`);
	return `${ADMIN_SESSION_COOKIE}=${(await sessionFor(user))._id}`;
}

export function call(
	method: string,
	path: string,
	cookie: string,
	body?: unknown
): Promise<Response> {
	return elysia.handle(
		new Request(`${ISSUER}${path}`, {
			method,
			headers: {
				cookie,
				...(body === undefined ? {} : { 'content-type': 'application/json' })
			},
			body: body === undefined ? undefined : JSON.stringify(body)
		})
	);
}

let rpcId = 0;

export async function rpc(body: unknown, token: string) {
	const { raw, message } = await postMcp(body, token);
	return { raw, payload: present(message, 'a JSON-RPC message') };
}

export function tool(name: string, args: Record<string, unknown>) {
	return {
		jsonrpc: '2.0',
		id: ++rpcId,
		method: 'tools/call',
		params: { name, arguments: args }
	};
}

export async function agent(kind: AdminKind = 'super'): Promise<string> {
	const user = await createAdministrator(
		kind,
		`facts-agent-${Math.random()}@x.io`
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
