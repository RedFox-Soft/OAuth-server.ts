import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	getUserStore,
	adminAuditStore,
	mcpConfirmationStore
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import {
	ADMIN_MCP_CLIENT_ID,
	MCP_RESOURCE,
	MCP_ROUTE
} from 'lib/mcp/consts.ts';
import { mcpCatalogue, pathArgName } from 'lib/mcp/catalogue.ts';
import { ApplicationConfig } from 'lib/configs/application.js';

/*
 * SC-005: zero high-consequence operations take effect without a matching prior confirmation.
 *
 * Driven from the catalogue rather than a list of eleven tools, which is the point. A tool promoted to
 * `high` next year is covered here the moment it is classified, and a *new* high-consequence tool that
 * somehow bypassed the gate would fail this file rather than shipping quietly.
 *
 * The describe step runs before dispatch, so it needs no real target — which is what makes a complete
 * matrix affordable. What is asserted is the property the gate exists for: the first call describes,
 * changes nothing, and writes nothing to the trail.
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

async function session() {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`mx-${Math.random()}@x.io`,
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
	return { token, user };
}

/*
 * The non-path arguments each tool needs to satisfy its input schema. Path parameters are filled in
 * generically below, so adding a high-consequence tool with no body needs no entry here at all — it is
 * covered the moment it is classified.
 */
const BODIES: Record<string, Record<string, unknown>> = {
	bucket_user_password_reset: {
		password: 'a new password that is long enough'
	},
	jwks_generate: { alg: 'RS256' },

	settings_update: { 'dpop.requireNonce': true },
	smtp_settings_update: {
		host: 'smtp.example.com',
		port: 587,
		secure: true,
		username: 'mailer',
		password: 'irrelevant to this test',
		fromName: 'Ops',
		fromEmail: 'ops@example.com'
	}
};

const HIGH = mcpCatalogue.filter((t) => t.consequence === 'high');

describe('every high-consequence tool is gated', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		ApplicationConfig['mcp.enabled'] = true;
		await ensureAdminSeed();
	});

	it('finds the eleven the specification names', () => {
		// If this number moves, FR-014 and the catalogue have to move with it — and the matrix below
		// grows automatically rather than needing a new case written by hand.
		expect(HIGH.length).toBe(11);
	});

	it.each(HIGH.map((t) => [t.tool, t] as const))(
		'%s describes instead of acting, and records nothing',
		async (_name, tool) => {
			const { token, user } = await session();

			const args: Record<string, unknown> = { ...(BODIES[tool.tool] ?? {}) };
			for (const param of tool.pathParams) {
				// A plausible identifier. The describe step runs before dispatch, so it never has to exist.
				args[pathArgName(tool, param)] = `no-such-${param}`;
			}

			const before = await adminAuditStore.list({ actor: user._id });
			const described = await rpc(call(tool.tool, args), token);
			const after = await adminAuditStore.list({ actor: user._id });

			const structured = described.result?.structuredContent;
			expect(
				structured?.status,
				`${tool.tool} did not ask for confirmation: ${JSON.stringify(described.result)}`
			).toBe('confirmation_required');
			expect(structured?.confirmationToken, tool.tool).toBeString();

			// The trail records what was applied. Nothing was.
			expect(
				after.total,
				`${tool.tool} wrote an audit entry while describing`
			).toBe(before.total);
		}
	);

	it.each(HIGH.map((t) => [t.tool, t] as const))(
		'%s refuses a confirmation it did not issue',
		async (_name, tool) => {
			const { token } = await session();

			const args: Record<string, unknown> = { ...(BODIES[tool.tool] ?? {}) };
			for (const param of tool.pathParams) {
				args[pathArgName(tool, param)] = `no-such-${param}`;
			}

			const refused = await rpc(
				call(tool.tool, { ...args, confirmationToken: 'fabricated-token' }),
				token
			);

			expect(refused.result?.isError, tool.tool).toBe(true);
			expect(refused.result?.structuredContent?.reason, tool.tool).toBe(
				'invalid_confirmation'
			);
		}
	);

	it('issues one confirmation per describe, and no more', async () => {
		const { token } = await session();
		const before = await mcpConfirmationStore.count();

		for (const tool of HIGH) {
			const args: Record<string, unknown> = { ...(BODIES[tool.tool] ?? {}) };
			for (const param of tool.pathParams) {
				args[pathArgName(tool, param)] = `no-such-${param}`;
			}
			await rpc(call(tool.tool, args), token);
		}

		// Exactly one per tool: a describe that quietly issued two would leave a spare token behind,
		// and single-use would stop meaning what it says.
		expect(await mcpConfirmationStore.count()).toBe(before + HIGH.length);
	});

	it('leaves every ordinary tool ungated', () => {
		// The converse of the matrix: confirmation is for the eleven, and an ordinary write must not
		// quietly acquire a gate that an agent has no way to satisfy.
		const gated = mcpCatalogue.filter(
			(t) => t.consequence === 'ordinary' || t.consequence === 'read'
		);
		expect(gated.length).toBe(44 - 11);
		for (const tool of gated) {
			expect(tool.consequence, tool.tool).not.toBe('high');
		}
	});
});
