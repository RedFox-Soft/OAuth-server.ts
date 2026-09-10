import { describe, it, expect, beforeAll } from 'bun:test';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { MCP_METADATA_ROUTE, MCP_ROUTE } from 'lib/mcp/consts.ts';
import { MCP_RESOURCE_SERVER } from 'lib/mcp/resource_server.ts';
import { insufficientScope } from 'lib/mcp/index.ts';

/*
 * What the surface tells a caller it needs.
 *
 * The specification asks an MCP server to name the required scopes in its `WWW-Authenticate` challenge
 * so a client is not sent to the protected resource metadata to guess from `scopes_supported`. What it
 * does NOT ask for is any weakening of the refusal itself: which check failed stays invisible, and the
 * reason still goes to the event bus rather than to the caller.
 */

async function challengeFor(headers: Record<string, string>) {
	const res = await elysia.handle(
		new Request(`http://e.ly${MCP_ROUTE}`, {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				accept: 'application/json, text/event-stream',
				...headers
			},
			body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize' })
		})
	);
	return { status: res.status, challenge: res.headers.get('www-authenticate') };
}

/**
 * @proves An unauthenticated agent learns from the challenge where to get a token and what to
 * ask for, and nothing about which check it failed.
 */
describe('the challenge an unauthenticated caller receives', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'mcp' });
	});

	it('names where to get a token and what to ask for', async () => {
		const { status, challenge } = await challengeFor({
			authorization: 'Bearer not-a-real-token'
		});

		expect(status).toBe(401);
		expect(challenge).toContain(
			`resource_metadata="http://e.ly${MCP_METADATA_ROUTE}"`
		);
		expect(challenge).toContain(`scope="${MCP_RESOURCE_SERVER.scope}"`);
		expect(challenge).toContain('error="invalid_token"');
	});

	/*
	 * The scope advertised in the challenge is the descriptor's own, so the two cannot drift into
	 * telling a client to ask for something the resource does not recognise.
	 */
	it('advertises exactly the scope the resource descriptor declares', async () => {
		const { challenge } = await challengeFor({
			authorization: 'Bearer not-a-real-token'
		});

		expect(challenge).toContain('scope="openid"');
		expect(MCP_RESOURCE_SERVER.scope).toBe('openid');
	});

	/*
	 * The refusal stays one answer for every cause. A challenge that named the failed check would hand
	 * an unauthenticated caller a way to probe for valid tokens, admin accounts and permitted clients.
	 */
	it('says nothing about which check failed', async () => {
		const unknown = await challengeFor({ authorization: 'Bearer nope' });
		const malformed = await challengeFor({ authorization: 'Whatever xyz' });

		expect(unknown.status).toBe(401);
		expect(malformed.status).toBe(401);
		expect(unknown.challenge).toBe(malformed.challenge);
	});
});

describe('the insufficient-scope response', () => {
	/*
	 * Asserted as a shape rather than driven through a request, and that is the honest form: every tool
	 * on this surface is authorized by the administrator's roles, and the descriptor declares `openid`
	 * alone — so there is no scope a valid token here can be missing, and no request can reach this arm
	 * today. It exists because the specification defines the response and a client implements a step-up
	 * flow against it; a declared resource's owner will need the same shape.
	 */
	it('carries the error, the required scope and where to look', () => {
		const set = { status: 200, headers: {} as Record<string, string> };

		const body = insufficientScope(set as never, 'files:write');

		expect(set.status).toBe(403);
		const challenge = set.headers['www-authenticate'];
		expect(challenge).toContain('error="insufficient_scope"');
		expect(challenge).toContain('scope="files:write"');
		expect(challenge).toContain('resource_metadata=');
		expect(body).toMatchObject({ jsonrpc: '2.0' });
	});
});
