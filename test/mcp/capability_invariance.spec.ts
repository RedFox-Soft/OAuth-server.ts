import {
	describe,
	it,
	expect,
	beforeAll,
	beforeEach,
	afterEach
} from 'bun:test';

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
import { ApplicationConfig } from 'lib/configs/application.js';
import { mock } from '../fetch_mock.ts';
import { idpStub } from '../federation/idp_stub.ts';

/*
 * FR-006, FR-037, SC-012: the published operation set does not vary with the instance's capability
 * switches.
 *
 * This looks like a strange thing to want until you know why the admin plane is built that way. `/admin`
 * is an `alwaysAvailablePrefixes` entry in `lib/consts/route_classification.ts`, and the table's own
 * comment names the deciding case: a federation provider must remain deletable by a deployment that has
 * just switched federation off. The console follows the same policy in its forms rather than mirroring
 * flags client-side, because that would restate a server rule in a second place.
 *
 * So an earlier reading of FR-006 — hide what is disabled — described behaviour the console does not
 * have. The requirement now says one operation set per release, and this is what holds it there.
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
		`inv-${Math.random()}@x.io`,
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

async function publishedToolNames(token: string): Promise<string[]> {
	const listed = await rpc(
		{ jsonrpc: '2.0', id: ++rpcId, method: 'tools/list', params: {} },
		token
	);
	return ((listed.result?.tools ?? []) as { name: string }[])
		.map((t) => t.name)
		.sort();
}

/* Flag configurations that differ in ways a naive implementation would have leaked into the tool list. */
const CONFIGURATIONS: [string, Record<string, boolean>][] = [
	['everything on', { 'federation.enabled': true, 'dpop.enabled': true }],
	['federation off', { 'federation.enabled': false }],
	['dpop off', { 'dpop.enabled': false }],
	[
		'several off at once',
		{
			'federation.enabled': false,
			'dpop.enabled': false,
			'introspection.enabled': false,
			'revocation.enabled': false,
			'userinfo.enabled': false
		}
	]
];

describe('published operation set is capability-invariant', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		ApplicationConfig['mcp.enabled'] = true;
		await ensureAdminSeed();
	});

	afterEach(() => {
		// The outbound stub is per-case: each provider create consumes its own single-use interceptor.
		mock.restore();
	});

	it('offers the same tools under every flag configuration', async () => {
		const seen = new Map<string, string[]>();

		for (const [label, flags] of CONFIGURATIONS) {
			for (const [key, value] of Object.entries(flags)) {
				(ApplicationConfig as Record<string, unknown>)[key] = value;
			}
			const token = await session();
			seen.set(label, await publishedToolNames(token));
		}

		const [first, ...rest] = [...seen.values()];
		expect(first.length).toBe(44);
		for (const [label, names] of [...seen.entries()].slice(1)) {
			expect(names, `tool list changed under: ${label}`).toEqual(first);
		}
		expect(rest.length).toBe(CONFIGURATIONS.length - 1);
	});

	it('still deletes a federation provider with federation switched off', async () => {
		ApplicationConfig['federation.enabled'] = true;
		const token = await session();

		const bucket = await rpc(call('bucket_create', { name: 'Fed' }), token);
		const bucketId = (
			bucket.result?.structuredContent?.result as { _id: string }
		)._id;

		/*
		 * Creating a provider validates its issuer by fetching the discovery document — deliberately, so a
		 * mistyped issuer is caught at configuration time rather than at somebody's first sign-in. The stub
		 * is therefore load-bearing: without it the create fails, and the deletion below would "pass" on a
		 * provider that was never there.
		 */
		const idp = await idpStub('https://idp-mcp-invariance.test');
		idp.expectDiscovery();

		const createdProvider = await rpc(
			call('federation_provider_create', {
				bucketId,
				id: 'okta',
				displayName: 'Okta',
				issuer: idp.origin,
				clientId: 'fed',
				clientSecret: 'fed-secret'
			}),
			token
		);
		expect(createdProvider.result?.isError).not.toBe(true);

		/*
		 * The case that decides the whole rule: a deployment that has just switched federation off must
		 * still be able to delete a provider it no longer trusts.
		 */
		ApplicationConfig['federation.enabled'] = false;

		const described = await rpc(
			call('federation_provider_delete', { id: bucketId, providerId: 'okta' }),
			token
		);
		const confirmationToken =
			described.result?.structuredContent?.confirmationToken;
		expect(confirmationToken).toBeString();

		const deleted = await rpc(
			call('federation_provider_delete', {
				id: bucketId,
				providerId: 'okta',
				confirmationToken
			}),
			token
		);
		expect(deleted.result?.isError).not.toBe(true);

		const remaining = await rpc(
			call('federation_provider_list', { id: bucketId }),
			token
		);
		expect(JSON.stringify(remaining)).not.toContain('okta');
	});

	it('reads a bucket with federation off, rather than hiding the operation', async () => {
		ApplicationConfig['federation.enabled'] = false;
		const token = await session();

		const bucket = await rpc(
			call('bucket_create', { name: 'Readable' }),
			token
		);
		const bucketId = (
			bucket.result?.structuredContent?.result as { _id: string }
		)._id;

		// The operation is offered and answers. If a capability affected the outcome, the operation
		// itself would say so — the surface does not pre-empt it (FR-037).
		const providers = await rpc(
			call('federation_provider_list', { id: bucketId }),
			token
		);
		expect(providers.result?.isError).not.toBe(true);
	});

	it('no tool body reads a capability flag', async () => {
		// A structural check, so the surface cannot start gating locally later and quietly diverge from
		// the console. The catalogue and the tool loop describe operations; deciding availability from a
		// flag belongs to featureGate and to the handlers, not here.
		const sources = await Promise.all(
			[
				'catalogue.ts',
				'server.ts',
				'dispatch.ts',
				'result.ts',
				'confirm.ts'
			].map(
				async (name) =>
					[name, await Bun.file(`lib/mcp/${name}`).text()] as const
			)
		);

		for (const [name, source] of sources) {
			expect(source, `${name} reads ApplicationConfig`).not.toContain(
				'ApplicationConfig'
			);
		}
	});
});
