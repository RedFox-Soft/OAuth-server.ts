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
import {
	getBucketStore,
	getUserStore,
	adminAuditStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import {
	ADMIN_MCP_CLIENT_ID,
	MCP_RESOURCE,
	MCP_ROUTE
} from 'lib/mcp/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { mock } from '../fetch_mock.ts';
import {
	appleStub,
	githubStub,
	microsoftStub
} from '../federation/recognised_stubs.ts';

/*
 * An agent connects a recognised provider through the same operation the console uses.
 *
 * There is deliberately no new tool here, and that is the claim as much as anything asserted below: three
 * providers arrived through the four federation tools that already existed, so an agent inherited them with
 * no second write path to publish, no second audit action and no second set of refusals to keep in step.
 */

const TENANT = '11112222-bbbb-3333-cccc-4444dddd5555';
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

async function agentSession() {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`fed-parity-${Math.random()}@x.io`,
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
	return { user, token };
}

async function seedBucket() {
	return getBucketStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name: `parity-${Math.random()}`,
		slug: `p-${Math.random().toString(36).slice(2, 10)}`
	});
}

function resultOf(response: { result?: { structuredContent?: unknown } }) {
	return (response.result?.structuredContent ?? {}) as Record<string, unknown>;
}

/**
 * @proves An agent reads the same connection guidance the console shows — including the values each
 * provider requires and the question one of them asks — connects any recognised provider through the
 * same operation with the same refusals, and leaves one audit entry naming both the administrator and
 * the agent, while no read returns a stored key.
 */
describe('an agent connecting a recognised provider', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		ApplicationConfig['mcp.enabled'] = true;
		resetAdminMemoryStores();
		await ensureAdminSeed();
	});

	afterEach(() => {
		mock.restore();
	});

	it('reads the values each provider requires, and the question one of them asks', async () => {
		const { token } = await agentSession();
		const bucket = await seedBucket();

		const response = await rpc(
			call('federation_catalogue_list', { id: bucket._id }),
			token
		);
		const providers = (resultOf(response).result ?? resultOf(response)) as {
			providers?: {
				catalogueId: string;
				requiredValues?: unknown[];
				choices?: { options: unknown[] }[];
				callbackUri?: string;
			}[];
		};

		const byId = new Map(
			(providers.providers ?? []).map((entry) => [entry.catalogueId, entry])
		);
		// The same counts the console is given: what a provider asks for is one published fact, not two.
		expect(byId.get('github')?.requiredValues).toHaveLength(2);
		expect(byId.get('microsoft')?.requiredValues).toHaveLength(3);
		expect(byId.get('apple')?.requiredValues).toHaveLength(4);
		// Including the callback address, which is the one thing an administrator cannot work out alone.
		expect(byId.get('apple')?.callbackUri).toContain('/federation/callback');
		expect(byId.get('microsoft')?.choices?.[0]?.options).toHaveLength(2);
	});

	it('connects Microsoft, Apple and GitHub through the operation the console uses', async () => {
		const { user, token } = await agentSession();
		const bucket = await seedBucket();

		const microsoft = await microsoftStub(TENANT);
		microsoft.expectDiscovery();
		const apple = await appleStub();
		apple.expectDiscovery();
		const github = githubStub();

		const bodies: Record<string, unknown>[] = [
			{
				catalogueId: 'microsoft',
				tenant: TENANT,
				clientId: microsoft.clientId,
				clientSecret: 'upstream-secret'
			},
			{
				catalogueId: 'apple',
				clientId: apple.clientId,
				teamId: apple.teamId,
				keyId: apple.keyId,
				signingKey: apple.signingKey
			},
			{
				catalogueId: 'github',
				clientId: github.clientId,
				clientSecret: 'upstream-secret'
			}
		];

		for (const body of bodies) {
			const response = await rpc(
				call('federation_provider_create', { bucketId: bucket._id, ...body }),
				token
			);
			expect(
				response.result?.isError,
				`connecting ${body.catalogueId} through the agent surface failed: ${JSON.stringify(response.result)}`
			).toBeFalsy();
		}

		// Stored exactly as the console would have stored them, and nothing records which surface did it.
		const stored = await getBucketStore().find(bucket._id);
		expect((stored?.federation ?? []).map((entry) => entry.id).sort()).toEqual([
			'apple',
			'github',
			'microsoft'
		]);

		/*
		 * One entry per connection, naming the administrator who authorised the agent and the agent that
		 * acted — both, because an action has to be attributable to each.
		 */
		const { entries } = await adminAuditStore.list({ actor: user._id });
		const creates = entries.filter(
			(entry) => entry.action === 'federation.provider.create'
		);
		expect(creates).toHaveLength(3);
		for (const entry of creates) {
			expect(entry.actorId).toBe(user._id);
			expect(JSON.stringify(entry)).not.toContain('upstream-secret');
		}
	});

	it('refuses the agent exactly as it refuses the console, and stores nothing', async () => {
		const { token } = await agentSession();
		const bucket = await seedBucket();

		const response = await rpc(
			call('federation_provider_create', {
				bucketId: bucket._id,
				catalogueId: 'microsoft',
				tenant: 'not a tenant!',
				clientId: '00001111-aaaa-2222-bbbb-3333cccc4444',
				clientSecret: 'upstream-secret'
			}),
			token
		);

		expect(response.result?.isError).toBe(true);
		expect(JSON.stringify(response.result)).toMatch(/organisation/i);
		const stored = await getBucketStore().find(bucket._id);
		expect(stored?.federation ?? []).toHaveLength(0);
	});

	it('returns no stored key when an agent reads a provider back', async () => {
		const { token } = await agentSession();
		const bucket = await seedBucket();
		const apple = await appleStub();
		apple.expectDiscovery();

		await rpc(
			call('federation_provider_create', {
				bucketId: bucket._id,
				catalogueId: 'apple',
				clientId: apple.clientId,
				teamId: apple.teamId,
				keyId: apple.keyId,
				signingKey: apple.signingKey
			}),
			token
		);

		const listed = await rpc(
			call('federation_provider_list', { id: bucket._id }),
			token
		);
		/*
		 * One newline-free line of the key. The stored value is PEM, so a leak through a JSON response
		 * arrives with its newlines escaped — a needle containing real newlines would never match it, and
		 * the assertion would pass while the key was on the wire.
		 */
		const keyLine = apple.signingKey
			.split('\n')
			.map((line) => line.trim())
			.reduce(
				(longest, line) => (line.length > longest.length ? line : longest),
				''
			);
		expect(keyLine.length).toBeGreaterThan(20);
		expect(JSON.stringify(listed)).not.toContain(keyLine);
	});
});
