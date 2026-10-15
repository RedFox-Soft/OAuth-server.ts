import { beforeAll, beforeEach, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminAuditStore,
	getBucketKeysStore,
	getBucketStore
} from 'lib/adapters/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { ADMIN_MCP_CLIENT_ID, MCP_RESOURCE } from 'lib/mcp/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { keysFor } from 'lib/keys/issuer_keys.ts';
import { createAdministrator } from '../administrators.ts';
import { postMcp } from './rpc.ts';
import { present, shaped } from '../shape.ts';
import { Type } from '@sinclair/typebox';

let rpcId = 0;

// The body as sent too: the assertions below look for key material in the raw text, not only the message.
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

async function agent() {
	const user = await createAdministrator(
		'super',
		`keys-agent-${Math.random()}@x.io`
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

async function keyedBucket() {
	const bucket = await getBucketStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name: 'Agent keyed',
		slug: `agentkeys${Math.random().toString(36).slice(2, 8)}`
	});
	await keysFor(bucket);
	return bucket;
}

const PRIVATE_MEMBERS = /"(d|p|q|dp|dq|qi|oth|k)"\s*:/;

/**
 * @proves An agent manages a bucket's signing keys through the same routes and checks as the
 * console, retiring one only through the confirmation gate, and no key tool ever returns key material.
 */
describe('an agent managing a bucket key set', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		ApplicationConfig['mcp.enabled'] = true;
		await ensureAdminSeed();
	});

	it('lists the keys of a bucket', async () => {
		const token = await agent();
		const bucket = await keyedBucket();

		const { payload } = await rpc(
			call('project_key_list', { id: bucket._id }),
			token
		);

		expect(payload.result?.isError).not.toBe(true);
		expect(
			shaped(
				Type.Object({ keys: Type.Array(Type.Unknown()) }),
				payload.result?.structuredContent?.result
			).keys
		).toHaveLength(1);
	});

	it('generates a published key for a bucket', async () => {
		const token = await agent();
		const bucket = await keyedBucket();

		const { payload } = await rpc(
			call('project_key_generate', { id: bucket._id, alg: 'ES256' }),
			token
		);

		expect(payload.result?.isError).not.toBe(true);
		expect(
			shaped(
				Type.Object({ state: Type.String() }),
				payload.result?.structuredContent?.result
			).state
		).toBe('published');
	});

	it('holds a retirement for confirmation and retires nothing', async () => {
		const token = await agent();
		const bucket = await keyedBucket();
		const generated = await rpc(
			call('project_key_generate', { id: bucket._id, alg: 'ES256' }),
			token
		);
		const { kid } = shaped(
			Type.Object({ kid: Type.String() }),
			generated.payload.result?.structuredContent?.result
		);

		const { payload } = await rpc(
			call('project_key_retire', { id: bucket._id, kid }),
			token
		);

		expect(payload.result?.structuredContent?.confirmationToken).toBeDefined();
		expect((await getBucketKeysStore().find(bucket._id, kid))?.state).toBe(
			'published'
		);
	});

	it('rotates an algorithm, publishing the next key, and the trail records it once naming the key', async () => {
		const token = await agent();
		const bucket = await keyedBucket();

		const { payload } = await rpc(
			call('project_key_rotate', { id: bucket._id, alg: 'RS256' }),
			token
		);

		expect(payload.result?.isError).not.toBe(true);
		const { generated } = shaped(
			Type.Object({ generated: Type.String() }),
			payload.result?.structuredContent?.result
		);
		expect(
			(await getBucketKeysStore().find(bucket._id, generated))?.state
		).toBe('published');
		const { entries } = await adminAuditStore.list({
			targetId: bucket._id,
			action: 'bucket.key.rotate'
		});
		expect(entries.map((entry) => [entry.keys, entry.viaSurface])).toEqual([
			[{ generated }, 'mcp']
		]);
	});

	it('holds a revocation for confirmation and revokes nothing', async () => {
		const token = await agent();
		const bucket = await keyedBucket();
		const [signer] = await getBucketKeysStore().listByBucket(bucket._id);

		const { payload } = await rpc(
			call('project_key_revoke', {
				id: bucket._id,
				kid: signer.kid,
				confirm: signer.kid
			}),
			token
		);

		expect(payload.result?.structuredContent?.confirmationToken).toBeDefined();
		expect(
			(await getBucketKeysStore().find(bucket._id, signer.kid))?.state
		).toBe('signing');
	});

	it('returns no key material from any key tool', async () => {
		const token = await agent();
		const bucket = await keyedBucket();

		const listedKeys = await rpc(
			call('project_key_list', { id: bucket._id }),
			token
		);
		const generated = await rpc(
			call('project_key_generate', { id: bucket._id, alg: 'RS256' }),
			token
		);

		expect(listedKeys.raw).not.toMatch(PRIVATE_MEMBERS);
		expect(generated.raw).not.toMatch(PRIVATE_MEMBERS);
	});
});
