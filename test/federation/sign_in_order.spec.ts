import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.ts';
import { adminAuditStore, getBucketStore } from 'lib/adapters/index.ts';
import type { UserBucket } from 'lib/adapters/types.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { loginOptionsForBucket } from 'lib/interactions/loginOptions.ts';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ADMIN_MCP_CLIENT_ID, MCP_RESOURCE } from 'lib/mcp/consts.ts';
import { shaped } from 'test/shape.js';
import { adminCookie } from '../end_user_lifecycle/fixtures.ts';
import { createAdministrator } from '../administrators.ts';
import { call, rpc } from '../mcp/rpc.ts';
import { admin } from '../provisioning/helpers.ts';
import { provider } from './harness.ts';

const Providers = Type.Array(Type.Object({ id: Type.String() }));
const Moved = Type.Object({ providers: Providers });

const GOOGLE = 'https://accounts.google.com';

async function bucketWith(ids: string[]): Promise<UserBucket> {
	return getBucketStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name: `order-${Math.random()}`,
		slug: `order-${Math.random().toString(36).slice(2, 10)}`,
		federation: ids.map((id) =>
			provider(id === 'google' ? GOOGLE : `https://${id}.idp.test`, {
				id,
				displayName: id
			})
		)
	});
}

function movePath(bucket: UserBucket, providerId: string): string {
	return `/admin/api/buckets/${bucket._id}/federation/${providerId}/move`;
}

async function tableOrder(bucket: UserBucket, cookie: string) {
	const reply = await admin(
		'GET',
		`/admin/api/buckets/${bucket._id}/federation`,
		cookie
	);
	return shaped(Providers, reply.body).map((p) => p.id);
}

async function pageOrder(bucket: UserBucket) {
	return (await loginOptionsForBucket(bucket._id)).providers.map((p) => p.id);
}

/**
 * @proves An administrator or an agent moves a bucket's provider one place up or down, and its sign-in page
 * and the console's table follow the new order, changing nothing but the order and recording it; a bucket
 * nobody reordered keeps its order; and a deleted provider leaves the order (spec 088, User Story 7).
 */
describe('the order of a bucket’s sign-in buttons', () => {
	let cookie: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'sign_in_order' });
		await ensureAdminSeed();
	});

	beforeEach(async () => {
		cookie = await adminCookie();
	});

	it('shows a provider moved up first on the sign-in page and in the table', async () => {
		const bucket = await bucketWith(['alpha', 'beta']);

		const moved = await admin('POST', movePath(bucket, 'beta'), cookie, {
			direction: 'up'
		});

		expect(moved.status).toBe(200);
		expect(shaped(Moved, moved.body).providers.map((p) => p.id)).toEqual([
			'beta',
			'alpha'
		]);
		expect(await tableOrder(bucket, cookie)).toEqual(['beta', 'alpha']);
		expect(await pageOrder(bucket)).toEqual(['beta', 'alpha']);
	});

	it('moves a provider down past the one after it', async () => {
		const bucket = await bucketWith(['alpha', 'beta', 'gamma']);

		await admin('POST', movePath(bucket, 'alpha'), cookie, {
			direction: 'down'
		});

		expect(await pageOrder(bucket)).toEqual(['beta', 'alpha', 'gamma']);
	});

	it('refuses to move the first provider up', async () => {
		const bucket = await bucketWith(['alpha', 'beta']);

		const moved = await admin('POST', movePath(bucket, 'alpha'), cookie, {
			direction: 'up'
		});

		expect(moved.status).toBe(409);
	});

	it('refuses to move the last provider down', async () => {
		const bucket = await bucketWith(['alpha', 'beta']);

		const moved = await admin('POST', movePath(bucket, 'beta'), cookie, {
			direction: 'down'
		});

		expect(moved.status).toBe(409);
	});

	it('keeps a bucket nobody reordered in the catalogue’s order, whatever order its providers were added in', async () => {
		const bucket = await bucketWith(['aaa', 'google']);

		expect(await pageOrder(bucket)).toEqual(['google', 'aaa']);
		expect(await tableOrder(bucket, cookie)).toEqual(['google', 'aaa']);
	});

	it('changes nothing about the providers themselves', async () => {
		const bucket = await bucketWith(['alpha', 'beta']);

		await admin('POST', movePath(bucket, 'beta'), cookie, { direction: 'up' });

		const stored = await getBucketStore().find(bucket._id);
		expect(stored?.federation).toEqual(bucket.federation);
	});

	it('records the provider and the order before and after', async () => {
		const bucket = await bucketWith(['alpha', 'beta']);

		await admin('POST', movePath(bucket, 'beta'), cookie, { direction: 'up' });

		const { entries } = await adminAuditStore.list({
			action: 'federation.provider.move',
			targetId: bucket._id,
			limit: 5
		});
		expect(entries).toHaveLength(1);
		expect(entries[0]).toMatchObject({
			attributes: ['beta'],
			from: 'alpha, beta',
			to: 'beta, alpha'
		});
	});

	it('drops a deleted provider from the order, so one re-created under its id comes after the ordered ones', async () => {
		const bucket = await bucketWith(['alpha', 'beta']);
		await admin('POST', movePath(bucket, 'beta'), cookie, { direction: 'up' });

		const deleted = await admin(
			'DELETE',
			`/admin/api/buckets/${bucket._id}/federation/beta`,
			cookie
		);
		const after = await getBucketStore().find(bucket._id);
		await getBucketStore().update(bucket._id, {
			federation: [
				...(after?.federation ?? []),
				provider('https://beta.idp.test', { id: 'beta', displayName: 'beta' })
			]
		});

		expect(deleted.status).toBe(200);
		expect(after?.signInOrder).toEqual(['alpha']);
		expect(await pageOrder(bucket)).toEqual(['alpha', 'beta']);
	});

	it('lets an agent move a provider as the console does', async () => {
		const bucket = await bucketWith(['alpha', 'beta']);
		const user = await createAdministrator('super');
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
				id: 1,
				method: 'initialize',
				params: {
					protocolVersion: '2026-07-28',
					capabilities: {},
					clientInfo: { name: 'test-agent', version: '1.0.0' }
				}
			},
			token
		);

		const answer = await rpc(
			call('federation_provider_move', {
				id: bucket._id,
				providerId: 'beta',
				direction: 'up'
			}),
			token
		);

		expect(answer.result?.isError).not.toBe(true);
		expect(await pageOrder(bucket)).toEqual(['beta', 'alpha']);
	});
});
