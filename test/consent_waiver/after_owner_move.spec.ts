import { describe, it, expect, beforeAll, afterAll } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap, {
	agent,
	clearSeededBuckets,
	getHeader,
	seedBucket,
	type Setup
} from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { shaped } from 'test/shape.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	getContainerOwnershipStore,
	getGroupStore
} from 'lib/adapters/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';

const BUCKET_ID = 'moving-bucket';
const ACCOUNT_ID = 'mover';

const Tokens = Type.Object({ access_token: Type.String() });
const UserInfo = Type.Object({ sub: Type.String() });

/**
 * @proves An end user signed in before their bucket moved to another administrator group keeps their
 * session, still skips the consent page their client never asked for, and gets tokens and userinfo as
 * before — a move changes who administers them, not how they sign in.
 */
describe('signing in after the bucket moved to another group', () => {
	let setup: Setup;
	let cookie: string;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'after_owner_move' });
		await ensureAdminSeed();
		await seedBucket({
			bucketId: BUCKET_ID,
			clientId: 'moving-app',
			accountId: ACCOUNT_ID
		});
		cookie = await setup.login({ accountId: ACCOUNT_ID, bucketId: BUCKET_ID });

		// Seeded in the System group with its project; it moves, with the project, to a tenant.
		const team = await getGroupStore().create({
			name: 'Team',
			kind: 'regular',
			members: [{ userId: 'team-owner', role: 'owner' }]
		});
		const moved = await getContainerOwnershipStore().moveBucket(
			BUCKET_ID,
			UNASSIGNED_GROUP_ID,
			team._id
		);
		expect(moved.status).toBe('moved');
	});

	afterAll(async () => {
		await clearSeededBuckets();
	});

	async function silentCode(auth: AuthorizationRequest) {
		const { response } = await agent.auth.get({
			query: auth.params,
			headers: { cookie }
		});
		return new URL(getHeader(response, 'location')).searchParams;
	}

	it('skips consent with the session signed in before the move', async () => {
		const auth = new AuthorizationRequest({
			client_id: 'moving-app',
			redirect_uri: 'https://moving.example.com/cb',
			scope: 'openid',
			prompt: 'none'
		});

		const answer = await silentCode(auth);

		expect(answer.get('error')).toBeNull();
		expect(answer.get('code')).toBeTruthy();
	});

	it('answers userinfo for the same person with tokens issued after the move', async () => {
		const auth = new AuthorizationRequest({
			client_id: 'moving-app',
			redirect_uri: 'https://moving.example.com/cb',
			scope: 'openid',
			prompt: 'none'
		});
		const code = (await silentCode(auth)).get('code') ?? '';

		const token = await auth.getToken(code);
		const { access_token } = shaped(Tokens, token.data);
		const info = await agent.userinfo.get({
			headers: { authorization: `Bearer ${access_token}` }
		});

		expect(shaped(UserInfo, info.data).sub).toBe(ACCOUNT_ID);
	});
});
