import { describe, it, beforeAll, afterEach, expect, spyOn } from 'bun:test';
import { nanoid } from 'nanoid';

import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import bootstrap, {
	agent,
	redirectParameter,
	setSeedClaims,
	type Setup
} from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { adminCookie, defaultBucket } from '../end_user_lifecycle/fixtures.ts';
import { admin, endUser } from './helpers.ts';

/**
 * @proves A `groups` value can never be stored on an account to stand in for real membership: an administrator
 * cannot set one, and one already on a record never reaches a relying party (spec 071, User Story 2
 * scenario 8, FR-015).
 */
describe('a stored groups claim', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'groups_claim' });
	});

	afterEach(() => {
		setSeedClaims(undefined);
	});

	it('is refused when an administrator sets one on an account', async () => {
		const cookie = await adminCookie();
		await defaultBucket();
		const uid = await endUser(cookie, DEFAULT_BUCKET_ID);

		const res = await admin(
			'PATCH',
			`/admin/api/buckets/${DEFAULT_BUCKET_ID}/users/${uid}`,
			cookie,
			{ claims: { groups: ['Admins'] } }
		);

		expect(res.status).toBe(422);
	});

	it('never reaches userinfo, which carries the account’s actual groups', async () => {
		spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(false);
		setSeedClaims({ groups: ['Admins'] });
		const cookie = await setup.login({
			scope: 'openid groups',
			accountId: nanoid()
		});
		const auth = new AuthorizationRequest({
			client_id: 'client',
			scope: 'openid groups',
			redirect_uri: 'https://client.example.com/cb'
		});
		const { response } = await agent.auth.get({
			query: auth.params,
			headers: { cookie }
		});
		const { data } = await auth.getToken(redirectParameter(response, 'code'));

		const info = await agent.userinfo.get({
			headers: { authorization: `Bearer ${data?.access_token}` }
		});

		expect((info.data as Record<string, unknown>).groups).toBeUndefined();
	});
});
