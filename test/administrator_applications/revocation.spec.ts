import { describe, it, expect, beforeAll, beforeEach, spyOn } from 'bun:test';
import { decodeJwt } from 'jose';
import { Type } from '@sinclair/typebox';

import bootstrap, { redirectParameter, type Setup } from '../test_helper.js';
import { AuthorizationRequest } from '../AuthorizationRequest.js';
import { elysia } from 'lib/index.js';
import { getGroupStore } from 'lib/adapters/index.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { ISSUER } from 'lib/configs/env.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { AccessToken } from 'lib/models/access_token.js';
import { RefreshToken } from 'lib/models/refresh_token.js';
import { shaped } from 'test/shape.js';
import { sessionFor } from '../admin_session.ts';
import { createAdministrator } from '../administrators.ts';

const Tokens = Type.Object({
	access_token: Type.String(),
	refresh_token: Type.String(),
	id_token: Type.String()
});

async function signIn(setup: Setup, accountId: string) {
	const cookie = await setup.login({
		bucketId: ADMIN_BUCKET_ID,
		accountId,
		scope: 'openid groups offline_access'
	});
	const request = new AuthorizationRequest({
		client_id: 'ops-tool',
		scope: 'openid groups offline_access',
		prompt: 'consent'
	});
	const auth = await request.authorize({ headers: { cookie } });
	const { data } = await request.getToken(redirectParameter(auth, 'code'));
	return { cookie, request, tokens: shaped(Tokens, data) };
}

/**
 * @proves A deactivated administrator's tokens for an administrators' application stop existing at once, and
 * a team they left or that was renamed shows in the next ID token.
 */
describe('removing an administrator', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		await ensureAdminSeed();
		spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(false);
	});

	it('removes the tokens of a deactivated administrator, not merely refuses them', async () => {
		const owner = await createAdministrator('super');
		const { _id: ownerCookieId } = await sessionFor(owner);
		const accountId = `admin-${Math.random().toString(36).slice(2)}`;
		const { tokens } = await signIn(setup, accountId);
		expect(await AccessToken.tryFind(tokens.access_token)).toBeTruthy();

		const res = await elysia.handle(
			new Request(`${ISSUER}/admin/api/admins/${accountId}`, {
				method: 'DELETE',
				headers: {
					cookie: `${ADMIN_SESSION_COOKIE}=${ownerCookieId}`,
					origin: ISSUER
				}
			})
		);
		expect(res.status).toBe(200);

		// Only a revocation removes them: `findAccount` already refuses a deactivated account at userinfo and refresh.
		expect(await AccessToken.tryFind(tokens.access_token)).toBeUndefined();
		expect(await RefreshToken.tryFind(tokens.refresh_token)).toBeUndefined();
	});

	it('drops a team they left, and shows a renamed team’s new name, in the next ID token', async () => {
		const accountId = `admin-${Math.random().toString(36).slice(2)}`;
		const left = await getGroupStore().create({
			name: 'Night shift',
			kind: 'regular',
			members: [{ userId: accountId, role: 'member' }]
		});
		const renamed = await getGroupStore().create({
			name: 'Ops',
			kind: 'regular',
			members: [{ userId: accountId, role: 'member' }]
		});
		const first = await signIn(setup, accountId);
		expect(decodeJwt(first.tokens.id_token).groups).toEqual([
			'Night shift',
			'Ops'
		]);

		await getGroupStore().update(left._id, { members: [] });
		await getGroupStore().update(renamed._id, { name: 'Operators' });
		const second = await signIn(setup, accountId);

		expect(decodeJwt(second.tokens.id_token).groups).toEqual(['Operators']);
	});
});
