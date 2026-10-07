import { expect, spyOn } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';

import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { endUserRoutes } from 'lib/admin/users-end/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	ADMIN_SESSION_COOKIE,
	DEFAULT_BUCKET_ID,
	UNASSIGNED_GROUP_ID
} from 'lib/admin/consts.ts';
import { getBucketStore } from 'lib/adapters/index.ts';
import type { UserBucket } from 'lib/adapters/types.ts';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { present } from 'test/shape.js';
import { sessionFor } from '../admin_session.ts';
import { agent, redirectParameter, type Setup } from '../test_helper.js';
import { createAdministrator } from '../administrators.ts';

/* The admin API as the console reaches it: the real routes behind the real admin resolver. */
const adminApp = new Elysia().use(resolveAdmin).use(endUserRoutes);
export const admin = treaty(adminApp);

/* A super administrator's console cookie. */
export async function adminCookie(): Promise<string> {
	await ensureAdminSeed();
	const user = await createAdministrator(
		'super',
		`super-${Math.random()}@x.io`
	);
	const session = await sessionFor(user);
	return `${ADMIN_SESSION_COOKIE}=${session._id}`;
}

/*
 * The bucket the spec's clients sign users into, as a record the admin API can address. Clients resolve
 * to it whether or not the record exists; the console needs the record.
 */
export async function defaultBucket(): Promise<UserBucket> {
	const store = getBucketStore();
	return (
		(await store.find(DEFAULT_BUCKET_ID)) ??
		store.create({
			_id: DEFAULT_BUCKET_ID,
			name: 'default',
			ownerGroupId: UNASSIGNED_GROUP_ID
		})
	);
}

export interface SignedIn {
	accountId: string;
	refreshToken: string;
	accessToken: string;
	cookie: string;
}

/*
 * A user signed in through `client`: a session holding both clients, and an opaque access token issued to
 * `client` — with a refresh token too under the default `offline_access` scope.
 */
export async function signIn(
	setup: Setup,
	scope = 'openid offline_access'
): Promise<SignedIn> {
	spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(false);
	const cookie = await setup.login({ scope });
	const auth = new AuthorizationRequest({
		client_id: 'client',
		scope,
		prompt: 'consent',
		redirect_uri: 'https://client.example.com/cb'
	});
	const { response } = await agent.auth.get({
		query: auth.params,
		headers: { cookie }
	});
	expect(response.status).toBe(303);
	const { data } = await auth.getToken(redirectParameter(response, 'code'));
	if (!data?.access_token) {
		throw new Error('expected an access token');
	}
	return {
		accountId: present(setup.getSession().accountId, 'accountId'),
		refreshToken: data.refresh_token ?? '',
		accessToken: data.access_token,
		cookie
	};
}

export async function userinfo(accessToken: string) {
	const { data } = await agent.userinfo.get({
		headers: { authorization: `Bearer ${accessToken}` }
	});
	return data;
}

export function refresh(refreshToken: string) {
	return agent.token.post(
		{ grant_type: 'refresh_token', refresh_token: refreshToken },
		{ headers: AuthorizationRequest.basicAuthHeader('client', 'secret') }
	);
}

export async function introspect(token: string) {
	const { data } = await agent.token.introspect.post(
		{ token },
		{ headers: AuthorizationRequest.basicAuthHeader('client', 'secret') }
	);
	return data;
}

/* An administrator deactivating or reactivating a user of the default bucket. */
export function setActive(cookie: string, uid: string, active: boolean) {
	return admin.admin.api
		.buckets({ id: DEFAULT_BUCKET_ID })
		.users({ uid })
		.patch({ active }, { headers: { cookie } });
}
