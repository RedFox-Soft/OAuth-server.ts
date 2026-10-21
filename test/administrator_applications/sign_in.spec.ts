import { describe, it, expect, beforeAll, beforeEach, spyOn } from 'bun:test';
import {
	createLocalJWKSet,
	decodeJwt,
	decodeProtectedHeader,
	jwtVerify
} from 'jose';
import { Type } from '@sinclair/typebox';

import bootstrap, { redirectParameter, type Setup } from '../test_helper.js';
import { AuthorizationRequest } from '../AuthorizationRequest.js';
import { elysia } from 'lib/index.js';
import {
	getBucketGroupStore,
	getGroupStore,
	getUserStore
} from 'lib/adapters/index.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	ADMIN_BUCKET_ID,
	DEFAULT_BUCKET_ID,
	SUPER_ADMINS_GROUP_NAME
} from 'lib/admin/consts.ts';
import { grantSuperAdmin } from 'lib/admin/super_admins.ts';
import { ISSUER } from 'lib/configs/env.js';
import { routeNames } from 'lib/consts/param_list.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { shaped } from 'test/shape.js';

const Tokens = Type.Object({
	access_token: Type.String(),
	id_token: Type.String()
});

let seq = 0;
const nextId = (prefix: string) =>
	`${prefix}-${++seq}-${Math.random().toString(36).slice(2, 8)}`;

async function team(
	name: string,
	userId: string,
	kind: 'regular' | 'personal' = 'regular'
) {
	return getGroupStore().create({
		name,
		kind,
		members: [{ userId, role: 'member' }]
	});
}

/* An authorization through `clientId` for a person signed in to `bucketId`; the response of /auth. */
async function authorize(
	setup: Setup,
	clientId: string,
	accountId: string,
	bucketId: string,
	scope: string
) {
	const cookie = await setup.login({ bucketId, accountId, scope });
	const request = new AuthorizationRequest({ client_id: clientId, scope });
	return { request, auth: await request.authorize({ headers: { cookie } }) };
}

async function signIn(
	setup: Setup,
	clientId: string,
	accountId: string,
	bucketId: string,
	scope: string
) {
	const { request, auth } = await authorize(
		setup,
		clientId,
		accountId,
		bucketId,
		scope
	);
	const { data } = await request.getToken(redirectParameter(auth, 'code'));
	return { request, tokens: shaped(Tokens, data) };
}

async function userinfo(accessToken: string) {
	const res = await elysia.handle(
		new Request(`${ISSUER}${routeNames.userinfo}`, {
			headers: { authorization: `Bearer ${accessToken}` }
		})
	);
	return {
		status: res.status,
		body: (await res.json()) as Record<string, unknown>
	};
}

/**
 * @proves An administrator can sign in to an internal tool registered in the Administrators project, the tool
 * can admit them by the teams they belong to, and no one but an active administrator signs in through it.
 */
describe('signing in through an administrators’ application', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		await ensureAdminSeed();
		spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(false);
	});

	it('names the administrator and their teams, sorted, without their personal team', async () => {
		const accountId = nextId('admin');
		await grantSuperAdmin(accountId);
		await team('Operators', accountId);
		await team(`${accountId}@personal`, accountId, 'personal');

		const { tokens } = await signIn(
			setup,
			'ops-tool',
			accountId,
			ADMIN_BUCKET_ID,
			'openid groups'
		);

		expect(decodeJwt(tokens.id_token)).toMatchObject({
			iss: ISSUER,
			sub: accountId,
			groups: ['Operators', SUPER_ADMINS_GROUP_NAME]
		});
		const info = await userinfo(tokens.access_token);
		expect(info.status).toBe(200);
		expect(info.body.groups).toEqual(['Operators', SUPER_ADMINS_GROUP_NAME]);
	});

	it('names no teams when the groups scope was not asked for', async () => {
		const accountId = nextId('admin');
		await team('Operators', accountId);

		const { tokens } = await signIn(
			setup,
			'ops-tool',
			accountId,
			ADMIN_BUCKET_ID,
			'openid'
		);

		expect(decodeJwt(tokens.id_token).groups).toBeUndefined();
	});

	it('points to userinfo when there are more teams than a token carries', async () => {
		const accountId = nextId('admin');
		for (let i = 0; i < 201; i += 1)
			await team(`Team ${String(i).padStart(3, '0')}`, accountId);

		const { tokens } = await signIn(
			setup,
			'ops-tool',
			accountId,
			ADMIN_BUCKET_ID,
			'openid groups'
		);

		const claims = decodeJwt(tokens.id_token);
		expect(claims.groups).toBeUndefined();
		expect(claims._claim_names).toEqual({ groups: 'groups' });
		const info = await userinfo(tokens.access_token);
		expect((info.body.groups as string[]).length).toBe(201);
	});

	it('passes the checks a strict internal tool makes on the ID token', async () => {
		// foxtrust's admin panel (src/web/oidc.ts): RS256 only, a kid in the issuer's keys, iss, aud/azp, nonce, exp/iat.
		const accountId = nextId('admin');
		await team('Operators', accountId);
		const { request, tokens } = await signIn(
			setup,
			'ops-tool',
			accountId,
			ADMIN_BUCKET_ID,
			'openid groups'
		);

		const header = decodeProtectedHeader(tokens.id_token);
		expect(header.alg).toBe('RS256');
		const jwks = (await (
			await elysia.handle(new Request(`${ISSUER}/jwks`))
		).json()) as {
			keys: { kid?: string }[];
		};
		expect(jwks.keys.map((k) => k.kid)).toContain(header.kid);
		const { payload } = await jwtVerify(
			tokens.id_token,
			createLocalJWKSet(jwks),
			{ issuer: ISSUER, audience: 'ops-tool', algorithms: ['RS256'] }
		);
		expect(payload.nonce).toBe(request.params.nonce);
		expect(typeof payload.exp).toBe('number');
		expect(typeof payload.iat).toBe('number');
		expect(payload.groups).toEqual(['Operators']);
	});

	it('signs the administrator out of the administrators’ sign-in and returns to the tool', async () => {
		const accountId = nextId('admin');
		const cookie = await setup.login({
			bucketId: ADMIN_BUCKET_ID,
			accountId,
			scope: 'openid'
		});
		const request = new AuthorizationRequest({
			client_id: 'ops-tool',
			scope: 'openid'
		});
		const auth = await request.authorize({ headers: { cookie } });
		const { data } = await request.getToken(redirectParameter(auth, 'code'));
		const { id_token } = shaped(Tokens, data);

		// The relying party's sign-out, as foxtrust sends it: the hint and the registered return address.
		const page = await elysia.handle(
			new Request(
				`${ISSUER}${routeNames.end_session}?${new URLSearchParams({
					id_token_hint: id_token,
					post_logout_redirect_uri: 'https://ops.example/'
				})}`,
				{ headers: { cookie } }
			)
		);
		expect(page.status).toBe(200);
		const html = await page.text();
		const action = /<form[^>]*action="([^"]+)"/
			.exec(html)?.[1]
			?.replaceAll('&amp;', '&');
		const xsrf = /name="xsrf"[^>]*value="([^"]+)"/.exec(html)?.[1];
		if (!action || !xsrf)
			throw new Error(`no confirmation form in ${html.slice(0, 300)}`);

		const confirmed = await elysia.handle(
			new Request(new URL(action, ISSUER), {
				method: 'POST',
				headers: {
					cookie,
					'content-type': 'application/x-www-form-urlencoded'
				},
				body: new URLSearchParams({ xsrf, logout: 'true' })
			})
		);

		expect(
			confirmed.headers.get('location') ?? (await confirmed.text())
		).toContain('https://ops.example/');
		const ended = await elysia.handle(
			new Request(
				`${ISSUER}/auth?${new URLSearchParams(Object.entries({ ...request.params, state: 'again' }).map(([k, v]) => [k, String(v)]))}`,
				{
					headers: { cookie }
				}
			)
		);
		expect(ended.headers.get('location')).not.toContain('code=');
	});

	it('does not sign in a person of the default project', async () => {
		const { auth } = await authorize(
			setup,
			'ops-tool',
			nextId('person'),
			DEFAULT_BUCKET_ID,
			'openid'
		);

		expect(auth.headers.get('location')).not.toContain('code=');
	});

	it('does not sign in a deactivated administrator', async () => {
		const accountId = nextId('admin');
		const cookie = await setup.login({
			bucketId: ADMIN_BUCKET_ID,
			accountId,
			scope: 'openid'
		});
		await getUserStore(ADMIN_BUCKET_ID).update(accountId, { active: false });
		const request = new AuthorizationRequest({
			client_id: 'ops-tool',
			scope: 'openid'
		});

		const auth = await request.authorize({ headers: { cookie } });

		expect(auth.headers.get('location')).not.toContain('code=');
	});

	it('leaves the groups claim of other projects’ applications naming their own groups', async () => {
		const accountId = nextId('person');
		await team('Operators', accountId);
		await getBucketGroupStore().create(
			{
				_id: nextId('grp'),
				bucketId: DEFAULT_BUCKET_ID,
				displayName: 'Customers'
			},
			[accountId]
		);

		const { tokens } = await signIn(
			setup,
			'portal',
			accountId,
			DEFAULT_BUCKET_ID,
			'openid groups'
		);

		expect(decodeJwt(tokens.id_token).groups).toEqual(['Customers']);
	});
});
