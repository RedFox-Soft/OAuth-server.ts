import {
	describe,
	it,
	beforeAll,
	beforeEach,
	afterEach,
	expect,
	spyOn
} from 'bun:test';
import { nanoid } from 'nanoid';

import {
	getBucketGroupStore,
	getProtectedResourceStore
} from 'lib/adapters/index.js';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { GROUPS_TOKEN_LIMIT } from 'lib/consts/groups_claim.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { decode } from 'lib/helpers/jwt.js';
import { ROOT_NAMESPACE } from 'lib/resources/namespace.ts';
import bootstrap, {
	agent,
	redirectParameter,
	type Setup
} from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { projectOf } from '../resources/owning_project.js';

const JWT_RESOURCE = 'https://api.example.com/jwt';
const OPAQUE_RESOURCE = 'https://api.example.com/opaque';
const basic = {
	headers: AuthorizationRequest.basicAuthHeader('client', 'secret')
};

interface Tokens {
	access_token: string;
	id_token?: string;
	refresh_token?: string;
}

/**
 * @proves A relying party that asks for the `groups` scope reads the user's group names from userinfo, the ID
 * token and a resource's access token — only when granted, never empty, current at every issue including a
 * refresh, and as a userinfo reference once there are too many for a token (spec 071, User Story 2).
 */
describe('the groups claim', () => {
	let setup: Setup;
	let accountId: string;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'groups_claim' });
		const projectId = await projectOf('client');
		const store = getProtectedResourceStore();
		for (const [identifier, tokenFormat] of [
			[JWT_RESOURCE, 'jwt'],
			[OPAQUE_RESOURCE, 'opaque']
		] as const) {
			await store.create({
				namespace: ROOT_NAMESPACE,
				identifier,
				projectId,
				name: identifier,
				scopes: ['api:read'],
				tokenFormat
			});
		}
	});

	beforeEach(async () => {
		accountId = nanoid();
		await getBucketGroupStore().destroyByBucket(DEFAULT_BUCKET_ID);
		spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(false);
	});

	afterEach(() => {
		ApplicationConfig['conformIdTokenClaims'] = true;
	});

	async function inGroups(...names: string[]): Promise<string[]> {
		const ids: string[] = [];
		for (const displayName of names) {
			const group = await getBucketGroupStore().create(
				{ _id: nanoid(), bucketId: DEFAULT_BUCKET_ID, displayName },
				[accountId]
			);
			ids.push(group._id);
		}
		return ids;
	}

	async function signIn(scope: string, resource?: string): Promise<Tokens> {
		const cookie = await setup.login({
			scope,
			accountId,
			resources: resource ? { [resource]: 'api:read' } : {}
		});
		const auth = new AuthorizationRequest({
			client_id: 'client',
			scope,
			prompt: 'consent',
			redirect_uri: 'https://client.example.com/cb',
			...(resource ? { resource: [resource] } : {})
		});
		const { response } = await agent.auth.get({
			query: auth.params,
			headers: { cookie }
		});
		expect(response.status).toBe(303);
		const res = await agent.token.post(
			{
				grant_type: 'authorization_code',
				code: redirectParameter(response, 'code') as string,
				code_verifier: auth.code_verifier,
				redirect_uri: 'https://client.example.com/cb',
				...(resource ? { resource } : {})
			},
			basic
		);
		expect(res.status).toBe(200);
		return res.data as Tokens;
	}

	async function userinfo(token: string): Promise<Record<string, unknown>> {
		const { data } = await agent.userinfo.get({
			headers: { authorization: `Bearer ${token}` }
		});
		return data as Record<string, unknown>;
	}

	function claimsOf(jwt: string): Record<string, unknown> {
		return decode(jwt).payload as Record<string, unknown>;
	}

	it('names the user’s groups at userinfo when the groups scope is granted', async () => {
		await inGroups('Editors', 'Admins', 'Readers');

		const tokens = await signIn('openid groups');

		expect((await userinfo(tokens.access_token)).groups).toEqual([
			'Admins',
			'Editors',
			'Readers'
		]);
	});

	it('names the user’s groups in a JWT access token for a resource', async () => {
		await inGroups('Editors');

		const tokens = await signIn('openid groups api:read', JWT_RESOURCE);

		expect(claimsOf(tokens.access_token).groups).toEqual(['Editors']);
	});

	it('names the user’s groups in the ID token when the access token is for a resource', async () => {
		await inGroups('Editors');

		const tokens = await signIn('openid groups api:read', JWT_RESOURCE);

		expect(claimsOf(tokens.id_token as string).groups).toEqual(['Editors']);
	});

	it('names the user’s groups in the ID token when conformIdTokenClaims is off', async () => {
		ApplicationConfig['conformIdTokenClaims'] = false;
		await inGroups('Editors');

		const tokens = await signIn('openid groups');

		expect(claimsOf(tokens.id_token as string).groups).toEqual(['Editors']);
	});

	it('leaves groups out of the ID token when the access token is for userinfo', async () => {
		await inGroups('Editors');

		const tokens = await signIn('openid groups');

		expect(claimsOf(tokens.id_token as string).groups).toBeUndefined();
	});

	it('carries no groups anywhere when the scope was not requested', async () => {
		await inGroups('Editors');

		const tokens = await signIn('openid api:read', JWT_RESOURCE);
		const atUserinfo = await signIn('openid');

		expect(claimsOf(tokens.access_token).groups).toBeUndefined();
		expect(claimsOf(tokens.id_token as string).groups).toBeUndefined();
		expect((await userinfo(atUserinfo.access_token)).groups).toBeUndefined();
	});

	it('carries no groups claim for a user in no group', async () => {
		const tokens = await signIn('openid groups');

		expect('groups' in (await userinfo(tokens.access_token))).toBe(false);
	});

	it('carries the current membership in the tokens a refresh issues', async () => {
		const [editors] = await inGroups('Editors');
		const tokens = await signIn(
			'openid groups offline_access api:read',
			JWT_RESOURCE
		);
		await inGroups('Reviewers');
		await getBucketGroupStore().change(editors, { remove: [accountId] });

		const refreshed = await agent.token.post(
			{
				grant_type: 'refresh_token',
				refresh_token: tokens.refresh_token as string,
				resource: JWT_RESOURCE
			},
			basic
		);

		const fresh = refreshed.data as Tokens;
		expect(claimsOf(fresh.access_token).groups).toEqual(['Reviewers']);
	});

	it('keeps the session and refresh token of a user removed from a group', async () => {
		const [editors] = await inGroups('Editors');
		const tokens = await signIn('openid groups offline_access');

		await getBucketGroupStore().change(editors, { remove: [accountId] });
		const refreshed = await agent.token.post(
			{
				grant_type: 'refresh_token',
				refresh_token: tokens.refresh_token as string
			},
			basic
		);

		expect(refreshed.status).toBe(200);
	});

	it('puts a userinfo reference in the token, and the whole list at userinfo, above the limit', async () => {
		const names = Array.from(
			{ length: GROUPS_TOKEN_LIMIT + 1 },
			(_, i) => `g${i.toString().padStart(4, '0')}`
		);
		await inGroups(...names);

		const tokens = await signIn('openid groups api:read', JWT_RESOURCE);
		const atUserinfo = await signIn('openid groups');

		const access = claimsOf(tokens.access_token);
		expect(access.groups).toBeUndefined();
		expect(access._claim_names).toEqual({ groups: 'groups' });
		expect(
			(access._claim_sources as { groups: { endpoint: string } }).groups
				.endpoint
		).toEndWith('/userinfo');
		expect((await userinfo(atUserinfo.access_token)).groups).toEqual(names);
	});

	it('introspects an opaque resource token to the groups a JWT would carry', async () => {
		await inGroups('Editors');

		const tokens = await signIn('openid groups api:read', OPAQUE_RESOURCE);
		const { data } = await agent.token.introspect.post(
			{ token: tokens.access_token },
			basic
		);

		expect((data as Record<string, unknown>).groups).toEqual(['Editors']);
	});
});
