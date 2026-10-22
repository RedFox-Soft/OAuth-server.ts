import { afterAll, beforeAll, describe, expect, it } from 'bun:test';

import bootstrap, {
	agent,
	clearSeededBuckets,
	getHeader,
	seedBucket
} from '../test_helper.js';
import { getUserStore } from 'lib/adapters/index.js';
import { elysia } from 'lib/index.js';
import { ISSUER } from 'lib/configs/env.js';
import { routeNames } from 'lib/consts/param_list.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { Type } from '@sinclair/typebox';
import { present, shaped } from 'test/shape.js';

/*
 * Every project without an address of its own is served at the root and shares the root's one issuer. A sign-in
 * for such a project records the project's own id on what it issues, yet a request at the root is addressed as
 * the default project — so a comparison of the two ids takes the root's own tokens for another issuer's.
 */

const BUCKET_ID = 'quiet-bucket';
const REDIRECT = 'https://quiet.example.com/cb';
const PASSWORD = 'correct horse battery';

function post(path: string, form: Record<string, string>) {
	return elysia.handle(
		new Request(`http://localhost${path}`, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams(form).toString()
		})
	);
}

/**
 * @proves A token issued at the root to an application of a project with no address is reported active by the
 * root's introspection endpoint, which is the authorization server that issued it.
 */
describe('a token issued at the root for a project with no address', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, {
			config: 'unaddressed_introspection'
		});
		await seedBucket({
			bucketId: BUCKET_ID,
			clientId: 'quiet-app',
			accountId: 'carol'
		});
	});

	afterAll(async () => {
		await clearSeededBuckets();
	});

	/*
	 * Through the sign-in screens, which is the path that records the project's own id: a request resumed after an
	 * interaction carries the project the sign-in resolved, where one answered from an existing session carries the
	 * address it arrived at.
	 */
	async function accessToken(): Promise<string> {
		const email = `quiet-${Math.random()}@x.io`;
		await getUserStore(BUCKET_ID).create(
			email,
			await Bun.password.hash(PASSWORD),
			true
		);
		const auth = new AuthorizationRequest({
			client_id: 'quiet-app',
			scope: 'openid',
			redirect_uri: REDIRECT
		});
		const { response } = await agent.auth.get({ query: auth.params });
		const uid = getHeader(response, 'location').split('/')[2];
		const signedIn = await elysia.handle(
			new Request(`http://localhost/ui/${uid}/login`, {
				method: 'POST',
				headers: {
					'content-type': 'application/x-www-form-urlencoded',
					cookie: present(
						response.headers.get('set-cookie'),
						'an interaction cookie'
					)
				},
				body: new URLSearchParams({
					username: email,
					password: PASSWORD
				}).toString()
			})
		);
		const code = present(
			new URL(
				present(signedIn.headers.get('location'), 'a redirect')
			).searchParams.get('code'),
			'an authorization code'
		);
		const redeemed = await post(routeNames.token, {
			grant_type: 'authorization_code',
			client_id: 'quiet-app',
			code,
			code_verifier: present(auth.code_verifier, 'a PKCE verifier'),
			redirect_uri: REDIRECT
		});
		return shaped(
			Type.Object({ access_token: Type.String() }),
			await redeemed.json()
		).access_token;
	}

	it('is reported active, with the root issuer, by the root introspection endpoint', async () => {
		const token = await accessToken();

		const response = await post(routeNames.introspect, {
			token,
			client_id: 'quiet-app'
		});

		expect(await response.json()).toMatchObject({ active: true, iss: ISSUER });
	});
});
