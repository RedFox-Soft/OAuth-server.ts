import { afterAll, beforeAll, describe, expect, it } from 'bun:test';

import bootstrap, {
	agent,
	clearSeededBuckets,
	getHeader,
	jsonToFormUrlEncoded,
	seedBucket,
	type Setup
} from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { getUserStore } from 'lib/adapters/index.js';
import { routeNames } from 'lib/consts/param_list.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { present } from 'test/shape.js';

/*
 * RFC 6749 §2.2: a client identifier is unique to the authorization server that issued it, and MCP's
 * SEP-2352 tells a client never to present one server's credentials to another. Every project with an
 * address is its own authorization server, so a client of one is unknown to another — at the endpoints
 * that authenticate a client as much as at the one that starts a sign-in.
 */

const ACME = 'acme';
const GLOBEX = 'globex';
const PASSWORD = 'correct horse battery';

function basic(clientId: string, secret: string): string {
	return `Basic ${btoa(`${clientId}:${secret}`)}`;
}

async function post(
	path: string,
	form: Record<string, string>,
	authorization?: string
): Promise<Response> {
	return elysia.handle(
		new Request(`http://localhost${path}`, {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
				...(authorization ? { authorization } : {})
			},
			body: new URLSearchParams(form).toString()
		})
	);
}

async function errorOf(response: Response): Promise<unknown> {
	return (await response.json()) as unknown;
}

/**
 * @proves A client of a project with its own address is unknown at every other issuer's
 * client-authenticating endpoints, and a code or refresh token is redeemable only at the issuer that
 * issued it, a refusal there leaving it usable where it belongs.
 */
describe('a client presented at an issuer other than its own', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'client_binding' });
		await seedBucket({
			bucketId: 'acme-bucket',
			slug: ACME,
			clientId: 'acme-app',
			accountId: 'bob'
		});
		await seedBucket({
			bucketId: 'globex-bucket',
			slug: GLOBEX,
			clientId: 'globex-app',
			accountId: 'gina'
		});
	});

	afterAll(async () => {
		await clearSeededBuckets();
	});

	describe('given a client of the acme project', () => {
		const acme = basic('acme-app', 'acme-secret');

		/*
		 * Compared with an identifier nobody registered, byte for byte: a refusal that differed would tell
		 * a caller the client exists at some other issuer.
		 */
		it('is refused at another project’s token endpoint exactly as an unknown client is', async () => {
			const refused = await post(
				`/${GLOBEX}${routeNames.token}`,
				{ grant_type: 'client_credentials' },
				acme
			);
			const unknown = await post(
				`/${GLOBEX}${routeNames.token}`,
				{ grant_type: 'client_credentials' },
				basic('nobody', 'nothing')
			);

			expect(refused.status).toBe(401);
			expect(await errorOf(refused)).toEqual(await errorOf(unknown));
		});

		it('is refused at another project’s introspection endpoint', async () => {
			const response = await post(
				`/${GLOBEX}${routeNames.introspect}`,
				{ token: 'anything' },
				acme
			);

			expect(response.status).toBe(401);
			expect(await errorOf(response)).toMatchObject({
				error: 'invalid_client'
			});
		});

		it('is refused at another project’s revocation endpoint', async () => {
			const response = await post(
				`/${GLOBEX}${routeNames.revocation}`,
				{ token: 'anything' },
				acme
			);

			expect(response.status).toBe(401);
			expect(await errorOf(response)).toMatchObject({
				error: 'invalid_client'
			});
		});

		it('is refused at another project’s pushed authorization endpoint, and issued no request URI', async () => {
			const auth = new AuthorizationRequest({
				client_id: 'acme-app',
				scope: 'openid',
				redirect_uri: 'https://acme.example.com/cb'
			});
			const response = await post(
				`/${GLOBEX}${routeNames.pushed_authorization_request}`,
				Object.fromEntries(
					Object.entries(auth.params).map(([k, v]) => [k, String(v)])
				),
				acme
			);

			expect(response.status).toBe(401);
			const body = await errorOf(response);
			expect(body).toMatchObject({ error: 'invalid_client' });
			expect(body).not.toHaveProperty('request_uri');
		});
	});

	describe('given a confidential client that belongs to no project', () => {
		it('is refused client credentials at a project’s own address', async () => {
			const response = await post(
				`/${GLOBEX}${routeNames.token}`,
				{ grant_type: 'client_credentials' },
				basic('root-app', 'root-secret')
			);

			expect(response.status).toBe(401);
			expect(await errorOf(response)).toMatchObject({
				error: 'invalid_client'
			});
		});

		it('is issued client credentials at the root, as before', async () => {
			const response = await post(
				routeNames.token,
				{ grant_type: 'client_credentials' },
				basic('root-app', 'root-secret')
			);

			expect(response.status).toBe(200);
		});
	});

	describe('given a code issued at the root to a client of no project', () => {
		const shared = basic('shared-root-app', 'shared-secret');

		async function codeAtTheRoot() {
			const cookie = await setup.login({ accountId: 'ana' });
			const auth = new AuthorizationRequest({
				client_id: 'shared-root-app',
				scope: 'openid',
				redirect_uri: 'https://shared.example.com/cb'
			});
			const authorized = await elysia.handle(
				new Request(
					`http://localhost${routeNames.authorization}?${jsonToFormUrlEncoded(auth.params)}`,
					{ headers: { cookie } }
				)
			);
			const code = new URL(
				authorized.headers.get('location') ?? ''
			).searchParams.get('code');
			return { auth, code: present(code, 'an authorization code') };
		}

		function redemption(auth: AuthorizationRequest, code: string) {
			return {
				grant_type: 'authorization_code',
				code,
				code_verifier: present(auth.code_verifier, 'a PKCE verifier'),
				redirect_uri: 'https://shared.example.com/cb'
			};
		}

		it('is refused at a project’s token endpoint', async () => {
			const { auth, code } = await codeAtTheRoot();

			const response = await post(
				`/${ACME}${routeNames.token}`,
				redemption(auth, code),
				shared
			);

			expect(response.status).toBe(400);
			expect(await errorOf(response)).toMatchObject({ error: 'invalid_grant' });
		});

		it('stays redeemable at its own issuer after being refused at another', async () => {
			const { auth, code } = await codeAtTheRoot();
			await post(`/${ACME}${routeNames.token}`, redemption(auth, code), shared);

			const response = await post(
				routeNames.token,
				redemption(auth, code),
				shared
			);

			expect(response.status).toBe(200);
		});
	});

	describe('given a refresh token issued at the root to a client of no project', () => {
		const shared = basic('shared-root-app', 'shared-secret');

		/* A refresh token needs `offline_access`, which is only granted with `prompt=consent` — so through the
		 * interaction screens rather than the harness's pre-built grant. */
		async function refreshTokenAtTheRoot(): Promise<string> {
			const email = `refresh-${Math.random()}@x.io`;
			await getUserStore().create(
				email,
				await Bun.password.hash(PASSWORD),
				true
			);
			const auth = new AuthorizationRequest({
				client_id: 'shared-root-app',
				scope: 'openid offline_access',
				prompt: 'consent',
				redirect_uri: 'https://shared.example.com/cb'
			});
			const { response } = await agent.auth.get({ query: auth.params });
			const uid = getHeader(response, 'location').split('/')[2];
			const cookie = present(
				response.headers.get('set-cookie'),
				'an interaction cookie'
			);
			const submitted = await elysia.handle(
				new Request(`http://localhost/ui/${uid}/login`, {
					method: 'POST',
					headers: {
						'content-type': 'application/x-www-form-urlencoded',
						cookie
					},
					body: new URLSearchParams({
						username: email,
						password: PASSWORD
					}).toString()
				})
			);
			const code = present(
				new URL(
					present(submitted.headers.get('location'), 'a redirect')
				).searchParams.get('code'),
				'an authorization code'
			);
			const tokens = (await (
				await post(
					routeNames.token,
					{
						grant_type: 'authorization_code',
						code,
						code_verifier: present(auth.code_verifier, 'a PKCE verifier'),
						redirect_uri: 'https://shared.example.com/cb'
					},
					shared
				)
			).json()) as { refresh_token?: string };
			return present(tokens.refresh_token, 'a refresh token');
		}

		function refresh(refreshToken: string) {
			return { grant_type: 'refresh_token', refresh_token: refreshToken };
		}

		it('is refused at a project’s token endpoint', async () => {
			const refreshToken = await refreshTokenAtTheRoot();

			const response = await post(
				`/${ACME}${routeNames.token}`,
				refresh(refreshToken),
				shared
			);

			expect(response.status).toBe(400);
			expect(await errorOf(response)).toMatchObject({ error: 'invalid_grant' });
		});

		/* Neither rotated nor revoked by the refusal: a request at the wrong address is not evidence of theft. */
		it('still refreshes at its own issuer after being refused at another', async () => {
			const refreshToken = await refreshTokenAtTheRoot();
			await post(`/${ACME}${routeNames.token}`, refresh(refreshToken), shared);

			const response = await post(
				routeNames.token,
				refresh(refreshToken),
				shared
			);

			expect(response.status).toBe(200);
		});
	});
});
