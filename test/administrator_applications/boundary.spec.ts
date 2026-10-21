import { describe, it, expect, beforeAll, beforeEach, spyOn } from 'bun:test';

import bootstrap, {
	agent,
	redirectParameter,
	type Setup
} from '../test_helper.js';
import { AuthorizationRequest } from '../AuthorizationRequest.js';
import { elysia } from 'lib/index.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import { grantSuperAdmin } from 'lib/admin/super_admins.ts';
import { ISSUER } from 'lib/configs/env.js';
import { SCIM_BASE_PATH } from 'lib/consts/scim.ts';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import {
	ADMIN_MCP_CLIENT_ID,
	MCP_RESOURCE,
	MCP_ROUTE
} from 'lib/mcp/consts.ts';
import { declareApi } from '../assertion_grants/helpers.js';

const ROOT_API = 'https://api.root.example/';

const SECRETS: Record<string, string | undefined> = {
	'ops-tool': 'ops-tool-secret',
	[ADMIN_MCP_CLIENT_ID]: undefined
};

/* A code for `clientId`, issued to an administrator signed in to the administrators' bucket. */
async function codeFor(setup: Setup, clientId: string, resource?: string) {
	const accountId = `admin-${Math.random().toString(36).slice(2)}`;
	const cookie = await setup.login({
		bucketId: ADMIN_BUCKET_ID,
		accountId,
		resources: resource ? { [resource]: 'openid' } : {}
	});
	await grantSuperAdmin(accountId);
	const request = new AuthorizationRequest({
		client_id: clientId,
		scope: 'openid',
		...(resource ? { resource: [resource] } : {})
	});
	const auth = await request.authorize({ headers: { cookie } });
	return { request, auth };
}

async function exchange(
	clientId: string,
	request: AuthorizationRequest,
	code: string,
	resource?: string
) {
	const secret = SECRETS[clientId];
	return agent.token.post(
		{
			grant_type: 'authorization_code',
			code,
			code_verifier: request.code_verifier,
			redirect_uri: request.params.redirect_uri,
			...(secret === undefined ? { client_id: clientId } : {}),
			...(resource ? { resource } : {})
		},
		{
			headers:
				secret === undefined
					? {}
					: AuthorizationRequest.basicAuthHeader(clientId, secret)
		}
	);
}

/* The error code of a refusal, whether /auth redirected with it or /token answered with it. */
function refusal(auth: Response): string | null {
	const location = auth.headers.get('location');
	return location ? new URL(location, ISSUER).searchParams.get('error') : null;
}

async function opsToolToken(setup: Setup): Promise<string> {
	const { request, auth } = await codeFor(setup, 'ops-tool');
	const { data } = await exchange(
		'ops-tool',
		request,
		redirectParameter(auth, 'code')
	);
	return (data as { access_token: string }).access_token;
}

/**
 * @proves An application registered in the Administrators project can never hold a token for the
 * administrative MCP resource or any API, only ever signs a person in, and its tokens never reach the control
 * plane or SCIM.
 */
describe('an administrators’ application at the boundary of the control plane', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url);
		await declareApi(ROOT_API, ['read']);
	});

	beforeEach(async () => {
		await ensureAdminSeed();
		spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(false);
	});

	it('is refused a token for the administrative MCP resource', async () => {
		const { request, auth } = await codeFor(setup, 'ops-tool', MCP_RESOURCE);
		const error = refusal(auth);
		if (error) {
			expect(error).toBe('invalid_target');
			return;
		}
		const { status, error: body } = await exchange(
			'ops-tool',
			request,
			redirectParameter(auth, 'code'),
			MCP_RESOURCE
		);
		expect(status).toBe(400);
		expect(body?.value).toMatchObject({ error: 'invalid_target' });
	});

	it('is refused a token for an API declared at the root issuer', async () => {
		const { request, auth } = await codeFor(setup, 'ops-tool', ROOT_API);
		const error = refusal(auth);
		if (error) {
			expect(error).toBe('invalid_target');
			return;
		}
		const { status, error: body } = await exchange(
			'ops-tool',
			request,
			redirectParameter(auth, 'code'),
			ROOT_API
		);
		expect(status).toBe(400);
		expect(body?.value).toMatchObject({ error: 'invalid_target' });
	});

	it('leaves the seeded agent client its administrative audience', async () => {
		const { request, auth } = await codeFor(
			setup,
			ADMIN_MCP_CLIENT_ID,
			MCP_RESOURCE
		);
		const { status } = await exchange(
			ADMIN_MCP_CLIENT_ID,
			request,
			redirectParameter(auth, 'code'),
			MCP_RESOURCE
		);
		expect(status).toBe(200);
	});

	it('is refused a grant outside its stored list', async () => {
		// `client_credentials` as the representative: the existing grant gate refuses every grant not stored.
		const { status, error } = await agent.token.post(
			{ grant_type: 'client_credentials' },
			{
				headers: AuthorizationRequest.basicAuthHeader(
					'ops-tool',
					'ops-tool-secret'
				)
			}
		);
		expect(status).toBe(400);
		expect(error?.value).toMatchObject({ error: 'unauthorized_client' });
	});

	it('cannot use its token at the administrative MCP endpoint', async () => {
		const token = await opsToolToken(setup);
		const res = await elysia.handle(
			new Request(`${ISSUER}${MCP_ROUTE}`, {
				method: 'POST',
				headers: {
					'content-type': 'application/json',
					accept: 'application/json, text/event-stream',
					authorization: `Bearer ${token}`
				},
				body: JSON.stringify({
					jsonrpc: '2.0',
					id: 1,
					method: 'tools/list',
					params: {}
				})
			})
		);
		expect(res.status).toBe(401);
	});

	it('cannot use its token at the console API', async () => {
		const token = await opsToolToken(setup);
		const res = await elysia.handle(
			new Request(`${ISSUER}/admin/api/me`, {
				headers: { authorization: `Bearer ${token}` }
			})
		);
		expect(res.status).toBe(401);
	});

	it('gains nothing at a SCIM endpoint with its token', async () => {
		const token = await opsToolToken(setup);
		const scim = (headers: Record<string, string>) =>
			elysia.handle(
				new Request(`${ISSUER}${SCIM_BASE_PATH}/Users`, { headers })
			);
		const withToken = await scim({ authorization: `Bearer ${token}` });
		const without = await scim({});
		expect(withToken.status).toBeGreaterThanOrEqual(400);
		expect(withToken.status).toBe(without.status);
	});
});
