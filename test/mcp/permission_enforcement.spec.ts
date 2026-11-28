import {
	describe,
	it,
	expect,
	beforeAll,
	beforeEach,
	afterEach
} from 'bun:test';

import bootstrap, { getHeader } from '../test_helper.js';
import { AuthorizationRequest } from '../AuthorizationRequest.js';
import { elysia } from 'lib/index.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adapter,
	getBucketStore,
	getProtectedResourceStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import {
	ADMIN_MCP_CLIENT_ID,
	MCP_RESOURCE,
	MCP_ROUTE
} from 'lib/mcp/consts.ts';
import { resolveBucketForRequest } from 'lib/admin/auth/resolveBucket.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { ROOT_NAMESPACE } from 'lib/resources/namespace.ts';
import { clearPermissions, permitIdentifier } from './permissions.ts';
import { DEFAULT_REQUEST_BUCKET } from 'lib/configs/issuer.ts';
import { createAdministrator } from '../administrators.ts';

/*
 * The three refusals the allowlist has to make, and the one thing it must never break.
 *
 * Covers what the tasks name separately as the dynamic-registration refusal, the empty default, the
 * key-proof requirement and withdrawal — kept in one file because every case is the same question
 * asked of one resolver, and four files of near-identical setup would obscure rather than clarify.
 */

const DOC = 'https://agent.example.com/oauth/client-metadata.json';
const DCR = 'https://selfmade.example.com/c.json';

async function seedClientRecord(
	clientId: string,
	extra: Record<string, unknown> = {}
) {
	await adapter('Client').upsert(clientId, {
		clientId,
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code', 'refresh_token'],
		responseTypes: ['code'],
		redirectUris: ['http://127.0.0.1:33418/callback'],
		...extra
	});
}

async function tokenFor(clientId: string) {
	const user = await createAdministrator(
		'super',
		`admin-${Math.random()}@x.io`
	);
	const at = new AccessToken({
		client: await Client.find(clientId),
		accountId: user._id,
		scope: 'openid'
	});
	at.setAudience(MCP_RESOURCE);
	return await at.save();
}

async function reach(token: string) {
	const res = await elysia.handle(
		new Request(`http://e.ly${MCP_ROUTE}`, {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				accept: 'application/json, text/event-stream',
				authorization: `Bearer ${token}`
			},
			body: JSON.stringify({
				jsonrpc: '2.0',
				id: 1,
				method: 'initialize',
				params: {
					protocolVersion: '2026-07-28',
					capabilities: {},
					clientInfo: { name: 'test-agent', version: '1.0.0' }
				}
			})
		})
	);
	return res.status;
}

/**
 * @proves The permission list is default-deny, is not satisfied by self-registration, takes a
 * withdrawal effect on the next call, and is scoped to the audience it was granted for.
 */
describe('enforcing the administrative client permission list', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'mcp' });
	});

	beforeEach(async () => {
		await ensureAdminSeed();
		await clearPermissions();
		await seedClientRecord(DOC);
		await seedClientRecord(DCR, { registeredDynamically: true });
	});

	/*
	 * FR-018, and the reason it is absolute rather than configurable: a dynamically registered client's
	 * identity is minted on demand by whoever asked for it, so permitting one permits whoever asks
	 * next. There is no configuration under which that is a decision an operator can meaningfully make.
	 */
	it('refuses a dynamically registered client even when it is on the list', async () => {
		await permitIdentifier(DCR);

		expect(await reach(await tokenFor(DCR))).toBe(401);
	});

	it('starts with an empty list, so nothing is permitted by default', async () => {
		expect(await reach(await tokenFor(DOC))).toBe(401);
	});

	/*
	 * The remedy an operator needs when a permitted host is taken over. Checked on every call rather
	 * than at issuance, so it does not wait for a token to expire.
	 */
	it('stops an agent on its next call once the permission is withdrawn', async () => {
		await permitIdentifier(DOC);
		const token = await tokenFor(DOC);
		expect(await reach(token)).toBe(200);

		await clearPermissions();

		expect(await reach(token)).toBe(401);
	});

	/*
	 * FR-019b. The check reads the client's declared authentication method, which is sufficient rather
	 * than approximate: a client declaring `none` could not have presented a key-proof assertion at the
	 * token endpoint.
	 */
	it('refuses a client that cannot prove possession of a published key when one is required', async () => {
		await permitIdentifier(DOC, { requireKeyProof: true });

		expect(await reach(await tokenFor(DOC))).toBe(401);
	});

	it('admits one that can', async () => {
		await seedClientRecord(DOC, {
			token_endpoint_auth_method: 'private_key_jwt',
			jwks_uri: 'https://agent.example.com/jwks.json'
		});
		await permitIdentifier(DOC, { requireKeyProof: true });

		expect(await reach(await tokenFor(DOC))).toBe(200);
	});
});

describe('signing in through a permitted identity', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'mcp' });
	});

	beforeEach(async () => {
		await ensureAdminSeed();
		await clearPermissions();
	});

	/*
	 * The other half of the permission: reaching the surface is no use if the administrator cannot sign
	 * in through the client in the first place. This is the rule `research.md` D6 refused to add
	 * without an operator decision behind it — the allowlist is that decision.
	 */
	it('routes a permitted identity naming the administrative audience to the admin bucket', async () => {
		await permitIdentifier(DOC);

		expect(
			await resolveBucketForRequest(DOC, MCP_RESOURCE, DEFAULT_REQUEST_BUCKET)
		).toBe(ADMIN_BUCKET_ID);
	});

	it('routes it nowhere special without a permission', async () => {
		expect(
			await resolveBucketForRequest(DOC, MCP_RESOURCE, DEFAULT_REQUEST_BUCKET)
		).toBe('redfox');
	});

	/*
	 * The parameter selects the surface; it never creates the permission. A permitted identity asking
	 * for anything else is an ordinary client.
	 */
	it('routes a permitted identity naming something else nowhere special', async () => {
		await permitIdentifier(DOC);

		expect(
			await resolveBucketForRequest(
				DOC,
				'https://elsewhere.example.com/mcp',
				DEFAULT_REQUEST_BUCKET
			)
		).toBe('redfox');
		expect(
			await resolveBucketForRequest(DOC, undefined, DEFAULT_REQUEST_BUCKET)
		).toBe('redfox');
	});
});

/*
 * Enforcing the same gate at `/auth` (RFC 8707 §2, FR-018/FR-019b/FR-020).
 *
 * Without this, an unpermitted client requesting `resource=<ISSUER>/mcp` passed `checkResource`,
 * fell through `resolveBucketForRequest` to `redfox`, and presented an administrator with the wrong
 * bucket's sign-in form — answering "Invalid username or password" for real admin credentials.
 */
describe('refusing unpermitted clients at /auth before sign-in', () => {
	const EXTRA_RESOURCE = 'https://other-api.example.com/mcp';

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'mcp' });
	});

	beforeEach(async () => {
		ApplicationConfig['mcp.enabled'] = true;
		await ensureAdminSeed();
		await clearPermissions();
		await seedClientRecord(DOC);
		await seedClientRecord(DCR, { registeredDynamically: true });
	});

	afterEach(() => {
		ApplicationConfig['mcp.enabled'] = true;
	});

	async function authorizeFor(
		clientId: string,
		resource: string | string[] = MCP_RESOURCE,
		path = '/auth'
	) {
		const req = new AuthorizationRequest({
			client_id: clientId,
			redirect_uri: 'http://127.0.0.1:33418/callback',
			scope: 'openid',
			state: 'fixed-state',
			resource: Array.isArray(resource) ? resource : [resource]
		});
		const qs = new URLSearchParams();
		for (const [k, v] of Object.entries(req.params)) {
			if (v === undefined) continue;
			if (Array.isArray(v)) {
				for (const item of v) qs.append(k, String(item));
			} else {
				qs.set(k, String(v));
			}
		}
		return elysia.handle(new Request(`http://e.ly${path}?${qs.toString()}`));
	}

	function expectInvalidTarget(res: Response) {
		expect(res.status).toBe(303);
		const location = new URL(getHeader(res, 'location'));
		expect(location.searchParams.get('error')).toBe('invalid_target');
		expect(location.searchParams.get('error_description')).toBe(
			'resource indicator is missing, or unknown'
		);
	}

	it('refuses an unpermitted document client with the same invalid_target an unknown resource gets', async () => {
		const unpermitted = await authorizeFor(DOC, MCP_RESOURCE);
		const unknown = await authorizeFor(DOC, 'https://unknown.example.com/mcp');

		expectInvalidTarget(unpermitted);
		expectInvalidTarget(unknown);
	});

	it('refuses a dynamically registered client even when listed', async () => {
		await permitIdentifier(DCR);

		const refused = await authorizeFor(DCR, MCP_RESOURCE);
		const unknown = await authorizeFor(DCR, 'https://unknown.example.com/mcp');

		/* Self-registered redirect URIs are not vouched for, so errors render the 400 confirmation page. */
		expect(refused.status).toBe(400);
		expect(unknown.status).toBe(400);
		const refusedHtml = await refused.text();
		expect(refusedHtml).toContain('invalid_target');
		expect(refusedHtml).toEqual(await unknown.text());
	});

	it('refuses a permitted client that lacks key proof when requireKeyProof is set', async () => {
		await permitIdentifier(DOC, { requireKeyProof: true });

		expectInvalidTarget(await authorizeFor(DOC, MCP_RESOURCE));
	});

	it('admits a permitted client and the reserved admin-mcp client to sign-in when mcp.enabled is on', async () => {
		await permitIdentifier(DOC);

		for (const clientId of [DOC, ADMIN_MCP_CLIENT_ID]) {
			const res = await authorizeFor(clientId, MCP_RESOURCE);
			expect(res.status).toBe(303);
			expect(getHeader(res, 'location')).toMatch(/^\/ui\/[^/]+\/login$/);
		}
	});

	it('refuses even the reserved admin-mcp client with invalid_target when mcp.enabled is off', async () => {
		ApplicationConfig['mcp.enabled'] = false;

		expectInvalidTarget(await authorizeFor(ADMIN_MCP_CLIENT_ID, MCP_RESOURCE));
	});

	it('refuses a permitted client requesting /mcp at a tenant project issuer', async () => {
		await permitIdentifier(DOC);
		const slug = `tenant-${Math.random().toString(36).slice(2, 8)}`;
		await getBucketStore().create({
			name: 'Tenant',
			slug,
			ownerGroupId: UNASSIGNED_GROUP_ID
		});
		forgetBucketAddresses();

		expectInvalidTarget(await authorizeFor(DOC, MCP_RESOURCE, `/${slug}/auth`));
	});

	it('refuses combining /mcp with another resource in one request', async () => {
		await permitIdentifier(DOC);
		await getProtectedResourceStore().create({
			namespace: ROOT_NAMESPACE,
			identifier: EXTRA_RESOURCE,
			bucketId: 'redfox',
			name: 'Other API',
			scopes: ['read']
		});

		expectInvalidTarget(
			await authorizeFor(DOC, [MCP_RESOURCE, EXTRA_RESOURCE])
		);
	});

	it('completes login resumption through /ui/:uid/login for a permitted client', async () => {
		await permitIdentifier(DOC);
		const email = `admin-resume-${Math.random()}@x.io`;
		const password = 'correct horse battery';
		await getUserStore(ADMIN_BUCKET_ID).create(
			email,
			await Bun.password.hash(password),
			true
		);

		const started = await authorizeFor(DOC, MCP_RESOURCE);
		expect(started.status).toBe(303);
		const loginPath = getHeader(started, 'location');
		expect(loginPath).toMatch(/^\/ui\/[^/]+\/login$/);
		const interactionCookie = started.headers
			.getSetCookie()
			.map((raw) => raw.split(';')[0])
			.join('; ');

		const loggedIn = await elysia.handle(
			new Request(`http://e.ly${loginPath}`, {
				method: 'POST',
				headers: {
					'content-type': 'application/x-www-form-urlencoded',
					cookie: interactionCookie
				},
				body: new URLSearchParams({ username: email, password })
			})
		);
		expect(loggedIn.status).toBe(303);
		expect(getHeader(loggedIn, 'location')).toMatch(/^\/ui\/[^/]+\/consent$/);
	});
});
