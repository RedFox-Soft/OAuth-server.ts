import { describe, it, beforeEach, expect } from 'bun:test';

import bootstrap, {
	agent,
	jsonToFormUrlEncoded,
	type Setup
} from '../test_helper.js';
import { send, UNSERVED_PATH } from '../feature_gate/helpers.js';
import { ApplicationConfig } from 'lib/configs/application.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { routeNames } from 'lib/consts/param_list.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { adminSessionStore, getUserStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';

import {
	gatedRoutes,
	alwaysAvailableRoutes
} from 'lib/consts/route_classification.js';

import {
	expectNonPageProfile,
	expectPageProfile,
	expectProfileByKind
} from './profile.js';

/*
 * Contract of record: specs/026-non-html-security-headers/contracts/response-headers.md.
 *
 * What this suite is actually organized around is **response construction paths**, not endpoints. The
 * headers are written from a single pre-routing hook, so which route was hit is nearly irrelevant —
 * what varies, and what has broken before, is *how the Response object came to exist*. Spec 018's
 * rejected plugin passed every endpoint test that mattered and still missed two construction paths
 * silently: a response built by the error pipeline, and one built inside a named sub-app instance.
 *
 * So the cases below are grouped by path: a serialized value, a raw Response, the error pipeline
 * before the handler runs, the validation stage, a thrown handler error, a rendered page, a page from
 * the error pipeline, a named sub-app, a gate refusal, a preflight short-circuit, and the static
 * surface. Endpoint breadth is covered separately and exhaustively by the drift-guarded sweep at the
 * bottom of this file.
 */

const form = { 'content-type': 'application/x-www-form-urlencoded' };
const credentials = { client_id: 'client', client_secret: 'secret' };

function postForm(path: string, body: Record<string, unknown>) {
	return send(path, {
		method: 'POST',
		headers: form,
		body: jsonToFormUrlEncoded(body)
	});
}

describe('security headers: protocol surfaces', () => {
	let setup: Setup;

	beforeEach(async () => {
		setup = await bootstrap(import.meta.url);
	});

	describe('a response serialized from a handler return value', () => {
		it('covers the discovery document', async () => {
			const { response } =
				await agent['.well-known']['openid-configuration'].get();

			expect(response.status).toBe(200);
			expectNonPageProfile(response);
		});

		it('covers a pushed authorization request', async () => {
			const res = await postForm(routeNames.pushed_authorization_request, {
				...credentials,
				response_type: 'code',
				redirect_uri: 'https://client.example.com/cb',
				scope: 'openid',
				// PKCE is mandatory for every client here, confidential ones included (OAuth 2.1).
				code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
				code_challenge_method: 'S256'
			});

			expect(res.status).toBe(201);
			expectNonPageProfile(res);
		});

		it('covers a device authorization request', async () => {
			const res = await postForm(routeNames.device_authorization, {
				...credentials,
				scope: 'openid'
			});

			expect(res.status).toBe(200);
			expectNonPageProfile(res);
		});

		it('covers introspection', async () => {
			const res = await postForm(routeNames.introspect, {
				...credentials,
				token: 'not-a-real-token'
			});

			expect(res.status).toBe(200);
			expectNonPageProfile(res);
		});

		it('covers revocation', async () => {
			const res = await postForm(routeNames.revocation, {
				...credentials,
				token: 'not-a-real-token'
			});

			expect(res.status).toBe(200);
			expectNonPageProfile(res);
		});

		it('covers userinfo carrying a real access token', async () => {
			// getAccountId() is only populated once a login has happened; a token minted without one
			// is rejected as invalid_token and would test nothing.
			await setup.login();
			const token = await new AccessToken({
				accountId: setup.getAccountId(),
				grantId: setup.getGrantId('client'),
				client: await Client.find('client'),
				scope: 'openid'
			}).save();

			const res = await send(routeNames.userinfo, {
				method: 'GET',
				headers: { authorization: `Bearer ${token}` }
			});

			expect(res.status).toBe(200);
			expectNonPageProfile(res);
		});
	});

	/*
	 * The jwks handler returns a fully-formed Response rather than a value. Elysia merges set.headers
	 * onto it, but a header the Response already carries wins — which is the property the whole design
	 * rests on, since it is what lets a rendered page keep its own policy (see the page cases below).
	 */
	describe('a handler returning a raw Response', () => {
		it('covers the key set', async () => {
			const res = await send(routeNames.jwks, { method: 'GET' });

			expect(res.status).toBe(200);
			expectNonPageProfile(res);
		});
	});

	/*
	 * The highest-value cases in this file. Both responses are built before the route handler ever
	 * runs — the 401 in AuthPlugin's derive (transform stage), the 422 in body-schema validation — and
	 * they are the responses a misconfigured browser application hits most often. This is precisely
	 * where the spec-018 mechanism failed, and it failed silently.
	 */
	describe('the error pipeline, before the handler runs', () => {
		it('covers the 401 from failed client authentication', async () => {
			const res = await postForm(routeNames.token, {
				...credentials,
				client_secret: 'wrong',
				grant_type: 'authorization_code',
				code: 'irrelevant'
			});

			expect(res.status).toBe(401);
			expect(await res.json()).toHaveProperty('error', 'invalid_client');
			expectNonPageProfile(res);
		});

		// Refused as invalid_request rather than invalid_client — the header never parses far enough to
		// name a client. Still raised in the transform stage, which is what this case is here for.
		it('covers the refusal of an unparseable Basic credential', async () => {
			const res = await send(routeNames.token, {
				method: 'POST',
				headers: { ...form, authorization: 'Basic @@not-base64@@' },
				body: jsonToFormUrlEncoded({ grant_type: 'authorization_code' })
			});

			expect(res.status).toBe(400);
			expectNonPageProfile(res);
		});

		it('covers the 422 from body-schema validation', async () => {
			const res = await postForm(routeNames.token, { ...credentials });

			expect(res.status).toBe(422);
			expectNonPageProfile(res);
		});

		it('covers a 400 thrown by a handler', async () => {
			const res = await postForm(routeNames.token, {
				...credentials,
				grant_type: 'authorization_code',
				code: 'no-such-code',
				redirect_uri: 'https://client.example.com/cb'
			});

			expect(res.status).toBe(400);
			expectNonPageProfile(res);
		});

		it('covers a not-found response', async () => {
			const res = await send(UNSERVED_PATH, { method: 'GET' });

			expect(res.status).toBe(404);
			expectNonPageProfile(res);
		});
	});

	/*
	 * The negative half of the contract, and the one whose failure mode is silent: if this layer ever
	 * reached a rendered page, the page would be served with `default-src 'none'` and render blank
	 * while every positive assertion above stayed green.
	 *
	 * Nothing here needs the plugin to know what a page is. htmlResponse sets the policy on the
	 * Response it builds, and that wins over the merge — so a page overrides the default by
	 * construction. These cases assert that property holds rather than that a branch was taken.
	 */
	describe('a rendered page keeps its own derived policy', () => {
		it('leaves the device user-code page alone', async () => {
			const res = await send(routeNames.code_verification, { method: 'GET' });

			expect(res.status).toBe(200);
			expect(res.headers.get('content-type')).toContain('text/html');
			expectPageProfile(res);
		});

		it('leaves an error page built by the error pipeline alone', async () => {
			const res = await send(UNSERVED_PATH, {
				method: 'GET',
				headers: { accept: 'text/html' }
			});

			expect(res.status).toBe(404);
			expect(res.headers.get('content-type')).toContain('text/html');
			expectPageProfile(res);
		});
	});

	/*
	 * A gate refusal throws from onRequest, ending the chain early. This is what pins the registration
	 * order in lib/index.ts — the plugin must be mounted before featureGate, and this asserts that it
	 * actually is rather than that someone intended it to be.
	 */
	describe('a feature-gate refusal', () => {
		it('covers a response for a switched-off capability', async () => {
			ApplicationConfig['introspection.enabled'] = false;

			const res = await postForm(routeNames.introspect, {
				...credentials,
				token: 'irrelevant'
			});

			expect(res.status).toBe(404);
			expectNonPageProfile(res);
		});
	});

	/*
	 * The preflight answer short-circuits the onRequest chain and carries no body at all. It is not a
	 * rendered page, so it is covered — the rule is "everything that is not a page", and an exception
	 * list is the thing that drifts.
	 */
	describe('a cross-origin preflight short-circuit', () => {
		it('covers the 204', async () => {
			ApplicationConfig['cors.enabled'] = true;

			const res = await send(routeNames.token, {
				method: 'OPTIONS',
				headers: {
					origin: 'https://app.example.com',
					'access-control-request-method': 'POST'
				}
			});

			expect(res.status).toBe(204);
			expectNonPageProfile(res);
		});
	});
});

/*
 * The management API lives on `adminApp`, a **named** Elysia instance — the second of the two
 * surfaces spec 018's mapResponse plugin missed silently, and the one carrying client secrets, user
 * records and signing-key material. Every case here goes through the real `elysia` via send(); the
 * other admin specs mount their routes onto a throwaway instance, which would not exercise the root
 * registration this feature depends on.
 */
describe('security headers: the administrative control plane', () => {
	beforeEach(async () => {
		await bootstrap(import.meta.url);
		await ensureAdminSeed();
	});

	async function superAdminCookie(): Promise<string> {
		const user = await getUserStore(ADMIN_BUCKET_ID).create(
			`headers-${Math.random()}@x.io`,
			'hash',
			['super_admin']
		);
		const session = await adminSessionStore.create({
			userId: user._id,
			bucketId: ADMIN_BUCKET_ID,
			tokens: {},
			ttlSeconds: 60,
			absoluteTtlSeconds: 3600
		});
		return `${ADMIN_SESSION_COOKIE}=${session._id}`;
	}

	it('covers an authenticated read', async () => {
		const res = await send('/admin/api/projects', {
			method: 'GET',
			headers: { cookie: await superAdminCookie() }
		});

		expect(res.status).toBe(200);
		expectNonPageProfile(res);
	});

	it('covers an authenticated write', async () => {
		const res = await send('/admin/api/projects', {
			method: 'POST',
			headers: {
				cookie: await superAdminCookie(),
				'content-type': 'application/json'
			},
			// The slug pattern is ^[a-z0-9-]+$, so the decimal point in a raw Math.random() is a 422.
			body: JSON.stringify({
				name: 'P',
				slug: `p-${Math.random().toString(36).slice(2)}`
			})
		});

		expect(res.status).toBeLessThan(300);
		expectNonPageProfile(res);
	});

	it('covers an unauthenticated refusal', async () => {
		const res = await send('/admin/api/projects', { method: 'GET' });

		expect(res.status).toBe(401);
		expectNonPageProfile(res);
	});

	/*
	 * The console shell is a rendered page served from that same named instance — the exact
	 * combination (named sub-app AND htmlResponse) where the previous mechanism failed. Asserted
	 * separately from the page cases above even though both go through htmlResponse, because it is the
	 * pairing rather than either half that broke before.
	 */
	it('leaves the rendered console shell alone', async () => {
		// Authenticated deliberately: GET /admin only renders the shell for a signed-in admin (or
		// before the first admin exists) and otherwise redirects, which made an anonymous request
		// order-dependent — it rendered or redirected depending on what an earlier case had seeded.
		const res = await send('/admin', {
			method: 'GET',
			headers: { accept: 'text/html', cookie: await superAdminCookie() }
		});

		expect(res.status).toBe(200);
		expect(res.headers.get('content-type')).toContain('text/html');
		expectPageProfile(res);
	});
});

/*
 * Constitution Principle II requires MCP to reach the control plane through the same checks a human
 * does. This asserts it is not privileged in the other direction either — an agent-facing response is
 * hardened exactly like every other.
 */
describe('security headers: the MCP endpoint', () => {
	beforeEach(async () => {
		await bootstrap(import.meta.url);
	});

	it('covers the MCP route', async () => {
		const res = await send(routeNames.mcp, {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' })
		});

		expectNonPageProfile(res);
	});

	it('covers the protected-resource metadata', async () => {
		const res = await send(routeNames.mcp_metadata, { method: 'GET' });

		expect(res.status).toBe(200);
		expectNonPageProfile(res);
	});
});

/*
 * The anti-omission guard (FR-011). Everything above asserts the paths that were thought of; this
 * asserts the ones that were not.
 *
 * The route tables it walks are the same ones the feature-gate and CORS suites use, and they are held
 * against `elysia.routes` by a two-way drift guard — so a route mounted later cannot slip past this
 * sweep by being absent from a hand-written list here. That is what delivers SC-004: a new endpoint is
 * covered without anyone remembering to add it, and an endpoint that somehow is not covered fails
 * rather than passing by omission.
 *
 * Status is deliberately not asserted. Most of these get a 400, 401 or 404 from a bare probe, and
 * that is fine — a rejection is a response, and the whole point of the contract is that it does not
 * depend on the route, the method or the outcome.
 */
describe('security headers: every mounted route', () => {
	beforeEach(async () => {
		await bootstrap(import.meta.url);
	});

	const routes = [...gatedRoutes, ...alwaysAvailableRoutes].map((route) => ({
		method: route.method,
		// Elysia declaration form: `/reg/:clientId` needs a concrete segment to be requestable.
		path: route.path.replaceAll(/:([A-Za-z0-9_]+)/g, 'probe')
	}));

	it('walks a non-trivial number of routes', () => {
		// A sweep that silently degraded to an empty list would pass every case below.
		expect(routes.length).toBeGreaterThan(10);
	});

	it.each(routes.map((r) => [`${r.method} ${r.path}`, r] as const))(
		'covers %s',
		async (_label, route) => {
			const res = await send(route.path, {
				method: route.method,
				headers:
					route.method === 'POST' || route.method === 'PUT' ? form : undefined,
				body: route.method === 'POST' || route.method === 'PUT' ? '' : undefined
			});

			expectProfileByKind(res);
		}
	);
});

/*
 * The static surface is mounted ahead of this plugin in lib/index.ts and is covered anyway, because
 * onRequest precedes routing — the registration-order constraint documented at lib/plugins/cors.ts:33
 * binds the per-route hooks CORS uses, not this one. Measured in both mount orders; see
 * specs/026-non-html-security-headers/research.md M3.
 *
 * These are also the responses where nosniff earns its keep most concretely: a script or stylesheet
 * whose declared type the browser is free to second-guess is where MIME confusion lands.
 */
describe('security headers: the static surface', () => {
	beforeEach(async () => {
		await bootstrap(import.meta.url);
	});

	it('covers a served stylesheet', async () => {
		const res = await send('/public/reset.css', { method: 'GET' });

		expect(res.status).toBe(200);
		expect(res.headers.get('content-type')).toContain('text/css');
		expectNonPageProfile(res);
	});

	it('covers a served script bundle', async () => {
		const res = await send('/public/admin.js', { method: 'GET' });

		expect(res.status).toBe(200);
		expectNonPageProfile(res);
	});

	it('covers a missing static file', async () => {
		const res = await send('/public/no-such-asset-xyz.js', { method: 'GET' });

		expect(res.status).toBe(404);
		expectNonPageProfile(res);
	});

	/*
	 * Revalidation is where a header is most easily dropped, since a 304 carries no body and is often
	 * assembled separately from the 200.
	 */
	it('covers a not-modified revalidation', async () => {
		const first = await send('/public/reset.css', { method: 'GET' });
		const etag = first.headers.get('etag');
		const lastModified = first.headers.get('last-modified');

		if (!etag && !lastModified) {
			// Nothing to revalidate against; the 200 above already carries the assertion.
			return;
		}

		const res = await send('/public/reset.css', {
			method: 'GET',
			headers: etag
				? { 'if-none-match': etag }
				: { 'if-modified-since': lastModified! }
		});

		expectNonPageProfile(res);
	});
});
