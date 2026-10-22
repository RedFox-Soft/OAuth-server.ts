import {
	afterAll,
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it
} from 'bun:test';

import bootstrap, {
	clearSeededBuckets,
	seedBucket,
	type Setup
} from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { ISSUER } from 'lib/configs/env.js';
import { getProtectedResourceStore } from 'lib/adapters/index.js';
import { clearDocumentCache } from 'lib/client_metadata_document/cache.ts';
import { resolver } from 'lib/client_metadata_document/fetch.ts';
import { decode as decodeJWT } from 'lib/helpers/jwt.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.js';
import { withCookies } from '../consent_page/flow.ts';
import { codeOf } from '../consent_choices/rows.ts';
import { present } from 'test/shape.js';
import { mock, serveDocument } from './document_host.js';

/*
 * MCP's SEP-2352 calls a client identifier that is a metadata document URL portable across authorization
 * servers: no registration is held anywhere, so there is nothing to keep apart. Each project with an address is
 * one such server. The binding that keeps clients to their own issuer must therefore leave a document client
 * free to sign in at any project that declared the resource it asks for — and to redeem there what it got.
 */

const SLUG = 'acme';
const BUCKET_ID = 'acme-bucket';
const AUDIENCE = 'https://mcp.acme.example/mcp';
const REDIRECT = 'https://app.example.com/callback';

/**
 * @proves A client identified by a metadata document that signs in at a project's own address, through a
 * resource that project declared, is issued tokens there carrying that project's issuer.
 */
describe('a document-identified client at a project’s own address', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'named_project' });
		await seedBucket({
			bucketId: BUCKET_ID,
			slug: SLUG,
			clientId: 'acme-owned',
			accountId: 'bob'
		});
		await getProtectedResourceStore().create({
			namespace: BUCKET_ID,
			identifier: AUDIENCE,
			bucketId: BUCKET_ID,
			name: 'Acme MCP',
			scopes: ['mcp:tools-basic']
		});
	});

	afterAll(async () => {
		await clearSeededBuckets();
	});

	beforeEach(() => {
		clearDocumentCache();
		resolver.lookup = async () => ['93.184.216.34'];
	});

	afterEach(() => {
		mock.restore();
		resolver.lookup = resolver.realLookup;
	});

	it('is issued tokens bearing the project’s issuer for the code it got there', async () => {
		const { identifier } = serveDocument({
			overrides: { redirect_uris: [REDIRECT] }
		});
		const cookie = await setup.login({ accountId: 'bob', bucketId: BUCKET_ID });
		const auth = new AuthorizationRequest({
			client_id: identifier,
			scope: 'openid',
			redirect_uri: REDIRECT
		});
		const query = new URLSearchParams({
			...Object.fromEntries(
				Object.entries(auth.params).map(([k, v]) => [k, String(v)])
			),
			resource: AUDIENCE
		});

		const started = await elysia.handle(
			new Request(`${ISSUER}/${SLUG}/auth?${query}`, { headers: { cookie } })
		);
		const consentPath = present(
			started.headers.get('location'),
			'a consent redirect'
		);
		const decided = await elysia.handle(
			new Request(`${ISSUER}${consentPath}`, {
				method: 'POST',
				headers: {
					cookie: withCookies(cookie, started),
					'content-type': 'application/x-www-form-urlencoded'
				},
				body: new URLSearchParams({
					action: 'allow',
					accountId: 'bob'
				}).toString()
			})
		);

		const redeemed = await elysia.handle(
			new Request(`${ISSUER}/${SLUG}/token`, {
				method: 'POST',
				headers: { 'content-type': 'application/x-www-form-urlencoded' },
				body: new URLSearchParams({
					grant_type: 'authorization_code',
					client_id: identifier,
					code: codeOf(decided),
					code_verifier: present(auth.code_verifier, 'a PKCE verifier'),
					redirect_uri: REDIRECT,
					resource: AUDIENCE
				}).toString()
			})
		);

		expect(redeemed.status).toBe(200);
		const { access_token } = (await redeemed.json()) as {
			access_token: string;
		};
		expect(decodeJWT(access_token).payload.iss).toBe(`${ISSUER}/${SLUG}`);
	});
});
