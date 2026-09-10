import {
	describe,
	it,
	expect,
	beforeAll,
	beforeEach,
	afterEach
} from 'bun:test';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getUserStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import {
	ADMIN_MCP_CLIENT_ID,
	MCP_RESOURCE,
	MCP_ROUTE
} from 'lib/mcp/consts.ts';
import { resolveBucketForRequest } from 'lib/admin/auth/resolveBucket.ts';
import { clearDocumentCache } from 'lib/client_metadata_document/cache.ts';
import { resolver } from 'lib/client_metadata_document/fetch.ts';
import { serveDocument, mock } from '../cimd/document_host.js';
import { clearPermissions, permitIdentifier } from './permissions.ts';

/*
 * Does the administrative plane actually work through a client identity document, end to end?
 *
 * The permission specs answer a narrower question: they seed a *stored* client whose id happens to be
 * a URL, because what they test is the allowlist rather than retrieval. That leaves the headline claim
 * of this capability — an agent host with nothing configured reaches the admin plane — resting on two
 * halves that were only ever tested apart. This joins them, and pins the configuration it needs: the
 * document path is gated on `clientIdMetadataDocument.enabled`, so with that off the identity does not
 * resolve to a client at all and the surface refuses however the allowlist is set.
 */

const publicAddress = '93.184.216.34';

async function tokenFor(clientId: string) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`admin-${Math.random()}@x.io`,
		'hash',
		['super_admin']
	);
	const at = new AccessToken({
		client: await Client.find(clientId),
		accountId: user._id,
		scope: 'openid'
	});
	at.setAudience(MCP_RESOURCE);
	return (await at.save()) as unknown as string;
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
 * @proves An agent identified only by a hosted document administers the instance when an
 * operator permitted it, and never otherwise.
 */
describe('the administrative plane through a client identity document', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'cimd_admin' });
	});

	beforeEach(async () => {
		await ensureAdminSeed();
		await clearPermissions();
		clearDocumentCache();
		resolver.lookup = async () => [publicAddress];
	});

	afterEach(() => {
		mock.restore();
		resolver.lookup = resolver.realLookup;
		ApplicationConfig['clientIdMetadataDocument.enabled'] = true;
	});

	/*
	 * The whole claim in one case: a client that exists only as a document it hosts, permitted by a
	 * super administrator, reaching the administrative surface. No client record is created at any
	 * point.
	 */
	it('admits a permitted identity that exists only as a hosted document', async () => {
		const { identifier } = serveDocument();
		await permitIdentifier(identifier);

		expect(await reach(await tokenFor(identifier))).toBe(200);
	});

	it('routes it to the administrator bucket, so the sign-in could have happened', async () => {
		const { identifier } = serveDocument();
		await permitIdentifier(identifier);

		expect(await resolveBucketForRequest(identifier, MCP_RESOURCE)).toBe(
			ADMIN_BUCKET_ID
		);
	});

	/*
	 * The configuration this path requires, and the reason the answer to "does admin MCP work through
	 * CIMD" is "yes, with both switches on". With the document capability off the identity resolves to
	 * no client at all, so the allowlist never even gets a say.
	 */
	it('refuses when document identifiers are not accepted, however the allowlist is set', async () => {
		const { identifier } = serveDocument();
		await permitIdentifier(identifier);
		const token = await tokenFor(identifier);
		expect(await reach(token)).toBe(200);

		ApplicationConfig['clientIdMetadataDocument.enabled'] = false;
		clearDocumentCache();

		expect(await reach(token)).toBe(401);
	});

	it('refuses a hosted document nobody permitted', async () => {
		const { identifier } = serveDocument();

		expect(await reach(await tokenFor(identifier))).toBe(401);
	});

	/*
	 * A document that stops validating takes the agent with it on the next call — the retrieval is
	 * part of resolving the client, not a one-off at permission time.
	 */
	it('refuses once the document stops being valid', async () => {
		const { identifier } = serveDocument();
		await permitIdentifier(identifier);
		const token = await tokenFor(identifier);
		expect(await reach(token)).toBe(200);

		clearDocumentCache();
		mock.restore();
		resolver.lookup = async () => [publicAddress];
		serveDocument({ rawBody: '{ not json' });

		expect(await reach(token)).toBe(401);
	});

	/*
	 * And the reserved client is unaffected by any of it: its route to the administrator bucket is
	 * membership of the reserved admin project, which needs neither an allowlist entry nor the
	 * document capability.
	 */
	it('leaves the reserved client working with the document capability off', async () => {
		ApplicationConfig['clientIdMetadataDocument.enabled'] = false;

		expect(await reach(await tokenFor(ADMIN_MCP_CLIENT_ID))).toBe(200);
	});
});
