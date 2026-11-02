import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	mock,
	spyOn
} from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap, { seedClient, type Setup } from '../test_helper.js';
import { assertNoPendingInterceptors } from '../fetch_mock.js';
import {
	adapter,
	adminAuditStore,
	getBucketStore,
	getProtectedResourceStore
} from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { ADMIN_MCP_CLIENT_ID, MCP_RESOURCE } from 'lib/mcp/consts.ts';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ROOT_NAMESPACE } from 'lib/resources/namespace.ts';
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { present, shaped } from '../shape.js';
import { TEST_KEYRING } from '../sealing/fixtures.ts';
import { createAdministrator } from '../administrators.ts';
import { cookieFor } from '../admin/ownership_fixtures.ts';
import { postMcp } from '../mcp/rpc.ts';
import { unique } from '../connected_services/stubs.ts';
import { admin } from '../connected_services/harness.ts';
import {
	EXCHANGE,
	allowAccount,
	connected,
	exchange,
	githubService,
	granted,
	refused,
	signIn
} from './harness.ts';

const SERVICES = `/admin/api/projects/${DEFAULT_BUCKET_ID}/connected-services`;

const ServiceView = Type.Object({
	identifier: Type.String(),
	applications: Type.Array(Type.String())
});

/**
 * @proves Only the applications an administrator listed on a connected service, each able to exchange at all, may
 * obtain its tokens; the list and an API's exchanging application change through the audited admin routes, from the
 * console and an agent alike, and a removal takes effect on the next exchange.
 */
describe('an administrator allowing applications to use a connected service', () => {
	let setup: Setup;
	let cookie: string;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'upstream_tokens' });
		cookie = await cookieFor(await createAdministrator('super'));
	});

	beforeEach(() => {
		resetKeyringForTests(TEST_KEYRING);
		spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(false);
	});

	afterEach(() => {
		assertNoPendingInterceptors();
		mock.restore();
	});

	async function consented(serviceId: string) {
		const bucket = present(
			await getBucketStore().find(DEFAULT_BUCKET_ID),
			'the project'
		);
		const service = present(
			bucket.connectedServices?.find((item) => item.id === serviceId),
			'the service'
		);
		const person = unique('person');
		const record = await connected(person, service);
		const signedIn = await signIn(setup, 'agent', person);
		await allowAccount(signedIn.grantId, record);
		return signedIn;
	}

	it('records the change first and lets the application exchange for that service only', async () => {
		const allowed = await githubService([]);
		const other = await githubService([]);

		const answer = await admin(cookie, 'PATCH', `${SERVICES}/${allowed.id}`, {
			applications: ['agent']
		});

		expect(answer.status).toBe(200);
		expect(shaped(ServiceView, answer.json)).toMatchObject({
			identifier: allowed.id,
			applications: ['agent']
		});
		const { entries } = await adminAuditStore.list({
			targetId: DEFAULT_BUCKET_ID
		});
		expect(
			entries.find(
				(entry) =>
					entry.action === 'connected.service.update' &&
					entry.serviceId === allowed.id
			)?.to
		).toBe('agent');
		const signedIn = await consented(allowed.id);
		granted(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: allowed.id
			})
		);
		const elsewhere = await consented(other.id);
		expect(
			refused(
				await exchange({
					subjectToken: elsewhere.accessToken,
					audience: other.id
				})
			).reason
		).toBe('not_permitted');
	});

	it('refuses the application’s next exchange once it is removed from the list', async () => {
		const service = await githubService(['agent']);
		const signedIn = await consented(service.id);
		granted(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id
			})
		);

		await admin(cookie, 'PATCH', `${SERVICES}/${service.id}`, {
			applications: []
		});

		expect(
			refused(
				await exchange({
					subjectToken: signedIn.accessToken,
					audience: service.id
				})
			).reason
		).toBe('not_permitted');
	});

	for (const [label, clientId, why] of [
		['registered itself', 'self-registered', 'registered itself'],
		['does not authenticate', 'spa', 'does not authenticate'],
		['lacks the token exchange grant', 'no-grant', 'token exchange grant'],
		[
			'belongs to another project',
			'elsewhere-app',
			'not an application of this project'
		]
	] as const) {
		it(`refuses listing an application that ${label}, naming it`, async () => {
			const service = await githubService([]);

			const answer = await admin(cookie, 'PATCH', `${SERVICES}/${service.id}`, {
				applications: [clientId]
			});

			expect(answer.status).toBe(400);
			expect(answer.json.field).toBe('applications');
			expect(String(answer.json.message)).toContain(clientId);
			expect(String(answer.json.message)).toContain(why);
		});
	}

	it('no longer lists an application that was deleted', async () => {
		const clientId = unique('short-lived');
		seedClient({
			clientId,
			clientSecret: 'short-lived-secret',
			bucketId: DEFAULT_BUCKET_ID,
			redirectUris: ['https://short.example/cb'],
			grantTypes: ['authorization_code', EXCHANGE],
			responseTypes: ['code']
		});
		const service = await githubService([clientId]);
		await adapter('Client').destroy(clientId);

		const answer = await admin(cookie, 'GET', SERVICES);

		const listed = shaped(
			Type.Object({ services: Type.Array(ServiceView) }),
			answer.json
		).services.find((item) => item.identifier === service.id);
		expect(present(listed, 'the service').applications).toEqual([]);
	});

	describe('an API’s exchanging application', () => {
		async function api(): Promise<string> {
			const identifier = `https://${unique('mcp')}.example/`;
			await getProtectedResourceStore().create({
				namespace: ROOT_NAMESPACE,
				identifier,
				bucketId: DEFAULT_BUCKET_ID,
				name: 'An MCP server',
				scopes: ['repos'],
				tokenFormat: 'jwt'
			});
			return identifier;
		}

		const path = (identifier: string) =>
			`/admin/api/projects/${DEFAULT_BUCKET_ID}/resources/${encodeURIComponent(identifier)}`;

		it('is set and cleared through the resource update', async () => {
			const identifier = await api();

			const set = await admin(cookie, 'PATCH', path(identifier), {
				exchangedBy: 'mcp-server'
			});
			const cleared = await admin(cookie, 'PATCH', path(identifier), {
				exchangedBy: null
			});

			expect(set.json.exchangedBy).toBe('mcp-server');
			expect(cleared.status).toBe(200);
			expect(cleared.json.exchangedBy).toBeUndefined();
		});

		it('is refused for an application that cannot exchange', async () => {
			const identifier = await api();

			const answer = await admin(cookie, 'PATCH', path(identifier), {
				exchangedBy: 'spa'
			});

			expect(answer.status).toBe(400);
			expect(answer.json.field).toBe('exchangedBy');
		});
	});

	it('is the same for an agent through the MCP endpoint', async () => {
		ApplicationConfig['mcp.enabled'] = true;
		await ensureAdminSeed();
		const operator = await createAdministrator('super');
		const at = new AccessToken({
			client: await Client.find(ADMIN_MCP_CLIENT_ID),
			accountId: operator._id,
			scope: 'openid'
		});
		at.setAudience(MCP_RESOURCE);
		const token = await at.save();
		await postMcp(
			{
				jsonrpc: '2.0',
				id: 1,
				method: 'initialize',
				params: {
					protocolVersion: '2026-07-28',
					capabilities: {},
					clientInfo: { name: 'test-agent', version: '1.0.0' }
				}
			},
			token
		);
		const service = await githubService([]);

		const { message } = await postMcp(
			{
				jsonrpc: '2.0',
				id: 2,
				method: 'tools/call',
				params: {
					name: 'connected_service_update',
					arguments: {
						id: DEFAULT_BUCKET_ID,
						serviceId: service.id,
						applications: ['agent']
					}
				}
			},
			token
		);

		expect(JSON.stringify(message)).toContain('"applications":["agent"]');
		const stored = present(
			await getBucketStore().find(DEFAULT_BUCKET_ID),
			'the project'
		).connectedServices?.find((item) => item.id === service.id);
		expect(stored?.applications).toEqual(['agent']);
	});
});
