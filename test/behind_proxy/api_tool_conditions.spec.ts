import {
	afterAll,
	afterEach,
	beforeAll,
	describe,
	expect,
	it,
	setSystemTime
} from 'bun:test';

import bootstrap, { seedClient } from '../test_helper.js';
import { getBucketGroupStore, getUserStore } from 'lib/adapters/index.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { eventBus } from 'lib/event_bus.ts';
import { whenUsageRecorded } from 'lib/behind_proxy/usage.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { admin } from '../provisioning/helpers.ts';
import { resetNetworkFacts } from '../network_facts/publication.ts';
import { group, member, world, type Member, type World } from './helpers.ts';
import {
	apiCheck,
	bearer,
	declareApi,
	jwtFor,
	opaqueFor,
	resourcesPath,
	type ApiView,
	type ToolsBody
} from './api_helpers.ts';
import { fromProxy, issueProxyKey } from './conditions_helpers.ts';

let w: World;
let ops: string;
let opsMember: Member;
let humanClient: string;
let pairwiseClient: string;
let key: string;

function seconds(): number {
	return Math.floor(Date.now() / 1000);
}

/* A person's token from an interactive sign-in, holding both scopes the tables below name. */
function personToken(
	api: ApiView,
	who: Member,
	claims: Record<string, unknown> = {}
): Promise<string> {
	return jwtFor(api, {
		claims: {
			sub: who.accountId,
			client_id: humanClient,
			auth_time: seconds(),
			scope: 'files:read files:write',
			...claims
		}
	});
}

/* A `tools/call` from an MCP 2026-07-28 client, through a proxy that passes the caller's address with the key. */
function callTool(
	api: ApiView,
	token: string,
	tool: string,
	options: {
		address?: string;
		mcpMethod?: string;
		protocolVersion?: string | null;
	} = {}
): Promise<Response> {
	return apiCheck({
		slug: w.acme.slug,
		identifier: api.identifier,
		authorization: bearer(token),
		mcpMethod: options.mcpMethod ?? 'tools/call',
		mcpName: tool,
		...(options.protocolVersion !== undefined
			? { protocolVersion: options.protocolVersion }
			: {}),
		headers: fromProxy(key, options.address ?? '203.0.113.10')
	});
}

async function withTools(tools: ToolsBody): Promise<ApiView> {
	const api = await declareApi(w.cookie, w.acme.id, { checkedBy: 'proxy' });
	/* One keyed check from a public address, so the API counts as proven and network conditions may be saved. */
	const proof = await callTool(api, await personToken(api, opsMember), 'any');
	await proof.arrayBuffer();
	await whenUsageRecorded();
	const reply = await admin(
		'PATCH',
		resourcesPath(w.acme.id, api.identifier),
		w.cookie,
		{ tools }
	);
	expect(reply.status).toBe(200);
	return api;
}

const OPEN = { otherTools: 'refuse', withoutMethod: 'refuse' } as const;

/**
 * @proves A condition on one tool of an API checked at the proxy holds for that tool alone, on top of the API's own:
 * only the people, the places and the hours it names may call the tool, every other tool stays as open as before, a
 * token without the tool's scope is refused for the scope and learns nothing of the condition, and the refusal is a
 * plain 403 with no challenge, since no new sign-in could meet it.
 */
describe('conditions on one MCP tool at the proxy check', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		w = await world();
		opsMember = await member(w.acme);
		ops = await group(w.acme.id, 'Ops', [opsMember.accountId]);
		humanClient = `human-${nanoid()}`;
		pairwiseClient = `pairwise-${nanoid()}`;
		for (const [clientId, subjectType] of [
			[humanClient, 'public'],
			[pairwiseClient, 'pairwise']
		] as const) {
			seedClient({
				clientId,
				bucketId: w.acme.id,
				clientName: clientId,
				applicationType: 'web',
				redirectUris: ['https://rp.example.com/cb'],
				responseTypes: ['code'],
				grantTypes: ['authorization_code'],
				subjectType,
				token_endpoint_auth_method: 'none'
			});
		}
		key = (await issueProxyKey(w.cookie, w.acme.id)).key;
	});

	afterEach(() => {
		setSystemTime();
	});

	describe('only Ops may call delete_files', () => {
		let api: ApiView;

		beforeAll(async () => {
			api = await withTools({
				rows: [
					{
						name: 'delete_files',
						scopes: ['files:write'],
						conditions: [{ kind: 'group', groups: [ops] }]
					},
					{ name: 'search_files', scopes: ['files:read'] }
				],
				...OPEN
			});
		});

		it('lets a member of Ops call the tool', async () => {
			const response = await callTool(
				api,
				await personToken(api, opsMember),
				'delete_files'
			);

			expect(response.status).toBe(200);
		});

		it('refuses someone outside Ops with not_in_group and no challenge', async () => {
			const response = await callTool(
				api,
				await personToken(api, w.acme.outsider),
				'delete_files'
			);

			expect(response.status).toBe(403);
			expect(response.headers.get('x-auth-reason')).toBe('not_in_group');
			expect(response.headers.get('www-authenticate')).toBeNull();
		});

		it('lets someone outside Ops call every other tool', async () => {
			const response = await callTool(
				api,
				await personToken(api, w.acme.outsider),
				'search_files'
			);

			expect(response.status).toBe(200);
		});

		it("refuses a token without the tool's scope for the scope, before the condition", async () => {
			const response = await callTool(
				api,
				await personToken(api, w.acme.outsider, { scope: 'files:read' }),
				'delete_files'
			);

			expect(response.status).toBe(403);
			expect(response.headers.get('x-auth-reason')).toBe('insufficient_scope');
			expect(response.headers.get('www-authenticate')).toContain(
				'scope="files:write"'
			);
		});

		it.each([
			[
				'a machine token',
				async () =>
					(
						await opaqueFor(api, w.acme.id, {
							scope: 'files:read files:write'
						})
					).value
			],
			[
				'a pairwise client’s token',
				() => personToken(api, opsMember, { client_id: pairwiseClient })
			]
		] as const)(
			'refuses %s for the tool as no person, as the API’s own group condition does',
			async (_case, mint) => {
				const response = await callTool(api, await mint(), 'delete_files');

				expect(response.status).toBe(403);
				expect(response.headers.get('x-auth-reason')).toBe('no_person');
			}
		);

		it('refuses a member removed from Ops once a minute has passed, and one who can no longer sign in at once', async () => {
			const leaving = await member(w.acme, [ops]);
			const locked = await member(w.acme, [ops]);
			const lockedToken = await personToken(api, locked);
			const before = await callTool(
				api,
				await personToken(api, leaving),
				'delete_files'
			);

			await getBucketGroupStore().change(ops, {
				add: [],
				remove: [leaving.accountId]
			});
			await getUserStore(w.acme.id).update(locked.accountId, { active: false });
			setSystemTime(Date.now() + 61_000);
			const afterLeaving = await callTool(
				api,
				await personToken(api, leaving),
				'delete_files'
			);
			const afterLocking = await callTool(api, lockedToken, 'delete_files');

			expect(before.status).toBe(200);
			expect(afterLeaving.headers.get('x-auth-reason')).toBe('not_in_group');
			expect(afterLocking.headers.get('x-auth-reason')).toBe('cannot_sign_in');
		});

		it('records the refusal with the tool, the reason and the app', async () => {
			const seen: unknown[] = [];
			const listener = (event: unknown) => {
				seen.push(event);
			};
			eventBus.on('behind_proxy.api_decision', listener);
			try {
				await callTool(
					api,
					await personToken(api, w.acme.outsider),
					'delete_files'
				);
			} finally {
				eventBus.off('behind_proxy.api_decision', listener);
			}

			expect(seen).toContainEqual(
				expect.objectContaining({
					resource: api.identifier,
					outcome: 'refuse',
					reason: 'not_in_group',
					tool: 'delete_files',
					clientId: humanClient
				})
			);
		});
	});

	describe('export_billing only from the office, in working hours', () => {
		let api: ApiView;
		/* Monday 16 November 2026. */
		const MONDAY = Date.UTC(2026, 10, 16);

		beforeAll(async () => {
			api = await withTools({
				rows: [
					{
						name: 'export_billing',
						scopes: [],
						conditions: [
							{ kind: 'network', only: ['203.0.113.0/24'], not: [] },
							{
								kind: 'time',
								windows: [{ days: [0, 1, 2, 3, 4], start: 540, end: 1080 }]
							}
						]
					},
					{ name: 'search_files', scopes: ['files:read'] }
				],
				...OPEN,
				access: { conditions: [], timeZone: 'UTC' }
			});
		});

		it('lets a call from the office at 10:00 through', async () => {
			setSystemTime(MONDAY + 10 * 3_600_000);
			const response = await callTool(
				api,
				await personToken(api, w.acme.outsider),
				'export_billing'
			);

			expect(response.status).toBe(200);
		});

		it('refuses a call from elsewhere with not_from_network', async () => {
			setSystemTime(MONDAY + 10 * 3_600_000);
			const response = await callTool(
				api,
				await personToken(api, w.acme.outsider),
				'export_billing',
				{ address: '198.51.100.7' }
			);

			expect(response.headers.get('x-auth-reason')).toBe('not_from_network');
		});

		it('refuses a call from the office at 20:00 with outside_hours', async () => {
			setSystemTime(MONDAY + 20 * 3_600_000);
			const response = await callTool(
				api,
				await personToken(api, w.acme.outsider),
				'export_billing'
			);

			expect(response.headers.get('x-auth-reason')).toBe('outside_hours');
		});

		it('judges another tool only by the API’s own conditions', async () => {
			setSystemTime(MONDAY + 20 * 3_600_000);
			const response = await callTool(
				api,
				await personToken(api, w.acme.outsider),
				'search_files',
				{ address: '198.51.100.7' }
			);

			expect(response.status).toBe(200);
		});
	});

	describe('a tool kept from Tor while network facts are not loaded', () => {
		let api: ApiView;

		beforeAll(async () => {
			ApplicationConfig['networkFacts.enabled'] = true;
			resetNetworkFacts();
			api = await withTools({
				rows: [
					{
						name: 'delete_files',
						scopes: [],
						conditions: [
							{
								kind: 'network',
								only: [],
								not: [],
								facts: { categories: ['tor'], outcome: { kind: 'refuse' } }
							}
						]
					}
				],
				...OPEN
			});
		});

		afterAll(() => {
			ApplicationConfig['networkFacts.enabled'] = false;
		});

		it('closes the tool with network_facts_unknown', async () => {
			const response = await callTool(
				api,
				await personToken(api, opsMember),
				'delete_files'
			);

			expect(response.headers.get('x-auth-reason')).toBe(
				'network_facts_unknown'
			);
		});
	});

	describe('a tool condition on top of the API’s own', () => {
		let api: ApiView;
		let staffOnly: Member;
		let opsOnly: Member;
		let both: Member;

		beforeAll(async () => {
			staffOnly = await member(w.acme, [w.acme.staff]);
			opsOnly = await member(w.acme, [ops]);
			both = await member(w.acme, [w.acme.staff, ops]);
			api = await withTools({
				rows: [
					{
						name: 'delete_files',
						scopes: [],
						conditions: [{ kind: 'group', groups: [ops] }]
					}
				],
				...OPEN,
				access: { conditions: [{ kind: 'group', groups: [w.acme.staff] }] }
			});
		});

		it.each([
			['in Ops but not Staff', () => opsOnly, 403],
			['in Staff but not Ops', () => staffOnly, 403],
			['in both', () => both, 200]
		] as const)('a person %s gets %d', async (_case, who, status) => {
			const response = await callTool(
				api,
				await personToken(api, who()),
				'delete_files'
			);

			expect(response.status).toBe(status);
		});

		it('answers an unmet sign-in requirement before the tool’s condition', async () => {
			const reply = await admin(
				'PATCH',
				resourcesPath(w.acme.id, api.identifier),
				w.cookie,
				{ signInEveryMinutes: 60, confirm: true }
			);
			const consented =
				reply.status === 409
					? await admin(
							'PATCH',
							resourcesPath(w.acme.id, api.identifier),
							w.cookie,
							{
								signInEveryMinutes: 60,
								confirm: true,
								expect: (reply.body as { expect: Record<string, number> })
									.expect
							}
						)
					: reply;
			expect(consented.status).toBe(200);

			const response = await callTool(
				api,
				await personToken(api, staffOnly, { auth_time: seconds() - 7200 }),
				'delete_files'
			);

			expect(response.status).toBe(401);
			expect(response.headers.get('www-authenticate')).toContain(
				'insufficient_user_authentication'
			);
		});
	});

	describe('an app too old to say which tool it calls', () => {
		it('is refused by an API whose tools carry conditions', async () => {
			const api = await withTools({
				rows: [
					{
						name: 'delete_files',
						scopes: [],
						conditions: [{ kind: 'group', groups: [ops] }]
					}
				],
				...OPEN
			});

			const response = await callTool(
				api,
				await personToken(api, opsMember),
				'delete_files',
				{ protocolVersion: '2025-06-18' }
			);

			expect(response.headers.get('x-auth-reason')).toBe('old_client');
		});
	});
});
