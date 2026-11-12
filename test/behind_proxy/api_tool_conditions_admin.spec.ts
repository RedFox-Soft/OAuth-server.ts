import { afterAll, beforeAll, describe, expect, it } from 'bun:test';

import bootstrap, { seedClient } from '../test_helper.js';
import { adminAuditStore } from 'lib/adapters/index.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { whenUsageRecorded } from 'lib/behind_proxy/usage.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { admin } from '../provisioning/helpers.ts';
import {
	agentFor,
	confirm,
	editor,
	group,
	member,
	tool,
	world,
	type World
} from './helpers.ts';
import {
	apiCheck,
	bearer,
	declareApi,
	jwtFor,
	resourcesPath,
	type ApiView
} from './api_helpers.ts';
import { fromProxy, issueProxyKey } from './conditions_helpers.ts';

let w: World;
let ops: string;

const OLD_CLIENTS =
	"an app too old to say which tool it calls can't be held to one tool's conditions";

function save(
	api: Pick<ApiView, 'identifier'>,
	tools: Record<string, unknown>,
	extra: Record<string, unknown> = {}
) {
	return admin('PATCH', resourcesPath(w.acme.id, api.identifier), w.cookie, {
		tools,
		...extra
	});
}

function opsRow(name = 'delete_files', scopes: string[] = []) {
	return { name, scopes, conditions: [{ kind: 'group', groups: [ops] }] };
}

function errorOf(body: unknown): string {
	return String((body as { message?: unknown }).message);
}

/**
 * @proves An administrator or an agent can give one tool of an API conditions of its own and see them as saved, while
 * the save refuses what could never hold: a row that asks for nothing, a condition on an API no proxy checks, hours
 * with no time zone, a network condition before the proxy has shown it passes addresses, and above all a tool
 * condition while apps too old to name their tool are let in, which those apps would walk around.
 */
describe('saving conditions on one MCP tool', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		w = await world();
		const opsMember = await member(w.acme);
		ops = await group(w.acme.id, 'Ops', [opsMember.accountId]);
	});

	describe('an API checked at the proxy', () => {
		let api: ApiView;

		beforeAll(async () => {
			api = await declareApi(w.cookie, w.acme.id, { checkedBy: 'proxy' });
		});

		it('keeps a group condition on a row with no scope, and reads it back by group id', async () => {
			const reply = await save(api, {
				rows: [opsRow(), { name: 'search_files', scopes: ['files:read'] }],
				otherTools: 'refuse',
				withoutMethod: 'refuse'
			});

			expect(reply.status).toBe(200);
			const read = await admin(
				'GET',
				resourcesPath(w.acme.id, api.identifier),
				w.cookie
			);
			expect(read.body).toMatchObject({
				tools: {
					rows: [
						{
							name: 'delete_files',
							scopes: [],
							conditions: [{ kind: 'group', groupIds: [ops] }]
						},
						{ name: 'search_files', scopes: ['files:read'] }
					]
				}
			});
		});

		it('records the change as resource.update', async () => {
			await save(api, {
				rows: [opsRow()],
				otherTools: 'refuse',
				withoutMethod: 'refuse'
			});

			const { entries } = await adminAuditStore.list({
				action: 'resource.update'
			});
			expect(entries.map((entry) => entry.targetId)).toContain(api.identifier);
		});

		it('refuses a row that needs neither a scope nor a condition, naming it', async () => {
			const reply = await save(api, {
				rows: [{ name: 'delete_files', scopes: [] }],
				otherTools: 'refuse',
				withoutMethod: 'refuse'
			});

			expect(reply.status).toBe(400);
			expect(errorOf(reply.body)).toBe(
				'the tool "delete_files" needs a scope or a condition'
			);
		});

		it('refuses a group that is not one of the project’s', async () => {
			const reply = await save(api, {
				rows: [
					{
						name: 'delete_files',
						scopes: [],
						conditions: [{ kind: 'group', groups: [nanoid()] }]
					}
				],
				otherTools: 'refuse',
				withoutMethod: 'refuse'
			});

			expect(reply.status).toBe(422);
		});

		it('refuses a tool condition while apps too old to name their tool are let in', async () => {
			const reply = await save(api, {
				rows: [opsRow()],
				otherTools: 'refuse',
				withoutMethod: 'token'
			});

			expect(reply.status).toBe(422);
			expect(errorOf(reply.body)).toStartWith(OLD_CLIENTS);
			expect(reply.body).toMatchObject({
				code: 'old_clients_with_tool_conditions'
			});
		});

		it('refuses hours on a row with no time zone, and keeps a zone with no condition of the API’s own', async () => {
			const timeRow = {
				name: 'export_billing',
				scopes: [],
				conditions: [
					{
						kind: 'time',
						windows: [{ days: [0, 1, 2, 3, 4], start: 540, end: 1080 }]
					}
				]
			};
			const noZone = await save(api, {
				rows: [timeRow],
				otherTools: 'refuse',
				withoutMethod: 'refuse'
			});
			const withZone = await save(api, {
				rows: [timeRow],
				otherTools: 'refuse',
				withoutMethod: 'refuse',
				access: { conditions: [], timeZone: 'Europe/Berlin' }
			});

			expect(noZone.status).toBe(422);
			expect(withZone.status).toBe(200);
			expect(withZone.body).toMatchObject({
				tools: { access: { conditions: [], timeZone: 'Europe/Berlin' } }
			});
		});

		it('refuses a network condition on a row before the proxy has shown it passes addresses', async () => {
			const fresh = await declareApi(w.cookie, w.acme.id, {
				checkedBy: 'proxy'
			});

			const reply = await save(fresh, {
				rows: [
					{
						name: 'export_billing',
						scopes: [],
						conditions: [{ kind: 'network', only: ['203.0.113.0/24'], not: [] }]
					}
				],
				otherTools: 'refuse',
				withoutMethod: 'refuse'
			});

			expect(reply.status).toBe(409);
			expect(reply.body).toMatchObject({ code: 'proxy_address_unproven' });
		});

		describe('network facts on a row', () => {
			afterAll(() => {
				ApplicationConfig['networkFacts.enabled'] = false;
			});

			it('refuses a new one while network facts are off', async () => {
				ApplicationConfig['networkFacts.enabled'] = false;
				const reply = await save(api, {
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
					otherTools: 'refuse',
					withoutMethod: 'refuse'
				});

				expect(reply.status).toBe(409);
				expect(reply.body).toMatchObject({ code: 'network_facts_off' });
			});

			it('refuses one that would ask for a new sign-in, which a tool cannot', async () => {
				ApplicationConfig['networkFacts.enabled'] = true;
				const key = (await issueProxyKey(w.cookie, w.acme.id)).key;
				const proven = await declareApi(w.cookie, w.acme.id, {
					checkedBy: 'proxy'
				});
				const proof = await apiCheck({
					slug: w.acme.slug,
					identifier: proven.identifier,
					authorization: bearer(await jwtFor(proven)),
					mcpMethod: 'tools/list',
					headers: fromProxy(key, '203.0.113.10')
				});
				await proof.arrayBuffer();
				await whenUsageRecorded();

				const reply = await save(proven, {
					rows: [
						{
							name: 'delete_files',
							scopes: [],
							conditions: [
								{
									kind: 'network',
									only: [],
									not: [],
									facts: {
										categories: ['tor'],
										outcome: { kind: 'sign_in_again', maxAgeMinutes: 15 }
									}
								}
							]
						}
					],
					otherTools: 'refuse',
					withoutMethod: 'refuse'
				});

				expect(reply.status).toBe(422);
			});
		});

		it('names the apps that act for no one or have pairwise subjects when a row has a group condition', async () => {
			const pairwise = `pairwise-${nanoid()}`;
			seedClient({
				clientId: pairwise,
				bucketId: w.acme.id,
				clientName: pairwise,
				applicationType: 'web',
				redirectUris: ['https://rp.example.com/cb'],
				responseTypes: ['code'],
				grantTypes: ['authorization_code'],
				subjectType: 'pairwise',
				token_endpoint_auth_method: 'none'
			});

			const reply = await save(api, {
				rows: [opsRow()],
				otherTools: 'refuse',
				withoutMethod: 'refuse'
			});

			const warned = reply.body as {
				warnings?: { pairwiseClients?: string[] };
			};
			expect(warned.warnings?.pairwiseClients).toContain(pairwise);
		});
	});

	it('refuses a tool condition on an API whose own server checks its tokens', async () => {
		const api = await declareApi(w.cookie, w.acme.id);

		const reply = await save(api, {
			rows: [opsRow()],
			otherTools: 'refuse',
			withoutMethod: 'refuse'
		});

		expect(reply.status).toBe(422);
	});

	it('refuses an agent the same tool condition while apps too old to name their tool are let in', async () => {
		const { user, cookie, project } = await editor();
		const api = await declareApi(cookie, project.id, { checkedBy: 'proxy' });
		const groupId = await group(project.id, 'Ops');
		const token = await agentFor(user);
		const args = {
			id: project.id,
			resourceId: api.identifier,
			tools: {
				rows: [
					{
						name: 'delete_files',
						scopes: [],
						conditions: [{ kind: 'group', groups: [groupId] }]
					}
				],
				otherTools: 'refuse',
				withoutMethod: 'token'
			}
		};

		const described = await tool(token, 'resource_update', args);
		const applied = await confirm(token, 'resource_update', args, described);

		expect(described.result?.structuredContent?.status).toBe(
			'confirmation_required'
		);
		expect(applied.result?.isError).toBe(true);
		expect(JSON.stringify(applied.result)).toContain(OLD_CLIENTS);
	});
});
