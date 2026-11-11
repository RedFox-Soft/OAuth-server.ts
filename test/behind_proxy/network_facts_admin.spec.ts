import { afterEach, beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.js';
import { ApplicationConfig } from 'lib/configs/application.js';
import { adminAuditStore } from 'lib/adapters/index.ts';
import { ADMIN_MCP_CLIENT_ID } from 'lib/mcp/consts.ts';
import { admin } from '../provisioning/helpers.ts';
import { createAdministrator } from '../administrators.ts';
import {
	agentFor,
	behindProxyPath,
	confirm,
	createApp,
	tool,
	world,
	type AppView,
	type World
} from './helpers.ts';
import { issueProxyKey, proveAddresses } from './conditions_helpers.ts';
import { declareApi, resourcesPath } from './api_helpers.ts';

let w: World;
let key: string;

const TOR_OUT = {
	categories: ['tor', 'vpn', 'hosting'],
	outcome: { kind: 'refuse' }
};

async function provenApp(): Promise<AppView> {
	const app = await createApp(w.cookie, w.acme.id, {
		rootGroups: [w.acme.staff]
	});
	await proveAddresses({ slug: w.acme.slug, app }, key);
	return app;
}

function withFacts(
	facts: unknown,
	ranges: { only?: string[]; not?: string[] } = {}
) {
	return {
		rules: [
			{
				path: '/',
				who: { kind: 'groups', groups: [w.acme.staff] },
				conditions: [
					{
						kind: 'network',
						only: ranges.only ?? [],
						not: ranges.not ?? [],
						facts
					}
				]
			}
		]
	};
}

/**
 * @proves An administrator adds network facts to "From where" only while a super administrator has the download on,
 * keeps what was saved when it goes off, is told plainly what is wrong with a condition that cannot be saved, and an
 * agent's change goes through the same checks and the same audit trail.
 */
describe('network facts in the conditions an administrator saves', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		w = await world();
		key = (await issueProxyKey(w.cookie, w.acme.id)).key;
	});

	afterEach(() => {
		ApplicationConfig['networkFacts.enabled'] = false;
	});

	it('saves a rule with network facts and no ranges while the download is on', async () => {
		ApplicationConfig['networkFacts.enabled'] = true;
		const app = await provenApp();
		const reply = await admin(
			'PATCH',
			behindProxyPath(w.acme.id, app.id),
			w.cookie,
			withFacts(TOR_OUT)
		);
		expect(reply.status).toBe(200);
		expect(JSON.stringify(reply.body)).toContain('"hosting"');
	});

	it('refuses adding network facts while the download is off', async () => {
		const app = await provenApp();
		const reply = await admin(
			'PATCH',
			behindProxyPath(w.acme.id, app.id),
			w.cookie,
			withFacts(TOR_OUT)
		);
		expect([reply.status, reply.json.code]).toEqual([409, 'network_facts_off']);
	});

	it('keeps a saved condition, and lets other changes save, after the download goes off', async () => {
		ApplicationConfig['networkFacts.enabled'] = true;
		const app = await provenApp();
		await admin(
			'PATCH',
			behindProxyPath(w.acme.id, app.id),
			w.cookie,
			withFacts(TOR_OUT)
		);
		ApplicationConfig['networkFacts.enabled'] = false;
		const reply = await admin(
			'PATCH',
			behindProxyPath(w.acme.id, app.id),
			w.cookie,
			withFacts(TOR_OUT, { not: ['198.51.100.0/24'] })
		);
		expect(reply.status).toBe(200);
		expect(JSON.stringify(reply.body)).toContain('"tor"');
	});

	it('still asks the proxy to prove the addresses it reports first', async () => {
		ApplicationConfig['networkFacts.enabled'] = true;
		const app = await createApp(w.cookie, w.acme.id, {
			rootGroups: [w.acme.staff]
		});
		const reply = await admin(
			'PATCH',
			behindProxyPath(w.acme.id, app.id),
			w.cookie,
			withFacts(TOR_OUT)
		);
		expect([reply.status, reply.json.code]).toEqual([
			409,
			'proxy_address_unproven'
		]);
	});

	describe('refuses, saying why,', () => {
		const refused = async (facts: unknown) => {
			ApplicationConfig['networkFacts.enabled'] = true;
			const app = await provenApp();
			return admin(
				'PATCH',
				behindProxyPath(w.acme.id, app.id),
				w.cookie,
				withFacts(facts)
			);
		};

		it('a condition that names no network and no country', async () => {
			const reply = await refused({
				categories: [],
				outcome: { kind: 'refuse' }
			});
			expect(reply.status).toBe(422);
		});

		it('a category that is not a network fact', async () => {
			const reply = await refused({
				categories: ['bogon'],
				outcome: { kind: 'refuse' }
			});
			expect(reply.status).toBe(422);
		});

		it('a code that is no country', async () => {
			const reply = await refused({
				categories: [],
				countries: { mode: 'only', codes: ['ZZ'] },
				outcome: { kind: 'refuse' }
			});
			expect(reply.status).toBe(422);
			expect(JSON.stringify(reply.body)).toContain('ZZ');
		});

		it('more than 250 countries', async () => {
			const codes = Array.from(
				{ length: 251 },
				(_, i) =>
					`${String.fromCharCode(65 + (i % 26))}${String.fromCharCode(65 + Math.floor(i / 26))}`
			);
			const reply = await refused({
				categories: [],
				countries: { mode: 'not', codes },
				outcome: { kind: 'refuse' }
			});
			expect(reply.status).toBe(422);
		});
	});

	it('stores countries in one form, whatever case they came in', async () => {
		ApplicationConfig['networkFacts.enabled'] = true;
		const app = await provenApp();
		const reply = await admin(
			'PATCH',
			behindProxyPath(w.acme.id, app.id),
			w.cookie,
			withFacts({
				categories: [],
				countries: { mode: 'only', codes: ['de', 'AT', 'DE'] },
				outcome: { kind: 'refuse' }
			})
		);
		expect(reply.status).toBe(200);
		expect(JSON.stringify(reply.body)).toContain('"codes":["AT","DE"]');
	});

	it('refuses "sign in again" on an API, which has no sign-in to ask for', async () => {
		ApplicationConfig['networkFacts.enabled'] = true;
		const api = await declareApi(w.cookie, w.acme.id, { checkedBy: 'proxy' });
		const reply = await admin(
			'PATCH',
			resourcesPath(w.acme.id, api.identifier),
			w.cookie,
			{
				tools: {
					rows: [],
					otherTools: 'token',
					withoutMethod: 'token',
					access: {
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
				}
			}
		);
		expect(reply.status).toBe(422);
	});

	it('previews asking matching addresses for a code, and saves only when confirmed with the numbers shown', async () => {
		ApplicationConfig['networkFacts.enabled'] = true;
		const app = await provenApp();
		const path = behindProxyPath(w.acme.id, app.id);
		const body = withFacts({
			categories: ['vpn'],
			outcome: { kind: 'sign_in_again', maxAgeMinutes: 15, withCode: true }
		});

		const asked = await admin('PATCH', path, w.cookie, body);
		expect([asked.status, asked.json.changes]).toEqual([
			409,
			['codeConditionOn']
		]);

		const applied = await admin('PATCH', path, w.cookie, {
			...body,
			confirm: true,
			expect: asked.json.expect
		});
		expect(applied.status).toBe(200);
		expect(JSON.stringify(applied.body)).toContain('"withCode":true');
	});

	it("records an agent's change in the audit trail, naming the agent", async () => {
		ApplicationConfig['networkFacts.enabled'] = true;
		const app = await provenApp();
		const user = await createAdministrator('super');
		const token = await agentFor(user);
		const args = { id: w.acme.id, appId: app.id, ...withFacts(TOR_OUT) };
		const described = await tool(token, 'behind_proxy_app_update', args);
		const applied = await confirm(
			token,
			'behind_proxy_app_update',
			args,
			described
		);
		expect(applied.result?.isError).not.toBe(true);
		const { entries } = await adminAuditStore.list({
			actor: user._id,
			action: 'behindproxy.update'
		});
		expect(entries.map((entry) => entry.viaClientId)).toContain(
			ADMIN_MCP_CLIENT_ID
		);
	});
});
