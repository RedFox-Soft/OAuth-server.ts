import { beforeAll, beforeEach, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { admin } from '../provisioning/helpers.ts';
import {
	agentFor,
	behindProxyPath,
	createApp,
	editor,
	group,
	tool
} from '../behind_proxy/helpers.ts';
import { declareApi, resourcesPath } from '../behind_proxy/api_helpers.ts';
import { adminAuditStore } from 'lib/adapters/index.ts';
import type { User } from 'lib/adapters/types.ts';

let reader: { user: User; cookie: string; project: { id: string } };

async function reads(action: string, targetId: string) {
	const { entries } = await adminAuditStore.list({ action, targetId });
	return entries;
}

/**
 * @proves Who read the people an app or an API refused is kept in the audit trail, once per reader, target and day, an
 * agent's read as the agent's.
 */
describe('reading who an app or an API refused', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		reader = await editor();
	});

	it('is audited once per reader, app and day, and through an agent as the agent', async () => {
		const staff = await group(reader.project.id, 'Readers');
		const app = await createApp(reader.cookie, reader.project.id, {
			rootGroups: [staff],
			name: 'Wiki'
		});
		const path = `${behindProxyPath(reader.project.id, app.id)}/refusals`;
		for (let i = 0; i < 3; i += 1) {
			expect((await admin('POST', path, reader.cookie, {})).status).toBe(200);
		}
		const inConsole = (await reads('behindproxy.refusals.read', app.id)).length;

		const token = await agentFor(reader.user);
		const answer = await tool(token, 'behind_proxy_app_refusal_list', {
			id: reader.project.id,
			appId: app.id
		});
		expect(answer.result?.isError ?? false).toBe(false);

		const entries = await reads('behindproxy.refusals.read', app.id);
		expect({
			inConsole,
			viaAgent: entries.filter((entry) => entry.viaClientId !== undefined)
				.length,
			total: entries.length
		}).toEqual({ inConsole: 1, viaAgent: 1, total: 2 });
	});

	it('is audited once per reader, API and day', async () => {
		const api = await declareApi(reader.cookie, reader.project.id, {
			checkedBy: 'proxy'
		});
		const path = `${resourcesPath(reader.project.id, api.identifier)}/refusals`;
		for (let i = 0; i < 2; i += 1) {
			expect((await admin('POST', path, reader.cookie, {})).status).toBe(200);
		}

		expect((await reads('resource.refusals.read', api.identifier)).length).toBe(
			1
		);
	});
});
