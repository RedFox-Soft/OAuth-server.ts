import { afterAll, beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adapter,
	getUserStore,
	mcpClientPermissionStore
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { writeLogo } from 'lib/models/client/logo.ts';
import { MCP_RESOURCE } from 'lib/mcp/consts.js';
import type { ConsentView } from 'lib/interactions/consentView.ts';
import { PNG } from '../consent_branding/consent_branding.config.ts';
import { MEMBER, PASSWORD, devicePages, ownProjects } from './seed.ts';

const ADMIN_DEVICE = 'https://device.acme.test/client.json';
const ADMIN_EMAIL = 'admin-device@acme.test';

function viewOf(html: string): ConsentView {
	return JSON.parse(
		/window\.PROPS=(.*?)<\/script>/s.exec(html)?.[1] ?? '{}'
	) as ConsentView;
}

/**
 * @proves A device's consent page never shows an application's logo — a familiar face is what makes a phished
 * device code convincing — even when a graver warning, about administrator rights, takes the device warning's
 * place on the page.
 */
describe('the logo on the consent page of a device’s sign-in', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'client_branding' });
		await ensureAdminSeed();
		await ownProjects();
		await writeLogo('own-device', PNG);
		ApplicationConfig['mcp.enabled'] = true;
		await adapter('Client').upsert(ADMIN_DEVICE, {
			clientId: ADMIN_DEVICE,
			client_name: 'Acme Admin Device',
			token_endpoint_auth_method: 'none',
			grantTypes: ['urn:ietf:params:oauth:grant-type:device_code'],
			responseTypes: [],
			redirectUris: [],
			applicationType: 'native'
		});
		await mcpClientPermissionStore.create({
			_id: ADMIN_DEVICE,
			kind: 'identifier'
		});
		await writeLogo(ADMIN_DEVICE, PNG);
		await getUserStore(ADMIN_BUCKET_ID).create(
			ADMIN_EMAIL,
			await Bun.password.hash(PASSWORD),
			true
		);
	});

	afterAll(async () => {
		ApplicationConfig['mcp.enabled'] = false;
		await mcpClientPermissionStore.destroy(ADMIN_DEVICE);
	});

	it('shows no logo for an own app on a device', async () => {
		const { consent } = await devicePages('own-device', MEMBER);

		expect(viewOf(consent.html).client.logo).toBeUndefined();
		expect(consent.html).not.toContain(PNG);
	});

	it('shows no logo for an own app on a device when the request asks for administrator rights', async () => {
		const { consent } = await devicePages(ADMIN_DEVICE, ADMIN_EMAIL, {
			resource: MCP_RESOURCE
		});
		const view = viewOf(consent.html);

		expect(view.warning?.kind).toBe('admin');
		expect(view.client.logo).toBeUndefined();
		expect(consent.html).not.toContain(PNG);
	});
});
