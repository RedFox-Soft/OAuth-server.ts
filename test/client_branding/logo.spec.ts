import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { writeLogo } from 'lib/models/client/logo.ts';
import { MCP_RESOURCE } from 'lib/mcp/consts.js';
import type { ConsentView } from 'lib/interactions/consentView.ts';
import { PNG } from '../consent_branding/consent_branding.config.ts';
import { MEMBER, devicePages, ownProjects } from './seed.ts';

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
	});

	it('shows no logo for an own app on a device', async () => {
		const { consent } = await devicePages('own-device', MEMBER);

		expect(viewOf(consent.html).client.logo).toBeUndefined();
		expect(consent.html).not.toContain(PNG);
	});

	it('shows no logo for an own app on a device when the request asks for administrator rights', async () => {
		const { consent } = await devicePages('own-device', MEMBER, {
			resource: MCP_RESOURCE
		});
		const view = viewOf(consent.html);

		expect(view.warning?.kind).toBe('admin');
		expect(view.client.logo).toBeUndefined();
		expect(consent.html).not.toContain(PNG);
	});
});
