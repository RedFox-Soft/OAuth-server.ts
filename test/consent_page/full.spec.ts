import { describe, it, expect, beforeAll, afterAll } from 'bun:test';

import bootstrap, { type Setup } from '../test_helper.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	getProjectStore,
	getProtectedResourceStore
} from 'lib/adapters/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { ROOT_NAMESPACE } from 'lib/resources/namespace.js';
import { ApplicationConfig } from 'lib/configs/application.js';
import { MCP_RESOURCE } from 'lib/mcp/consts.js';
import { CONSENT_TEXTS as T } from 'lib/interactions/consentTexts.js';
import { MCP } from './consent_page.config.ts';
import { openConsent, decide, withCookies } from './flow.ts';

/**
 * @proves A person connecting an application to a service is told what it will be able to see and what
 * it will be able to do for them, in the words of whoever runs that service, with what nobody described
 * shown for what it is — and the request that would hand an agent the administrator's own power is never
 * shown as anything less.
 */
describe('the consent page for access to a service', () => {
	let setup: Setup;
	let cookie: string;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'consent_page' });
		await ensureAdminSeed();
		const project = await getProjectStore().create({
			name: 'Company',
			slug: 'company-mcp',
			ownerGroupId: UNASSIGNED_GROUP_ID
		});
		await getProtectedResourceStore().create({
			namespace: ROOT_NAMESPACE,
			identifier: MCP,
			projectId: project._id,
			name: 'Company MCP',
			scopes: ['tools:read', 'tools:call', 'tools:admin', 'files.write'],
			scopeDescriptions: {
				'tools:read': {
					description: 'see which tools the service offers',
					kind: 'see'
				},
				'tools:call': { description: 'run the service’s tools as you' },
				'files.write': {
					description: 'create and change files',
					kind: 'act'
				}
			}
		});
		ApplicationConfig['consent.scopeDescriptions'] = {
			billing: 'see your invoices'
		};
		cookie = await setup.login({ scope: 'openid' });
	});

	afterAll(() => {
		ApplicationConfig['consent.scopeDescriptions'] = {};
	});

	function toService(scope: string, extra: Record<string, unknown> = {}) {
		return openConsent(
			{ client_id: 'own-app', scope, resource: [MCP], ...extra },
			cookie
		);
	}

	it('puts a described scope under what the app will do for the person when its kind is not declared', async () => {
		const page = await toService('openid tools:call');

		const act = page.text.slice(page.text.indexOf(T.groups.act));
		expect(act).toContain('run the service’s tools as you');
	});

	it('puts a scope under what the app will see when the service declared it so', async () => {
		const page = await toService('openid tools:read');

		expect(page.text).toContain(T.groups.see);
		expect(page.text).not.toContain(T.groups.act);
		expect(page.text).toContain('see which tools the service offers');
	});

	it('shows a scope nobody described by its technical name, in sight', async () => {
		const page = await toService('openid tools:admin');

		expect(page.text).toContain(T.groups.other);
		expect(page.text).toContain(T.resource.undescribedOwner('Company MCP'));
		expect(page.text).toContain('tools:admin');
	});

	it('names the service by its declared name and its host', async () => {
		const page = await toService('openid tools:call');

		expect(page.text).toContain(
			`${T.resource.heading} Company MCP — mcp.acme.test`
		);
	});

	it('describes a custom scope in the instance’s words when the setting describes it', async () => {
		const page = await openConsent(
			{ client_id: 'own-app', scope: 'openid billing' },
			cookie
		);

		const act = page.text.slice(page.text.indexOf(T.groups.act));
		expect(act).toContain('see your invoices');
	});

	it('shows a custom scope nobody described under the permissions that are not described', async () => {
		ApplicationConfig['consent.scopeDescriptions'] = {};
		try {
			const page = await openConsent(
				{ client_id: 'own-app', scope: 'openid billing' },
				cookie
			);

			expect(page.text).toContain(T.groups.other);
			expect(page.text).toContain('billing');
		} finally {
			ApplicationConfig['consent.scopeDescriptions'] = {
				billing: 'see your invoices'
			};
		}
	});

	it('says until when the app keeps access when a refresh token will be issued', async () => {
		const page = await openConsent(
			{
				client_id: 'own-app',
				scope: 'openid email offline_access',
				prompt: 'consent'
			},
			cookie
		);

		expect(page.view.keepsAccessUntil).toBeString();
		expect(page.text).toContain(T.lifetime(page.view.keepsAccessUntil ?? ''));
	});

	it('says nothing of long-lived access when the request did not ask for consent and so cannot have it', async () => {
		const page = await openConsent(
			{ client_id: 'own-app', scope: 'openid email offline_access billing' },
			cookie
		);

		expect(page.view.keepsAccessUntil).toBeUndefined();
	});
});

/**
 * @proves The request that would hand an agent the administrator's own power is never shown as anything
 * less, whatever the agent already holds.
 */
describe('the consent page for the administrative MCP', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'consent_page' });
		await ensureAdminSeed();
	});

	function toAdmin(cookie: string) {
		return openConsent(
			{
				client_id: 'own-app',
				scope: 'openid',
				resource: [MCP_RESOURCE],
				prompt: 'consent'
			},
			cookie
		);
	}

	it('shows the administrator-rights block when the request is for the administrative MCP', async () => {
		const cookie = await setup.login({ scope: 'openid' });

		const page = await toAdmin(cookie);

		expect(page.view.warning).toEqual({ kind: 'admin' });
		expect(page.text).toContain(T.warning.adminTitle);
	});

	it('still shows it on a repeat consent after the agent was granted it once', async () => {
		const cookie = await setup.login({ scope: 'openid' });
		const first = await toAdmin(cookie);
		const allowed = await decide(first, 'allow');
		expect(allowed.status).toBe(303);

		const again = await toAdmin(withCookies(first.cookie, allowed));

		expect(again.view.warning).toEqual({ kind: 'admin' });
	});
});
