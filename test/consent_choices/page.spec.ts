import { describe, it, expect, beforeAll } from 'bun:test';

import bootstrap, { type Setup } from '../test_helper.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	getProjectStore,
	getProtectedResourceStore
} from 'lib/adapters/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { ROOT_NAMESPACE } from 'lib/resources/namespace.js';
import { CONSENT_TEXTS as T } from 'lib/interactions/consentTexts.js';
import { openConsent, decide, withCookies } from '../consent_page/flow.ts';
import { MCP, PAYMENT } from './consent_choices.config.ts';
import { checkboxes } from './rows.ts';

/**
 * @proves A person signing in to an application its operator marked as coping with partial access can
 * leave out each thing it asks for beyond signing in, starting from nothing ticked — and every other
 * application keeps the all-or-nothing page.
 */
describe('the consent page with choices', () => {
	let setup: Setup;
	let cookie: string;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'consent_choices' });
		await ensureAdminSeed();
		const project = await getProjectStore().create({
			name: 'Company',
			slug: 'company-choices',
			ownerGroupId: UNASSIGNED_GROUP_ID
		});
		await getProtectedResourceStore().create({
			namespace: ROOT_NAMESPACE,
			identifier: MCP,
			projectId: project._id,
			name: 'Company MCP',
			scopes: ['tools:read', 'tools:call'],
			scopeDescriptions: {
				'tools:read': { description: 'see your projects', kind: 'see' },
				'tools:call': { description: 'create and update issues' }
			}
		});
		cookie = await setup.login({ scope: 'openid' });
	});

	it('draws each item beyond signing in as an unticked checkbox, and the sign-in items without one, when the client handles partial access', async () => {
		const page = await openConsent(
			{
				client_id: 'partial-app',
				scope: 'openid email phone billing tools:read tools:call',
				resource: [MCP]
			},
			cookie
		);

		const boxes = checkboxes(page.html);
		expect(boxes.map((b) => b.value).sort()).toEqual(
			[
				'oidc:phone',
				'scope:billing',
				`resource:${MCP} tools:read`,
				`resource:${MCP} tools:call`
			].sort()
		);
		expect(boxes.every((b) => !b.checked)).toBe(true);
		expect(page.text).toContain(T.choices.fixedHeading);
		const fixed = page.text.slice(
			page.text.indexOf(T.choices.fixedHeading),
			page.text.indexOf(T.groups.see)
		);
		expect(fixed).toContain(T.categories.email);
		expect(page.view.mode).toBe('full');
	});

	it('is the all-or-nothing page when the client does not handle partial access', async () => {
		const page = await openConsent(
			{
				client_id: 'plain-app',
				scope: 'openid email phone billing tools:read tools:call',
				resource: [MCP]
			},
			cookie
		);

		expect(checkboxes(page.html)).toEqual([]);
		expect(page.view.choices).toBeUndefined();
	});

	it('is the all-or-nothing page when only one item could be left out', async () => {
		const page = await openConsent(
			{ client_id: 'partial-app', scope: 'openid email phone' },
			cookie
		);

		expect(checkboxes(page.html)).toEqual([]);
		expect(page.view.choices).toBeUndefined();
	});

	it('offers the phone number when the person has none on record', async () => {
		const page = await openConsent(
			{ client_id: 'partial-app', scope: 'openid phone billing' },
			cookie
		);

		expect(checkboxes(page.html).map((b) => b.value)).toContain('oidc:phone');
		expect(page.text).toContain(T.categories.phone);
	});

	it('makes keeping access a row of its own carrying the date when a refresh token would be issued', async () => {
		const page = await openConsent(
			{
				client_id: 'partial-app',
				scope: 'openid offline_access billing',
				prompt: 'consent'
			},
			cookie
		);

		expect(checkboxes(page.html).map((b) => b.value)).toContain('oidc:offline');
		const until = page.view.keepsAccessUntil ?? '';
		expect(until).not.toBe('');
		expect(page.text).toContain(T.choices.offline);
		expect(page.text).toContain(T.choices.offlineUntil(until));
		expect(page.text).not.toContain(T.lifetime(until));
	});
	it('sums up only what is certain and says the rest depends on the selection on an escalation with choices', async () => {
		const signedIn = await setup.login({ scope: 'openid email' });
		const page = await openConsent(
			{
				client_id: 'partial-app',
				scope: 'openid email billing tools:call offline_access',
				resource: [MCP],
				prompt: 'consent'
			},
			signedIn
		);

		const summary = page.text.slice(
			page.text.indexOf(T.repeat.afterApproval),
			page.text.indexOf(T.buttons.deny)
		);
		expect(summary).toContain(T.categories.email);
		expect(summary).toContain(T.choices.afterApprovalRest);
		expect(summary).not.toContain('create and update issues');
		expect(summary).not.toContain('billing');
	});

	it('leaves an item refused before out of the already-allowed line', async () => {
		const signedIn = await setup.login({ scope: 'openid' });
		const first = await openConsent(
			{ client_id: 'partial-app', scope: 'openid phone billing' },
			signedIn
		);
		const decided = await decide(first, 'allow', undefined, ['scope:billing']);

		const page = await openConsent(
			{
				client_id: 'partial-app',
				scope: 'openid phone billing groups',
				prompt: 'consent'
			},
			withCookies(first.cookie, decided)
		);

		const already = page.text.slice(
			page.text.indexOf(T.repeat.alreadyAllowed),
			page.text.indexOf(T.repeat.alsoAsks)
		);
		expect(already).toContain('billing');
		expect(already).not.toContain(T.categories.phone);
	});

	it('gives authorization details no checkbox and says they come with the rest', async () => {
		const page = await openConsent(
			{
				client_id: 'partial-app',
				scope: 'openid phone billing',
				resource: [MCP],
				authorization_details: [{ type: PAYMENT, actions: ['initiate'] }]
			},
			cookie
		);

		expect(
			checkboxes(page.html)
				.map((b) => b.value)
				.sort()
		).toEqual(['oidc:phone', 'scope:billing']);
		expect(page.text).toContain('Initiate a payment');
		expect(page.text).toContain(T.choices.rarTogether);
	});
});
