import { describe, it, expect, beforeAll, afterEach } from 'bun:test';

import bootstrap, { setSeedClaims, type Setup } from '../test_helper.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	getProjectStore,
	getProtectedResourceStore
} from 'lib/adapters/index.ts';
import { UNASSIGNED_GROUP_ID, DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { ROOT_NAMESPACE } from 'lib/resources/namespace.js';
import { CONSENT_TEXTS } from 'lib/i18n/texts/consent/index.ts';
import { text as fill } from 'lib/i18n/message.tsx';

const T = CONSENT_TEXTS.en;
import { MCP } from './consent_page.config.ts';
import { openConsent } from './flow.ts';

/**
 * @proves When an application asks for more than it already has, the person sees what they allowed
 * before in one line, is asked only about what is new, and — when the new part lets the app act or keep
 * access — is shown everything the app will hold once they agree.
 */
describe('the consent page when an application asks for more', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'consent_page' });
		await ensureAdminSeed();
		const project = await getProjectStore().create({
			bucketId: DEFAULT_BUCKET_ID,
			name: 'Company',
			slug: 'company-repeat',
			ownerGroupId: UNASSIGNED_GROUP_ID
		});
		await getProtectedResourceStore().create({
			namespace: ROOT_NAMESPACE,
			identifier: MCP,
			projectId: project._id,
			name: 'Company MCP',
			scopes: ['tools:call'],
			scopeDescriptions: {
				'tools:call': { description: 'run the service’s tools as you' }
			}
		});
	});

	afterEach(() => {
		setSeedClaims(undefined);
	});

	it('names what was allowed before and lists only what is new', async () => {
		const cookie = await setup.login({ scope: 'openid email' });

		const page = await openConsent(
			{
				client_id: 'own-app',
				scope: 'openid email tools:call',
				resource: [MCP]
			},
			cookie
		);

		expect(page.text).toContain(
			fill(T.repeat.alreadyAllowed, { items: T.categories.email })
		);
		const asked = page.text.slice(page.text.indexOf(T.repeat.alsoAsks));
		expect(asked).toContain('run the service’s tools as you');
		expect(asked.slice(0, asked.indexOf(T.repeat.afterApproval))).not.toContain(
			T.categories.email
		);
	});

	it('sums up everything the app will hold when the new part lets it act', async () => {
		const cookie = await setup.login({ scope: 'openid email' });

		const page = await openConsent(
			{
				client_id: 'own-app',
				scope: 'openid email tools:call',
				resource: [MCP]
			},
			cookie
		);

		expect(page.text).toContain(
			`${T.repeat.afterApproval} ${fill(T.repeat.afterApprovalItems, { items: `${T.categories.email} and run the service’s tools as you` })}`
		);
	});

	it('sums up everything the app will hold when the new part is long-lived access', async () => {
		const cookie = await setup.login({ scope: 'openid email' });

		const page = await openConsent(
			{
				client_id: 'own-app',
				scope: 'openid email phone offline_access',
				prompt: 'consent'
			},
			cookie
		);

		expect(page.view.afterApproval.length).toBeGreaterThan(0);
	});

	it('does not sum up when the new part is only more personal data', async () => {
		setSeedClaims({ name: 'Anna Ivanova' });
		const cookie = await setup.login({ scope: 'openid email' });

		const page = await openConsent(
			{ client_id: 'own-app', scope: 'openid email profile' },
			cookie
		);

		expect(page.text).toContain(T.categories.profileName);
		expect(page.view.afterApproval).toEqual([]);
	});
});
