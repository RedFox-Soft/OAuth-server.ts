import { describe, it, expect, beforeAll } from 'bun:test';

import bootstrap, { type Setup } from '../test_helper.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getProtectedResourceStore } from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { ROOT_NAMESPACE } from 'lib/resources/namespace.js';
import { openConsent, decide } from '../consent_page/flow.ts';
import { MCP } from './consent_choices.config.ts';
import { codeOf, grantsOf } from './rows.ts';

/**
 * @proves What comes back from the consent page can only narrow what the server offered: a submission
 * naming anything the page did not draw, or choosing where there was no choice, changes nothing — and a
 * partial allow never takes back what the person allowed before.
 */
describe('a consent submission that the page did not produce', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'consent_choices' });
		await ensureAdminSeed();
		await getProtectedResourceStore().create({
			namespace: ROOT_NAMESPACE,
			identifier: MCP,
			bucketId: DEFAULT_BUCKET_ID,
			name: 'Company MCP',
			scopes: ['tools:read', 'tools:call']
		});
	});

	async function refusedWithNothingWritten(
		clientId: string,
		params: Record<string, unknown>,
		allow: string[],
		accountId?: string
	) {
		const cookie = await setup.login({ scope: 'openid' });
		const page = await openConsent({ client_id: clientId, ...params }, cookie);
		const before = grantsOf(clientId);

		const response = await decide(page, 'allow', accountId, allow);

		expect(response.status).toBeGreaterThanOrEqual(400);
		expect(response.headers.get('location')).toBeNull();
		expect(grantsOf(clientId)).toBe(before);
	}

	it('is refused and changes nothing on the grant when it names an item the page did not offer', async () => {
		await refusedWithNothingWritten(
			'partial-app',
			{ scope: 'openid phone billing' },
			['scope:billing', 'resource:https://elsewhere.test/api x']
		);
	});

	it('is refused when it names a row of the right shape for something not asked', async () => {
		await refusedWithNothingWritten(
			'partial-app',
			{ scope: 'openid phone billing' },
			['oidc:address']
		);
	});

	it('is refused when it names a sign-in item as if it were a row', async () => {
		await refusedWithNothingWritten(
			'partial-app',
			{ scope: 'openid email phone billing' },
			['oidc:email']
		);
	});

	it('is refused when the client does not handle partial access', async () => {
		await refusedWithNothingWritten(
			'plain-app',
			{ scope: 'openid phone billing' },
			['scope:billing']
		);
	});

	it('is refused when only one item could have been left out', async () => {
		await refusedWithNothingWritten(
			'partial-app',
			{ scope: 'openid email phone' },
			['oidc:phone']
		);
	});

	it('is refused when a selection is posted for another account than the one shown', async () => {
		await refusedWithNothingWritten(
			'partial-app',
			{ scope: 'openid phone billing' },
			['scope:billing'],
			'somebody-else'
		);
	});

	it('keeps what the person allowed before when a partial allow leaves the new items unticked', async () => {
		const cookie = await setup.login({
			scope: 'openid',
			resources: { [MCP]: 'tools:read' }
		});
		const page = await openConsent(
			{
				client_id: 'partial-app',
				scope: 'openid billing tools:read tools:call',
				resource: [MCP],
				prompt: 'consent'
			},
			cookie
		);

		const decided = await decide(page, 'allow', undefined, []);
		const response = await page.auth.getToken(codeOf(decided));

		expect(response.status).toBe(200);
		const scope = ((response.data as { scope?: string }).scope ?? '').split(
			' '
		);
		expect(scope).toContain('tools:read');
		expect(scope).not.toContain('tools:call');
		expect(scope).not.toContain('billing');
	});
});
