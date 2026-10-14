import { describe, it, expect, beforeAll } from 'bun:test';

import bootstrap, { agent, setSeedClaims, type Setup } from '../test_helper.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	getProjectStore,
	getProtectedResourceStore
} from 'lib/adapters/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { ROOT_NAMESPACE } from 'lib/resources/namespace.js';
import { decode } from 'lib/helpers/jwt.js';
import { openConsent, decide } from '../consent_page/flow.ts';
import { MCP } from './consent_choices.config.ts';
import { codeOf, grantsOf } from './rows.ts';

interface Tokens {
	access_token: string;
	id_token?: string;
	refresh_token?: string;
	scope?: string;
}

function scopeSet(scope: string | undefined): string[] {
	return (scope ?? '').split(' ').filter(Boolean).sort();
}

/**
 * @proves An application whose operator lets people choose receives exactly what the person ticked and
 * what signing in needs — in its tokens, its ID token and its userinfo — and nothing the person left out.
 */
describe('what an application receives after a partial allow', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'consent_choices' });
		await ensureAdminSeed();
		const project = await getProjectStore().create({
			name: 'Company',
			slug: 'company-outcome',
			ownerGroupId: UNASSIGNED_GROUP_ID
		});
		await getProtectedResourceStore().create({
			namespace: ROOT_NAMESPACE,
			identifier: MCP,
			projectId: project._id,
			name: 'Company MCP',
			scopes: ['tools:read', 'tools:call']
		});
		setSeedClaims({ phone_number: '+1 555 0100' });
	});

	async function allowAndRedeem(
		params: Record<string, unknown>,
		ticked: string[]
	): Promise<Tokens> {
		const cookie = await setup.login({ scope: 'openid' });
		const page = await openConsent(
			{ client_id: 'partial-app', ...params },
			cookie
		);
		const decided = await decide(page, 'allow', undefined, ticked);
		expect(decided.status).toBe(303);
		const response = await page.auth.getToken(codeOf(decided));
		expect(response.status).toBe(200);
		return response.data as Tokens;
	}

	it('issues a token whose scope holds only the ticked items and the sign-in items after a partial allow', async () => {
		const tokens = await allowAndRedeem(
			{ scope: 'openid email phone billing' },
			['scope:billing']
		);

		expect(scopeSet(tokens.scope)).toEqual(['billing', 'email', 'openid']);
	});

	it('leaves the phone number out of the ID token and userinfo when its row was left unticked, even when the request marked it essential', async () => {
		const tokens = await allowAndRedeem(
			{
				scope: 'openid email phone billing',
				claims: {
					id_token: { phone_number: { essential: true } },
					userinfo: { phone_number: { essential: true } }
				}
			},
			['scope:billing']
		);

		expect(decode(tokens.id_token ?? '').payload).not.toHaveProperty(
			'phone_number'
		);
		const { data } = await agent.userinfo.get({
			headers: { authorization: `Bearer ${tokens.access_token}` }
		});
		const info = data as Record<string, unknown>;
		expect(info).toHaveProperty('email');
		expect(info).not.toHaveProperty('phone_number');
	});

	it('issues no refresh token when keeping access was left unticked', async () => {
		const tokens = await allowAndRedeem(
			{ scope: 'openid offline_access billing', prompt: 'consent' },
			['scope:billing']
		);

		expect(tokens.refresh_token).toBeUndefined();
	});

	it('issues a refresh token when keeping access was ticked', async () => {
		const tokens = await allowAndRedeem(
			{ scope: 'openid offline_access billing', prompt: 'consent' },
			['oidc:offline']
		);

		expect(tokens.refresh_token).toBeString();
	});

	it('signs the person in with the sign-in items only when nothing is ticked', async () => {
		const tokens = await allowAndRedeem(
			{ scope: 'openid email phone billing' },
			[]
		);

		expect(scopeSet(tokens.scope)).toEqual(['email', 'openid']);
	});

	it('refuses the application and records nothing when nothing is ticked and nothing for signing in was asked', async () => {
		const cookie = await setup.login({ scope: 'openid' });
		const before = grantsOf('partial-app');
		expect(before).not.toBe('[]');
		const page = await openConsent(
			{
				client_id: 'partial-app',
				scope: 'tools:read tools:call',
				resource: [MCP]
			},
			cookie
		);

		const decided = await decide(page, 'allow', undefined, []);

		expect(decided.status).toBe(303);
		const location = URL.parse(decided.headers.get('location') ?? '');
		expect(location?.searchParams.get('error')).toBe('access_denied');
		expect(grantsOf('partial-app')).toBe(before);
	});
});
