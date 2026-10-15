import { describe, it, expect, beforeAll } from 'bun:test';

import bootstrap, { type Setup } from '../test_helper.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	getProjectStore,
	getProtectedResourceStore
} from 'lib/adapters/index.ts';
import { UNASSIGNED_GROUP_ID, DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { ROOT_NAMESPACE } from 'lib/resources/namespace.js';
import { CONSENT_TEXTS } from 'lib/i18n/texts/consent/index.ts';

const T = CONSENT_TEXTS.en;
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { openConsent, decide, withCookies } from '../consent_page/flow.ts';
import { MCP } from './consent_choices.config.ts';
import { checkboxes, codeOf } from './rows.ts';

type Params = ConstructorParameters<typeof AuthorizationRequest>[0];

function scopeOf(data: unknown): string[] {
	return ((data as { scope?: string }).scope ?? '').split(' ').filter(Boolean);
}

/**
 * @proves A permission the person refused is not refused forever: an application that asks again with
 * prompt=consent is shown it again, marked as refused last time, and once allowed it is issued from then on
 * — while an application that does not ask again simply goes without it, and the person is not asked on
 * every sign-in.
 */
describe('a permission the person refused before', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'consent_choices' });
		await ensureAdminSeed();
		const project = await getProjectStore().create({
			bucketId: DEFAULT_BUCKET_ID,
			name: 'Company',
			slug: 'company-refusal',
			ownerGroupId: UNASSIGNED_GROUP_ID
		});
		await getProtectedResourceStore().create({
			namespace: ROOT_NAMESPACE,
			identifier: MCP,
			projectId: project._id,
			name: 'Company MCP',
			scopes: ['tools:read', 'tools:call']
		});
	});

	/* A signed-in browser whose person allowed `billing` and refused their phone number and address. */
	async function afterRefusingPhoneAndAddress(): Promise<string> {
		const cookie = await setup.login({ scope: 'openid' });
		const page = await openConsent(
			{ client_id: 'partial-app', scope: 'openid phone address billing' },
			cookie
		);
		const decided = await decide(page, 'allow', undefined, ['scope:billing']);
		expect(decided.status).toBe(303);
		return withCookies(page.cookie, decided);
	}

	/* An authorization that needs no page: the browser goes straight back to the client with a code. */
	async function straightThrough(params: Params, cookie: string) {
		const auth = new AuthorizationRequest(params);
		const response = await auth.authorize({ headers: { cookie } });
		expect(response.status).toBe(303);
		const token = await auth.getToken(codeOf(response));
		expect(token.status).toBe(200);
		return scopeOf(token.data);
	}

	it('is offered again and marked as refused last time when the client sends prompt=consent', async () => {
		const cookie = await afterRefusingPhoneAndAddress();

		const page = await openConsent(
			{
				client_id: 'partial-app',
				scope: 'openid phone address',
				prompt: 'consent'
			},
			cookie
		);

		expect(
			checkboxes(page.html)
				.map((b) => b.value)
				.sort()
		).toEqual(['oidc:address', 'oidc:phone']);
		expect(page.text).toContain(T.choices.refusedBefore);
	});

	it('is issued without asking from then on once allowed on a page it was offered again on', async () => {
		const cookie = await afterRefusingPhoneAndAddress();
		const page = await openConsent(
			{
				client_id: 'partial-app',
				scope: 'openid phone address',
				prompt: 'consent'
			},
			cookie
		);
		const decided = await decide(page, 'allow', undefined, [
			'oidc:phone',
			'oidc:address'
		]);
		const jar = withCookies(page.cookie, decided);

		const scope = await straightThrough(
			{ client_id: 'partial-app', scope: 'openid phone address' },
			jar
		);

		expect(scope).toContain('phone');
		expect(scope).toContain('address');
	});

	it('is left out without a consent page when the client asks for it without prompt=consent', async () => {
		const cookie = await afterRefusingPhoneAndAddress();

		const scope = await straightThrough(
			{ client_id: 'partial-app', scope: 'openid phone billing' },
			cookie
		);

		expect(scope).toContain('billing');
		expect(scope).not.toContain('phone');
	});

	it('is not offered beside a new item when the client asks without prompt=consent', async () => {
		const cookie = await afterRefusingPhoneAndAddress();

		const page = await openConsent(
			{
				client_id: 'partial-app',
				scope: 'openid phone address tools:read tools:call',
				resource: [MCP]
			},
			cookie
		);

		expect(
			checkboxes(page.html)
				.map((b) => b.value)
				.sort()
		).toEqual(
			[`resource:${MCP} tools:call`, `resource:${MCP} tools:read`].sort()
		);
		expect(page.text).not.toContain(T.choices.refusedBefore);
	});

	it('is offered again on the all-or-nothing page when a client without partial access sends prompt=consent', async () => {
		const cookie = await setup.login({
			scope: 'openid',
			rejectedScopes: ['billing']
		});

		const page = await openConsent(
			{ client_id: 'plain-app', scope: 'openid billing', prompt: 'consent' },
			cookie
		);

		expect(checkboxes(page.html)).toEqual([]);
		expect(page.view.groups.other.items.map((i) => i.codes)).toEqual([
			['billing']
		]);
		expect(page.text).toContain(T.choices.refusedBefore);
	});

	it('is issued without asking from then on once allowed on the all-or-nothing page', async () => {
		const cookie = await setup.login({
			scope: 'openid',
			rejectedScopes: ['billing']
		});
		const page = await openConsent(
			{ client_id: 'plain-app', scope: 'openid billing', prompt: 'consent' },
			cookie
		);
		const decided = await decide(page, 'allow');
		const jar = withCookies(page.cookie, decided);

		const scope = await straightThrough(
			{ client_id: 'plain-app', scope: 'openid billing' },
			jar
		);

		expect(scope).toContain('billing');
	});
});
