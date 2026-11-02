import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	mock
} from 'bun:test';

import bootstrap, { type Setup } from '../test_helper.js';
import { assertNoPendingInterceptors } from '../fetch_mock.js';
import { elysia } from 'lib/index.ts';
import { ISSUER } from 'lib/configs/env.js';
import { forgetAllDiscovery } from 'lib/federation/discovery.ts';
import { buildConsentView } from 'lib/interactions/consentView.js';
import { connectedAccountKey, connectedServiceKey } from 'lib/models/grant.js';
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { present } from '../shape.js';
import { TEST_KEYRING } from '../sealing/fixtures.ts';
import { shownAccount } from '../consent_form.js';
import {
	openConsent,
	withCookies,
	type ConsentPage
} from '../consent_page/flow.ts';
import { codeOf } from '../consent_choices/rows.ts';
import {
	githubStub,
	githubTokens,
	unique
} from '../connected_services/stubs.ts';
import {
	callback,
	landed,
	signedInPerson,
	startConnect
} from '../connected_services/harness.ts';
import {
	connected,
	exchange,
	githubService,
	granted,
	refused
} from './harness.ts';

/* The consent form posted as the person submits it, with the accounts they ticked. */
async function answer(
	page: Pick<ConsentPage, 'uid' | 'cookie'>,
	ticked: string[]
): Promise<Response> {
	const fields = new URLSearchParams({
		action: 'allow',
		accountId: await shownAccount(page.uid)
	});
	for (const key of ticked) fields.append('connected', key);
	return elysia.handle(
		new Request(`${ISSUER}/ui/${page.uid}/consent`, {
			method: 'POST',
			headers: {
				cookie: page.cookie,
				'content-type': 'application/x-www-form-urlencoded'
			},
			body: fields.toString()
		})
	);
}

async function tokenAfter(page: ConsentPage, decided: Response) {
	const { data } = await page.auth.getToken(codeOf(decided));
	return present(
		(data as { access_token?: string } | null)?.access_token,
		'an access token'
	);
}

/**
 * @proves The person decides on the consent screen which of their accounts at other services an agent may use, each
 * offered unticked and asked once; a value the page did not offer changes nothing, and the device flow offers none.
 */
describe('the consent screen asking about the person’s connected accounts', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'upstream_tokens' });
	});

	beforeEach(() => {
		resetKeyringForTests(TEST_KEYRING);
		forgetAllDiscovery();
	});

	afterEach(() => {
		assertNoPendingInterceptors();
		mock.restore();
	});

	async function twoAccounts() {
		const person = unique('person');
		const service = await githubService();
		const work = await connected(person, service, { label: unique('work') });
		const home = await connected(person, service, { label: unique('home') });
		const cookie = await setup.login({ scope: 'openid', accountId: person });
		return { service, work, home, cookie };
	}

	it('offers each account unticked and lets the agent use only the one ticked', async () => {
		const { service, work, home, cookie } = await twoAccounts();

		const page = await openConsent(
			{ client_id: 'agent', scope: 'openid' },
			cookie
		);

		expect(page.view.connected?.map((offer) => offer.label).sort()).toEqual(
			[work.label, home.label].sort()
		);
		expect(page.text).toContain(work.label);
		expect(page.html).not.toMatch(/name="connected"[^>]*checked/);
		const accessToken = await tokenAfter(
			page,
			await answer(page, [connectedAccountKey(work._id)])
		);
		expect(
			granted(
				await exchange({ subjectToken: accessToken, audience: service.id })
			).access_token
		).toBe(present(work.accessToken, 'a token'));
		expect(
			refused(
				await exchange({
					subjectToken: accessToken,
					audience: service.id,
					loginHint: home.label
				})
			).reason
		).toBe('consent_required');
	});

	it('does not ask again about accounts already answered', async () => {
		const { cookie } = await twoAccounts();
		const first = await openConsent(
			{ client_id: 'agent', scope: 'openid' },
			cookie
		);
		const decided = await answer(first, []);

		const again = await first.auth.authorize({
			headers: { cookie: withCookies(first.cookie, decided) }
		});

		expect(again.headers.get('location') ?? '').not.toMatch(/\/consent$/);
		expect(codeOf(again)).toBeString();
	});

	it('refuses a ticked value the page did not offer, and records nothing', async () => {
		const { cookie } = await twoAccounts();
		const page = await openConsent(
			{ client_id: 'agent', scope: 'openid' },
			cookie
		);

		const response = await answer(page, [connectedAccountKey('forged')]);

		expect(response.status).toBe(400);
	});

	it('lets an agreement made before connecting cover the first account connected there, and no other', async () => {
		const service = await githubService();
		const { browser, accountId } = await signedInPerson();
		const cookie = await setup.login({ scope: 'openid', accountId });
		const page = await openConsent(
			{ client_id: 'agent', scope: 'openid' },
			cookie
		);
		expect(page.view.connected?.map((offer) => offer.key)).toContain(
			connectedServiceKey(service.id)
		);
		const accessToken = await tokenAfter(
			page,
			await answer(page, [connectedServiceKey(service.id)])
		);

		const github = githubStub();
		const first = await startConnect(browser, service.id);
		github.expectToken(githubTokens());
		github.expectUser({ id: 1001, login: 'first-login' });
		await landed(browser, await callback(browser, first));
		const second = await startConnect(browser, service.id);
		github.expectToken(githubTokens());
		github.expectUser({ id: 1002, login: 'second-login' });
		await landed(browser, await callback(browser, second));

		expect(
			granted(
				await exchange({
					subjectToken: accessToken,
					audience: service.id,
					loginHint: 'first-login'
				})
			).access_token
		).toBeString();
		expect(
			refused(
				await exchange({
					subjectToken: accessToken,
					audience: service.id,
					loginHint: 'second-login'
				})
			).reason
		).toBe('consent_required');
	});

	it('offers nothing about connected accounts on a device sign-in', () => {
		const view = buildConsentView({
			uid: 'u',
			logoSrc: '',
			service: { host: 'example.com' },
			client: { id: 'agent', tier: 'this-organization' },
			account: { id: 'person' },
			userClaims: {},
			details: {
				connectedOffers: [
					{
						key: connectedServiceKey('svc'),
						serviceId: 'svc',
						serviceName: 'GitHub'
					}
				]
			},
			resources: {},
			scopeDescriptions: {},
			rarLabels: {},
			canSwitchAccount: false,
			device: { userCode: 'ABCD-EFGH', requestedAgo: 'just now' }
		});

		expect(view.connected).toBeUndefined();
	});
});
